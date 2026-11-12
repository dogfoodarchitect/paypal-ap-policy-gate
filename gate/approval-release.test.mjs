/**
 * approval-release.test.mjs — Run 5 (approval and release), simulation transport only: no keys, no network.
 * Gate behaviour is exercised on the real PolicyGate; the runner's simulation receipt is checked by the
 * unmodified verifier (child process).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { ReceiptLedger } from './receipt-ledger.mjs';
import { PolicyGate, DEFAULT_AP_POLICY_GATE_CONFIG, processAgentPaymentProposal } from './policy-gate.mjs';
import { PayPalSandboxClient } from './paypal-client.mjs';
import { runApprovalRelease } from './run-approval-release.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TS = '2026-11-11T12:00:00.000Z';
const APPROVER = 'Dana Whitfield, AP manager';
const SUITE = JSON.parse(fs.readFileSync(path.join(HERE, 'approval-release-suite.json'), 'utf8'));
const rec = (id) => SUITE.records.find((r) => r.suiteId === id);
const asProposal = (id, over = {}) => ({ ...rec(id).honestProposal, agentId: 'agent:test', ...over });

function rig() {
  const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const ledger = new ReceiptLedger({ genesisTimestamp: TS });
  const client = new PayPalSandboxClient({ mode: 'simulation' });
  const send = (proposal) =>
    processAgentPaymentProposal({ proposal, policyGate: gate, paypalClient: client, ledger, timestamp: TS, captureImmediately: true });
  return { gate, ledger, client, send };
}
const stages = (ledger, proposalId) => ledger.entries.filter((e) => e.proposalId === proposalId).map((e) => e.stage);

async function heldPair() {
  const r = rig();
  const p1 = asProposal('R5-01');
  const p2 = asProposal('R5-02');
  assert.equal((await r.send(p1)).status, 'EXECUTED');
  const held = await r.send(p2);
  assert.equal(held.status, 'HELD');
  assert.equal(held.verdict.reasonCode, 'POSSIBLE_DUPLICATE_PAYMENT');
  assert.equal(held.apiCallsDelta, 0);
  return { ...r, p1, p2 };
}

test('1. held, approved by a named person, released under a new proposal id and paid with order, capture, read-back', async () => {
  const { gate, ledger, send, p2 } = await heldPair();
  const ap = gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  assert.equal(ap.status, 'APPROVED');
  assert.equal(ap.idempotent, false);
  assert.equal(ledger.entries.at(-1).stage, 'APPROVED');
  assert.equal(ledger.entries.at(-1).proposalId, p2.proposalId);
  const release = { ...p2, proposalId: `${p2.proposalId}-release` };
  const paid = await send(release);
  assert.equal(paid.status, 'EXECUTED');
  assert.equal(paid.apiCallsDelta, 3);
  assert.ok(paid.order.id && paid.capture.id);
  assert.deepEqual(stages(ledger, release.proposalId), ['PROPOSED', 'ADMITTED', 'EXECUTED']);
});

test('2. an unapproved held proposal is not released: the same hold comes back, 0 PayPal calls', async () => {
  const { send, p2 } = await heldPair();
  const again = await send({ ...p2, proposalId: `${p2.proposalId}-release` });
  assert.equal(again.status, 'HELD');
  assert.equal(again.apiCallsDelta, 0);
});

test('3. approval DENIED at re-check: OVER_DAILY_SPEND_CAP, no ledger entry, 0 PayPal calls (runner scenario)', async () => {
  const receipt = await runApprovalRelease({ simulate: true });
  const denied = receipt.approverSteps.find((s) => s.action === 'approve' && s.target === 'R5-05');
  assert.equal(denied.status, 'DENIED');
  assert.equal(denied.ok, false);
  assert.equal(denied.verdict.reasonCode, 'OVER_DAILY_SPEND_CAP');
  assert.equal(denied.signedLedgerEntryIndex, null);
  assert.equal(denied.ledgerEntriesAdded, 0);
  assert.equal(receipt.ledger.entries.filter((e) => e.stage === 'APPROVED').length, 1);
});

test('4. reject is terminal: approve after reject throws NOT_HELD, release stays HELD-free of PayPal calls', async () => {
  const { gate, ledger, send, p2 } = await heldPair();
  const rj = gate.rejectHeldProposal(p2, { rejectedBy: APPROVER, timestamp: TS, ledger });
  assert.equal(rj.status, 'REJECTED');
  assert.equal(ledger.entries.at(-1).stage, 'REJECTED');
  assert.throws(() => gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger }), /NOT_HELD/);
  assert.throws(() => gate.rejectHeldProposal(p2, { rejectedBy: APPROVER, timestamp: TS, ledger }), /NOT_HELD/);
  const sent = await send({ ...p2, proposalId: `${p2.proposalId}-release` });
  assert.notEqual(sent.status, 'EXECUTED');
  assert.equal(sent.apiCallsDelta, 0);
});

test('5. second approval: same name is idempotent (no new entry); a different name throws ALREADY_APPROVED', async () => {
  const { gate, ledger, p2 } = await heldPair();
  gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  const n = ledger.entries.length;
  const same = gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  assert.equal(same.ok, true);
  assert.equal(same.idempotent, true);
  assert.equal(same.status, 'APPROVED');
  assert.equal(ledger.entries.length, n);
  assert.throws(
    () => gate.approveHeldProposal(p2, { approvedBy: 'Someone Else, controller', timestamp: TS, ledger }),
    /ALREADY_APPROVED: this held payment has already been approved once/
  );
  assert.equal(ledger.entries.length, n);
});

test('6. reject after approve throws ALREADY_APPROVED', async () => {
  const { gate, ledger, p2 } = await heldPair();
  gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  assert.throws(() => gate.rejectHeldProposal(p2, { rejectedBy: APPROVER, timestamp: TS, ledger }), /ALREADY_APPROVED/);
});

test('7. a paid proposal sent again under the SAME proposal id: DENY DUPLICATE_PROPOSAL, REFUSED, 0 PayPal calls', async () => {
  const { gate, ledger, send, p2 } = await heldPair();
  gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  const release = { ...p2, proposalId: `${p2.proposalId}-release` };
  assert.equal((await send(release)).status, 'EXECUTED');
  const again = await send(release);
  assert.equal(again.status, 'REFUSED');
  assert.equal(again.verdict.decision, 'DENY');
  assert.equal(again.verdict.reasonCode, 'DUPLICATE_PROPOSAL');
  assert.equal(again.apiCallsDelta, 0);
});

test('8. the approved payment sent again under ANOTHER new proposal id: REFUSED DUPLICATE_INVOICE, 0 calls (an approval pays once)', async () => {
  const { gate, ledger, send, p2 } = await heldPair();
  gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  assert.equal((await send({ ...p2, proposalId: `${p2.proposalId}-release` })).status, 'EXECUTED');
  const again = await send({ ...p2, proposalId: `${p2.proposalId}-again` });
  assert.equal(again.status, 'REFUSED');
  assert.equal(again.verdict.reasonCode, 'DUPLICATE_INVOICE');
  assert.equal(again.apiCallsDelta, 0);
});

test('9. the approval is bound to the exact proposal: another invoice number with the same fields does not ride it', async () => {
  const { gate, ledger, send, p2 } = await heldPair();
  gate.approveHeldProposal(p2, { approvedBy: APPROVER, timestamp: TS, ledger });
  assert.throws(() => gate.approveHeldProposal({ ...p2, amountValue: '1001.00' }, { approvedBy: APPROVER, timestamp: TS, ledger }), /NOT_HELD/);
  const other = await send({ ...p2, proposalId: 'other-id', invoiceId: 'INV-2026-9999' });
  assert.equal(other.status, 'HELD');
  assert.equal(other.apiCallsDelta, 0);
});

test('10. runner scenario in simulation: 8 passes, 4 paid = 4300.00, 1 rejected, 1 approval denied, 1 refusal, 6 model calls', async () => {
  const r = await runApprovalRelease({ simulate: true });
  assert.equal(r.suiteRecords.length, 8);
  assert.deepEqual(
    r.suiteRecords.map((x) => `${x.suiteId}:${x.outcome}:${x.reasonCode}`),
    [
      'R5-01:EXECUTED:POLICY_ADMITTED',
      'R5-02:HELD:POSSIBLE_DUPLICATE_PAYMENT',
      'R5-03:HELD:POSSIBLE_DUPLICATE_PAYMENT',
      'R5-02-RELEASE:EXECUTED:POLICY_ADMITTED',
      'R5-02-AGAIN:REFUSED:DUPLICATE_INVOICE',
      'R5-04:EXECUTED:POLICY_ADMITTED',
      'R5-05:HELD:SUPPLIER_DAILY_TOTAL_OVER_CAP',
      'R5-06:EXECUTED:POLICY_ADMITTED',
    ]
  );
  assert.equal(r.summary.modelCalls, 6);
  assert.equal(r.scoreboard.controlsSettledUsd, '4300.00');
  const st = r.chainVerification.stageCounts;
  assert.equal(st.EXECUTED, 4);
  assert.equal(st.APPROVED, 1);
  assert.equal(st.REJECTED, 1);
  assert.equal(st.REFUSED, 1);
  assert.equal(st.HELD, 3);
  assert.equal(r.approver.clickedByAPerson, false);
});

test('11. a runner receipt passes the unmodified verifier; tamper and forge demos fail it (child processes)', async () => {
  const receipt = await runApprovalRelease({ simulate: true });
  const name = `.tmp-run5-sim-${process.pid}.json`;
  const file = path.join(HERE, name);
  fs.writeFileSync(file, `${JSON.stringify(receipt, null, 2)}\n`);
  try {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'run5-home-'));
    const run = (...a) => spawnSync(process.execPath, ['verify-payments.mjs', name, ...a], { cwd: HERE, env: { ...process.env, HOME: home }, encoding: 'utf8' });
    const ok = run();
    assert.equal(ok.status, 0, ok.stdout);
    assert.match(ok.stdout, /VERDICT: PASS/);
    assert.match(ok.stdout, /8 of 8 records match the signed ledger entries and the suite files/);
    assert.equal(run('--tamper-demo').status, 1);
    assert.equal(run('--forge-rehash-demo').status, 1);
  } finally {
    fs.rmSync(file, { force: true });
  }
});
