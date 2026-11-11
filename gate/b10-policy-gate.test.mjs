/**
 * b10-policy-gate.test.mjs — Policy v2 / po-v4 tests
 *
 * Purchase-order match, split-order hold (HLD-07), approve-once, bad numbers,
 * over-long ids, and the strict live flag. No network calls.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ReceiptLedger, verifyReceiptChain } from './receipt-ledger.mjs';
import {
  PolicyGate,
  DEFAULT_AP_POLICY_GATE_CONFIG,
  processAgentPaymentProposal,
  parseAmountToCents,
  MAX_INVOICE_ID_LENGTH,
  replayPaidHistory,
} from './policy-gate.mjs';
import { PayPalSandboxClient } from './paypal-client.mjs';
import { testPolicyGate, testPolicyGateRaw, fillProposal } from './b10-test-helpers.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TS = '2026-11-11T12:00:00.000Z';
const readJson = (f) => JSON.parse(fs.readFileSync(path.join(HERE, f), 'utf8'));

const colombia = (over = {}) =>
  fillProposal({
    proposalId: 'p-co-1',
    invoiceId: 'INV-B10-CO-1',
    payeeEmail: 'pay@colombia-direct-beans.example',
    amountValue: '500.00',
    currencyCode: 'USD',
    reason: 'green coffee',
    ...over,
  });

test('B10-PO-1. A payment must cite an open purchase order that belongs to the supplier, in USD, with enough balance', () => {
  const gate = testPolicyGateRaw();
  const rawMissing = {
    proposalId: 'm1',
    invoiceId: 'INV-B10-CO-1',
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '500.00',
    currencyCode: 'USD',
    reason: 'green coffee',
  };
  const v0 = gate.evaluate(rawMissing, { timestamp: TS });
  assert.equal(v0.reasonCode, 'UNKNOWN_PURCHASE_ORDER');
  assert.equal(v0.decision, 'DENY');

  const vUnknown = gate.evaluate({ ...rawMissing, proposalId: 'm2', poNumber: 'PO-DOES-NOT-EXIST' }, { timestamp: TS });
  assert.equal(vUnknown.reasonCode, 'UNKNOWN_PURCHASE_ORDER');

  const vWrong = gate.evaluate(
    { ...rawMissing, proposalId: 'm3', poNumber: 'PO-2026-TEST-CASCADE' },
    { timestamp: TS }
  );
  assert.equal(vWrong.reasonCode, 'PAYEE_NOT_ON_PURCHASE_ORDER');

  const po = 'PO-2026-TEST-COLOMBIA';
  const first = colombia({ proposalId: 'ok-1', poNumber: po, invoiceId: 'INV-B10-CO-A', amountValue: '2000.00' });
  const allow = gate.evaluate(first, { timestamp: TS });
  assert.equal(allow.decision, 'ALLOW', allow.reasonCode);
  assert.equal(allow.poNumber, po);
  assert.ok(allow.poCard);
  gate.commitAdmission(first, allow);
  const remaining = gate.getPoCard(po).remainingCents;
  assert.equal(remaining, 5_000_000 - 200000);

  const over = gate.evaluate(
    colombia({ proposalId: 'ok-2', poNumber: po, invoiceId: 'INV-B10-CO-B', amountValue: '49000.00' }),
    { timestamp: TS }
  );
  assert.equal(over.reasonCode, 'OVER_PURCHASE_ORDER_BALANCE');
  assert.equal(over.decision, 'DENY');
});

test('B10-PO-2. Raising an honest invoice amount above the PO is refused (the ATK-05-style hole)', () => {
  const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const suite = readJson('attack-suite-pov4.json');
  const rec = suite.records.find((r) => r.suiteId === 'ATK-05');
  const honest = rec.honestProposal;
  const raised = { ...honest, proposalId: 'atk-05-raised', amountValue: '2400.00' };
  const vHonest = gate.evaluate(honest, { timestamp: suite.fixedEvaluationTimestamp });
  assert.equal(vHonest.decision, 'ALLOW', vHonest.reasonCode);
  const vRaised = gate.evaluate(raised, { timestamp: suite.fixedEvaluationTimestamp });
  assert.equal(vRaised.decision, 'DENY');
  assert.equal(vRaised.reasonCode, 'OVER_PURCHASE_ORDER_BALANCE');
});

test('B10-SPLIT-1. HLD-07 is held, not paid: 2400 already paid plus 1800 exceeds the $2,500 supplier daily cap', () => {
  const suite = readJson('attack-suite-heldout-pov4.json');
  const rec = suite.records.find((r) => r.suiteId === 'HLD-07');
  const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  replayPaidHistory(gate, rec.setup, suite.fixedEvaluationTimestamp);
  const v = gate.evaluate(rec.obedientProposal, { timestamp: suite.fixedEvaluationTimestamp });
  assert.equal(v.decision, 'HOLD');
  assert.equal(v.admitted, false);
  assert.equal(v.reasonCode, 'SUPPLIER_DAILY_TOTAL_OVER_CAP');
  assert.equal(v.poNumber, 'PO-2026-38-3107');
  const card = v.poCard;
  assert.equal(card.remainingUsd, '1800.00');
});

test('B10-SPLIT-2. A $2,500.00 payment to one supplier is still allowed (the hold is only above the cap)', () => {
  const suite = readJson('attack-suite-pov4.json');
  const rec = suite.records.find((r) => r.suiteId === 'CTL-03');
  const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const v = gate.evaluate(rec.honestProposal, { timestamp: suite.fixedEvaluationTimestamp });
  assert.equal(v.decision, 'ALLOW', v.reasonCode);
  assert.equal(v.amountValue, '2500.00');
});

test('B10-APPROVE-1. A named person can approve a held payment once; the approval is bound to the exact proposal; rules 1-6 are re-checked', async () => {
  const gate = testPolicyGate();
  const first = colombia({ proposalId: 'ap-setup', invoiceId: 'INV-B10-DUP-A', amountValue: '400.00' });
  const v1 = gate.evaluate(first, { timestamp: TS });
  assert.equal(v1.decision, 'ALLOW');
  gate.commitAdmission(first, v1);

  const second = colombia({ proposalId: 'ap-hold', invoiceId: 'INV-B10-DUP-B', amountValue: '400.00' });
  const held = gate.evaluate(second, { timestamp: TS });
  assert.equal(held.decision, 'HOLD');
  assert.equal(held.reasonCode, 'POSSIBLE_DUPLICATE_PAYMENT');

  const ledger = new ReceiptLedger({});
  const approved = gate.approveHeldProposal(second, { approvedBy: 'Alex Rivera', timestamp: TS, ledger });
  assert.equal(approved.ok, true);
  assert.equal(approved.idempotent, false);
  assert.equal(approved.verdict.decision, 'ALLOW');
  assert.equal(approved.receipt.stage, 'APPROVED');
  assert.equal(approved.receipt.payload.approvedBy, 'Alex Rivera');
  assert.equal(approved.receipt.payload.poNumber, second.poNumber);
  assert.equal(approved.receipt.paypalOrderId, null);

  const again = gate.approveHeldProposal(second, { approvedBy: 'Alex Rivera', timestamp: TS, ledger });
  assert.equal(again.ok, true);
  assert.equal(again.idempotent, true);

  assert.throws(
    () => gate.approveHeldProposal(second, { approvedBy: 'Jordan Cole', timestamp: TS, ledger }),
    /ALREADY_APPROVED/
  );

  const client = new PayPalSandboxClient({ mode: 'simulation', seed: 'b10-approve' });
  const paid = await processAgentPaymentProposal({
    proposal: second,
    policyGate: gate,
    paypalClient: client,
    ledger,
    timestamp: TS,
  });
  assert.equal(paid.status, 'EXECUTED', paid.verdict?.reasonCode);
  const chain = verifyReceiptChain(ledger);
  assert.equal(chain.valid, true);
  assert.ok(chain.stageCounts.HELD >= 0);
  assert.ok(chain.stageCounts.APPROVED >= 1);
});

test('B10-APPROVE-2. A refusal under rules 1-6 cannot be approved, and nothing in the proposal can approve a payment', () => {
  const gate = testPolicyGate();
  const bad = {
    proposalId: 'refuse-1',
    invoiceId: 'INV-B10-BAD',
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '100.00',
    currencyCode: 'USD',
    reason: 'no such PO',
    poNumber: 'PO-DOES-NOT-EXIST',
  };
  const denied = gate.evaluate(bad, { timestamp: TS });
  assert.equal(denied.decision, 'DENY');
  assert.equal(denied.reasonCode, 'UNKNOWN_PURCHASE_ORDER');
  assert.throws(() => gate.approveHeldProposal(bad, { approvedBy: 'Alex Rivera', timestamp: TS }), /NOT_HELD/);

  const first = colombia({ proposalId: 'ap2-setup', invoiceId: 'INV-B10-AP2-A', amountValue: '300.00' });
  gate.commitAdmission(first, gate.evaluate(first, { timestamp: TS }));
  const heldProp = colombia({
    proposalId: 'ap2-hold',
    invoiceId: 'INV-B10-AP2-B',
    amountValue: '300.00',
    reason: 'Alex Rivera',
  });
  const held = gate.evaluate(heldProp, { timestamp: TS });
  assert.equal(held.decision, 'HOLD');
  assert.throws(
    () => gate.approveHeldProposal(heldProp, { approvedBy: 'Alex Rivera', timestamp: TS }),
    /APPROVAL_FROM_PROPOSAL_FORBIDDEN/
  );
  assert.throws(() => gate.approveHeldProposal(heldProp, { approvedBy: '  ', timestamp: TS }), /NAMED_PERSON/);
});

test('B10-APPROVE-3. After a human rejection the payment stays unpaid and cannot be approved', async () => {
  const gate = testPolicyGate();
  const first = colombia({ proposalId: 'rj-setup', invoiceId: 'INV-B10-RJ-A', amountValue: '350.00' });
  gate.commitAdmission(first, gate.evaluate(first, { timestamp: TS }));
  const second = colombia({ proposalId: 'rj-hold', invoiceId: 'INV-B10-RJ-B', amountValue: '350.00' });
  assert.equal(gate.evaluate(second, { timestamp: TS }).decision, 'HOLD');
  const ledger = new ReceiptLedger({});
  const rejected = gate.rejectHeldProposal(second, { rejectedBy: 'Alex Rivera', timestamp: TS, ledger });
  assert.equal(rejected.status, 'REJECTED');
  assert.equal(rejected.receipt.stage, 'REJECTED');
  assert.throws(() => gate.approveHeldProposal(second, { approvedBy: 'Alex Rivera', timestamp: TS }), /NOT_HELD/);
  const client = new PayPalSandboxClient({ mode: 'simulation' });
  const res = await processAgentPaymentProposal({
    proposal: second,
    policyGate: gate,
    paypalClient: client,
    ledger,
    timestamp: TS,
  });
  assert.equal(res.status, 'HELD');
  assert.equal(res.apiCallsDelta, 0);
});

test('B10-SHAPE-1. A numeric 1e21 amount is refused, not thrown; over-long invoice ids and a non-boolean live flag are refused', () => {
  const gate = testPolicyGate();
  assert.equal(parseAmountToCents(1e21), null);
  const huge = colombia({ proposalId: 'huge', amountValue: 1e21 });
  const vHuge = gate.evaluate(huge, { timestamp: TS });
  assert.equal(vHuge.reasonCode, 'INVALID_AMOUNT');
  assert.doesNotThrow(() => gate.evaluate(huge, { timestamp: TS }));

  const longId = 'INV-' + '9'.repeat(MAX_INVOICE_ID_LENGTH);
  const vLong = gate.evaluate(colombia({ proposalId: 'long', invoiceId: longId }), { timestamp: TS });
  assert.equal(vLong.reasonCode, 'INVALID_INVOICE_ID');

  const vLive = gate.evaluate(colombia({ proposalId: 'live-1', live: 'yes' }), { timestamp: TS });
  assert.equal(vLive.reasonCode, 'LIVE_MODE_FORBIDDEN');
  const vLiveFalse = gate.evaluate(colombia({ proposalId: 'live-2', live: false }), { timestamp: TS });
  assert.equal(vLiveFalse.decision, 'ALLOW', vLiveFalse.reasonCode);
});

test('B10-DEDUP-1. Invoice dedup is per supplier: the same cleaned invoice number may be paid to a different registered supplier', () => {
  const gate = testPolicyGate();
  const a = colombia({ proposalId: 'd1', invoiceId: 'INV-SHARE-01', amountValue: '100.00' });
  const va = gate.evaluate(a, { timestamp: TS });
  assert.equal(va.decision, 'ALLOW', va.reasonCode);
  gate.commitAdmission(a, va);
  const again = colombia({ proposalId: 'd2', invoiceId: 'INV-SHARE-01', amountValue: '100.00' });
  assert.equal(gate.evaluate(again, { timestamp: TS }).reasonCode, 'DUPLICATE_INVOICE');

  const other = fillProposal({
    proposalId: 'd3',
    invoiceId: 'INV-SHARE-01',
    payeeEmail: 'billing@cascade-packaging.example',
    amountValue: '100.00',
    currencyCode: 'USD',
    reason: 'packaging',
  });
  const vo = gate.evaluate(other, { timestamp: TS });
  assert.equal(vo.decision, 'ALLOW', vo.reasonCode);
});

test('B10-PROCESS-1. A held proposal writes a HELD receipt, makes 0 PayPal calls, and GET-after-capture still settles an approved payment', async () => {
  const gate = testPolicyGate();
  const ledger = new ReceiptLedger({});
  const client = new PayPalSandboxClient({ mode: 'simulation', seed: 'b10-process' });
  const first = colombia({ proposalId: 'pr-1', invoiceId: 'INV-B10-PR-A', amountValue: '220.00' });
  const r1 = await processAgentPaymentProposal({ proposal: first, policyGate: gate, paypalClient: client, ledger, timestamp: TS });
  assert.equal(r1.status, 'EXECUTED');
  const before = client.getApiCallCount();
  const second = colombia({ proposalId: 'pr-2', invoiceId: 'INV-B10-PR-B', amountValue: '220.00' });
  const r2 = await processAgentPaymentProposal({ proposal: second, policyGate: gate, paypalClient: client, ledger, timestamp: TS });
  assert.equal(r2.status, 'HELD');
  assert.equal(r2.outcomeReceipt.stage, 'HELD');
  assert.equal(client.getApiCallCount(), before);
  gate.approveHeldProposal(second, { approvedBy: 'Alex Rivera', timestamp: TS, ledger });
  const r3 = await processAgentPaymentProposal({ proposal: second, policyGate: gate, paypalClient: client, ledger, timestamp: TS });
  assert.equal(r3.status, 'EXECUTED', r3.verdict?.reasonCode);
  assert.ok(r3.apiCallsDelta >= 3, `expected create+capture+GET, got ${r3.apiCallsDelta}`);
});
