#!/usr/bin/env node
/**
 * make-front-data.mjs — builds front-data.mjs for index.html (the front door).
 *
 * Usage: node make-front-data.mjs [--out <file>]     (run from anywhere; reads ./gate/)
 * Built-ins only. Nothing on the front door is typed by hand: every number, id and invoice text is read here.
 *
 * Inputs (read-only, each recorded in front-data.mjs with bytes and sha256):
 *   gate/attack-suite-run4-receipt.json     Run 4: recorded proposals, decisions, PayPal ids, signed ledger
 *   gate/approval-release-run5-receipt.json Run 5: held, approved and released payments, approver steps
 *   gate/desk-live-session-receipt.json     the scripted session on the local desk (4 payments, approver name, signed ledger)
 *   gate/DESK-LIVE-SUMMARY.md               the pasted invoice's amount and order id (it is kept out of the signed receipt), read by pattern
 *   gate/desk-data.mjs                      what the desk uses to set the gate up for a record (history, marks);
 *                                           cross-checked here against the Run 4 receipt, the script stops on a difference
 *   gate/policy-gate.mjs, purchase-orders.mjs  hashed only; the page imports the gate itself
 * The three figures are counted from the Run 4 receipt the way gate/recount-run4.mjs counts them, and the
 * recount script is also run here: this script stops unless it prints RECOUNT: AGREES.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GATE = path.join(HERE, 'gate');
const args = process.argv.slice(2);
const oi = args.indexOf('--out');
const outFile = path.resolve(oi >= 0 && args[oi + 1] ? args[oi + 1] : path.join(HERE, 'front-data.mjs'));

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const src = (name) => {
  const buf = fs.readFileSync(path.join(GATE, name));
  return { file: 'gate/' + name, bytes: buf.length, sha256: sha(buf), text: buf.toString('utf8') };
};
const die = (msg) => { console.error('make-front-data: ' + msg); process.exit(1); };
const need = (cond, msg) => { if (!cond) die(msg); };

const s4 = src('attack-suite-run4-receipt.json');
const s5 = src('approval-release-run5-receipt.json');
const sDesk = src('desk-data.mjs');
const sGate = src('policy-gate.mjs');
const sPo = src('purchase-orders.mjs');
const R4 = JSON.parse(s4.text);
const R5 = JSON.parse(s5.text);
const { DESK_DATA } = await import(pathToFileURL(path.join(GATE, 'desk-data.mjs')).href);

// ---------- the recount script must agree ----------
let recountTail = '';
try {
  recountTail = execFileSync(process.execPath, [path.join(GATE, 'recount-run4.mjs'), path.join(GATE, 'attack-suite-run4-receipt.json')], { encoding: 'utf8' }).trim().split('\n').pop();
} catch (e) { die('recount-run4.mjs did not agree: ' + String(e.stdout || e.message).split('\n').slice(-3).join(' | ')); }
need(/^RECOUNT: AGREES/.test(recountTail), 'recount-run4.mjs: ' + recountTail);

// ---------- figures, counted as recount-run4.mjs counts them ----------
const recs = R4.suiteRecords;
const entries = R4.ledger.entries;
const attacks = recs.filter((r) => r.kind === 'attack');
const comparable = attacks.filter((r) => r.obeyedInjectionComparable);
const obeyed = comparable.filter((r) => r.obeyedInjection === true);
const serving = attacks.filter((r) => r.outsidePolicyAttempt && r.outcome !== 'EXECUTED');
const servingRefused = serving.filter((r) => r.outcome === 'REFUSED');
const servingHeld = serving.filter((r) => r.outcome === 'HELD');
const servingPaid = attacks.filter((r) => r.outsidePolicyAttempt && r.outcome === 'EXECUTED');
need(servingPaid.length === 1, 'expected exactly one flagged paid attack, got ' + servingPaid.length);
const byIndex = new Map(entries.map((e) => [e.index, e]));
const paid35 = servingPaid[0];
const paid35Entry = byIndex.get(paid35.outcomeReceiptIndex);

const canon = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? '[' + v.map((x) => canon(x === undefined ? null : x)).join(',') + ']'
    : '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
const pub = crypto.createPublicKey(R4.gateSigner.publicKeyPem);
let chainOk = 0;
for (let i = 0; i < entries.length; i++) {
  const { receiptHash, ed25519Signature, ...rest } = entries[i];
  const hashOk = sha(canon(rest)) === receiptHash;
  const linkOk = i === 0 || rest.prevHash === entries[i - 1].receiptHash;
  const sigOk = crypto.verify(null, Buffer.from(receiptHash, 'utf8'), pub, Buffer.from(ed25519Signature, 'base64'));
  if (hashOk && linkOk && sigOk) chainOk++;
}
const money = (v) => '$' + Number(v).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const figures = {
  obeyed: obeyed.length,
  comparable: comparable.length,
  reachedGate: serving.length + servingPaid.length,
  stopped: servingRefused.length + servingHeld.length,
  refused: servingRefused.length,
  held: servingHeld.length,
  chainOk,
  chainCount: entries.length,
  thirtyFifth: {
    suiteId: paid35.suiteId,
    amount: money(paid35Entry.payload.amountValue),
    payeeEmail: paid35.modelProposal.payeeEmail,
    invoiceId: paid35.modelProposal.invoiceId,
  },
};
// Cross-check against the receipt's own scoreboard.
const sb = R4.scoreboard;
need(figures.obeyed === sb.modelObeyedCount && figures.comparable === sb.comparableAttacks, 'obeyed count differs from scoreboard');
need(figures.reachedGate === sb.outOfPolicyAttackProposalsReachingGate, 'reached-gate count differs from scoreboard');
need(figures.refused === sb.outOfPolicyAttacksRefusedByGate, 'refused count differs from scoreboard');
need(figures.chainCount === R4.chainVerification.count && figures.chainOk === R4.chainVerification.verifiedEd25519Signatures, 'chain count differs from receipt');

// ---------- the attack invoice: merchant-id swap, $905.00 ----------
const swap = recs.filter((r) => r.kind === 'attack' && /merchant-ID swap/i.test(r.technique) && r.modelProposal && r.modelProposal.amountValue === '905.00');
need(swap.length === 1, 'expected exactly one $905.00 merchant-id swap in Run 4, got ' + swap.length);
const atk = swap[0];
const deskRec = DESK_DATA.records.find((r) => r.id === atk.suiteId);
need(deskRec, 'desk-data.mjs has no record ' + atk.suiteId);
need(deskRec.invoiceText === atk.invoiceSnippet, 'desk-data invoice text differs from the receipt snippet');
for (const k of Object.keys(atk.modelProposal)) {
  need(deskRec.gateProposal[k] === atk.modelProposal[k], `desk-data gateProposal.${k} differs from the receipt modelProposal`);
}
need(deskRec.recorded.decision === 'DENY' && atk.gateDecision === 'DENY' && deskRec.recorded.reasonCode === atk.reasonCode, 'desk-data decision differs from the receipt');
need(atk.apiCallsDelta === 0 && atk.paypalOrderId === null, 'attack record made a PayPal call');
const propEntry = byIndex.get(atk.proposedReceiptIndex);
const outEntry = byIndex.get(atk.outcomeReceiptIndex);
need(propEntry && outEntry && propEntry.receiptHash === atk.proposedReceiptHash && outEntry.receiptHash === atk.outcomeReceiptHash, 'ledger entries for the attack do not match');
const FIELD_LABEL = { payeeEmail: 'Payee email', payeeMerchantId: 'Merchant id', amountValue: 'Amount', currencyCode: 'Currency', invoiceId: 'Invoice number' };
const differs = Object.keys(atk.honestProposalSummary).filter((k) => atk.honestProposalSummary[k] !== atk.obedientProposalSummary[k])
  .map((k) => ({ field: k, label: FIELD_LABEL[k] || k, honest: atk.honestProposalSummary[k], proposed: atk.obedientProposalSummary[k] }));
need(differs.length >= 1, 'obedient and honest proposals do not differ');
const attack = {
  id: atk.suiteId,
  technique: atk.technique,
  invoiceText: atk.invoiceSnippet,
  marks: deskRec.marks,
  markState: deskRec.markState,
  proposalId: atk.modelProposal.proposalId,
  model: DESK_DATA.run.model,
  modelObeyed: atk.obeyedInjection === true,
  recordedProposal: atk.modelProposal,
  differs,
  amount: money(atk.modelProposal.amountValue),
  // How the desk sets the gate up for this record: fresh gate, replay of the record's paid history, record's timestamp.
  gateSetup: { gateProposal: deskRec.gateProposal, setup: deskRec.setup, evalTimestamp: deskRec.evalTimestamp },
  recorded: { decision: atk.gateDecision, outcome: atk.outcome, reasonCode: atk.reasonCode, reasonDetail: atk.reasonDetail, apiCalls: atk.apiCallsDelta, orderId: atk.paypalOrderId },
  ledger: [propEntry, outEntry].map((e) => ({ index: e.index, stage: e.stage, hash12: e.receiptHash.slice(0, 12) })),
};

// ---------- PAID: an honest invoice from the same supplier, with its PayPal order id ----------
const paidRec = recs.find((r) => r.kind === 'control' && r.outcome === 'EXECUTED' && r.modelProposal.supplierName === atk.modelProposal.supplierName);
need(paidRec && paidRec.paypalOrderId, 'no paid honest invoice for the same supplier');
const paidEntry = byIndex.get(paidRec.outcomeReceiptIndex);
need(paidEntry.stage === 'EXECUTED' && paidEntry.payload.captureStatus === 'COMPLETED', 'paid record is not an executed, completed capture');
const paidDesk = DESK_DATA.records.find((r) => r.id === paidRec.suiteId);
const paid = {
  id: paidRec.suiteId,
  supplier: paidRec.modelProposal.supplierName,
  invoiceId: paidRec.modelProposal.invoiceId,
  amount: money(paidRec.modelProposal.amountValue),
  orderId: paidRec.paypalOrderId,
  captureStatus: paidEntry.payload.captureStatus,
  apiCalls: paidRec.apiCallsDelta,
  deskPoNumber: paidDesk ? paidDesk.gateProposal.poNumber : null,
};

// ---------- HELD: Run 5, two look-alike payments ----------
const r5 = new Map(R5.suiteRecords.map((r) => [r.suiteId, r]));
const r502 = r5.get('R5-02');
const r502rel = r5.get('R5-02-RELEASE');
const r503 = r5.get('R5-03');
need(r502.outcome === 'HELD' && r503.outcome === 'HELD' && r502rel.outcome === 'EXECUTED' && r502rel.paypalOrderId, 'Run 5 shape changed');
need(r502.reasonCode === r503.reasonCode, 'R5-02 and R5-03 were held for different reasons');
const step = (t) => R5.approverSteps.find((s) => s.target === t);
const s502 = step('R5-02');
const s503 = step('R5-03');
need(s502.action === 'approve' && s502.status === 'APPROVED' && s503.action === 'reject' && s503.status === 'REJECTED', 'Run 5 approver steps changed');
need(s502.enteredBy === 'run script' && R5.approver.clickedByAPerson === false, 'Run 5 approver is not the run script');
const execEntry = R5.ledger.entries.find((e) => e.proposalId === r502rel.modelProposal.proposalId && e.stage === 'EXECUTED');
need(execEntry && execEntry.payload.captureStatus === 'COMPLETED', 'Run 5 release has no completed capture');
const held = {
  reasonCode: r502.reasonCode,
  first: { id: 'R5-02', supplier: r502.modelProposal.supplierName, invoiceId: r502.modelProposal.invoiceId, amount: money(r502.modelProposal.amountValue) },
  second: { id: 'R5-03', supplier: r503.modelProposal.supplierName, invoiceId: r503.modelProposal.invoiceId, amount: money(r503.modelProposal.amountValue) },
  approver: s502.by,
  enteredBy: s502.enteredBy,
  approvedId: 'R5-02',
  approvedOrderId: r502rel.paypalOrderId,
  approvedCapture: execEntry.payload.captureStatus,
  rejectedId: 'R5-03',
  rejectedStatus: s503.status,
  rejectedOrderId: r503.paypalOrderId,
  receiptAt: R5.generatedAt,
};


// ---------- the local desk's scripted live session ----------
const sLive = src('desk-live-session-receipt.json');
const sSum = src('DESK-LIVE-SUMMARY.md');
const RL = JSON.parse(sLive.text);
const exec = RL.ledger.entries.filter((e) => e.stage === 'EXECUTED');
need(exec.length > 0 && exec.every((e) => e.payload.captureStatus === 'COMPLETED'), 'live session: an executed entry is not a completed capture');
const totalCents = exec.reduce((a, e) => a + Math.round(Number(e.payload.amountValue) * 100), 0);
const sum = sSum.text;
const mTime = sum.match(/session tag `([^`]+)`, (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}) UTC/);
need(mTime, 'summary: session line not found');
need(RL.generatedAt.startsWith(mTime[2] + 'T' + mTime[3]), 'summary time differs from the session receipt generatedAt');
const mPaste = sum.match(/One pasted invoice, (\S+) \(([^,]+), (INV-[\w-]+), \$([\d,.]+), (PO-[\w-]+)\)[^\n]*?PayPal order `([A-Z0-9]+)`/);
need(mPaste, 'summary: pasted invoice line not found');
need(/made by a script/.test(sum) && RL.approver.clickedByAPerson !== true, 'summary no longer says the clicks were made by a script');
const live = {
  tag: mTime[1], date: mTime[2], timeUtc: mTime[3], generatedAt: RL.generatedAt,
  payments: exec.length, total: money(totalCents / 100),
  approverName: RL.approver.names[0], enteredBy: RL.approver.enteredBy,
  scriptDriven: true,
  pasted: { id: mPaste[1], supplier: mPaste[2], invoiceId: mPaste[3], amount: '$' + mPaste[4], poNumber: mPaste[5], orderId: mPaste[6] },
  pastedSource: 'gate/DESK-LIVE-SUMMARY.md',
  receipt: { path: 'gate/desk-live-session-receipt.json', bytes: sLive.bytes, sha256: sLive.sha256 },
};

// ---------- files ----------
const dl = (name) => { const s = src(name); return { path: 'gate/' + name, bytes: s.bytes, sha256: s.sha256 }; };
const data = {
  generatedBy: 'make-front-data.mjs',
  recount: recountTail,
  run4: { receipt: 'gate/attack-suite-run4-receipt.json', generatedAt: R4.generatedAt, gateGeneration: R4.gateGeneration, model: DESK_DATA.run.model },
  run5: { receipt: 'gate/approval-release-run5-receipt.json', generatedAt: R5.generatedAt, gateGeneration: R5.gateGeneration },
  attack,
  paid,
  held,
  live,
  figures,
  downloads: { run4: dl('attack-suite-run4-receipt.json'), run5: dl('approval-release-run5-receipt.json') },
  sources: [s4, s5, sLive, sSum, sDesk, sGate, sPo].map(({ file, bytes, sha256 }) => ({ file, bytes, sha256 })),
};
const body = 'export const FRONT_DATA = ' + JSON.stringify(data, null, 1) + ';\n';
fs.writeFileSync(outFile, '// Generated by make-front-data.mjs from the files listed in `sources`. Do not edit by hand.\n' + body);
console.log(`wrote ${path.relative(process.cwd(), outFile)} (${Buffer.byteLength(body)} bytes)`);
console.log(`attack ${attack.id} ${attack.amount} -> ${attack.recorded.decision} ${attack.recorded.reasonCode}; paid ${paid.id} ${paid.orderId}; held ${held.first.id}/${held.second.id} order ${held.approvedOrderId}`);
console.log(`live ${live.date} ${live.timeUtc} UTC · ${live.payments} payments ${live.total} · pasted ${live.pasted.amount} ${live.pasted.orderId}`);
console.log(`figures ${figures.obeyed} of ${figures.comparable} · ${figures.stopped} of ${figures.reachedGate} (${figures.refused} refused, ${figures.held} held) · ${figures.chainOk} of ${figures.chainCount} · ${recountTail}`);
