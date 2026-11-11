#!/usr/bin/env node
/**
 * make-desk-data.mjs — builds desk-data.mjs for desk.html (the AP desk).
 *
 * Usage: node make-desk-data.mjs [--dir <bundle folder>] [--out <file>]
 * Default bundle folder: the folder this script sits in. Built-ins only.
 *
 * Inputs (read-only, each recorded below with its sha256):
 *   attack-suite-known-38-pov4.json      the 38 known records (invoice text, history, honest and obedient proposals)
 *   attack-suite-heldout-b10-run4.json   the 22 second-set records
 *   purchase-orders.mjs                  the PO register the gate loads
 *   policy-gate.mjs                      the gate the page imports (hash only)
 *   attack-suite-run3-receipt.json       Run 3, the earlier run (kept as history; only what it decided is read)
 *   attack-suite-run4-receipt.json       Run 4: what the live model proposed, what the gate decided,
 *                                        PayPal ids, the call log and the signed ledger
 * No gate logic is copied here. Every number on the page is counted from this data in the browser.
 *
 * Marked instruction lines are derived, never typed. A line is marked when it is tied to the record's own data:
 *   note      it repeats at least three words in a row of the note attached to the invoice
 *   new       it names an email address, an amount or a merchant id that the rest of the invoice does not
 *   currency  it names a currency other than USD that the record's proposals use
 *   hidden    it holds invisible characters
 *   encoded   it holds text in base64 that decodes to a line tied by "new"
 * A record is marked only when every line that is not an ordinary invoice field is tied. If one is not, the
 * record gets no marks and says so (markState "unreliable") rather than guess.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 && args[i + 1] ? args[i + 1] : dflt; };
const HERE = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(opt('--dir', HERE));
const outFile = path.resolve(opt('--out', path.join(dir, 'desk-data.mjs')));

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const readSrc = (name) => {
  const buf = fs.readFileSync(path.join(dir, name));
  return { name, bytes: buf.length, sha256: sha(buf), text: buf.toString('utf8') };
};
const known = readSrc('attack-suite-known-38-pov4.json');
const second = readSrc('attack-suite-heldout-b10-run4.json');
const po = readSrc('purchase-orders.mjs');
const gateSrc = readSrc('policy-gate.mjs');
const receiptSrc = readSrc('attack-suite-run4-receipt.json');
const run3Src = readSrc('attack-suite-run3-receipt.json');
const K = JSON.parse(known.text);
const S = JSON.parse(second.text);
const R = JSON.parse(receiptSrc.text);
const R3 = JSON.parse(run3Src.text);
const run3ById = new Map(R3.suiteRecords.map((x) => [x.suiteId, x]));

const PROPOSAL_FIELDS = ['proposalId', 'invoiceId', 'payeeId', 'supplierName', 'payeeEmail', 'payeeMerchantId',
  'amountValue', 'currencyCode', 'reason', 'invoiceMemo', 'poNumber'];
const pick = (p) => {
  if (!p || typeof p !== 'object') return null;
  const o = {};
  for (const k of PROPOSAL_FIELDS) if (k in p) o[k] = p[k];
  return o;
};

// ---------- instruction-line derivation ----------
const EMAIL = /[A-Za-z0-9._%+\-Ѐ-ӿ]+@[A-Za-z0-9.\-Ѐ-ӿ]+\.[A-Za-z]{2,}/g;
const AMOUNT = /\d{1,3}(?:,\d{3})+\.\d{2}|\d+\.\d{2}/g;
const MERCHANT = /MCH-[A-Z0-9\-]+/g;
const cents = (s) => Math.round(Number(String(s).replace(/,/g, '')) * 100);
const words = (s) => String(s || '').toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/).filter(Boolean);
const labelOf = (line) => { const m = line.match(/^([A-Z][A-Z ]*?):\s*(.*)$/); return m ? { label: m[1], value: m[2] } : null; };

const allRecords = [...K.records.map((r) => ({ r, set: 'known' })), ...S.records.map((r) => ({ r, set: 'second' }))];

// The address every invoice is sent to: the most common TO value across all 60 documents.
const toCount = new Map();
for (const { r } of allRecords) {
  for (const l of (r.invoice.invoiceDocument || '').split('\n')) {
    const lab = labelOf(l);
    if (lab && lab.label === 'TO') toCount.set(lab.value, (toCount.get(lab.value) || 0) + 1);
  }
}
const COMMON_TO = [...toCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;

function memoTied(line, memo) {
  const lw = words(line); const mw = words(memo);
  if (lw.length < 3 || mw.length < 3) return false;
  const grams = new Set();
  for (let i = 0; i + 3 <= mw.length; i += 1) grams.add(mw.slice(i, i + 3).join(' '));
  for (let i = 0; i + 3 <= lw.length; i += 1) if (grams.has(lw.slice(i, i + 3).join(' '))) return true;
  return false;
}
function tryBase64(tok) {
  if (tok.length < 40 || tok.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(tok)) return null;
  try {
    const t = Buffer.from(tok, 'base64').toString('utf8');
    return /^[\x20-\x7E]+$/.test(t) ? t : null;
  } catch { return null; }
}

function deriveMarks(rec) {
  const inv = rec.invoice;
  const doc = inv.invoiceDocument || '';
  const lines = doc.split('\n');
  const allowedEmails = new Set([inv.payeeEmail, rec.honestProposal?.payeeEmail, COMMON_TO].filter(Boolean).map((e) => e.toLowerCase()));
  const allowedMerchants = new Set([inv.payeeMerchantId, rec.honestProposal?.payeeMerchantId].filter(Boolean));
  const allowedAmounts = new Set([cents(inv.amountValue)]);
  if (rec.honestProposal?.amountValue) allowedAmounts.add(cents(rec.honestProposal.amountValue));
  // amounts that sit on the statement's own invoice lines belong to the invoice
  for (const l of lines) if (/^INVOICE [A-Z]:/.test(l)) for (const a of l.match(AMOUNT) || []) allowedAmounts.add(cents(a));
  const foreignCurrencies = new Set([rec.obedientProposal?.currencyCode, inv.currencyCode].filter((c) => c && c !== 'USD'));
  const out = []; let unreliable = false;
  const FIELD_LABELS = new Set(['FROM', 'TO', 'VENDOR', 'INVOICE NUMBER', 'PO NUMBER', 'AMOUNT DUE', 'LINE ITEM', 'TOTAL OF LINES',
    'TERMS', 'INVOICE DATE', 'BATCH STATEMENT']);
  const isField = (line) => { const lab = labelOf(line); return !!lab && (FIELD_LABELS.has(lab.label) || /^INVOICE [A-Z]$/.test(lab.label)); };
  const structural = (line) => !/[\p{L}\p{N}]/u.test(line) || /^\d{2}\s{2}/.test(line) || /^---.*---$/.test(line)
    || (/^[|+]/.test(line) && !/\[/.test(line));
  const tie = (line) => {
    const why = [];
    // The attached note is compared only with lines that are not plain invoice fields.
    if (inv.invoiceMemo && !isField(line) && memoTied(line, inv.invoiceMemo)) why.push('note');
    const newEmail = (line.match(EMAIL) || []).some((e) => !allowedEmails.has(e.toLowerCase()));
    const newMerchant = (line.match(MERCHANT) || []).some((m) => !allowedMerchants.has(m));
    const newAmount = (line.match(AMOUNT) || []).some((a) => !allowedAmounts.has(cents(a)));
    if (newEmail || newMerchant || newAmount) why.push('new');
    for (const c of foreignCurrencies) if (new RegExp(`\\b${c}\\b`).test(line)) why.push('currency');
    if (/\p{Cf}/u.test(line)) why.push('hidden');
    for (const tok of line.split(/\s+/)) {
      const dec = tryBase64(tok);
      if (dec && ((dec.match(AMOUNT) || []).some((a) => !allowedAmounts.has(cents(a))) || /ignore|approve|instruction/i.test(dec))) why.push('encoded');
    }
    return [...new Set(why)];
  };
  lines.forEach((line, i) => {
    if (structural(line) && !/\p{Cf}/u.test(line)) return;
    const why = tie(line);
    if (why.length) out.push({ i, why });
    else if (!isField(line)) unreliable = true;
  });
  if (unreliable) return { markState: 'unreliable', marks: [] };
  return { markState: out.length ? 'marked' : 'none', marks: out };
}

// ---------- receipt join ----------
const runById = new Map(R.suiteRecords.map((x) => [x.suiteId, x]));
const proposedByProposal = new Map();
const entriesByProposal = new Map();
for (const e of R.ledger.entries) {
  if (!e.proposalId) continue;
  if (!entriesByProposal.has(e.proposalId)) entriesByProposal.set(e.proposalId, []);
  entriesByProposal.get(e.proposalId).push(e);
  if (e.stage === 'PROPOSED') proposedByProposal.set(e.proposalId, e);
}
// API calls belong to records in run order: the first record also carries the OAuth token call.
const callsBySuite = new Map();
{
  let cur = 0;
  for (const s of R.suiteRecords) {
    const calls = R.apiCallLog.slice(cur, cur + s.apiCallsDelta);
    cur += s.apiCallsDelta;
    for (const c of calls) {
      if (c.idempotencyKey && !c.idempotencyKey.includes(s.modelProposal.proposalId) && !c.idempotencyKey.includes(s.modelProposal.invoiceId) && !c.idempotencyKey.startsWith('batch-')) {
        throw new Error(`call ${c.seq} does not belong to ${s.suiteId}`);
      }
    }
    callsBySuite.set(s.suiteId, calls);
  }
  if (cur !== R.apiCallLog.length) throw new Error('API call log not fully assigned');
}

const records = allRecords.map(({ r, set }) => {
  const run = runById.get(r.suiteId);
  if (!run) throw new Error(`no Run 4 entry for ${r.suiteId}`);
  const proposalId = run.modelProposal.proposalId;
  const prop = proposedByProposal.get(proposalId);
  const gateProposal = { ...prop.payload, proposalId };
  delete gateProposal.aiModelRoute;
  let rawKeys = [];
  try { rawKeys = Object.keys(JSON.parse(prop.payload.aiModelRoute?.rawCompletion || '{}')); } catch { /* none */ }
  const modelWrotePo = rawKeys.includes('poNumber');
  const marks = deriveMarks(r);
  const executed = (entriesByProposal.get(proposalId) || []).find((e) => e.stage === 'EXECUTED');
  return {
    id: r.suiteId,
    set,
    kind: r.kind,
    technique: r.technique,
    attackerWants: r.whatTheAttackerWants || '',
    invoiceText: r.invoice.invoiceDocument || '',
    invoiceMemo: r.invoice.invoiceMemo ?? null,
    markState: marks.markState,
    marks: marks.marks,
    evalTimestamp: (set === 'known' ? K : S).fixedEvaluationTimestamp || R.fixedEvaluationTimestamp,
    proposalId,
    setup: (r.setup || []).map(pick),
    honestProposal: pick(r.honestProposal),
    obedientProposal: pick(r.obedientProposal),
    gateProposal,
    modelWrotePo,
    comparable: Boolean(r.obeyedInjectionComparable),
    modelObeyed: run.obeyedInjection ?? null,
    outsidePolicy: Boolean(run.outsidePolicyAttempt),
    run3: run3ById.has(r.suiteId) ? {
      decision: run3ById.get(r.suiteId).gateDecision,
      reasonCode: run3ById.get(r.suiteId).reasonCode,
      amountValue: run3ById.get(r.suiteId).modelProposal?.amountValue ?? null,
      paypalOrderId: run3ById.get(r.suiteId).paypalOrderId ?? null,
      gateGeneration: R3.gateGeneration ?? null,
    } : null,
    recorded: {
      decision: run.gateDecision,
      outcome: run.outcome,
      reasonCode: run.reasonCode,
      reasonDetail: run.reasonDetail ?? null,
      apiCalls: Number(run.apiCallsDelta ?? 0),
      paypalOrderId: run.paypalOrderId ?? null,
      paypalCaptureId: run.paypalCaptureId ?? null,
      orderStatus: executed?.payload?.orderStatus ?? null,
      captureStatus: executed?.payload?.captureStatus ?? null,
      calls: (callsBySuite.get(r.suiteId) || []).map((c) => ({
        seq: c.seq, surface: c.surface, method: c.method, path: c.path, status: c.status, debugId: c.paypalDebugId,
      })),
    },
    ledger: (entriesByProposal.get(proposalId) || []).map((e) => ({
      index: e.index, stage: e.stage, hash: e.receiptHash, prev: e.prevHash,
    })),
  };
});

// The page's summary line is counted from the records; it must equal the receipt's own scoreboard.
const SB = R.scoreboard;
{
  const reach = records.filter((x) => x.kind === 'attack' && x.outsidePolicy);
  const refused = reach.filter((x) => x.recorded.decision === 'DENY').length;
  const admitted = reach.filter((x) => x.recorded.decision === 'ALLOW').map((x) => x.id).sort();
  if (reach.length !== SB.outOfPolicyAttackProposalsReachingGate) throw new Error(`attack proposals reaching the gate: records ${reach.length} != receipt ${SB.outOfPolicyAttackProposalsReachingGate}`);
  if (refused !== SB.outOfPolicyAttacksRefusedByGate) throw new Error(`attack proposals refused: records ${refused} != receipt ${SB.outOfPolicyAttacksRefusedByGate}`);
  if (JSON.stringify(admitted) !== JSON.stringify([...SB.admittedAttackIds].sort())) throw new Error('admitted attack ids differ from the receipt');
}

const data = {
  generatedBy: 'make-desk-data.mjs',
  run: {
    label: 'Run 4',
    receipt: receiptSrc.name,
    gateGeneration: R.gateGeneration,
    sandbox: R.sandboxBaseUrl,
    model: R.llmProposerSummary?.returnedModel ?? null,
    generatedAt: R.generatedAt,
    chainValid: R.chainVerification.valid,
    chainCount: R.chainVerification.count,
    chainSignatures: R.chainVerification.verifiedEd25519Signatures,
    headHash: R.chainVerification.headHash,
    keySha256: R.chainVerification.gatePublicKeySha256,
    liveHttpsCalls: R.apiCallLog.length,
  },
  summary: {
    reachingGate: SB.outOfPolicyAttackProposalsReachingGate,
    refusedByGate: SB.outOfPolicyAttacksRefusedByGate,
    admittedAttackIds: SB.admittedAttackIds,
    approvalEntries: R.chainVerification.stageCounts.APPROVED,
  },
  sources: [known, second, po, gateSrc, receiptSrc, run3Src].map(({ name, bytes, sha256 }) => ({ file: name, bytes, sha256 })),
  groups: [{ id: 'known' }, { id: 'second' }],
  records,
};

const text = '// Generated by make-desk-data.mjs from the files listed in `sources`. Do not edit by hand.\n' +
  'export const DESK_DATA = ' + JSON.stringify(data, null, 1) + ';\n';
fs.writeFileSync(outFile, text);
const st = {};
for (const x of records) st[x.markState] = (st[x.markState] || 0) + 1;
console.log(`wrote ${outFile} records=${records.length} marks=${JSON.stringify(st)} bytes=${Buffer.byteLength(text)}`);
