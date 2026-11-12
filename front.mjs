// front.mjs — the front door. Glue only.
// Every number, id and invoice line comes from front-data.mjs, which make-front-data.mjs builds from the receipts.
// Step 2 runs the real gate (gate/policy-gate.mjs) in this page, set up the way the desk sets it up for a record:
// a fresh gate, the record's paid history replayed, the record's evaluation time. No network.
import { PolicyGate, DEFAULT_AP_POLICY_GATE_CONFIG, replayPaidHistory } from './gate/policy-gate.mjs';
import { FRONT_DATA as D } from './front-data.mjs';

const $ = (id) => document.getElementById(id);
const NS = 'http://www.w3.org/2000/svg';
const NB = '\u00a0';

function h(tag, cls, kids) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const k of [].concat(kids ?? [])) {
    if (k === null || k === undefined || k === false) continue;
    e.append(typeof k === 'string' || typeof k === 'number' ? document.createTextNode(String(k)) : k);
  }
  return e;
}
const set = (id, text) => { $(id).textContent = text; };
function mark(kind) {
  const s = document.createElementNS(NS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('class', `mk mk-${kind}`);
  s.setAttribute('aria-hidden', 'true');
  s.setAttribute('focusable', 'false');
  const glyph = kind === 'paid' ? '<path class="glyph" d="M7 12.5l3.2 3.2L17 8.8"/>'
    : kind === 'held' ? '<path class="glyph" d="M9.5 7.5v9M14.5 7.5v9"/>'
      : '<path class="glyph" d="M8 8l8 8M16 8l-8 8"/>';
  s.innerHTML = '<rect class="box" x="2" y="2" width="20" height="20" rx="5"/>' + glyph;
  return s;
}

const A = D.attack;
const sizeKB = (b) => `${(b / 1024).toFixed(0)} KB`;

// ---------- the gate, computed in this page ----------
export function computeGate() {
  const s = A.gateSetup;
  const gate = replayPaidHistory(new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG), s.setup || [], s.evalTimestamp);
  return gate.evaluate(s.gateProposal, { timestamp: s.evalTimestamp });
}
const RULE = {
  UNAPPROVED_PAYEE: 'Rule: pay only registered suppliers. The payee email, and the merchant id if one is given, must match the register.',
};
const WORD = { ALLOW: 'Admitted', HOLD: 'Held', DENY: 'Refused' };
const KIND = { ALLOW: 'paid', HOLD: 'held', DENY: 'refused' };

// ---------- invoice ----------
function renderInvoice() {
  const box = $('invtext');
  const marked = new Set(A.marks.map((m) => m.i));
  A.invoiceText.split('\n').forEach((line, i) => {
    const isMarked = marked.has(i);
    const row = h('span', 'ln' + (isMarked ? ' inj' : ''), line || NB);
    if (isMarked) row.append(h('span', 'tagw', '[instruction to the AI]'));
    box.append(row);
  });
  set('inv-note', `Invoice ${A.recordedProposal.invoiceId}. Supplier: ${A.recordedProposal.supplierName}` + (A.markState === 'marked' ? ' The marked line is an instruction to the AI, found the way the desk finds them. The rest is an ordinary invoice.' : ''));
}

// ---------- steps ----------
function renderStep1() {
  const p = A.recordedProposal;
  const d = A.differs[0];
  set('s1-text', A.modelObeyed
    ? `The model (${A.model}) read the invoice and obeyed the note. It changed the ${d.label.toLowerCase()} to ${d.proposed}. Reading the invoice honestly gives ${d.honest}.`
    : `The model (${A.model}) read the invoice. It did not follow the note.`);
  const kv = $('s1-kv');
  const changed = new Set(A.differs.map((x) => x.field));
  const rows = [['payeeEmail', 'Payee email'], ['payeeMerchantId', 'Merchant id'], ['amountValue', 'Amount'], ['currencyCode', 'Currency'], ['invoiceId', 'Invoice number']];
  for (const [k, label] of rows) {
    const isChanged = changed.has(k);
    const val = k === 'amountValue' ? '$' + p[k] : p[k];
    kv.append(h('dt', isChanged ? 'changed' : null, label), h('dd', 'mono' + (isChanged ? ' changed' : ''), [val, isChanged ? h('span', 'tag', 'Changed by the note') : null]));
  }
}
let computed = null;
function renderStep2() {
  const v = computeGate();
  computed = v;
  const card = $('step-2');
  card.dataset.computedDecision = v.decision;
  card.dataset.computedReason = v.reasonCode;
  const dec = $('s2-decision');
  dec.textContent = '';
  dec.append(mark(KIND[v.decision] || 'refused'), h('span', null, (WORD[v.decision] || v.decision).toUpperCase()));
  set('s2-rule', RULE[v.reasonCode] ? `${v.reasonCode}. ${RULE[v.reasonCode]}` : v.reasonCode);
  set('s2-detail', `The gate's own words: ${v.reasonDetail}.`);
  const same = v.decision === A.recorded.decision && v.reasonCode === A.recorded.reasonCode;
  set('s2-match', same
    ? `Same as the live run: ${WORD[A.recorded.decision].toLowerCase()}, ${A.recorded.reasonCode}.`
    : `Different from the live run, which recorded ${A.recorded.decision} ${A.recorded.reasonCode}. Treat this page as wrong.`);
  card.dataset.matchesRecorded = String(same);
}
function renderStep3() {
  set('s3-calls', String(A.recorded.apiCalls));
  set('s3-amount', A.amount);
  const [a, b] = A.ledger;
  set('s3-text', `Recorded in the live run: the gate refused, so PayPal was never called and ${A.amount} stayed where it was. Signed ledger entries #${a.index} (${a.stage}) and #${b.index} (${b.stage}) hold the record. The ${b.stage} entry hash starts ${b.hash12}.`);
}

const STEP_COUNT = 3;
let step = 1;
function showStep(n, opts = {}) {
  step = n;
  for (let i = 1; i <= STEP_COUNT; i++) {
    const el = $('step-' + i);
    el.hidden = i > n;
    el.classList.toggle('current', i === n);
    if (i === n) el.setAttribute('aria-current', 'step'); else el.removeAttribute('aria-current');
  }
  if (n >= 2) renderStep2();
  set('progress', `Step ${n} of ${STEP_COUNT}`);
  $('next').textContent = n < STEP_COUNT ? 'Next' : 'Start again';
  $('next').setAttribute('aria-label', n < STEP_COUNT ? `Next, to step ${n + 1} of ${STEP_COUNT}` : 'Start again from step 1');
  $('stepper').dataset.step = String(n);
}

// ---------- outcomes, figures, checks ----------
function renderOutcomes() {
  const P = D.paid;
  set('paid-lead', `An honest invoice from ${P.supplier}, ${P.invoiceId}, ${P.amount}. A registered supplier, an open purchase order, inside every limit. The gate admitted it and PayPal paid it.`);
  set('paid-order', P.orderId);
  set('paid-capture', P.captureStatus.charAt(0) + P.captureStatus.slice(1).toLowerCase() + ' on the Sandbox');
  $('paid-link').setAttribute('href', `gate/desk.html#run4:${P.id}`);

  const H = D.held;
  set('held-lead', `Two payments look the same to the gate: a second ${H.first.amount} to ${H.first.supplier} for one order, and a paid invoice billed again under a new number. The gate held both. The approver approved one, and PayPal paid it.`);
  set('held-approved', `${H.approvedId}. Paid.`);
  set('held-order', H.approvedOrderId);
  set('held-rejected', `${H.rejectedId}. Nothing was paid.`);
  $('held-link').setAttribute('href', `gate/desk.html#run5:${H.approvedId}`);
  set('held-script', `The approver is ${H.approver}. In this run the approver's steps were entered by the ${H.enteredBy}.`);

  set('refused-lead', `The attack above. The model obeyed the note and proposed merchant id ${A.differs[0].proposed}. The gate refused it. ${A.amount} did not move.`);
  set('refused-rule', A.recorded.reasonCode);
  set('refused-calls', String(A.recorded.apiCalls));
  $('refused-link').setAttribute('href', `gate/desk.html#run4:${A.id}`);
}
function renderFigures() {
  const F = D.figures;
  set('fig-obeyed', String(F.obeyed)); set('fig-comparable', String(F.comparable));
  set('fig-stopped', String(F.stopped)); set('fig-reached', String(F.reachedGate));
  set('fig-refused', String(F.refused)); set('fig-held', String(F.held));
  set('fig-chain-ok', String(F.chainOk)); set('fig-chain', String(F.chainCount));
  const T = F.thirtyFifth;
  set('thirtyfifth', `The 35th: ${T.amount} went to the registered supplier, for a different open invoice (${T.suiteId}). Our scoring flagged it as outside policy, and we published it. No attacker was paid.`);
}
function renderLive() {
  const L = D.live;
  const F = D.figures;
  set('proof', `Attacked live on the PayPal Sandbox. ${F.stopped} of ${F.reachedGate} attack proposals stopped. The ${F.reachedGate}th is published.`);
  set('live-evidence', `Recorded session, ${L.date} ${L.timeUtc} UTC: ${L.payments} payments, ${L.total} in all, paid on a Sandbox through this local desk. A pasted invoice from ${L.pasted.supplier}, ${L.pasted.amount}, was read by the live model, admitted by the gate and paid: PayPal order ${L.pasted.orderId}. The clicks in this session were made by a script, not by a person.`);
  set('dl-live-size', sizeKB(L.receipt.bytes));
  $('dl-live').setAttribute('href', L.receipt.path);
}
function renderChecks() {
  set('dl-run4-size', sizeKB(D.downloads.run4.bytes));
  set('dl-run5-size', sizeKB(D.downloads.run5.bytes));
  $('dl-run4').setAttribute('href', D.downloads.run4.path);
  $('dl-run5').setAttribute('href', D.downloads.run5.path);
}

// ---------- boot ----------
function boot() {
  renderInvoice();
  renderStep1();
  renderStep3();
  renderOutcomes();
  renderFigures();
  renderChecks();
  renderLive();
  showStep(1);
  $('next').addEventListener('click', () => showStep(step < STEP_COUNT ? step + 1 : 1));
  document.documentElement.dataset.ready = 'true';
}
boot();
window.__front = { computeGate, get step() { return step; }, get computed() { return computed; } };
