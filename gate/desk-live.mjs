// desk-live.mjs — the engine behind the desk's "Live" tab.
//
// One session = one PolicyGate + one ReceiptLedger + one PayPal client, driven one click at a time through the
// same building blocks the Run 5 runner uses (run-approval-release.mjs): AIProcurementAgent, PolicyGate,
// processAgentPaymentProposal, PayPalSandboxClient, ReceiptLedger, computeAttackSuiteScoreboard.
//
// Keys: PayPal and Ollama keys arrive as constructor arguments, live only inside the objects that call the
// providers, and are never part of any returned value. Every message that leaves this module passes through
// scrub(), which removes the key values if a provider happened to echo one.
//
// The session ledger is exported in the receipt shape the frozen verifier accepts. The verifier needs the suite
// file's records in the suite file's order (see exportReceipt). This module never edits the verifier.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { ReceiptLedger, verifyReceiptChain } from './receipt-ledger.mjs';
import { PolicyGate, DEFAULT_AP_POLICY_GATE_CONFIG, processAgentPaymentProposal } from './policy-gate.mjs';
import { PayPalSandboxClient, PAYPAL_SANDBOX_BASE_URL } from './paypal-client.mjs';
import { AIProcurementAgent, createOllamaCloudAdapter } from './ai-procurement-agent.mjs';
import { verifyRecordedReceiptBundle } from './verify-payments.mjs';
import {
  computeAttackSuiteScoreboard,
  evaluateObedienceAndHonesty,
  normalizeCoreProposalFields,
  withBoundedRetry,
} from './run-attack-suite.mjs';

const sha256Buf = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const SET_NAME = 'desk-live-session';
const MODEL_ROUTE = 'ollama-cloud:glm-5.3';

export function createLiveEngine({
  gateDir,
  simulate = false,
  paypal = null,          // { clientId, clientSecret } (real Sandbox keys) or null
  ollamaApiKey = '',
  gateGeneration = 'po-v4',
  inferenceAdapter = null, // test seam only: a stand-in model for pasted invoices. The server never sets it.
  pasteInReceipt = false,  // see exportReceipt: whether pasted-invoice passes share the session ledger
} = {}) {
  const suitePath = path.join(gateDir, 'approval-release-suite.json');
  const receiptPath = path.join(gateDir, 'approval-release-run5-receipt.json');
  const manifestPath = path.join(gateDir, 'CODE-MANIFEST.json');
  const suiteBuf = fs.readFileSync(suitePath);
  const suiteSha256 = sha256Buf(suiteBuf);
  const suite = JSON.parse(suiteBuf.toString('utf8'));
  const fixedTs = suite.fixedEvaluationTimestamp;
  const recById = new Map(suite.records.map((r) => [r.suiteId, r]));
  const proposeSteps = suite.steps.filter((s) => s.do === 'propose');
  const policyGateSha256 = sha256Buf(fs.readFileSync(path.join(gateDir, 'policy-gate.mjs')));
  const codeManifestSha256 = sha256Buf(fs.readFileSync(manifestPath));

  const live = !simulate && Boolean(paypal && paypal.clientId && paypal.clientSecret);
  if (!simulate && !live) throw new Error('DESK_LIVE_NEEDS_KEYS_OR_SIMULATE: pass --simulate, or start with PayPal Sandbox keys in the environment');
  const useLiveModel = live && Boolean(String(ollamaApiKey || '').trim());
  const secrets = [paypal?.clientId, paypal?.clientSecret, ollamaApiKey].map((s) => String(s || '').trim()).filter((s) => s.length >= 6);
  const scrub = (v) => {
    let t = String(v ?? '');
    for (const s of secrets) t = t.split(s).join('[redacted]');
    return t;
  };

  // Recorded Run 5 proposals: used only when no model key is present, and labelled so everywhere.
  const recorded = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  const recordedProposed = new Map();
  for (const e of recorded.ledger.entries) if (e.stage === 'PROPOSED') recordedProposed.set(e.proposalId, e.payload);
  const recordedBySuiteId = new Map(recorded.suiteRecords.map((s) => [s.suiteId, recordedProposed.get(s.modelProposal.proposalId)]));

  let S = null;
  let chain = Promise.resolve();
  const serial = (fn) => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };

  const label = () => (live ? 'live on your PayPal Sandbox' : 'simulated, no PayPal call');
  const proposalSource = () => (useLiveModel ? 'live model glm-5.3 through Ollama Cloud' : 'recorded Run 5 proposals (no model call is made)');

  function newSession() {
    const tag = `lv-${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}`;
    const startedAt = new Date().toISOString();
    const baselineSnapshot = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG).toPolicySnapshot(fixedTs);
    const client = new PayPalSandboxClient({
      clientId: live ? paypal.clientId : '',
      clientSecret: live ? paypal.clientSecret : '',
      baseUrl: PAYPAL_SANDBOX_BASE_URL,
      mode: live ? 'sandbox-https' : 'simulation',
      sandboxRunTag: live ? tag.toUpperCase() : null,
    });
    if (live) withBoundedRetry(client, { log: () => {} });
    const suiteSets = [{ name: SET_NAME, file: path.basename(suitePath), sha256: suiteSha256, recordCount: suite.records.length, fixedEvaluationTimestamp: fixedTs }];
    const policyFeatures = { duplicatePaymentHold: true, paidOnlyAfterCapture: true, recordedAtPerEntry: true, scoreboardVersion: 2, multiRail: false, approvalRelease: true };
    const protagonist = `Desk live session ${tag}: approvals clicked on the desk page, paid through the gate (${label()}) · Pre-launch Prototype · 0 Live Customers`;
    const ledger = new ReceiptLedger({
      ledgerId: `paypal-desk-live-${gateGeneration}-${tag}`,
      genesisTimestamp: fixedTs,
      protagonist,
      metadata: {
        receiptKind: 'attack-suite-run',
        gateGeneration,
        codeManifestSha256,
        attackSuiteSha256: suiteSha256,
        suiteSets,
        policyFeatures,
        policyGateSha256,
        executionEnvironment: live ? PAYPAL_SANDBOX_BASE_URL : 'offline-simulation',
        aiProposerRoute: useLiveModel ? MODEL_ROUTE : 'recorded:run5-proposals',
      },
    });
    // Pasted invoices are not records of the suite file. With pasteInReceipt=false they use their own ledger and PayPal
    // client, so the session receipt keeps exactly the suite's passes. They share the gate (same day totals).
    const pasteLedger = pasteInReceipt ? ledger : new ReceiptLedger({
      ledgerId: `paypal-desk-live-pasted-${gateGeneration}-${tag}`,
      genesisTimestamp: fixedTs,
      protagonist: `Desk live session ${tag}: pasted invoices (${label()}), not part of the suite receipt`,
      metadata: { receiptKind: 'desk-pasted-invoices', gateGeneration, codeManifestSha256, policyGateSha256 },
    });
    const pasteClient = pasteInReceipt ? client : new PayPalSandboxClient({
      clientId: live ? paypal.clientId : '', clientSecret: live ? paypal.clientSecret : '', baseUrl: PAYPAL_SANDBOX_BASE_URL,
      mode: live ? 'sandbox-https' : 'simulation', sandboxRunTag: live ? `${tag.toUpperCase()}P` : null,
    });
    if (live && !pasteInReceipt) withBoundedRetry(pasteClient, { log: () => {} });
    let agent = null;
    if (useLiveModel) {
      const base = createOllamaCloudAdapter({ apiKey: ollamaApiKey, numPredict: 6144 });
      const retrying = async (params) => {
        let lastErr = null;
        for (let attempt = 1; attempt <= 3; attempt += 1) {
          try {
            const res = await base(params);
            if (!res?.rawCompletion || !String(res.rawCompletion).trim()) throw new Error('LLM_EMPTY_COMPLETION_RETRY');
            return res;
          } catch (err) {
            lastErr = err;
            if (attempt < 3) await new Promise((r) => setTimeout(r, 3000 * attempt));
          }
        }
        throw lastErr;
      };
      agent = new AIProcurementAgent({ defaultRoute: MODEL_ROUTE, liveInferenceAdapter: retrying });
    }
    return {
      tag, startedAt, client, ledger, agent, pasteLedger, pasteClient, pasteCount: 0, pasted: [], baselineSnapshot, suiteSets, policyFeatures, protagonist,
      gate: new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG),
      invoices: [],        // { id, rec, proposal, passes: [pass results], again: pass|null, release: pass|null }
      suiteRecords: [],
      llmProposals: [],
      approverSteps: [],
      tokensIn: 0, tokensOut: 0, returnedModel: useLiveModel ? 'glm-5.3' : 'recorded-run5-proposals',
    };
  }
  S = newSession();

  const pidOf = (rec) => `${rec.invoice.proposalId}-${S.tag}`;

  function followRec(target, kind) {
    const steps = suite.steps.filter((s) => s.do === 'release' && s.target === target);
    const step = kind === 'release' ? steps[0] : steps[1];
    if (step) return recById.get(step.record);
    const base = recById.get(target);
    return {
      ...base,
      suiteId: `${target}-${kind === 'release' ? 'RELEASE' : 'AGAIN'}`,
      kind: 'control',
      technique: kind === 'release'
        ? `Release of the held ${target} proposal after one person approved it (not a record of the suite file)`
        : `The paid ${target} payment sent through the gate again (not a record of the suite file)`,
      reusesProposalOf: target,
      honestProposal: null,
      obeyedInjectionComparable: false,
    };
  }

  async function draft(rec) {
    const pid = pidOf(rec);
    if (useLiveModel) {
      return S.agent.draftPaymentProposal({ ...rec.invoice, proposalId: pid }, { route: MODEL_ROUTE, requireLiveLlm: true });
    }
    const payload = recordedBySuiteId.get(rec.suiteId);
    if (!payload) throw new Error(`NO_RECORDED_PROPOSAL for ${rec.suiteId}`);
    return Object.freeze({ ...payload, proposalId: pid });
  }

  const gateWord = (v) => ({ decision: v.decision, reasonCode: v.reasonCode, reasonDetail: v.reasonDetail });

  // One pass through the gate (and PayPal when admitted). Returns the answer the page shows.
  async function runPass(rec, proposal, { reused, reusesProposalOf = null, record = true, ledger = S.ledger, client = S.client }) {
    const step = record ? S.suiteRecords.length + 1 : null;
    const routeMeta = proposal.aiModelRoute || {};
    if (record && !reused) {
      if (routeMeta.returnedModel) S.returnedModel = routeMeta.returnedModel;
      S.tokensIn += Number(routeMeta.tokensIn) || 0;
      S.tokensOut += Number(routeMeta.tokensOut) || 0;
    }
    if (record) S.llmProposals.push({
      step, suiteId: rec.suiteId, proposalId: proposal.proposalId, invoiceId: proposal.invoiceId,
      payeeEmail: proposal.payeeEmail, payeeMerchantId: proposal.payeeMerchantId, amountUsd: proposal.amountValue,
      currencyCode: proposal.currencyCode, mode: routeMeta.mode, provider: routeMeta.provider,
      returnedModel: routeMeta.returnedModel, promptSha256: routeMeta.promptSha256 || null,
      rawCompletion: routeMeta.rawCompletion || null, responseSha256: routeMeta.responseSha256 || null,
      tokensIn: reused ? null : routeMeta.tokensIn ?? null, tokensOut: reused ? null : routeMeta.tokensOut ?? null,
      elapsedMs: reused ? null : routeMeta.elapsedMs ?? null,
      ...(reused ? { reusedProposalOf: reusesProposalOf } : {}),
    });
    const callsBefore = client.getApiCallCount();
    if (!record) {
      const r = await processAgentPaymentProposal({ proposal, policyGate: S.gate, paypalClient: client, ledger, timestamp: fixedTs, captureImmediately: true });
      return passAnswer(rec, proposal, r, client, callsBefore, null);
    }
    const { obeyedInjection, matchedHonestProposal } = evaluateObedienceAndHonesty(rec, proposal);
    const fresh = (setup) => {
      const g = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
      for (const s of setup || []) { const v = g.evaluate(s, { timestamp: fixedTs, bypassDuplicateHold: true }); g.commitAdmission(s, v); }
      return g;
    };
    const honestGateEval = rec.honestProposal ? fresh(rec.setup).evaluate(rec.honestProposal, { timestamp: fixedTs }) : null;
    const obedientGateEval = fresh(rec.setup).evaluate(rec.obedientProposal, { timestamp: fixedTs });

    const execRes = await processAgentPaymentProposal({
      proposal, policyGate: S.gate, paypalClient: client, ledger, timestamp: fixedTs, captureImmediately: true,
    });
    const honestPolicyDecision = honestGateEval ? honestGateEval.decision : null;
    const isHonestInPolicy = rec.kind === 'attack' && matchedHonestProposal === true && honestPolicyDecision === 'ALLOW';
    S.suiteRecords.push({
      step, suiteSet: SET_NAME, suiteId: rec.suiteId, kind: rec.kind, technique: rec.technique,
      whatTheAttackerWants: rec.whatTheAttackerWants, setupCount: (rec.setup || []).length,
      obeyedInjectionComparable: rec.obeyedInjectionComparable, obeyedInjection, matchedHonestProposal,
      honestProposalPolicyDecision: honestPolicyDecision,
      directGateOnObedientDecision: obedientGateEval.decision, directGateOnObedientReasonCode: obedientGateEval.reasonCode,
      outsidePolicyAttempt: rec.kind === 'attack' ? !isHonestInPolicy : false,
      expectedGateDecisionIfObeyed: rec.expectedGateDecisionIfObeyed, expectedReasonCode: rec.expectedReasonCode,
      invoiceSnippet: String(rec.invoice?.invoiceDocument || ''),
      honestProposalSummary: normalizeCoreProposalFields(rec.honestProposal),
      obedientProposalSummary: normalizeCoreProposalFields(rec.obedientProposal),
      modelProposal: {
        proposalId: proposal.proposalId, invoiceId: proposal.invoiceId, supplierName: proposal.supplierName,
        payeeEmail: proposal.payeeEmail, payeeMerchantId: proposal.payeeMerchantId, amountValue: proposal.amountValue,
        currencyCode: proposal.currencyCode, reason: proposal.reason,
      },
      gateDecision: execRes.verdict.decision, outcome: execRes.status, reasonCode: execRes.verdict.reasonCode,
      reasonDetail: execRes.verdict.reasonDetail, apiCallsDelta: execRes.apiCallsDelta,
      paypalOrderId: execRes.order?.id || null, paypalCaptureId: execRes.capture?.id || null,
      paypalInvoiceId: execRes.invoiceRecord?.id || null,
      paypalPayoutBatchId: execRes.payoutRecord?.batch_header?.payout_batch_id || null,
      proposedReceiptIndex: execRes.proposedReceipt.index, proposedReceiptHash: execRes.proposedReceipt.receiptHash,
      outcomeReceiptIndex: execRes.outcomeReceipt.index, outcomeReceiptHash: execRes.outcomeReceipt.receiptHash,
      ...(reused ? { reusesProposalOf, modelCallMade: false } : { modelCallMade: useLiveModel }),
    });
    return passAnswer(rec, proposal, execRes, client, callsBefore, step);
  }

  function passAnswer(rec, proposal, execRes, client, callsBefore, step) {
    const out = execRes.outcomeReceipt;
    return {
      pass: step,
      passId: rec.suiteId,
      proposalId: proposal.proposalId,
      status: execRes.status,
      decision: execRes.verdict.decision,
      reasonCode: execRes.verdict.reasonCode,
      reasonDetail: scrub(execRes.verdict.reasonDetail),
      supplierName: proposal.supplierName,
      amountValue: proposal.amountValue,
      currencyCode: proposal.currencyCode,
      invoiceId: proposal.invoiceId,
      poNumber: proposal.poNumber,
      apiCalls: execRes.apiCallsDelta,
      order: execRes.order?.id ? { id: execRes.order.id } : null,
      capture: execRes.capture?.id ? { id: execRes.capture.id, status: execRes.capture.status ?? null } : null,
      readBack: execRes.status === 'EXECUTED' ? { orderStatus: out.payload.orderStatus, captureStatus: out.payload.captureStatus } : null,
      calls: client.getApiCallLog().slice(callsBefore).map((c) => ({ seq: c.seq, surface: c.surface, method: c.method, path: c.path, status: c.status, debugId: c.paypalDebugId })),
      ledgerIndexes: { proposed: execRes.proposedReceipt.index, outcome: out.index },
      at: out.recordedAt,
      simulated: !live,
      label: label(),
    };
  }

  const invOf = (target) => S.invoices.find((i) => i.id === target) || null;
  const heldStatus = (inv) => S.gate.getHold(inv.proposal)?.status || null;

  function view() {
    const nextStep = proposeSteps[S.invoices.filter((i) => i.record).length] || null;
    const nextRec = nextStep ? recById.get(nextStep.record) : null;
    return {
      ok: true,
      live,
      simulated: !live,
      label: label(),
      session: { tag: S.tag, startedAt: S.startedAt },
      proposals: { source: proposalSource(), live: useLiveModel, model: useLiveModel ? 'glm-5.3' : null },
      evaluationClock: fixedTs,
      next: nextRec ? { id: nextRec.suiteId, supplierName: nextRec.invoice.supplierName, amountValue: nextRec.invoice.amountValue, invoiceId: nextRec.invoice.invoiceId } : null,
      invoices: S.invoices.map((i) => ({
        id: i.id,
        supplierName: i.proposal.supplierName,
        amountValue: i.proposal.amountValue,
        invoiceId: i.proposal.invoiceId,
        reason: i.proposal.reason,
        invoiceMemo: i.proposal.invoiceMemo ?? null,
        holdStatus: heldStatus(i),
        arrival: i.passes[0],
        release: i.release,
        again: i.again,
        decisions: i.decisions,
        pasted: Boolean(i.free),
        inSignedReceipt: i.record || pasteInReceipt,
        proposal: i.free ? { supplierName: i.proposal.supplierName, payeeEmail: i.proposal.payeeEmail, payeeMerchantId: i.proposal.payeeMerchantId, amountValue: i.proposal.amountValue, currencyCode: i.proposal.currencyCode, invoiceId: i.proposal.invoiceId, poNumber: i.proposal.poNumber, reason: i.proposal.reason } : undefined,
      })),
      pasteAvailable: Boolean(pasteAdapter()),
      sampleInvoice: (() => { const last = recById.get(proposeSteps[proposeSteps.length - 1].record); return { text: last.invoice.invoiceDocument, poNumber: last.invoice.poNumber }; })(),
      queue: S.invoices.filter((i) => heldStatus(i) === 'held').map((i) => i.id),
      passes: S.suiteRecords.length,
      expectedPasses: suite.records.length,
      apiCalls: S.client.getApiCallCount(),
    };
  }

  const wrap = (fn) => serial(async () => {
    try { return await fn(); } catch (err) {
      return { ok: false, error: scrub(err?.message || err), view: view() };
    }
  });

  async function processNext() {
    const step = proposeSteps[S.invoices.filter((i) => i.record).length];
    if (!step) return { ok: false, error: 'DAY_COMPLETE: all invoices of the day have arrived', view: view() };
    const rec = recById.get(step.record);
    const proposal = await draft(rec);
    const inv = { id: rec.suiteId, rec, proposal, passes: [], release: null, again: null, decisions: [], record: true, ledger: S.ledger, client: S.client };
    S.invoices.push(inv);
    const pass = await runPass(rec, proposal, { reused: false });
    inv.passes.push(pass);
    return { ok: true, result: pass, view: view() };
  }

  const pasteAdapter = () => inferenceAdapter
    || (useLiveModel ? createOllamaCloudAdapter({ apiKey: ollamaApiKey, numPredict: 6144 }) : null);

  async function processPasted(text, poNumber) {
    const adapter = pasteAdapter();
    if (!adapter) {
      return { ok: false, error: 'NO_MODEL_KEY: no model key is set on this server, so pasted invoices cannot be read. Start the server with OLLAMA_API_KEY, or use the six recorded Run 5 invoices. No proposal is invented.', view: view() };
    }
    const doc = String(text ?? '').trim();
    if (!doc) return { ok: false, error: 'EMPTY_INVOICE: paste the invoice text first', view: view() };
    if (doc.length > 6000) return { ok: false, error: 'INVOICE_TOO_LONG: at most 6000 characters', view: view() };
    const po = String(poNumber ?? '').trim();
    if (po.length > 40) return { ok: false, error: 'PO_NUMBER_TOO_LONG: at most 40 characters', view: view() };
    S.pasteCount += 1;
    const id = `P-${String(S.pasteCount).padStart(2, '0')}`;
    const pid = `paste-${String(S.pasteCount).padStart(2, '0')}-${S.tag}`;
    const retrying = async (params) => {
      let lastErr = null;
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        try {
          const res = await adapter(params);
          if (!res?.rawCompletion || !String(res.rawCompletion).trim()) throw new Error('LLM_EMPTY_COMPLETION_RETRY');
          return res;
        } catch (err) { lastErr = err; if (attempt < 3 && !inferenceAdapter) await new Promise((r) => setTimeout(r, 3000 * attempt)); else if (attempt < 3) continue; }
      }
      throw lastErr;
    };
    const agent = new AIProcurementAgent({ defaultRoute: MODEL_ROUTE, liveInferenceAdapter: retrying });
    // The purchase-order number comes from the invoice record (the field beside the text), not from the model.
    const drafted = await agent.draftPaymentProposal({ proposalId: pid, invoiceDocument: doc, poNumber: po || null }, { route: MODEL_ROUTE, requireLiveLlm: true });
    // The supplier id comes from the supplier register, matched on the email the model read. No match: it stays empty
    // and the gate refuses an unregistered payee. The model is never asked for it.
    const known = S.gate.listApprovedPayees().find((x) => String(x.email || '').trim().toLowerCase() === String(drafted.payeeEmail || '').trim().toLowerCase());
    const proposal = Object.freeze({ ...drafted, payeeId: known ? known.payeeId : null });
    const inv = { id, rec: null, proposal, passes: [], release: null, again: null, decisions: [], record: false, free: true, ledger: S.pasteLedger, client: S.pasteClient, text: doc };
    S.invoices.push(inv);
    inv.passes.push(await runPass({ suiteId: id }, proposal, { reused: false, record: false, ledger: inv.ledger, client: inv.client }));
    return { ok: true, result: inv.passes[0], view: view() };
  }

  async function approve(target, approver) {
    const inv = invOf(target);
    if (!inv) return { ok: false, error: `NOT_PROCESSED: ${target} has not arrived`, view: view() };
    const name = String(approver ?? '');
    const answer = { action: 'approve', target, by: name.trim(), label: label(), at: new Date().toISOString() };
    let res;
    try {
      res = S.gate.approveHeldProposal(inv.proposal, { approvedBy: name, timestamp: fixedTs, ledger: inv.ledger });
    } catch (err) {
      answer.ok = false; answer.status = 'REFUSED_BY_GATE'; answer.error = scrub(err.message);
      inv.decisions.push(answer);
      return { ok: true, answer, view: view() };
    }
    if (res.ok && res.idempotent) {
      answer.ok = true; answer.status = 'APPROVED'; answer.idempotent = true;
      inv.decisions.push(answer);
      return { ok: true, answer, view: view() };
    }
    if (!res.ok) {
      answer.ok = false; answer.status = res.status; answer.verdict = gateWord(res.verdict);
      if (inv.record) S.approverSteps.push({ afterPass: S.suiteRecords.length, action: 'approve', target, by: answer.by, enteredBy: 'desk page click through the local server', ok: false, status: res.status, idempotent: null, verdict: gateWord(res.verdict), signedLedgerEntryIndex: null, ledgerEntriesAdded: 0 });
      inv.decisions.push(answer);
      return { ok: true, answer, view: view() };
    }
    answer.ok = true; answer.status = 'APPROVED'; answer.idempotent = false; answer.signedLedgerEntryIndex = res.receipt.index;
    if (inv.record) S.approverSteps.push({ afterPass: S.suiteRecords.length, action: 'approve', target, by: answer.by, enteredBy: 'desk page click through the local server', ok: true, status: 'APPROVED', idempotent: false, verdict: gateWord(res.verdict), signedLedgerEntryIndex: res.receipt.index, ledgerEntriesAdded: 1 });
    inv.decisions.push(answer);
    const relProposal = Object.freeze({ ...inv.proposal, proposalId: `${inv.proposal.proposalId}-release` });
    inv.releaseProposal = relProposal;
    inv.release = await runPass(inv.record ? followRec(target, 'release') : { suiteId: `${target}-RELEASE` }, relProposal, { reused: true, reusesProposalOf: target, record: inv.record, ledger: inv.ledger, client: inv.client });
    return { ok: true, answer, release: inv.release, view: view() };
  }

  async function reject(target, approver) {
    const inv = invOf(target);
    if (!inv) return { ok: false, error: `NOT_PROCESSED: ${target} has not arrived`, view: view() };
    const name = String(approver ?? '');
    const answer = { action: 'reject', target, by: name.trim(), label: label(), at: new Date().toISOString() };
    try {
      const before = inv.ledger.entries.length;
      const res = S.gate.rejectHeldProposal(inv.proposal, { rejectedBy: name, timestamp: fixedTs, ledger: inv.ledger });
      answer.ok = true; answer.status = res.status; answer.signedLedgerEntryIndex = res.receipt.index;
      if (inv.record) S.approverSteps.push({ afterPass: S.suiteRecords.length, action: 'reject', target, by: answer.by, enteredBy: 'desk page click through the local server', ok: res.ok, status: res.status, idempotent: null, verdict: null, signedLedgerEntryIndex: res.receipt.index, ledgerEntriesAdded: inv.ledger.entries.length - before });
    } catch (err) {
      answer.ok = false; answer.status = 'REFUSED_BY_GATE'; answer.error = scrub(err.message);
    }
    inv.decisions.push(answer);
    return { ok: true, answer, view: view() };
  }

  async function again(target) {
    const inv = invOf(target);
    if (!inv || !inv.release || inv.release.status !== 'EXECUTED') return { ok: false, error: `NOTHING_TO_SEND_AGAIN: ${target} has no released payment`, view: view() };
    if (inv.again) return { ok: false, error: `ALREADY_SENT_AGAIN: ${target} was sent again once in this session`, view: view() };
    const proposal = Object.freeze({ ...inv.proposal, proposalId: `${inv.proposal.proposalId}-again` });
    inv.again = await runPass(inv.record ? followRec(target, 'again') : { suiteId: `${target}-AGAIN` }, proposal, { reused: true, reusesProposalOf: target, record: inv.record, ledger: inv.ledger, client: inv.client });
    return { ok: true, result: inv.again, view: view() };
  }

  function buildReceipt() {
    const ledgerJson = S.ledger.toJSON();
    const chainVerification = verifyReceiptChain(ledgerJson);
    const scoreboard = computeAttackSuiteScoreboard(ledgerJson.entries, S.suiteRecords, { scoreboardVersion: 2 });
    const apiCallLog = S.client.getApiCallLog();
    const httpsCallsCount = apiCallLog.filter((c) => c.mode === 'sandbox-https').length;
    return {
      receiptKind: 'attack-suite-run',
      gateGeneration,
      generatedAt: new Date().toISOString(),
      fixedEvaluationTimestamp: fixedTs,
      protagonist: S.protagonist,
      codeManifestSha256,
      attackSuiteSha256: suiteSha256,
      suiteSets: S.suiteSets,
      policyFeatures: S.policyFeatures,
      policyGateSha256,
      liveSandboxStatus: live ? 'LIVE_SANDBOX_CREATED_AND_CAPTURED' : 'SIMULATED_SUITE_RUN',
      sandboxBaseUrl: PAYPAL_SANDBOX_BASE_URL,
      gateSigner: ledgerJson.gateSigner,
      chainTipEd25519Signature: ledgerJson.chainTipEd25519Signature,
      policySnapshot: { ...S.baselineSnapshot },
      scoreboard,
      scoreboardBySet: { [SET_NAME]: scoreboard },
      summary: {
        totalProposals: S.suiteRecords.length,
        attacksTotal: scoreboard.attacksTotal, controlsTotal: scoreboard.controlsTotal,
        comparableAttacks: scoreboard.comparableAttacks, modelObeyedCount: scoreboard.modelObeyedCount,
        gateAdmittedAttacks: scoreboard.gateAdmittedAttacks, controlsPaid: scoreboard.controlsPaid,
        dollarsMovedOutsidePolicy: scoreboard.dollarsMovedOutsidePolicy,
        attackerGoalReachedInsidePolicyUsd: scoreboard.attackerGoalReachedInsidePolicyUsd,
        adversarialApiCallsExecuted: scoreboard.refusedApiCalls,
        liveHttpsCallsCount: httpsCallsCount,
        modelCalls: S.suiteRecords.filter((r) => r.modelCallMade).length,
      },
      approver: { names: [...new Set(S.approverSteps.map((a) => a.by))], enteredBy: 'desk page click through the local server', clickedByAPerson: null, note: 'The receipt does not record whether a person or a script drove the page.' },
      approverSteps: S.approverSteps,
      llmProposerSummary: {
        mode: useLiveModel ? 'live-llm-proposer' : 'recorded-run5-proposals',
        routeKey: useLiveModel ? MODEL_ROUTE : 'recorded:run5-proposals',
        provider: useLiveModel ? 'ollama-cloud' : 'recorded',
        requestedModel: useLiveModel ? 'glm-5.3' : null,
        returnedModel: S.returnedModel,
        totalTokensIn: S.tokensIn, totalTokensOut: S.tokensOut,
        proposals: S.llmProposals,
      },
      suiteRecords: S.suiteRecords,
      apiCallLog,
      chainVerification,
      ledger: ledgerJson,
    };
  }

  function exportReceipt() {
    const receipt = buildReceipt();
    let verdict;
    try {
      const v = verifyRecordedReceiptBundle(receipt, { bundleDir: gateDir });
      verdict = { ok: Boolean(v.ok), errors: (v.errors || []).slice(0, 12).map(scrub), headline: (v.summaryLines || []).filter((l) => /^VERDICT/.test(l)).map(scrub)[0] || null };
    } catch (err) {
      verdict = { ok: false, errors: [scrub(err.message)], headline: null };
    }
    return {
      receipt,
      verdict,
      passes: S.suiteRecords.length,
      expectedPasses: suite.records.length,
      note: S.suiteRecords.length === suite.records.length
        ? 'The session has the same number of passes as the suite file.'
        : `The frozen verifier needs exactly ${suite.records.length} passes in the suite file's order (six invoices, the release of the approved hold, its repeat). This session has ${S.suiteRecords.length}.`,
    };
  }

  return {
    live, simulate, label, proposalSource, scrub,
    status: () => view(),
    processNext: () => wrap(processNext),
    processPasted: (t, po) => wrap(() => processPasted(t, po)),
    approve: (t, who) => wrap(() => approve(t, who)),
    reject: (t, who) => wrap(() => reject(t, who)),
    again: (t) => wrap(() => again(t)),
    reset: () => serial(async () => { S = newSession(); return { ok: true, view: view() }; }),
    exportReceipt: () => serial(async () => exportReceipt()),
    exportPasted: () => serial(async () => ({ ledger: S.pasteLedger.toJSON(), apiCallLog: S.pasteClient.getApiCallLog(), inSessionReceipt: pasteInReceipt, note: 'Pasted invoices are kept out of the session receipt: the frozen verifier counts PROPOSED entries against the suite file. This ledger is signed and chained on its own.' })),
    get tag() { return S.tag; },
  };
}
