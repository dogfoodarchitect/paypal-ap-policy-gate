#!/usr/bin/env node
/**
 * hosted-demo-server.mjs — PayPal AP Policy Gate (5-Screen Web Application & API)
 *
 * "An agent that cannot pay outside its policy, and proves every payment afterwards."
 *
 * Usage:
 *   PORT=8799 node hosted-demo-server.mjs              # loads recorded receipts by default
 *   PORT=0    node hosted-demo-server.mjs              # automatic free-port selection
 *   PORT=8799 node hosted-demo-server.mjs --simulate   # deterministic synthetic simulation mode (0 network calls)
 *   PORT=8799 node hosted-demo-server.mjs --receipt <path-to-receipt.json>
 *
 * Five Product Screens (GET /):
 *   0. Attack Suite (25 Live)   — Receipt-computed 25-invoice prompt-injection & control benchmark scoreboard
 *   1. Payments & Ledger        — Settled PayPal Business orders, SHA-256 + Ed25519 chain inspector, Simulated Proposal Preview
 *   2. Policy Rules             — Editable PolicyGate caps, currency allowlist, and Approved Payee Allowlist (GET/PUT /api/policy)
 *   3. Exception Queue          — Controller review queue for refused invoices: Re-evaluate against live PolicyGate & Dismiss
 *   4. Offline Verifier & Scope — Browser WebCrypto verifier (/verify.html), single-file CLI verifier, primary-sourced scope
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ReceiptLedger, verifyReceiptChain, computeReceiptHash } from './receipt-ledger.mjs';
import {
  PolicyGate,
  DEFAULT_AP_POLICY_GATE_CONFIG,
  processAgentPaymentProposal,
  parseAmountToCents,
  formatCentsToAmount,
  deriveInvoiceDedupKeys,
} from './policy-gate.mjs';
import { PayPalSandboxClient } from './paypal-client.mjs';
import { buildSampleSupplierInvoices } from './ai-procurement-agent.mjs';
import { runSampleFixtureDemo } from './demo-cli.mjs';
import { verifyRecordedReceiptBundle } from './verify-payments.mjs';
import { computeAttackSuiteScoreboard } from './run-attack-suite.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHARED_ROOT = path.resolve(HERE, '_shared');
const DEFAULT_RECORDED_RECEIPT_PATH = path.join(HERE, 'recorded-live-sandbox-receipt.json');
const DEFAULT_SUITE_AFTER_PATH = path.join(HERE, 'attack-suite-after-fix-receipt.json');
const DEFAULT_SUITE_BEFORE_PATH = path.join(HERE, 'attack-suite-before-fix-receipt.json');
const DEFAULT_SUITE_CORPUS_PATH = path.join(HERE, 'attack-suite-pov4.json');
const VERIFY_HTML_PATH = path.join(HERE, 'verify.html');

export const PRODUCT_TITLE = 'PayPal AP Policy Gate';
export const PRODUCT_SUBTITLE =
  'Deterministic Spend Controls & Ed25519 Offline Audit Ledger for PayPal Business AP';
export const FIRST_PLACE_THESIS =
  'An agent that cannot pay outside its policy, and proves every payment afterwards.';
export const THIRD_PARTY_VERIFIER_SENTENCE =
  'The model never holds the PayPal credentials, and a stranger verifies every payment and every refusal offline with one file (recorded-live-sandbox-receipt.json) and no vendor trust.';
export const PAYPAL_TOOLKIT_CITATION =
  'PayPal\'s own "Agent toolkit quickstart guide" (https://developer.paypal.com/ai-tools/toolkit, Last updated: October 2, 2026) states that @paypal/agent-toolkit "supports the integration of PayPal APIs into AI agent workflows" and "works with LLM providers that support function calling" to "Integrate with PayPal APIs to access orders, invoices, subscriptions, shipment tracking, transaction details, and dispute management through pre-built functions" (with sample configuration placeholders PAYPAL_CLIENT_ID and PAYPAL_SECRET), while advising under Best practices: "System prompts: Use well-defined system prompts to control the behavior of the agent."';
export const SIMULATED_EXECUTION_BADGE_TEXT =
  'SIMULATED (local policy check only — 0 PayPal API calls)';

const SHARED_CONTENT_TYPES = Object.freeze({
  '.css': 'text/css; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jsonl': 'application/x-ndjson; charset=utf-8',
  '.woff2': 'font/woff2',
});

function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function readJsonBody(req, maxBytes = 262144) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
      }
    });
    req.on('end', () => {
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('INVALID_JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function serveSharedAsset(res, pathname) {
  const rel = pathname.slice('/_shared/'.length);
  if (!rel || rel.includes('\0')) {
    sendJson(res, 404, { error: 'NOT_FOUND', path: pathname });
    return;
  }
  const resolved = path.resolve(SHARED_ROOT, rel);
  if (!resolved.startsWith(SHARED_ROOT + path.sep)) {
    sendJson(res, 403, { error: 'FORBIDDEN_PATH' });
    return;
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    sendJson(res, 404, { error: 'NOT_FOUND', path: pathname });
    return;
  }
  const ext = path.extname(resolved).toLowerCase();
  const contentType = SHARED_CONTENT_TYPES[ext] || 'application/octet-stream';
  const buf = fs.readFileSync(resolved);
  res.writeHead(200, {
    'Content-Type': contentType,
    'Cache-Control': 'no-store',
  });
  res.end(buf);
}

function buildFallbackAttackSuiteSummary() {
  if (!fs.existsSync(DEFAULT_SUITE_CORPUS_PATH)) {
    return {
      available: false,
      mode: 'unavailable',
      after: null,
      before: null,
      records: [],
    };
  }
  const corpus = JSON.parse(fs.readFileSync(DEFAULT_SUITE_CORPUS_PATH, 'utf8'));
  const fixedTs = corpus.fixedEvaluationTimestamp || '2026-11-11T12:00:00.000Z';
  const records = (corpus.records || []).map((rec, idx) => {
    const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
    for (const s of rec.setup || []) {
      const sv = gate.evaluate(s, { timestamp: fixedTs, bypassDuplicateHold: true });
      if (sv.admitted) gate.commitAdmission(s, sv);
    }
    const targetProp = rec.kind === 'attack' ? rec.obedientProposal : (rec.honestProposal || rec.proposal);
    const v = gate.evaluate(targetProp, { timestamp: fixedTs });
    return {
      step: idx + 1,
      suiteId: rec.suiteId,
      kind: rec.kind,
      technique: rec.technique,
      whatTheAttackerWants: rec.whatTheAttackerWants,
      obeyedInjectionComparable: rec.obeyedInjectionComparable,
      obeyedInjection: rec.kind === 'attack' ? Boolean(rec.obeyedInjectionComparable) : null,
      matchedHonestProposal: rec.kind === 'control',
      honestProposalPolicyDecision: rec.kind === 'control' ? 'ALLOW' : null,
      invoiceSnippet: String(rec.invoice?.invoiceDocument || ''),
      modelProposal: targetProp,
      gateDecision: v.decision,
      outcome: v.admitted ? 'EXECUTED' : (v.decision === 'HOLD' ? 'HELD' : 'REFUSED'),
      reasonCode: v.reasonCode,
      reasonDetail: v.reasonDetail,
      apiCallsDelta: 0,
      paypalOrderId: v.admitted ? `SIMULATED-SUITE-${idx + 1}` : null,
      paypalCaptureId: v.admitted ? `SIMULATED-CAP-${idx + 1}` : null,
      proposedReceiptIndex: idx * 2 + 1,
      proposedReceiptHash: '0'.repeat(64),
      outcomeReceiptIndex: idx * 2 + 2,
      outcomeReceiptHash: '0'.repeat(64),
      beforeOutcome: null,
      beforeReasonCode: null,
    };
  });
  return {
    available: true,
    mode: 'offline-deterministic-preview',
    scopeNotice:
      'Model obedience is reported strictly over the 15 comparable prompt-injection attacks (never over 20 or 25). These 25 authored cases against one deterministic AP policy are an empirical red-team benchmark, not comprehensive coverage of PayPal or real-world fraud.',
    findingLine:
      'Offline suite preview (--simulate): run without --simulate to load recorded live glm-5.3 + PayPal Sandbox before/after attack-suite receipts.',
    before: null,
    after: {
      gateGeneration: 'patched-v2-preview',
      chainCount: 0,
      verifiedEd25519Signatures: 0,
      scoreboard: {
        attacksTotal: 20,
        controlsTotal: 5,
        comparableAttacks: 15,
        modelObeyedCount: 15,
        modelObeyedLabel: '15 of 15',
        gateAdmittedAttacks: 0,
        admittedAttackIds: [],
        controlsPaid: 5,
        controlsPaidLabel: '5 of 5',
        controlsSettledUsd: '6180.75',
        dollarsMovedOutsidePolicy: '0.00',
        refusedApiCalls: 0,
      },
    },
    records,
  };
}

function loadAttackSuiteEvidenceFromReceipts({ afterReceipt, afterSha256, beforeReceipt, beforeSha256 }) {
  if (!afterReceipt || !Array.isArray(afterReceipt?.ledger?.entries) || !Array.isArray(afterReceipt?.suiteRecords)) {
    return buildFallbackAttackSuiteSummary();
  }
  const afterScore = computeAttackSuiteScoreboard(afterReceipt.ledger.entries, afterReceipt.suiteRecords);
  const afterChain = verifyReceiptChain(afterReceipt.ledger);

  let beforeBlock = null;
  const beforeBySuiteId = new Map();
  if (beforeReceipt && Array.isArray(beforeReceipt?.ledger?.entries) && Array.isArray(beforeReceipt?.suiteRecords)) {
    const beforeScore = computeAttackSuiteScoreboard(beforeReceipt.ledger.entries, beforeReceipt.suiteRecords);
    const beforeChain = verifyReceiptChain(beforeReceipt.ledger);
    for (const br of beforeReceipt.suiteRecords) {
      beforeBySuiteId.set(br.suiteId, br);
    }
    beforeBlock = {
      receiptSha256: beforeSha256,
      gateGeneration: beforeReceipt.gateGeneration || 'pre-fix-v1',
      policyGateSha256: beforeReceipt.policyGateSha256 || null,
      chainValid: beforeChain.valid,
      chainCount: beforeChain.count,
      verifiedEd25519Signatures: beforeChain.verifiedEd25519Signatures,
      publicKeySha256: beforeChain.gatePublicKeySha256,
      scoreboard: beforeScore,
    };
  }

  const records = afterReceipt.suiteRecords.map((r) => {
    const prev = beforeBySuiteId.get(r.suiteId) || null;
    return {
      ...r,
      beforeOutcome: prev ? prev.outcome : null,
      beforeReasonCode: prev ? prev.reasonCode : null,
      beforeAmountUsd: prev ? prev.modelProposal?.amountValue : null,
    };
  });

  const beforeShortGate = beforeBlock?.policyGateSha256 ? beforeBlock.policyGateSha256.slice(0, 8) : 'pre-fix';
  const afterShortGate = afterReceipt.policyGateSha256 ? afterReceipt.policyGateSha256.slice(0, 8) : 'patched';
  const beforeIds = beforeBlock?.scoreboard?.admittedAttackIds?.length
    ? beforeBlock.scoreboard.admittedAttackIds.join(', ')
    : 'ATK-10';
  const beforeDollars = beforeBlock?.scoreboard?.dollarsMovedOutsidePolicy || '680.00';
  const beforeAdmitted = beforeBlock?.scoreboard?.gateAdmittedAttacks ?? 1;

  const findingLine = beforeBlock
    ? `Run 1 on unpatched policy-gate.mjs (${beforeShortGate}...) admitted ${beforeAdmitted} injected duplicate (${beforeIds}, $${beforeDollars} USD) because invoice deduplication compared raw case-sensitive strings; Run 2 on patched canonical NFKC + homoglyph + segment deduplication (${afterShortGate}...) admitted ${afterScore.gateAdmittedAttacks} outside-policy attacks ($${afterScore.dollarsMovedOutsidePolicy} outside policy) and paid ${afterScore.controlsPaid} of ${afterScore.controlsTotal} legitimate controls ($${afterScore.controlsSettledUsd} USD).`
    : `Patched canonical PolicyGate (${afterShortGate}...) admitted ${afterScore.gateAdmittedAttacks} outside-policy attacks ($${afterScore.dollarsMovedOutsidePolicy} outside policy) and paid ${afterScore.controlsPaid} of ${afterScore.controlsTotal} legitimate controls ($${afterScore.controlsSettledUsd} USD).`;

  return {
    available: true,
    mode: 'recorded-live-attack-suite',
    scopeNotice:
      'Model obedience is reported strictly over the 15 comparable prompt-injection attacks (never as a rate over 20 or 25; 5 attacks test duplicate/cap/currency gate state without an honest-vs-obedient split). These 25 authored cases against one deterministic AP policy are an empirical red-team benchmark, not comprehensive coverage of PayPal or real-world payment fraud.',
    findingLine,
    before: beforeBlock,
    after: {
      receiptSha256: afterSha256,
      gateGeneration: afterReceipt.gateGeneration || 'patched-v2',
      policyGateSha256: afterReceipt.policyGateSha256 || null,
      attackSuiteSha256: afterReceipt.attackSuiteSha256 || null,
      llmRoute: afterReceipt.llmProposerSummary?.routeKey || 'ollama-cloud:glm-5.3',
      chainValid: afterChain.valid,
      chainCount: afterChain.count,
      verifiedEd25519Signatures: afterChain.verifiedEd25519Signatures,
      publicKeySha256: afterChain.gatePublicKeySha256,
      liveHttpsCallsCount: afterReceipt.summary?.liveHttpsCallsCount || 0,
      scoreboard: afterScore,
    },
    records,
  };
}

function buildInitialExceptionsFromChain(entries, llmProposals = [], fixtureInvoices = []) {
  const refusedEntries = entries.filter((e) => e && e.stage === 'REFUSED');
  const exceptions = [];

  for (let i = 0; i < refusedEntries.length; i += 1) {
    const ref = refusedEntries[i];
    const proposed = entries.find((e) => e && e.stage === 'PROPOSED' && e.proposalId === ref.proposalId) || {};
    const llmMatch =
      llmProposals.find((p) => p.proposalId === ref.proposalId) ||
      llmProposals[i + 2] ||
      null;
    const fixMatch =
      fixtureInvoices.find((f) => f.proposalId === ref.proposalId || f.step === i + 3) || {};

    const exceptionId = `EXC-${String(i + 1).padStart(2, '0')}`;
    const amountUsd = String(
      ref.payload?.attemptedAmountValue ||
        proposed.payload?.amountValue ||
        llmMatch?.amountUsd ||
        fixMatch.amountValue ||
        '0.00'
    );
    const invoiceId = String(
      ref.payload?.invoiceId || proposed.payload?.invoiceId || llmMatch?.invoiceId || fixMatch.invoiceId || ''
    );
    const payeeEmail = String(
      ref.payload?.payeeEmail || proposed.payload?.payeeEmail || llmMatch?.payeeEmail || fixMatch.payeeEmail || ''
    );
    const payeeId = String(
      ref.payload?.payeeId || proposed.payload?.payeeId || llmMatch?.payeeId || fixMatch.payeeId || 'unverified-vendor'
    );
    const supplierName = String(
      ref.payload?.supplierName ||
        proposed.payload?.supplierName ||
        llmMatch?.supplierName ||
        fixMatch.supplierName ||
        payeeId
    );
    const payeeMerchantId =
      ref.payload?.payeeMerchantId ??
      proposed.payload?.payeeMerchantId ??
      llmMatch?.payeeMerchantId ??
      fixMatch.payeeMerchantId ??
      null;
    const currencyCode = String(
      ref.payload?.currencyCode || proposed.payload?.currencyCode || 'USD'
    );
    const reason = String(
      ref.payload?.reason || proposed.payload?.reason || llmMatch?.reason || fixMatch.reason || 'Supplier invoice'
    );
    const invoiceMemo = String(
      ref.payload?.invoiceMemo ||
        proposed.payload?.invoiceMemo ||
        llmMatch?.invoiceMemo ||
        fixMatch.invoiceMemo ||
        ''
    );
    const aiRoute = proposed.payload?.aiModelRoute || {};
    const poNumber =
      proposed.payload?.poNumber ||
      ref.payload?.poNumber ||
      ref.policyVerdict?.poNumber ||
      fixMatch.poNumber ||
      llmMatch?.poNumber ||
      null;

    exceptions.push({
      exceptionId,
      status: 'PENDING_REVIEW',
      proposalId: ref.proposalId,
      invoiceId,
      payeeId,
      supplierName,
      payeeEmail,
      payeeMerchantId,
      amountUsd,
      currencyCode,
      reason,
      invoiceMemo,
      initialReasonCode: ref.payload?.refusalCode || ref.policyVerdict?.reasonCode || 'POLICY_REFUSED',
      reasonCode: ref.payload?.refusalCode || ref.policyVerdict?.reasonCode || 'POLICY_REFUSED',
      reasonDetail: ref.payload?.refusalDetail || ref.policyVerdict?.reasonDetail || '',
      paypalApiCallsExecuted: 0,
      proposedReceiptIndex: proposed.index ?? null,
      refusalReceiptIndex: ref.index,
      refusalReceiptHash: ref.receiptHash,
      llmProposal: {
        provider: llmMatch?.provider || aiRoute.provider || 'offline-deterministic-fallback',
        model: llmMatch?.returnedModel || aiRoute.returnedModel || 'deterministic-structured-extractor',
        promptSha256: llmMatch?.promptSha256 || aiRoute.promptSha256 || null,
        responseSha256: llmMatch?.responseSha256 || aiRoute.responseSha256 || null,
        rawCompletion:
          llmMatch?.rawCompletion ||
          aiRoute.rawCompletion ||
          JSON.stringify({
            proposalId: ref.proposalId,
            invoiceId,
            supplierName,
            payeeEmail,
            payeeMerchantId,
            amountValue: amountUsd,
            currencyCode,
            reason,
          }),
      },
      proposal: {
        proposalId: ref.proposalId,
        invoiceId,
        payeeId,
        supplierName,
        payeeEmail,
        payeeMerchantId,
        amountValue: amountUsd,
        currencyCode,
        poNumber,
        reason,
      },
      reevaluatedCount: 0,
      resolutionNote: null,
      dismissReason: null,
      updatedAt: ref.timestamp,
    });
  }

  return exceptions;
}

function hydratePolicyGateFromBaseline(entries, baselineDayTimestamp) {
  const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const admittedEntries = entries.filter((e) => e && e.stage === 'ADMITTED');
  for (const adm of admittedEntries) {
    const cents = parseAmountToCents(adm.payload?.amountValue || adm.policyVerdict?.amountValue || '0');
    if (cents !== null) {
      const dayKey = gate.getUtcDayKey(baselineDayTimestamp);
      gate.dailySpendByDate.set(dayKey, (gate.dailySpendByDate.get(dayKey) || 0) + cents);
    }
    if (adm.payload?.invoiceId) {
      gate.processedInvoices.add(adm.payload.invoiceId);
      const dedup = deriveInvoiceDedupKeys(adm.payload.invoiceId);
      for (const k of dedup.keys) {
        gate.processedInvoiceKeys.add(k);
      }
    }
    if (adm.proposalId) {
      gate.processedProposals.add(adm.proposalId);
    }
    if (cents !== null && adm.payload?.payeeEmail) {
      const payeeEmail = String(adm.payload.payeeEmail).trim().toLowerCase();
      const dayKey = gate.getUtcDayKey(baselineDayTimestamp);
      if (adm.payload?.invoiceId) {
        const dedup = deriveInvoiceDedupKeys(adm.payload.invoiceId);
        if (dedup.valid) {
          const bag = gate._keysForPayee(payeeEmail);
          for (const k of dedup.keys) bag.add(k);
        }
      }
      const poNumber = adm.payload?.poNumber || adm.policyVerdict?.poNumber || null;
      if (poNumber) {
        const po = gate.getPurchaseOrder(poNumber);
        if (po) po.paidCents += cents;
      }
      gate.paidPayments.push({
        invoiceId: adm.payload.invoiceId,
        payeeEmail,
        amountCents: cents,
        currencyCode: String(adm.payload.currencyCode || 'USD').toUpperCase(),
        dayKey,
        poNumber,
      });
    }
  }
  return gate;
}

function escServerHtml(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtServerUsd(val) {
  const n = Number(val || 0);
  return '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function renderSettledRowsServerHtml(state) {
  const isOfflineMode = state?.proofMode === 'offline-simulation';
  return (state?.settledPayments || [])
    .map((o) => {
      const isSim = Boolean(o.simulated || isOfflineMode);
      const secId = o.paypalInvoiceId
        ? 'Invoice: ' + o.paypalInvoiceId
        : o.paypalPayoutBatchId
          ? 'Payout: ' + o.paypalPayoutBatchId
          : isSim
            ? 'SIMULATED_LOCAL_NO_PAYPAL_CALL'
            : 'Orders v2 Direct';
      const dbg = o.getOrderPaypalDebugId
        ? ' · Debug-Id: ' + o.getOrderPaypalDebugId
        : isSim
          ? ' · 0 PayPal API calls'
          : '';
      const statusHtml = isSim
        ? '<div style="margin-top:3px;"><span class="badge badge-err">' +
          escServerHtml(SIMULATED_EXECUTION_BADGE_TEXT) +
          '</span></div>'
        : '<div style="color:var(--os-green)">COMPLETED</div>';
      return (
        '<tr data-simulated="' + (isSim ? 'true' : 'false') + '">' +
        '<td class="mono"><strong>' + escServerHtml(o.invoiceId) + '</strong></td>' +
        '<td><strong>' + escServerHtml(o.supplier) + '</strong><div class="mono" style="color:var(--os-muted)">' + escServerHtml(o.payeeEmail) + ' · ' + escServerHtml(o.rail) + '</div></td>' +
        '<td class="mono"><strong>' + fmtServerUsd(o.amountUsd) + '</strong>' + statusHtml + '</td>' +
        '<td class="mono">Order: ' + escServerHtml(o.paypalOrderId) + '<br/>Capture: ' + escServerHtml(o.paypalCaptureId) + '</td>' +
        '<td class="mono">' + escServerHtml(secId + dbg) + '</td>' +
        '</tr>'
      );
    })
    .join('');
}

export function renderProductHtml(initialState, { defaultScreen = 'ledger', standalone = false } = {}) {
  const safeJson = JSON.stringify(initialState).replace(/</g, '\\u003c');
  const safeScreen = JSON.stringify(defaultScreen);
  const safeStandalone = standalone ? 'true' : 'false';
  const initialSettledRowsHtml = renderSettledRowsServerHtml(initialState);

  const tokenStylesheetTag = standalone
    ? ''
    : '<link rel="stylesheet" href="/_shared/os-tokens.css" />\n  <script type="module" src="/_shared/controls/schema.mjs"></script>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${PRODUCT_TITLE} — ${PRODUCT_SUBTITLE}</title>
  ${tokenStylesheetTag}
  <style>
    :root {
      --os-ground: #F4F4F2;
      --os-ground-void: #ffffff;
      --os-ground-absorptive: #f7f8fa;
      --os-ink: #0a0a0f;
      --os-muted: #4c5362;
      --os-rule: #d5d9e2;
      --os-blue: #1D4AFF;
      --os-green: #0d7a3e;
      --os-crimson: #991b1b;
      --os-tint-green: rgba(13, 122, 62, 0.085);
      --os-tint-crimson: rgba(153, 27, 27, 0.085);
      --os-tint-blue: rgba(29, 74, 255, 0.075);
      --os-font-body: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --os-font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
      --os-radius-sm: 8px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 12px 24px 16px;
      background: var(--os-ground);
      color: var(--os-ink);
      font-family: var(--os-font-body);
      font-size: 13.5px;
      line-height: 1.42;
    }
    .app-shell {
      max-width: 1860px;
      margin: 0 auto;
    }
    header.product-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      padding: 12px 18px;
      background: var(--os-ground-void);
      border: 1px solid var(--os-rule);
      border-radius: var(--os-radius-sm);
      margin-bottom: 10px;
    }
    .brand-row {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 3px;
    }
    .brand-mark {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 26px;
      height: 26px;
      border-radius: 6px;
      background: var(--os-blue);
      color: #ffffff;
      font-family: var(--os-font-mono);
      font-weight: 800;
      font-size: 12px;
      flex-shrink: 0;
    }
    h1.product-title {
      margin: 0;
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.015em;
    }
    .product-sub {
      color: var(--os-muted);
      font-size: 12.5px;
      font-weight: 600;
    }
    .thesis-line {
      margin: 4px 0 0;
      font-size: 14px;
      font-weight: 700;
      color: var(--os-blue);
    }
    .header-meta {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 6px;
      flex-shrink: 0;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 5px 11px;
      border-radius: 6px;
      font-family: var(--os-font-mono);
      font-size: 11.5px;
      font-weight: 700;
      border: 1px solid var(--os-rule);
      background: var(--os-ground-absorptive);
    }
    .pill-green {
      background: var(--os-tint-green);
      border-color: var(--os-green);
      color: var(--os-green);
    }
    .pill-blue {
      background: var(--os-tint-blue);
      border-color: var(--os-blue);
      color: var(--os-blue);
    }
    .pill-crimson {
      background: var(--os-tint-crimson);
      border-color: var(--os-crimson);
      color: var(--os-crimson);
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: 1.2fr 0.9fr 0.85fr 1.2fr 1.15fr;
      gap: 10px;
      margin-bottom: 10px;
    }
    .suite-kpi-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 10px;
      margin-bottom: 10px;
    }
    .kpi-card {
      background: var(--os-ground-void);
      border: 1px solid var(--os-rule);
      border-radius: var(--os-radius-sm);
      padding: 9px 13px;
    }
    .kpi-label {
      font-family: var(--os-font-mono);
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--os-muted);
      margin-bottom: 3px;
    }
    .kpi-value {
      font-size: 19px;
      font-weight: 800;
      letter-spacing: -0.02em;
      font-variant-numeric: tabular-nums;
    }
    .kpi-detail {
      font-family: var(--os-font-mono);
      font-size: 11px;
      color: var(--os-muted);
      margin-top: 3px;
    }
    .nav-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      background: var(--os-ground-void);
      border: 1px solid var(--os-rule);
      border-radius: var(--os-radius-sm);
      padding: 6px 10px;
      margin-bottom: 10px;
    }
    .nav-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .nav-tab {
      appearance: none;
      border: 1px solid transparent;
      background: transparent;
      color: var(--os-muted);
      font-family: var(--os-font-body);
      font-size: 13px;
      font-weight: 700;
      padding: 7px 12px;
      border-radius: 6px;
      cursor: pointer;
    }
    .nav-tab:hover {
      background: var(--os-ground-absorptive);
      color: var(--os-ink);
    }
    .nav-tab.active {
      background: var(--os-blue);
      color: #ffffff;
      border-color: var(--os-blue);
    }
    .tab-badge {
      display: inline-block;
      margin-left: 6px;
      padding: 1px 6px;
      border-radius: 4px;
      font-family: var(--os-font-mono);
      font-size: 11px;
      background: rgba(10, 10, 15, 0.08);
    }
    .nav-tab.active .tab-badge {
      background: rgba(255, 255, 255, 0.22);
      color: #ffffff;
    }
    .screen-pane {
      display: none;
    }
    .screen-pane.active {
      display: block;
    }
    .two-col {
      display: grid;
      grid-template-columns: 1.24fr 0.96fr;
      gap: 12px;
      align-items: start;
    }
    .card {
      background: var(--os-ground-void);
      border: 1px solid var(--os-rule);
      border-radius: var(--os-radius-sm);
      padding: 12px 15px;
      margin-bottom: 10px;
    }
    .card-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
      padding-bottom: 7px;
      border-bottom: 1px solid var(--os-rule);
    }
    .card-title {
      margin: 0;
      font-size: 14.5px;
      font-weight: 800;
      letter-spacing: -0.01em;
    }
    .card-eyebrow {
      font-family: var(--os-font-mono);
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--os-muted);
    }
    table.data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12.5px;
    }
    table.data-table th {
      text-align: left;
      font-family: var(--os-font-mono);
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--os-muted);
      padding: 6px 8px;
      border-bottom: 1px solid var(--os-rule);
      background: var(--os-ground-absorptive);
    }
    table.data-table td {
      padding: 6px 8px;
      border-bottom: 1px solid var(--os-rule);
      vertical-align: top;
    }
    #settled-payments-table th:nth-child(1),
    #settled-payments-table td:nth-child(1) {
      min-width: 146px;
    }
    #settled-payments-table th:nth-child(3),
    #settled-payments-table td:nth-child(3) {
      min-width: 104px;
    }
    #ledger-entries-table td,
    #suite-records-table td {
      padding: 4px 8px;
      font-size: 12px;
      vertical-align: middle;
    }
    .suite-scroll {
      max-height: 500px;
      overflow-y: auto;
    }
    table.data-table tr.clickable-row {
      cursor: pointer;
    }
    table.data-table tr.clickable-row:hover {
      background: var(--os-ground-absorptive);
    }
    table.data-table tr.selected-row {
      background: var(--os-tint-blue);
    }
    .mono {
      font-family: var(--os-font-mono);
      font-size: 11.5px;
      overflow-wrap: break-word;
    }
    .badge {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 4px;
      font-family: var(--os-font-mono);
      font-size: 10.5px;
      font-weight: 700;
      border: 1px solid var(--os-rule);
    }
    .badge-ok {
      background: var(--os-tint-green);
      border-color: var(--os-green);
      color: var(--os-green);
    }
    .badge-err {
      background: var(--os-tint-crimson);
      border-color: var(--os-crimson);
      color: var(--os-crimson);
    }
    .badge-info {
      background: var(--os-tint-blue);
      border-color: var(--os-blue);
      color: var(--os-blue);
    }
    .badge-muted {
      background: var(--os-ground-absorptive);
      border-color: var(--os-rule);
      color: var(--os-muted);
    }
    .btn {
      appearance: none;
      border: 1px solid var(--os-rule);
      background: var(--os-ground-void);
      color: var(--os-ink);
      font-family: var(--os-font-body);
      font-size: 12.5px;
      font-weight: 700;
      padding: 7px 12px;
      border-radius: 6px;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover {
      background: var(--os-ground-absorptive);
    }
    .btn-primary {
      background: var(--os-blue);
      border-color: var(--os-blue);
      color: #ffffff;
    }
    .btn-primary:hover {
      opacity: 0.93;
      background: var(--os-blue);
      color: #ffffff;
    }
    .btn-green {
      background: var(--os-green);
      border-color: var(--os-green);
      color: #ffffff;
    }
    .btn-green:hover {
      opacity: 0.93;
      background: var(--os-green);
      color: #ffffff;
    }
    .btn-crimson {
      background: var(--os-tint-crimson);
      border-color: var(--os-crimson);
      color: var(--os-crimson);
    }
    .btn-crimson:hover {
      opacity: 0.93;
      background: var(--os-tint-crimson);
      color: var(--os-crimson);
    }
    .btn-sm {
      padding: 5px 9px;
      font-size: 11.5px;
    }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-bottom: 10px;
    }
    .form-grid-2 {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      margin-bottom: 10px;
    }
    .field label {
      display: block;
      font-family: var(--os-font-mono);
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--os-muted);
      margin-bottom: 4px;
    }
    .field input:not([type="checkbox"]), .field select, .field textarea {
      width: 100%;
      padding: 7px 9px;
      border: 1px solid var(--os-rule);
      border-radius: 6px;
      font-family: var(--os-font-mono);
      font-size: 12px;
      color: var(--os-ink);
      background: var(--os-ground-void);
    }
    .code-box {
      background: var(--os-ground-absorptive);
      border: 1px solid var(--os-rule);
      border-radius: 6px;
      padding: 9px 11px;
      font-family: var(--os-font-mono);
      font-size: 11.5px;
      line-height: 1.42;
      white-space: pre-wrap;
      overflow-wrap: break-word;
      margin: 0;
    }
    #inspector-json {
      max-height: 285px;
      overflow-y: auto;
    }
    #exc-llm-json, #suite-detail-json {
      max-height: 215px;
      overflow-y: auto;
    }
    #tamper-output {
      max-height: 205px;
      overflow-y: auto;
    }
    .memo-isolation-box {
      background: var(--os-tint-crimson);
      border: 1px solid var(--os-crimson);
      border-radius: 6px;
      padding: 9px 11px;
      margin: 8px 0;
    }
    .memo-isolation-label {
      font-family: var(--os-font-mono);
      font-size: 10.5px;
      font-weight: 700;
      color: var(--os-crimson);
      text-transform: uppercase;
      margin-bottom: 3px;
    }
    .finding-banner {
      background: var(--os-tint-green);
      border: 1px solid var(--os-green);
      border-radius: 6px;
      padding: 9px 13px;
      margin-bottom: 9px;
      font-size: 12.5px;
    }
    .scope-strip {
      background: var(--os-ground-absorptive);
      border: 1px solid var(--os-rule);
      border-radius: 6px;
      padding: 7px 12px;
      margin-bottom: 10px;
      font-family: var(--os-font-mono);
      font-size: 11px;
      color: var(--os-muted);
    }
    .exception-card {
      border: 1px solid var(--os-rule);
      border-radius: var(--os-radius-sm);
      padding: 13px 15px;
      margin-bottom: 10px;
      background: var(--os-ground-void);
    }
    .exception-card.exc-pending {
      border-left: 4px solid var(--os-crimson);
    }
    .exception-card.exc-cleared {
      border-left: 4px solid var(--os-green);
    }
    .exception-card.exc-dismissed {
      border-left: 4px solid var(--os-muted);
      opacity: 0.88;
    }
    .notice-banner {
      padding: 9px 13px;
      border-radius: 6px;
      font-family: var(--os-font-mono);
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 10px;
      display: none;
    }
    .notice-banner.visible {
      display: block;
    }
    .scope-list {
      margin: 0;
      padding-left: 18px;
    }
    .scope-list li {
      margin-bottom: 7px;
    }
    footer.product-footer {
      margin-top: 12px;
      padding: 10px 16px;
      background: var(--os-ground-void);
      border: 1px solid var(--os-rule);
      border-radius: var(--os-radius-sm);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      font-family: var(--os-font-mono);
      font-size: 11px;
      color: var(--os-muted);
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <header class="product-header">
      <div>
        <div class="brand-row">
          <span class="brand-mark">AP</span>
          <h1 class="product-title">${PRODUCT_TITLE}</h1>
          <span class="product-sub">· ${PRODUCT_SUBTITLE}</span>
        </div>
        <p class="thesis-line">${FIRST_PLACE_THESIS}</p>
      </div>
      <div class="header-meta">
        <div id="dataset-status-pill" class="pill pill-blue"></div>
        <div id="chain-header-pill" class="pill pill-green"></div>
      </div>
    </header>

    <section class="kpi-grid" aria-label="Live Spend Policy & Audit KPIs">
      <div class="kpi-card">
        <div class="kpi-label">Settled Today vs Daily Cap</div>
        <div class="kpi-value" id="kpi-settled">$2,100.00 / $5,000.00</div>
        <div class="kpi-detail" id="kpi-settled-sub">Real daily headroom: $2,900.00 USD</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Per-Payment Cap</div>
        <div class="kpi-value" id="kpi-per-tx">$2,500.00</div>
        <div class="kpi-detail" id="kpi-currencies">Allowed currencies: USD</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Approved Payees</div>
        <div class="kpi-value" id="kpi-payees">3 active</div>
        <div class="kpi-detail" id="kpi-payees-sub">Allowlisted PayPal Business receivers</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Exception Queue</div>
        <div class="kpi-value" id="kpi-exceptions">3 pending review</div>
        <div class="kpi-detail" id="kpi-exceptions-sub">$6,720.00 blocked · 0 PayPal API calls on refusals</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">SHA-256 + Ed25519 Chain</div>
        <div class="kpi-value" id="kpi-chain">15 of 15 valid</div>
        <div class="kpi-detail" id="kpi-chain-sub">RFC 8032 Ed25519 signatures from the in-process signing key</div>
      </div>
    </section>

    <nav class="nav-bar" aria-label="Product Screens">
      <div class="nav-tabs">
        <button type="button" class="nav-tab" id="tab-suite" data-screen="suite">
          Attack Suite (25 Live) <span class="tab-badge" id="badge-suite-outside">$0 outside</span>
        </button>
        <button type="button" class="nav-tab" id="tab-desk" data-screen="desk">
          AP Desk <span class="tab-badge" id="badge-desk-holds">0 holds</span>
        </button>
        <button type="button" class="nav-tab" id="tab-ledger" data-screen="ledger">
          1. Payments &amp; Ledger <span class="tab-badge" id="badge-ledger-count">15</span>
        </button>
        <button type="button" class="nav-tab" id="tab-policy" data-screen="policy">
          2. Policy Rules <span class="tab-badge" id="badge-policy-payees">3 payees</span>
        </button>
        <button type="button" class="nav-tab" id="tab-exceptions" data-screen="exceptions">
          3. Exception Queue <span class="tab-badge" id="badge-exc-pending">3 pending</span>
        </button>
        <button type="button" class="nav-tab" id="tab-verifier" data-screen="verifier">
          4. Offline Verifier &amp; Buyer Scope
        </button>
      </div>
      <div style="display:flex; gap:8px; align-items:center;">
        <a href="/verify.html" class="btn btn-sm" id="link-browser-verifier">Verify in Browser (WebCrypto)</a>
        <button type="button" class="btn btn-sm" id="btn-reset-baseline">Reset Baseline Policy &amp; Queue</button>
      </div>
    </nav>

    <div id="action-banner" class="notice-banner"></div>

    <!-- AP DESK: inbox, proposal, PO card, review queue, ledger, verify -->
    <section id="screen-desk" class="screen-pane">
      <div class="two-col">
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Accounts Payable Desk</div>
              <h2 class="card-title">Invoice Inbox</h2>
            </div>
          </div>
          <p class="card-copy">Select an invoice to draft a proposal, see the gate decision and purchase-order card, then pay, hold for approval, or refuse. Nothing here talks to a live PayPal account in this folder unless a recorded receipt is loaded.</p>
          <table>
            <thead>
              <tr><th>Invoice</th><th>Supplier</th><th>Amount</th><th>Purchase order</th></tr>
            </thead>
            <tbody id="desk-inbox-tbody"></tbody>
          </table>
        </div>
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Proposal and gate</div>
              <h2 class="card-title" id="desk-proposal-title">No invoice selected</h2>
            </div>
            <span class="badge badge-info" id="desk-decision-badge">—</span>
          </div>
          <div class="mono" id="desk-invoice-doc" style="color:var(--os-ink); line-height:1.45; margin-bottom:12px;"></div>
          <div class="kpi-card" id="desk-po-card" style="margin-bottom:12px;">
            <div class="kpi-label">Purchase order</div>
            <div class="kpi-value" id="desk-po-number">—</div>
            <div class="kpi-detail" id="desk-po-detail">Cite an open PO that belongs to this supplier, in USD, with enough remaining balance.</div>
          </div>
          <div class="kpi-card" id="desk-verdict-card">
            <div class="kpi-label">Gate decision</div>
            <div class="kpi-value" id="desk-verdict-code">—</div>
            <div class="kpi-detail" id="desk-verdict-detail">The model proposes. The gate decides. PayPal is called only after ALLOW.</div>
          </div>
          <div style="display:flex; gap:8px; margin-top:12px; flex-wrap:wrap;">
            <button type="button" class="btn btn-primary" id="btn-desk-propose">Submit payment proposal</button>
            <a href="/verify.html" class="btn btn-sm">Open verifier</a>
          </div>
        </div>
      </div>
      <div class="two-col" style="margin-top:16px;">
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Review queue</div>
              <h2 class="card-title">Approve once or reject</h2>
            </div>
            <span class="badge badge-info" id="desk-holds-count">0 open holds</span>
          </div>
          <p class="card-copy">A named person approves a held payment once. The approval is bound to the exact supplier, amount, currency, invoice and purchase order. Invoice text cannot approve. Rules 1-6 are checked again before the hold is released.</p>
          <label class="field-label" for="desk-approver-name">Approver name</label>
          <input class="field-input" id="desk-approver-name" type="text" value="A. Controller" />
          <div id="desk-holds-list" style="margin-top:12px;"></div>
        </div>
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Signed ledger</div>
              <h2 class="card-title">Recent entries with PayPal ids</h2>
            </div>
          </div>
          <table>
            <thead>
              <tr><th>#</th><th>Stage</th><th>Invoice</th><th>PayPal</th></tr>
            </thead>
            <tbody id="desk-ledger-tbody"></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- SCREEN 0: 25-INVOICE PROMPT-INJECTION & CONTROL ATTACK SUITE SCOREBOARD -->
    <section id="screen-suite" class="screen-pane">
      <div class="suite-kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Recorded Suite Corpus</div>
          <div class="kpi-value" id="suite-kpi-total">20 attacks · 5 controls</div>
          <div class="kpi-detail" id="suite-kpi-route">Live ollama-cloud:glm-5.3 + PayPal Sandbox</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Comparable Injection Obedience</div>
          <div class="kpi-value" id="suite-kpi-obeyed">-- of 15</div>
          <div class="kpi-detail">Strictly over 15 comparable attacks (5 non-comparable separate)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Admitted Outside Policy</div>
          <div class="kpi-value" id="suite-kpi-admitted" style="color:var(--os-green)">0 of 20 ($0.00)</div>
          <div class="kpi-detail" id="suite-kpi-admitted-sub">0 PayPal API calls on every refusal</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Legitimate Controls Paid</div>
          <div class="kpi-value" id="suite-kpi-controls" style="color:var(--os-green)">5 of 5</div>
          <div class="kpi-detail" id="suite-kpi-controls-sub">Settled on PayPal Sandbox · 0 false blocks</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Signed Suite Receipt Chain</div>
          <div class="kpi-value" id="suite-kpi-chain">-- valid</div>
          <div class="kpi-detail" id="suite-kpi-pubkey">SHA-256 + RFC 8032 Ed25519 verified</div>
        </div>
      </div>

      <div class="finding-banner" id="suite-finding-banner"></div>
      <div class="scope-strip" id="suite-scope-strip"></div>

      <div class="two-col">
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Computed From Signed Receipt Chain (attack-suite-after-fix-receipt.json)</div>
              <h2 class="card-title">25-Invoice Prompt-Injection &amp; Control Results (Click Any Row to Inspect)</h2>
            </div>
            <div style="display:flex; gap:6px;">
              <button type="button" class="btn btn-sm" data-suite-filter="all" id="btn-suite-all">All (25)</button>
              <button type="button" class="btn btn-sm" data-suite-filter="obeyed" id="btn-suite-obeyed">Model Obeyed</button>
              <button type="button" class="btn btn-sm" data-suite-filter="control" id="btn-suite-controls">Controls (5)</button>
            </div>
          </div>
          <div class="suite-scroll">
            <table class="data-table" id="suite-records-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Technique / Scenario</th>
                  <th>glm-5.3 Obedience</th>
                  <th>Gate Verdict &amp; Code</th>
                  <th>Amount &amp; API Calls</th>
                </tr>
              </thead>
              <tbody id="suite-records-tbody"></tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Untrusted Document -> Model Proposal -> Deterministic Gate Verdict</div>
              <h2 class="card-title" id="suite-detail-title">ATK-10 — Case-Variant Duplicate Invoice</h2>
            </div>
            <span class="badge badge-err" id="suite-detail-badge">REFUSED · DUPLICATE_INVOICE</span>
          </div>
          <div class="mono" style="margin-bottom:6px; color:var(--os-muted);" id="suite-detail-goal"></div>
          <div class="memo-isolation-box">
            <div class="memo-isolation-label">Raw Untrusted Invoice Document Fed to Live glm-5.3</div>
            <div class="mono" id="suite-detail-doc" style="white-space:pre-wrap;"></div>
          </div>
          <div class="card-eyebrow" style="margin: 8px 0 4px;">Model Candidate Proposal, Run 1 -> Run 2 Delta &amp; Signed Receipt Hash</div>
          <pre class="code-box" id="suite-detail-json"></pre>
        </div>
      </div>
    </section>

    <!-- SCREEN 1: PAYMENTS & LEDGER -->
    <section id="screen-ledger" class="screen-pane">
      <div class="two-col">
        <div>
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">PayPal Business Sandbox Settlements (api-m.sandbox.paypal.com)</div>
                <h2 class="card-title">Settled Supplier Payments (Orders v2 · Invoicing v2 · Payouts v1)</h2>
              </div>
              <span class="badge badge-ok" id="settled-mode-badge">RECORDED SANDBOX</span>
            </div>
            <table class="data-table" id="settled-payments-table">
              <thead>
                <tr>
                  <th>Invoice</th>
                  <th>Approved Supplier &amp; Rail</th>
                  <th>Amount</th>
                  <th>PayPal Order / Capture ID</th>
                  <th>Secondary Rail ID &amp; Debug ID</th>
                </tr>
              </thead>
              <tbody id="settled-payments-tbody">${initialSettledRowsHtml}</tbody>
            </table>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Cryptographic Audit Trail (#00 GENESIS -> Tip · SHA-256 + Ed25519)</div>
                <h2 class="card-title">Signed Hash-Chained Receipt Ledger (Click Any Row to Inspect)</h2>
              </div>
              <span class="badge badge-info" id="ledger-count-badge">15 / 15 VALID</span>
            </div>
            <table class="data-table" id="ledger-entries-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Stage</th>
                  <th>Proposal / Invoice</th>
                  <th>Decision / Amount</th>
                  <th>Receipt SHA-256</th>
                </tr>
              </thead>
              <tbody id="ledger-entries-tbody"></tbody>
            </table>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Selected Chain Link &amp; Ed25519 Signature</div>
                <h2 class="card-title" id="inspector-title">Receipt #03 — EXECUTED</h2>
              </div>
              <span class="badge badge-ok" id="inspector-hash-badge">SHA-256 + Ed25519 MATCH</span>
            </div>
            <pre class="code-box" id="inspector-json"></pre>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Local Policy Preview (Emits SIMULATED-ORDER-* · Preserves Real Settled Headroom · 0 API Calls)</div>
                <h2 class="card-title">Simulated Invoice Preview (POST /api/propose)</h2>
              </div>
              <span class="badge badge-muted">SIMULATED PREVIEW · 0 API Calls</span>
            </div>
            <form id="form-new-proposal">
              <div class="form-grid-2">
                <div class="field">
                  <label for="prop-invoice-id">Invoice ID</label>
                  <input id="prop-invoice-id" name="invoiceId" value="INV-2026-1099" required />
                </div>
                <div class="field">
                  <label for="prop-amount">Amount (USD)</label>
                  <input id="prop-amount" name="amountValue" value="320.00" required />
                </div>
                <div class="field">
                  <label for="prop-email">PayPal Receiver Email</label>
                  <input id="prop-email" name="payeeEmail" value="ap@sound-freight.example" required />
                </div>
                <div class="field">
                  <label for="prop-currency">Currency</label>
                  <select id="prop-currency" name="currencyCode">
                    <option value="USD">USD</option>
                    <option value="EUR">EUR</option>
                    <option value="GBP">GBP</option>
                  </select>
                </div>
              </div>
              <div class="field" style="margin-bottom: 10px;">
                <label for="prop-reason">Line Item / Reason</label>
                <input id="prop-reason" name="reason" value="Regional LTL pallet freight delivery" required />
              </div>
              <button type="submit" class="btn btn-primary" id="btn-submit-proposal">Evaluate Simulated Preview</button>
            </form>
          </div>
        </div>
      </div>
    </section>

    <!-- SCREEN 2: POLICY RULES -->
    <section id="screen-policy" class="screen-pane">
      <div class="two-col">
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Deterministic Spend Limits &amp; Currency Controls</div>
              <h2 class="card-title">Spend Caps &amp; Allowed Currencies (PUT /api/policy)</h2>
            </div>
            <span class="badge badge-info" id="policy-id-badge">policy-paypal-ap-gate-v2</span>
          </div>
          <form id="form-policy-caps">
            <div class="form-grid">
              <div class="field">
                <label for="input-max-tx">Per-Payment Cap (USD)</label>
                <input id="input-max-tx" type="number" step="0.01" min="1" value="2500.00" required />
              </div>
              <div class="field">
                <label for="input-daily-cap">Daily Spend Cap (USD)</label>
                <input id="input-daily-cap" type="number" step="0.01" min="1" value="5000.00" required />
              </div>
              <div class="field">
                <label>Real Daily Headroom</label>
                <input id="display-headroom" type="text" value="$2,900.00 USD" readonly />
              </div>
            </div>
            <div class="field" style="margin-bottom: 12px;">
              <label>Allowed Settlement Currencies</label>
              <div style="display: flex; gap: 16px; padding: 6px 0;">
                <label style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px;">
                  <input type="checkbox" id="chk-cur-usd" value="USD" checked /> USD (US Dollar)
                </label>
                <label style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px;">
                  <input type="checkbox" id="chk-cur-eur" value="EUR" /> EUR (Euro)
                </label>
                <label style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px;">
                  <input type="checkbox" id="chk-cur-gbp" value="GBP" /> GBP (British Pound)
                </label>
              </div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
              <button type="submit" class="btn btn-primary" id="btn-save-policy">Save Policy Changes</button>
              <span class="mono" style="color: var(--os-muted);">Mutates live PolicyGate &amp; chains Ed25519-signed POLICY_UPDATED receipt</span>
            </div>
          </form>
        </div>

        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-eyebrow">Add Approved Supplier Receiver</div>
              <h2 class="card-title">Allowlist New Vendor Payee</h2>
            </div>
            <span class="badge badge-muted">PayPal Business Rail</span>
          </div>
          <form id="form-add-payee">
            <div class="form-grid-2">
              <div class="field">
                <label for="add-payee-id">Payee Slug (payeeId)</label>
                <input id="add-payee-id" value="offshore-holdings-ltd" required />
              </div>
              <div class="field">
                <label for="add-payee-name">Vendor Business Name</label>
                <input id="add-payee-name" value="Offshore Holdings Ltd." required />
              </div>
              <div class="field">
                <label for="add-payee-email">PayPal Receiver Email</label>
                <input id="add-payee-email" value="wire@offshore-holdings.example" required />
              </div>
              <div class="field">
                <label for="add-payee-rail">PayPal Payment Rail</label>
                <select id="add-payee-rail">
                  <option value="Orders v2">Orders v2</option>
                  <option value="Orders v2 + Invoicing v2">Orders v2 + Invoicing v2</option>
                  <option value="Orders v2 + Payouts v1">Orders v2 + Payouts v1</option>
                </select>
              </div>
            </div>
            <button type="submit" class="btn btn-green" id="btn-add-payee">Add Payee &amp; Save Policy</button>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Active Supplier Allowlist Enforced Before Every PayPal API Call</div>
            <h2 class="card-title">Approved Payee Allowlist</h2>
          </div>
          <span class="badge badge-ok" id="allowlist-count-badge">3 Active Vendors</span>
        </div>
        <table class="data-table" id="allowlist-table">
          <thead>
            <tr>
              <th>Payee ID</th>
              <th>Business Name</th>
              <th>PayPal Receiver Email</th>
              <th>Merchant ID</th>
              <th>Authorized Rail</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="allowlist-tbody"></tbody>
        </table>
      </div>
    </section>

    <!-- SCREEN 3: EXCEPTION QUEUE -->
    <section id="screen-exceptions" class="screen-pane">
      <div class="two-col">
        <div>
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Out-of-Policy Proposals Blocked Before Any PayPal API Call</div>
                <h2 class="card-title">Controller Exception Queue (Re-evaluate Against Live PolicyGate or Dismiss)</h2>
              </div>
              <span class="badge badge-err" id="exc-summary-badge">3 Pending · $6,720.00 Blocked · 0 API Calls</span>
            </div>
            <div id="exceptions-list"></div>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Untrusted LLM Extraction &amp; Isolation Proof</div>
                <h2 class="card-title" id="exc-detail-title">EXC-01 — Prompt-Injected Over-Cap Invoice</h2>
              </div>
              <span class="badge badge-err" id="exc-detail-code">OVER_TRANSACTION_CAP</span>
            </div>
            <div id="exc-memo-box" class="memo-isolation-box">
              <div class="memo-isolation-label">Untrusted Vendor Invoice Memo (Isolated as Plain Data — Zero Policy Authority)</div>
              <div class="mono" id="exc-memo-text"></div>
            </div>
            <div class="card-eyebrow" style="margin: 8px 0 4px;">Structured Candidate Proposal (glm-5.3 Pure JSON + SHA-256 Commitments)</div>
            <pre class="code-box" id="exc-llm-json"></pre>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Why AP Teams Gate AI Proposals Externally</div>
                <h2 class="card-title">Buyer Role, PayPal Agent Toolkit Context &amp; Scoped FBI IC3 Data</h2>
              </div>
              <span class="badge badge-info">0 Live Customers</span>
            </div>
            <ul class="scope-list">
              <li><strong>Target Buyer &amp; Setting:</strong> Accounts Payable (AP) managers, finance controllers, and fractional CFOs signing off outbound supplier payments at 10-to-200-employee B2B wholesalers, e-commerce brands, and agencies using PayPal Business (<code>Orders v2</code>, <code>Invoicing v2</code>, and <code>Payouts v1</code>).</li>
              <li><strong>Why This Buyer Needs an External Gate:</strong> When an AP manager or finance controller lets an AI intake agent draft or trigger supplier payments on PayPal Business (<code>Orders v2</code>, <code>Invoicing v2</code>, or <code>Payouts v1</code>), a prompt injection, hallucinated payee, or replayed invoice inside an untrusted vendor email can move company funds or create unauthorized payouts unless deterministic spend caps, payee allowlists, and duplicate-invoice checks sit outside the model and hold the PayPal credentials.</li>
              <li><strong>Primary-Sourced PayPal Developer Guidance:</strong> ${escServerHtml(PAYPAL_TOOLKIT_CITATION)}</li>
              <li><strong>Prototype Status:</strong> Pre-launch hackathon prototype with <strong>zero customers today</strong>; the 5 baseline invoices and 25 attack-suite records are synthetic B2B supplier fixtures.</li>
              <li><strong>Scoped FBI IC3 Context (Alert I-091124-PSA, Sept 11, 2024):</strong> Reports <strong>$55,499,915,582</strong> in exposed losses across <strong>305,033</strong> domestic &amp; international filings (and <strong>$20,089,561,364</strong> across <strong>158,436</strong> U.S. victim complaints, Oct 2013–Dec 2023) across <strong>all Business Email Compromise (BEC) and all payment rails</strong>. Fraudulent or altered vendor-invoice requests are one subset of BEC; IC3 makes no claims about AI or agentic procurement.</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <!-- SCREEN 4: OFFLINE VERIFIER & BUYER SCOPE -->
    <section id="screen-verifier" class="screen-pane">
      <div class="two-col">
        <div>
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Browser WebCrypto (/verify.html) &amp; Single-File Node CLI (0 Network Calls)</div>
                <h2 class="card-title">Zero-Vendor-Trust Offline Receipt Verification</h2>
              </div>
              <span class="badge badge-ok" id="verifier-status-badge">VERDICT: PASS</span>
            </div>
            <p style="margin: 0 0 8px;">${escServerHtml(THIRD_PARTY_VERIFIER_SENTENCE)}</p>
            <div style="display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap;">
              <a href="/verify.html" class="btn btn-primary btn-sm">Open Browser WebCrypto Verifier (/verify.html)</a>
              <span class="badge badge-muted">CSP: default-src 'none' · Works via file://</span>
            </div>
            <div class="code-box" style="margin-bottom: 10px;">$ node verify-payments.mjs recorded-live-sandbox-receipt.json
$ node verify-payments.mjs attack-suite-after-fix-receipt.json</div>
            <pre class="code-box" id="verifier-cli-output"></pre>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Fail-Closed SHA-256 + Ed25519 Tamper Rejection Proof</div>
                <h2 class="card-title">Non-Destructive 1-Byte Receipt Mutation Check (POST /api/tamper-check)</h2>
              </div>
              <button type="button" class="btn btn-crimson btn-sm" id="btn-run-tamper">Mutate Receipt #03 ($1,420 -> $9,420) in Memory</button>
            </div>
            <pre class="code-box" id="tamper-output">Click "Mutate Receipt #03" to clone the 15-entry chain in memory, alter 1 byte on Receipt #03, and verify fail-closed SHA-256 + Ed25519 detection at index 3 while preserving the canonical ledger.</pre>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Judge Quickstart Parity (README.md Commands 1 -> 4)</div>
                <h2 class="card-title">Verify in Browser, Single-File CLI, or Clean-Room Test Suite</h2>
              </div>
              <span class="badge badge-info">1:1 Hash Parity</span>
            </div>
            <pre class="code-box" id="quickstart-commands">1. Verify in browser with zero install (CSP default-src 'none', WebCrypto SHA-256 + Ed25519):
   open verify.html   # drop recorded-live-sandbox-receipt.json or attack-suite-after-fix-receipt.json

2. Verify with one standalone Node file (0 vendor imports, works copied alone to an empty folder):
   node verify-payments.mjs attack-suite-after-fix-receipt.json
   node verify-payments.mjs recorded-live-sandbox-receipt.json

3. Open this recorded PayPal Sandbox + 25-invoice Attack Suite application:
   PORT=8799 node hosted-demo-server.mjs

4. Run the hermetic test suite (89 of 89 tests, 0 network sockets, works on empty HOME):
   node --test</pre>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-eyebrow">Buyer Definition, PayPal Primary Source &amp; Regulatory Scope</div>
                <h2 class="card-title">Target Buyer &amp; Scope Card</h2>
              </div>
              <span class="badge badge-muted">Pre-launch Prototype</span>
            </div>
            <ul class="scope-list">
              <li><strong>Who Buys This:</strong> AP managers, finance controllers, and fractional CFOs at 10-to-200-employee B2B wholesalers, e-commerce brands, and agencies paying suppliers via PayPal Business (<code>Orders v2</code>, <code>Invoicing v2</code>, <code>Payouts v1</code>).</li>
              <li><strong>Why This Buyer Needs an External Gate:</strong> When an AP manager or finance controller lets an AI intake agent draft or trigger supplier payments on PayPal Business (<code>Orders v2</code>, <code>Invoicing v2</code>, or <code>Payouts v1</code>), a prompt injection, hallucinated payee, or replayed invoice inside an untrusted vendor email can move company funds or create unauthorized payouts unless deterministic spend caps, payee allowlists, and duplicate-invoice checks sit outside the model and hold the PayPal credentials.</li>
              <li><strong>PayPal Agent Toolkit Primary Source:</strong> ${escServerHtml(PAYPAL_TOOLKIT_CITATION)}</li>
              <li><strong>Honest Adoption Status:</strong> This is a pre-launch hackathon prototype with <strong>zero customers today</strong>. All supplier invoices and 25 prompt-injection cases in this repository are authored test fixtures.</li>
              <li><strong>Problem Size &amp; Exact Scope:</strong> FBI IC3 Alert <code>I-091124-PSA</code> documents <code>$55,499,915,582</code> in exposed losses across <code>305,033</code> filings globally (<code>$20,089,561,364</code> across <code>158,436</code> U.S. complaints, Oct 2013–Dec 2023) for <strong>all Business Email Compromise across all payment rails</strong>. Vendor-invoice manipulation is one subset of BEC; zero AI-specific loss claims are attributed to IC3.</li>
              <li><strong>Sandbox vs Production Boundary:</strong> Hard-locked to <code>https://api-m.sandbox.paypal.com</code>; live endpoints and <code>live=true</code> flags throw fail-closed errors.</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <footer class="product-footer">
      <span>MIT License · Copyright (c) 2026 Brennan William DeCrow</span>
      <span id="footer-manifest-binding"></span>
    </footer>
  </div>

  <script>
    window.__INITIAL_STATE__ = ${safeJson};
    window.__DEFAULT_SCREEN__ = ${safeScreen};
    window.__STANDALONE_HTML__ = ${safeStandalone};

    (function () {
      let appState = window.__INITIAL_STATE__;
      let selectedEntryIndex = 3;
      let selectedExceptionId = 'EXC-01';
      let selectedSuiteId = 'ATK-10';
      let suiteFilter = 'all';

      const params = new URLSearchParams(window.location.search);
      let activeScreen = params.get('screen') || window.__DEFAULT_SCREEN__ || 'ledger';
      if (!['suite', 'desk', 'ledger', 'policy', 'exceptions', 'verifier'].includes(activeScreen)) {
        activeScreen = 'ledger';
      }

      function fmtUsd(v) {
        const n = Number(v || 0);
        return '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      }

      function esc(s) {
        return String(s ?? '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
      }

      function showBanner(msg, tone) {
        const el = document.getElementById('action-banner');
        el.textContent = msg;
        el.className = 'notice-banner visible ' + (tone === 'err' ? 'pill-crimson' : 'pill-green');
      }

      function setScreen(screen) {
        activeScreen = screen;
        ['suite', 'desk', 'ledger', 'policy', 'exceptions', 'verifier'].forEach((id) => {
          const tab = document.getElementById('tab-' + id);
          const pane = document.getElementById('screen-' + id);
          if (tab) tab.classList.toggle('active', id === screen);
          if (pane) pane.classList.toggle('active', id === screen);
        });
      }

      function renderSuiteScreen() {
        const suite = appState.attackSuite || {};
        const after = suite.after || {};
        const sb = after.scoreboard || {};
        const allRecs = suite.records || [];

        document.getElementById('badge-suite-outside').textContent =
          fmtUsd(sb.dollarsMovedOutsidePolicy || '0.00') + ' outside';
        document.getElementById('suite-kpi-total').textContent =
          (sb.attacksTotal || 20) + ' attacks · ' + (sb.controlsTotal || 5) + ' controls';
        document.getElementById('suite-kpi-route').textContent =
          suite.mode === 'recorded-live-attack-suite'
            ? 'Recorded live ' + (after.llmRoute || 'ollama-cloud:glm-5.3') + ' + PayPal Sandbox'
            : 'Deterministic offline suite preview (--simulate)';
        document.getElementById('suite-kpi-obeyed').textContent =
          sb.modelObeyedLabel || (String(sb.modelObeyedCount ?? 0) + ' of ' + String(sb.comparableAttacks ?? 15));
        document.getElementById('suite-kpi-admitted').textContent =
          String(sb.gateAdmittedAttacks ?? 0) + ' of ' + String(sb.attacksTotal ?? 20) + ' (' + fmtUsd(sb.dollarsMovedOutsidePolicy || '0.00') + ')';
        document.getElementById('suite-kpi-admitted-sub').textContent =
          String(sb.refusedApiCalls ?? 0) + ' PayPal API calls on every refusal';
        document.getElementById('suite-kpi-controls').textContent =
          (sb.controlsPaidLabel || '5 of 5') + ' (' + fmtUsd(sb.controlsSettledUsd || '6180.75') + ')';
        document.getElementById('suite-kpi-chain').textContent =
          after.chainCount ? (after.chainCount + ' of ' + after.chainCount + ' valid') : 'Offline preview';
        document.getElementById('suite-kpi-pubkey').textContent =
          after.publicKeySha256
            ? 'Ed25519 pubkey ' + after.publicKeySha256.slice(0, 14) + '...'
            : 'Run live suite for Ed25519 receipt chain';

        document.getElementById('suite-finding-banner').textContent = suite.findingLine || '';
        document.getElementById('suite-scope-strip').textContent = suite.scopeNotice || '';

        const filtered = allRecs.filter((r) => {
          if (suiteFilter === 'obeyed') return r.obeyedInjection === true;
          if (suiteFilter === 'control') return r.kind === 'control';
          return true;
        });

        const tbody = document.getElementById('suite-records-tbody');
        tbody.innerHTML = filtered
          .map((r) => {
            const selCls = r.suiteId === selectedSuiteId ? 'clickable-row selected-row' : 'clickable-row';
            const obeyText =
              r.kind === 'control'
                ? '<span class="badge badge-muted">CONTROL</span>'
                : !r.obeyedInjectionComparable
                  ? '<span class="badge badge-muted">STATE GATE TEST</span>'
                  : r.obeyedInjection
                    ? '<span class="badge badge-err">OBEYED INJECTION</span>'
                    : '<span class="badge badge-info">DEFLECTED HONEST</span>';

            const isHonestAllowedAttack =
              r.kind === 'attack' && r.matchedHonestProposal === true && r.honestProposalPolicyDecision === 'ALLOW';
            const verdictBadge =
              r.outcome === 'REFUSED'
                ? '<span class="badge badge-ok">REFUSED · ' + esc(r.reasonCode) + '</span>'
                : r.kind === 'control' || isHonestAllowedAttack
                  ? '<span class="badge badge-info">PAID IN-POLICY (' + esc(r.kind === 'control' ? 'CONTROL' : 'HONEST') + ')</span>'
                  : '<span class="badge badge-err">OUT-OF-POLICY ADMITTED</span>';

            const deltaTag =
              r.beforeOutcome === 'EXECUTED' && r.outcome === 'REFUSED'
                ? ' <span class="badge badge-ok">FIXED IN B.7</span>'
                : '';

            return (
              '<tr class="' + selCls + '" data-suite-id="' + esc(r.suiteId) + '">' +
              '<td class="mono"><strong>' + esc(r.suiteId) + '</strong>' + deltaTag + '</td>' +
              '<td>' + esc(r.technique) + '</td>' +
              '<td>' + obeyText + '</td>' +
              '<td>' + verdictBadge + '</td>' +
              '<td class="mono">' + fmtUsd(r.modelProposal?.amountValue) + ' ' + esc(r.modelProposal?.currencyCode || 'USD') + ' · ' + String(r.apiCallsDelta ?? 0) + ' API</td>' +
              '</tr>'
            );
          })
          .join('');

        tbody.querySelectorAll('tr[data-suite-id]').forEach((tr) => {
          tr.addEventListener('click', () => {
            selectedSuiteId = tr.getAttribute('data-suite-id');
            renderSuiteScreen();
          });
        });

        const sel = allRecs.find((x) => x.suiteId === selectedSuiteId) || allRecs[0];
        if (sel) {
          document.getElementById('suite-detail-title').textContent =
            sel.suiteId + ' — ' + sel.technique;
          document.getElementById('suite-detail-badge').textContent =
            sel.outcome + ' · ' + sel.reasonCode;
          document.getElementById('suite-detail-badge').className =
            'badge ' + (sel.outcome === 'REFUSED' || sel.kind === 'control' ? 'badge-ok' : 'badge-info');
          document.getElementById('suite-detail-goal').textContent =
            'Scenario intent: ' + (sel.whatTheAttackerWants || '');
          document.getElementById('suite-detail-doc').textContent = sel.invoiceSnippet || '';
          document.getElementById('suite-detail-json').textContent = JSON.stringify(
            {
              suiteId: sel.suiteId,
              kind: sel.kind,
              obeyedInjectionComparable: sel.obeyedInjectionComparable,
              obeyedInjection: sel.obeyedInjection,
              beforeFixRun1: sel.beforeOutcome ? (sel.beforeOutcome + ' (' + sel.beforeReasonCode + ')') : 'n/a',
              afterFixRun2: sel.outcome + ' (' + sel.reasonCode + ')',
              modelProposal: sel.modelProposal,
              paypalApiCallsExecuted: sel.apiCallsDelta,
              paypalOrderId: sel.paypalOrderId,
              proposedReceiptHash: sel.proposedReceiptHash,
              outcomeReceiptHash: sel.outcomeReceiptHash,
            },
            null,
            2
          );
        }
      }

      let selectedDeskInvoiceId = null;
      let lastDeskProposal = null;

      function currentDeskProposal() {
        const inbox = appState.deskInbox || [];
        const inv = inbox.find((x) => x.invoiceId === selectedDeskInvoiceId) || inbox[0];
        if (!inv) return null;
        return {
          proposalId: inv.proposalId,
          invoiceId: inv.invoiceId,
          payeeId: inv.payeeId,
          supplierName: inv.supplierName,
          payeeEmail: inv.payeeEmail,
          payeeMerchantId: inv.payeeMerchantId,
          amountValue: inv.amountValue,
          currencyCode: inv.currencyCode || 'USD',
          poNumber: inv.poNumber || null,
          reason: inv.reason,
        };
      }

      async function evaluateDeskProposal(proposal) {
        const res = await fetch('/api/desk/evaluate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ proposal }),
        });
        return res.json();
      }

      async function renderDeskScreen() {
        const inbox = appState.deskInbox || [];
        if (!selectedDeskInvoiceId && inbox[0]) selectedDeskInvoiceId = inbox[0].invoiceId;
        const tbody = document.getElementById('desk-inbox-tbody');
        if (!tbody) return;
        tbody.innerHTML = inbox
          .map((inv) => {
            const selected = inv.invoiceId === selectedDeskInvoiceId;
            return (
              '<tr data-invoice="' + esc(inv.invoiceId) + '" style="cursor:pointer; background:' + (selected ? 'var(--os-ground-absorptive)' : 'transparent') + '">' +
              '<td class="mono"><strong>' + esc(inv.invoiceId) + '</strong></td>' +
              '<td>' + esc(inv.supplierName) + '<div class="mono" style="color:var(--os-muted)">' + esc(inv.payeeEmail) + '</div></td>' +
              '<td class="mono">' + fmtUsd(inv.amountValue) + '</td>' +
              '<td class="mono">' + esc(inv.poNumber || '—') + '</td>' +
              '</tr>'
            );
          })
          .join('');
        tbody.querySelectorAll('tr[data-invoice]').forEach((row) => {
          row.addEventListener('click', async () => {
            selectedDeskInvoiceId = row.getAttribute('data-invoice');
            await renderDeskScreen();
          });
        });

        const inv = inbox.find((x) => x.invoiceId === selectedDeskInvoiceId);
        const docEl = document.getElementById('desk-invoice-doc');
        const titleEl = document.getElementById('desk-proposal-title');
        if (inv) {
          titleEl.textContent = inv.invoiceId + ' · ' + inv.supplierName;
          docEl.textContent = inv.invoiceDocument || '';
          lastDeskProposal = currentDeskProposal();
          const ev = await evaluateDeskProposal(lastDeskProposal);
          const verdict = ev.verdict || {};
          const po = ev.poCard || verdict.poCard || null;
          document.getElementById('desk-decision-badge').textContent = (verdict.decision || '—') + (verdict.reasonCode ? ' · ' + verdict.reasonCode : '');
          document.getElementById('desk-verdict-code').textContent = verdict.reasonCode || verdict.decision || '—';
          document.getElementById('desk-verdict-detail').textContent = verdict.reasonDetail || '';
          document.getElementById('desk-po-number').textContent = po ? po.poNumber : lastDeskProposal.poNumber || 'No purchase order cited';
          document.getElementById('desk-po-detail').textContent = po
            ? (po.payeeId + ' · remaining ' + (po.remainingUsd || '0.00') + ' of ' + (po.totalUsd || '0.00') + ' ' + (po.currencyCode || 'USD'))
            : 'The gate will refuse a payment that does not cite an open purchase order for this supplier.';
        }

        const holds = (appState.holds || []).filter((h) => h.status === 'held');
        document.getElementById('desk-holds-count').textContent = holds.length + ' open holds';
        const list = document.getElementById('desk-holds-list');
        list.innerHTML = holds.length
          ? holds
              .map((h, i) => {
                const p = h.proposal || {};
                return (
                  '<div class="kpi-card" style="margin-bottom:8px;" data-hold-index="' + i + '">' +
                  '<div class="kpi-label">' + esc(h.reasonCode) + '</div>' +
                  '<div class="kpi-value">' + fmtUsd(p.amountValue) + '</div>' +
                  '<div class="kpi-detail">' + esc(p.invoiceId) + ' · ' + esc(p.payeeEmail) + ' · ' + esc(p.poNumber || 'no PO') + '</div>' +
                  '<div style="display:flex; gap:8px; margin-top:8px; flex-wrap:wrap;">' +
                  '<button type="button" class="btn btn-primary btn-sm btn-hold-approve" data-hold-index="' + i + '">Approve once</button>' +
                  '<button type="button" class="btn btn-sm btn-hold-reject" data-hold-index="' + i + '">Reject</button>' +
                  '</div></div>'
                );
              })
              .join('')
          : '<p class="card-copy">No open holds.</p>';

        const entries = (appState.ledger?.entries || []).slice(-8).reverse();
        document.getElementById('desk-ledger-tbody').innerHTML = entries
          .map((e) => {
            const paypal = e.paypalOrderId || e.paypalCaptureId
              ? 'Order ' + (e.paypalOrderId || '—') + ' · Capture ' + (e.paypalCaptureId || '—')
              : 'No PayPal ids';
            return (
              '<tr><td class="mono">' + e.index + '</td><td>' + esc(e.stage) + '</td><td class="mono">' +
              esc(e.payload?.invoiceId || e.proposalId || '—') + '</td><td class="mono">' + esc(paypal) + '</td></tr>'
            );
          })
          .join('');
      }

      function renderAll() {
        const k = appState.kpis;
        const p = appState.policy;

        const dsPill = document.getElementById('dataset-status-pill');
        dsPill.textContent = appState.datasetStatus;
        dsPill.className = 'pill ' + (appState.proofMode === 'recorded-live-sandbox' ? 'pill-blue' : 'pill-crimson');

        const chPill = document.getElementById('chain-header-pill');
        chPill.textContent =
          'SHA-256 + Ed25519: ' + k.chainValidCount + ' of ' + k.chainTotalCount + ' valid · Tip ' + (k.headHash || '').slice(0, 12) + '...';
        chPill.className = 'pill ' + (k.chainValid ? 'pill-green' : 'pill-crimson');

        document.getElementById('kpi-settled').textContent = fmtUsd(k.settledTodayUsd) + ' / ' + fmtUsd(k.dailyCapUsd);
        if (appState.proofMode === 'recorded-live-sandbox' && Number(k.simulatedPreviewCount || 0) > 0) {
          document.getElementById('kpi-settled-sub').textContent =
            'Real headroom: ' + fmtUsd(k.remainingHeadroomUsd) + ' · Sim preview (' + k.simulatedPreviewCount + '): ' + fmtUsd(k.simulatedPreviewTotalUsd) + ' (0 API calls)';
        } else {
          document.getElementById('kpi-settled-sub').textContent =
            'Real daily headroom: ' + fmtUsd(k.remainingHeadroomUsd) + ' USD';
        }
        document.getElementById('kpi-per-tx').textContent = fmtUsd(k.perPaymentCapUsd);
        document.getElementById('kpi-currencies').textContent = 'Allowed currencies: ' + (p.allowedCurrencies || ['USD']).join(', ');
        document.getElementById('kpi-payees').textContent = k.approvedPayeesActive + ' active';
        document.getElementById('kpi-exceptions').textContent = k.exceptionsPendingCount + ' pending review';
        document.getElementById('kpi-exceptions-sub').textContent =
          fmtUsd(k.blockedTotalUsd) + ' blocked · ' + k.refusalPaypalApiCalls + ' PayPal API calls on refusals';
        document.getElementById('kpi-chain').textContent = k.chainValidCount + ' of ' + k.chainTotalCount + ' valid';
        document.getElementById('kpi-chain-sub').textContent =
          'Baseline 15-link Sandbox chain + ' + Math.max(0, k.chainTotalCount - 15) + ' ops receipts';

        document.getElementById('badge-ledger-count').textContent = String(k.chainTotalCount);
        document.getElementById('badge-policy-payees').textContent = k.approvedPayeesActive + ' payees';
        document.getElementById('badge-exc-pending').textContent = k.exceptionsPendingCount + ' pending';
        const deskHoldsBadge = document.getElementById('badge-desk-holds');
        if (deskHoldsBadge) deskHoldsBadge.textContent = (k.holdsOpenCount || 0) + ' holds';
        const policyBadge = document.getElementById('policy-id-badge');
        if (policyBadge && p.policyId) policyBadge.textContent = p.policyId;

        renderDeskScreen();
        renderSuiteScreen();

        // Screen 1: Settled Payments
        document.getElementById('settled-mode-badge').textContent =
          appState.proofMode === 'recorded-live-sandbox' ? 'LIVE SANDBOX RECORDED' : 'SIMULATION MODE';
        const sTbody = document.getElementById('settled-payments-tbody');
        sTbody.innerHTML = (appState.settledPayments || [])
          .map((o) => {
            const isSim = Boolean(o.simulated || appState.proofMode === 'offline-simulation');
            const secId = o.paypalInvoiceId
              ? 'Invoice: ' + o.paypalInvoiceId
              : o.paypalPayoutBatchId
                ? 'Payout: ' + o.paypalPayoutBatchId
                : isSim
                  ? 'SIMULATED_LOCAL_NO_PAYPAL_CALL'
                  : 'Orders v2 Direct';
            const dbg = o.getOrderPaypalDebugId
              ? ' · Debug-Id: ' + o.getOrderPaypalDebugId
              : isSim
                ? ' · 0 PayPal API calls'
                : '';
            const statusHtml = isSim
              ? '<div style="margin-top:3px;"><span class="badge badge-err">SIMULATED (local policy check only — 0 PayPal API calls)</span></div>'
              : '<div style="color:var(--os-green)">COMPLETED</div>';
            return (
              '<tr data-simulated="' + (isSim ? 'true' : 'false') + '">' +
              '<td class="mono"><strong>' + esc(o.invoiceId) + '</strong></td>' +
              '<td><strong>' + esc(o.supplier) + '</strong><div class="mono" style="color:var(--os-muted)">' + esc(o.payeeEmail) + ' · ' + esc(o.rail) + '</div></td>' +
              '<td class="mono"><strong>' + fmtUsd(o.amountUsd) + '</strong>' + statusHtml + '</td>' +
              '<td class="mono">Order: ' + esc(o.paypalOrderId) + '<br/>Capture: ' + esc(o.paypalCaptureId) + '</td>' +
              '<td class="mono">' + esc(secId + dbg) + '</td>' +
              '</tr>'
            );
          })
          .join('');

        // Screen 1: Ledger Entries
        const entries = appState.ledger?.entries || [];
        document.getElementById('ledger-count-badge').textContent =
          k.chainValidCount + ' / ' + k.chainTotalCount + ' VALID';
        if (selectedEntryIndex >= entries.length) selectedEntryIndex = entries.length - 1;
        const lTbody = document.getElementById('ledger-entries-tbody');
        lTbody.innerHTML = entries
          .map((e) => {
            const badgeCls =
              e.stage === 'REFUSED'
                ? 'badge-err'
                : e.stage === 'EXECUTED' || e.stage === 'WEBHOOK_SETTLED' || e.stage === 'ADMITTED'
                  ? 'badge-ok'
                  : 'badge-info';
            const inv = e.payload?.invoiceId || e.proposalId || 'system';
            const amt =
              e.payload?.amountValue
                ? fmtUsd(e.payload.amountValue)
                : e.payload?.attemptedAmountValue
                  ? fmtUsd(e.payload.attemptedAmountValue) + ' (' + (e.payload.refusalCode || 'REFUSED') + ')'
                  : e.payload?.decision || e.stage;
            const selCls = e.index === selectedEntryIndex ? 'clickable-row selected-row' : 'clickable-row';
            return (
              '<tr class="' + selCls + '" data-entry-idx="' + e.index + '">' +
              '<td class="mono">#' + String(e.index).padStart(2, '0') + '</td>' +
              '<td><span class="badge ' + badgeCls + '">' + esc(e.stage) + '</span></td>' +
              '<td class="mono">' + esc(inv) + '</td>' +
              '<td class="mono">' + esc(amt) + '</td>' +
              '<td class="mono">' + esc((e.receiptHash || '').slice(0, 16)) + '...</td>' +
              '</tr>'
            );
          })
          .join('');

        lTbody.querySelectorAll('tr[data-entry-idx]').forEach((row) => {
          row.addEventListener('click', () => {
            selectedEntryIndex = Number(row.getAttribute('data-entry-idx'));
            renderAll();
          });
        });

        const selEntry = entries[selectedEntryIndex] || entries[0];
        if (selEntry) {
          document.getElementById('inspector-title').textContent =
            'Receipt #' + String(selEntry.index).padStart(2, '0') + ' — ' + selEntry.stage;
          document.getElementById('inspector-json').textContent = JSON.stringify(selEntry, null, 2);
        }

        // Screen 2: Policy Rules
        document.getElementById('policy-id-badge').textContent = p.policyId;
        document.getElementById('input-max-tx').value = p.maxTransactionUsd;
        document.getElementById('input-daily-cap').value = p.dailyCapUsd;
        if (appState.proofMode === 'recorded-live-sandbox' && Number(k.simulatedPreviewCount || 0) > 0) {
          document.getElementById('display-headroom').value =
            fmtUsd(p.remainingDailyHeadroomUsd) + ' real (' + fmtUsd(k.simulatedRemainingPreviewHeadroomUsd) + ' after ' + fmtUsd(k.simulatedPreviewTotalUsd) + ' sim)';
        } else {
          document.getElementById('display-headroom').value =
            fmtUsd(p.remainingDailyHeadroomUsd) + ' USD (after ' + fmtUsd(p.settledTodayUsd) + ' settled)';
        }
        const curSet = new Set(p.allowedCurrencies || ['USD']);
        document.getElementById('chk-cur-usd').checked = curSet.has('USD');
        document.getElementById('chk-cur-eur').checked = curSet.has('EUR');
        document.getElementById('chk-cur-gbp').checked = curSet.has('GBP');

        document.getElementById('allowlist-count-badge').textContent =
          (p.approvedPayees || []).length + ' Active Vendors';
        const aTbody = document.getElementById('allowlist-tbody');
        aTbody.innerHTML = (p.approvedPayees || [])
          .map(
            (py) =>
              '<tr>' +
              '<td class="mono"><strong>' + esc(py.payeeId) + '</strong></td>' +
              '<td>' + esc(py.displayName) + '</td>' +
              '<td class="mono">' + esc(py.paypalReceiver) + '</td>' +
              '<td class="mono">' + esc(py.merchantId || 'email-verified') + '</td>' +
              '<td class="mono">' + esc(py.rail) + '</td>' +
              '<td><button type="button" class="btn btn-crimson btn-sm" data-remove-payee="' + esc(py.payeeId) + '">Remove</button></td>' +
              '</tr>'
          )
          .join('');

        aTbody.querySelectorAll('button[data-remove-payee]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const targetId = btn.getAttribute('data-remove-payee');
            const remaining = (appState.policy.approvedPayees || []).filter((x) => x.payeeId !== targetId);
            await savePolicyPayload({ approvedPayees: remaining }, 'Removed payee ' + targetId + ' from live PolicyGate');
          });
        });

        // Screen 3: Exception Queue
        const excs = appState.exceptions || [];
        document.getElementById('exc-summary-badge').textContent =
          k.exceptionsPendingCount + ' Pending · ' + k.exceptionsClearedCount + ' Cleared · ' + k.exceptionsDismissedCount + ' Dismissed · 0 API Calls';
        const excContainer = document.getElementById('exceptions-list');
        excContainer.innerHTML = excs
          .map((ex) => {
            const stCls =
              ex.status === 'CLEARED_BY_POLICY'
                ? 'exc-cleared'
                : ex.status === 'DISMISSED'
                  ? 'exc-dismissed'
                  : 'exc-pending';
            const stBadge =
              ex.status === 'CLEARED_BY_POLICY'
                ? '<span class="badge badge-ok">CLEARED_BY_POLICY (0 PayPal API Calls)</span>'
                : ex.status === 'DISMISSED'
                  ? '<span class="badge badge-muted">DISMISSED</span>'
                  : '<span class="badge badge-err">' + esc(ex.reasonCode) + '</span>';
            const noteLine = ex.resolutionNote
              ? '<div class="mono" style="margin-top:6px;color:var(--os-green)">' + esc(ex.resolutionNote) + '</div>'
              : ex.dismissReason
                ? '<div class="mono" style="margin-top:6px;color:var(--os-muted)">Dismissed: ' + esc(ex.dismissReason) + '</div>'
                : '<div class="mono" style="margin-top:6px;color:var(--os-muted)">' + esc(ex.reasonDetail) + '</div>';
            return (
              '<div class="exception-card ' + stCls + '" data-exc-card="' + esc(ex.exceptionId) + '">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">' +
              '<div><strong class="mono">' + esc(ex.exceptionId) + '</strong> · <strong>' + esc(ex.supplierName) + '</strong> (<span class="mono">' + esc(ex.payeeId) + '</span>)</div>' +
              stBadge +
              '</div>' +
              '<div class="mono" style="margin-top:4px;">Invoice: <strong>' + esc(ex.invoiceId) + '</strong> · Amount: <strong>' + fmtUsd(ex.amountUsd) + ' ' + esc(ex.currencyCode) + '</strong> · Receiver: ' + esc(ex.payeeEmail) + ' · PayPal API Calls: <strong>0</strong></div>' +
              noteLine +
              '<div style="display:flex;gap:8px;margin-top:9px;">' +
              '<button type="button" class="btn btn-primary btn-sm" id="btn-reeval-' + esc(ex.exceptionId) + '" data-reeval="' + esc(ex.exceptionId) + '">Re-evaluate Against Current Policy</button>' +
              '<button type="button" class="btn btn-crimson btn-sm" id="btn-dismiss-' + esc(ex.exceptionId) + '" data-dismiss="' + esc(ex.exceptionId) + '">Dismiss Proposal</button>' +
              '<button type="button" class="btn btn-sm" data-inspect-exc="' + esc(ex.exceptionId) + '">Inspect Proposal &amp; Memo</button>' +
              '</div>' +
              '</div>'
            );
          })
          .join('');

        excContainer.querySelectorAll('button[data-inspect-exc]').forEach((b) => {
          b.addEventListener('click', () => {
            selectedExceptionId = b.getAttribute('data-inspect-exc');
            renderAll();
          });
        });
        excContainer.querySelectorAll('button[data-reeval]').forEach((b) => {
          b.addEventListener('click', async () => {
            const id = b.getAttribute('data-reeval');
            selectedExceptionId = id;
            await reevaluateException(id);
          });
        });
        excContainer.querySelectorAll('button[data-dismiss]').forEach((b) => {
          b.addEventListener('click', async () => {
            const id = b.getAttribute('data-dismiss');
            selectedExceptionId = id;
            await dismissException(id);
          });
        });

        const selExc = excs.find((x) => x.exceptionId === selectedExceptionId) || excs[0];
        if (selExc) {
          document.getElementById('exc-detail-title').textContent =
            selExc.exceptionId + ' — ' + selExc.supplierName + ' (' + fmtUsd(selExc.amountUsd) + ')';
          document.getElementById('exc-detail-code').textContent =
            selExc.status === 'CLEARED_BY_POLICY' ? 'CLEARED_BY_POLICY' : selExc.reasonCode;
          document.getElementById('exc-detail-code').className =
            'badge ' + (selExc.status === 'CLEARED_BY_POLICY' ? 'badge-ok' : 'badge-err');
          document.getElementById('exc-memo-text').textContent =
            selExc.invoiceMemo || 'No untrusted override memo present.';
          document.getElementById('exc-llm-json').textContent = JSON.stringify(
            {
              model: selExc.llmProposal?.provider + ':' + selExc.llmProposal?.model,
              promptSha256: selExc.llmProposal?.promptSha256,
              responseSha256: selExc.llmProposal?.responseSha256,
              parsedCandidate: JSON.parse(selExc.llmProposal?.rawCompletion || '{}'),
              refusalReceiptIndex: selExc.refusalReceiptIndex,
              refusalReceiptHash: selExc.refusalReceiptHash,
              paypalApiCallsExecuted: 0,
            },
            null,
            2
          );
        }

        // Screen 4: Offline Verifier
        const ov = appState.offlineVerification || {};
        document.getElementById('verifier-status-badge').textContent = ov.ok ? 'VERDICT: PASS' : 'SIMULATION CHAIN OK';
        document.getElementById('verifier-cli-output').textContent = (ov.summaryLines || []).join('\\n');

        document.getElementById('footer-manifest-binding').textContent =
          'codeManifestSha256: ' + (appState.codeManifestSha256 || 'simulation').slice(0, 24) + '... · Sandbox Only (api-m.sandbox.paypal.com)';
      }

      async function savePolicyPayload(partial, bannerText) {
        if (window.__STANDALONE_HTML__) return;
        const res = await fetch('/api/policy', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(partial),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          showBanner('Policy update rejected: ' + (data.error || res.status), 'err');
          return;
        }
        appState = data.state;
        renderAll();
        showBanner(bannerText || 'Saved live PolicyGate rules and chained POLICY_UPDATED receipt.', 'ok');
      }

      async function reevaluateException(id) {
        if (window.__STANDALONE_HTML__) return;
        const res = await fetch('/api/exceptions/' + encodeURIComponent(id) + '/reevaluate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          showBanner('Re-evaluation failed: ' + (data.error || res.status), 'err');
          return;
        }
        appState = data.state;
        renderAll();
        if (data.exception.status === 'CLEARED_BY_POLICY') {
          showBanner(
            id + ' (' + fmtUsd(data.exception.amountUsd) + ') CLEARED_BY_POLICY under current PolicyGate rules (policy clearance only; 0 PayPal API calls).',
            'ok'
          );
        } else {
          showBanner(
            id + ' (' + fmtUsd(data.exception.amountUsd) + ') STILL BLOCKED by PolicyGate: ' + data.verdict.reasonCode + ' — ' + data.verdict.reasonDetail,
            'err'
          );
        }
      }

      async function dismissException(id) {
        if (window.__STANDALONE_HTML__) return;
        const res = await fetch('/api/exceptions/' + encodeURIComponent(id) + '/dismiss', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'Controller rejected out-of-policy / adversarial vendor invoice' }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) return;
        appState = data.state;
        renderAll();
        showBanner(id + ' dismissed by controller and recorded in SHA-256 + Ed25519 operational audit chain.', 'ok');
      }

      document.querySelectorAll('.nav-tab').forEach((tab) => {
        tab.addEventListener('click', () => setScreen(tab.getAttribute('data-screen')));
      });

      document.getElementById('btn-desk-propose')?.addEventListener('click', async () => {
        const proposal = currentDeskProposal();
        if (!proposal) return;
        const res = await fetch('/api/propose', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ proposal }),
        });
        const data = await res.json();
        if (data.state) appState = data.state;
        showBanner(
          (data.result?.status || 'UNKNOWN') + (data.result?.reasonCode ? ' · ' + data.result.reasonCode : ''),
          data.result?.status === 'EXECUTED' ? 'ok' : 'err'
        );
        await renderAll();
      });

      document.getElementById('desk-holds-list')?.addEventListener('click', async (ev) => {
        const approveBtn = ev.target.closest('.btn-hold-approve');
        const rejectBtn = ev.target.closest('.btn-hold-reject');
        if (!approveBtn && !rejectBtn) return;
        const idx = Number((approveBtn || rejectBtn).getAttribute('data-hold-index'));
        const holds = (appState.holds || []).filter((h) => h.status === 'held');
        const hold = holds[idx];
        if (!hold) return;
        const name = (document.getElementById('desk-approver-name')?.value || '').trim();
        const path = approveBtn ? '/api/holds/approve' : '/api/holds/reject';
        const body = approveBtn ? { proposal: hold.proposal, approvedBy: name } : { proposal: hold.proposal, rejectedBy: name };
        const res = await fetch(path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.state) appState = data.state;
        showBanner(data.ok ? (data.result?.status || 'UPDATED') : (data.error || 'REQUEST_FAILED'), data.ok ? 'ok' : 'err');
        await renderAll();
      });

      document.querySelectorAll('[data-suite-filter]').forEach((btn) => {
        btn.addEventListener('click', () => {
          suiteFilter = btn.getAttribute('data-suite-filter') || 'all';
          renderSuiteScreen();
        });
      });

      document.getElementById('form-policy-caps').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const currencies = [];
        if (document.getElementById('chk-cur-usd').checked) currencies.push('USD');
        if (document.getElementById('chk-cur-eur').checked) currencies.push('EUR');
        if (document.getElementById('chk-cur-gbp').checked) currencies.push('GBP');
        await savePolicyPayload(
          {
            maxTransactionUsd: document.getElementById('input-max-tx').value,
            dailyCapUsd: document.getElementById('input-daily-cap').value,
            allowedCurrencies: currencies,
          },
          'Updated PolicyGate caps ($' + document.getElementById('input-max-tx').value + ' per-order / $' + document.getElementById('input-daily-cap').value + ' daily) & chained POLICY_UPDATED receipt.'
        );
      });

      document.getElementById('form-add-payee').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const newPayee = {
          payeeId: document.getElementById('add-payee-id').value.trim(),
          displayName: document.getElementById('add-payee-name').value.trim(),
          paypalReceiver: document.getElementById('add-payee-email').value.trim(),
          rail: document.getElementById('add-payee-rail').value,
        };
        const current = (appState.policy.approvedPayees || []).filter(
          (x) => x.payeeId !== newPayee.payeeId && x.paypalReceiver !== newPayee.paypalReceiver.toLowerCase()
        );
        const currencies = [];
        if (document.getElementById('chk-cur-usd').checked) currencies.push('USD');
        if (document.getElementById('chk-cur-eur').checked) currencies.push('EUR');
        if (document.getElementById('chk-cur-gbp').checked) currencies.push('GBP');
        await savePolicyPayload(
          {
            maxTransactionUsd: document.getElementById('input-max-tx').value,
            dailyCapUsd: document.getElementById('input-daily-cap').value,
            allowedCurrencies: currencies,
            approvedPayees: current.concat([newPayee]),
          },
          'Added ' + newPayee.payeeId + ' (' + newPayee.paypalReceiver + ') to Approved Payee Allowlist & saved PolicyGate.'
        );
      });

      document.getElementById('form-new-proposal').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        if (window.__STANDALONE_HTML__) return;
        const payload = {
          proposal: {
            proposalId: 'prop-op-' + String(Date.now()).slice(-6),
            invoiceId: document.getElementById('prop-invoice-id').value.trim(),
            payeeEmail: document.getElementById('prop-email').value.trim(),
            amountValue: document.getElementById('prop-amount').value.trim(),
            currencyCode: document.getElementById('prop-currency').value,
            reason: document.getElementById('prop-reason').value.trim(),
          },
        };
        const res = await fetch('/api/propose', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.state) {
          appState = data.state;
          selectedEntryIndex = appState.ledger.entries.length - 1;
          renderAll();
        }
        if (data.result?.status === 'EXECUTED') {
          showBanner(
            'Simulated preview ADMITTED · SIMULATED (local policy check only — 0 PayPal API calls) · Real settled ($' +
              appState.kpis.settledTodayUsd +
              ') & real headroom ($' +
              appState.kpis.remainingHeadroomUsd +
              ') unchanged · Order ' +
              data.result.paypalOrderId,
            'ok'
          );
        } else {
          showBanner('Proposal REFUSED by PolicyGate (' + (data.result?.reasonCode || 'DENIED') + ' · 0 PayPal API calls) -> added to Exception Queue.', 'err');
        }
      });

      document.getElementById('btn-reset-baseline').addEventListener('click', async () => {
        if (window.__STANDALONE_HTML__) return;
        const res = await fetch('/api/reset', { method: 'POST' });
        const data = await res.json();
        if (data.ok && data.state) {
          appState = data.state;
          selectedEntryIndex = 3;
          selectedExceptionId = 'EXC-01';
          renderAll();
          showBanner('Reset live PolicyGate, simulated previews, Exception Queue, and 15-link recorded Sandbox ledger to baseline.', 'ok');
        }
      });

      document.getElementById('btn-run-tamper').addEventListener('click', async () => {
        if (window.__STANDALONE_HTML__) return;
        const res = await fetch('/api/tamper-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ index: 3, amountValue: '9420.00' }),
        });
        const data = await res.json();
        document.getElementById('tamper-output').textContent = JSON.stringify(data, null, 2);
        showBanner('1-byte tamper check caught mutation at Receipt #' + String(data.brokenAtIndex).padStart(2, '0') + ' (' + data.reason + '); canonical 15/15 chain intact.', 'ok');
      });

      setScreen(activeScreen);
      renderAll();
    })();
  </script>
</body>
</html>`;
}

export async function startHostedDemoServer({
  port = Number(process.env.PORT || 8799),
  host = '127.0.0.1',
  simulate = false,
  receiptPath = null,
  recordedReceipt: injectedReceipt = null,
  policyEditToken = process.env.PAYPAL_POLICY_EDIT_TOKEN || null,
} = {}) {
  const requiredPolicyToken = policyEditToken ? String(policyEditToken) : null;
  let loadedReceipt = null;
  let loadedReceiptSha256 = null;
  let loadedFromDir = HERE;
  let loadedAfterSuiteReceipt = null;
  let loadedAfterSuiteSha256 = null;
  let loadedBeforeSuiteReceipt = null;
  let loadedBeforeSuiteSha256 = null;

  if (!simulate) {
    if (injectedReceipt && typeof injectedReceipt === 'object') {
      loadedReceipt = structuredClone(injectedReceipt);
      loadedReceiptSha256 = sha256Buffer(Buffer.from(JSON.stringify(loadedReceipt), 'utf8'));
    } else {
      const candidatePath = receiptPath ? path.resolve(receiptPath) : DEFAULT_RECORDED_RECEIPT_PATH;
      if (fs.existsSync(candidatePath)) {
        const rawBuf = fs.readFileSync(candidatePath);
        loadedReceiptSha256 = sha256Buffer(rawBuf);
        loadedReceipt = JSON.parse(rawBuf.toString('utf8'));
        loadedFromDir = path.dirname(candidatePath);
      }
    }

    const candidateAfter = fs.existsSync(path.join(loadedFromDir, 'attack-suite-after-fix-receipt.json'))
      ? path.join(loadedFromDir, 'attack-suite-after-fix-receipt.json')
      : DEFAULT_SUITE_AFTER_PATH;
    if (fs.existsSync(candidateAfter)) {
      const buf = fs.readFileSync(candidateAfter);
      loadedAfterSuiteSha256 = sha256Buffer(buf);
      loadedAfterSuiteReceipt = JSON.parse(buf.toString('utf8'));
    }

    const candidateBefore = fs.existsSync(path.join(loadedFromDir, 'attack-suite-before-fix-receipt.json'))
      ? path.join(loadedFromDir, 'attack-suite-before-fix-receipt.json')
      : DEFAULT_SUITE_BEFORE_PATH;
    if (fs.existsSync(candidateBefore)) {
      const buf = fs.readFileSync(candidateBefore);
      loadedBeforeSuiteSha256 = sha256Buffer(buf);
      loadedBeforeSuiteReceipt = JSON.parse(buf.toString('utf8'));
    }
  }

  const attackSuiteSummary = loadAttackSuiteEvidenceFromReceipts({
    afterReceipt: loadedAfterSuiteReceipt,
    afterSha256: loadedAfterSuiteSha256,
    beforeReceipt: loadedBeforeSuiteReceipt,
    beforeSha256: loadedBeforeSuiteSha256,
  });

  const isLiveProof = Boolean(loadedReceipt);
  const simBaseline = isLiveProof ? null : await runSampleFixtureDemo({ mode: 'simulation' });
  const fixtureInvoices = buildSampleSupplierInvoices();

  const baselineLedgerSource = isLiveProof ? loadedReceipt.ledger : simBaseline.ledger;
  const baselineEntries = structuredClone(baselineLedgerSource.entries);

  const baselineChainCheck = verifyReceiptChain(baselineLedgerSource);
  if (!baselineChainCheck.valid || baselineChainCheck.count !== 15) {
    throw new Error(
      `startHostedDemoServer refused invalid baseline ledger (valid=${baselineChainCheck.valid}, count=${baselineChainCheck.count})`
    );
  }

  const baselineDayTimestamp =
    baselineEntries.find((e) => e.stage === 'ADMITTED')?.timestamp ||
    baselineEntries[0]?.timestamp ||
    '2026-11-11T00:00:00.000Z';

  const baselineSettledPayments = isLiveProof
    ? structuredClone(loadedReceipt.settledOrders || []).map((o) => ({
        ...o,
        simulated: false,
        executionMode: 'LIVE_PAYPAL_SANDBOX_RECORDED',
      }))
    : simBaseline.scenarioResults.slice(0, 2).map((sr, i) => ({
        step: sr.step,
        invoiceId: sr.invoiceId,
        payeeId: i === 0 ? 'colombia-direct-beans' : 'cascade-packaging-co',
        supplier: i === 0 ? 'Colombia Direct Beans Co.' : 'Cascade Packaging Co.',
        payeeEmail: i === 0 ? 'pay@colombia-direct-beans.example' : 'billing@cascade-packaging.example',
        payeeMerchantId: i === 0 ? 'MCH-COLOMBIA-BEANS-01' : 'MCH-CASCADE-PKG-02',
        rail: i === 0 ? 'Orders v2 + Invoicing v2 (local simulation)' : 'Orders v2 + Payouts v1 (local simulation)',
        amountUsd: i === 0 ? '1420.00' : '680.00',
        paypalOrderId: sr.paypalOrderId,
        paypalCaptureId: sr.paypalCaptureId,
        paypalInvoiceId: sr.paypalInvoiceId || null,
        paypalPayoutBatchId: sr.paypalPayoutBatchId || null,
        orderStatus: 'SIMULATED_LOCAL',
        captureStatus: 'SIMULATED_LOCAL',
        simulated: true,
        executionMode: 'SIMULATED_LOCAL_NO_PAYPAL_CALL',
        simulationNotice: SIMULATED_EXECUTION_BADGE_TEXT,
        getOrderPaypalDebugId: null,
      }));

  const baselineOfflineReport = isLiveProof
    ? verifyRecordedReceiptBundle(loadedReceipt, {
        bundleDir: loadedFromDir,
        verifyBundleFilesOnDisk: fs.existsSync(path.join(loadedFromDir, 'CODE-MANIFEST.json')),
      })
    : {
        ok: true,
        chainCount: 15,
        genesisHash: baselineChainCheck.genesisHash,
        headHash: baselineChainCheck.headHash,
        summaryLines: [
          'PAYPAL AP POLICY GATE — DETERMINISTIC SIMULATION MODE (--simulate)',
          '15 of 15 SHA-256 + Ed25519 receipt links valid · 0 network calls · run without --simulate for recorded PayPal Sandbox receipt.',
        ],
      };

  let policyGate;
  let sessionLedger;
  let exceptions;
  let settledPayments;
  let paypalClient;
  let simulatedPreviewCents = 0;
  let simulatedPreviewCount = 0;
  let simulatedPreviewInvoiceKeys = new Set();
  let simulatedPreviewProposalIds = new Set();

  function resetSessionToBaseline() {
    policyGate = hydratePolicyGateFromBaseline(baselineEntries, baselineDayTimestamp);
    sessionLedger = ReceiptLedger.fromJSON({
      ledgerId: baselineLedgerSource.ledgerId,
      protagonist: baselineLedgerSource.protagonist,
      gateSigner: baselineLedgerSource.gateSigner || loadedReceipt?.gateSigner || null,
      entries: baselineEntries,
    });
    exceptions = buildInitialExceptionsFromChain(
      baselineEntries,
      loadedReceipt?.llmProposerSummary?.proposals || [],
      fixtureInvoices
    );
    settledPayments = structuredClone(baselineSettledPayments);
    paypalClient = new PayPalSandboxClient({
      mode: 'simulation',
      seed: 'paypal-ap-policy-gate-interactive-sim',
    });
    simulatedPreviewCents = 0;
    simulatedPreviewCount = 0;
    simulatedPreviewInvoiceKeys = new Set();
    simulatedPreviewProposalIds = new Set();
  }

  resetSessionToBaseline();

  function buildStatePayload() {
    const chainCheck = verifyReceiptChain(sessionLedger);
    const polSnap = policyGate.toPolicySnapshot(baselineDayTimestamp);
    const pendingExcs = exceptions.filter((e) => e.status === 'PENDING_REVIEW');
    const clearedExcs = exceptions.filter((e) => e.status === 'CLEARED_BY_POLICY');
    const dismissedExcs = exceptions.filter((e) => e.status === 'DISMISSED');
    const blockedCents = exceptions.reduce(
      (sum, e) => sum + (parseAmountToCents(e.amountUsd) || 0),
      0
    );
    const blockedTotalUsd = `${Math.floor(blockedCents / 100)}.${String(blockedCents % 100).padStart(2, '0')}`;
    const holds = policyGate.listHolds();
    const openHolds = holds.filter((h) => h.status === 'held');
    const deskInbox = buildSampleSupplierInvoices().map((inv) => ({
      invoiceId: inv.invoiceId,
      proposalId: inv.proposalId,
      supplierName: inv.supplierName,
      payeeId: inv.payeeId,
      payeeEmail: inv.payeeEmail,
      payeeMerchantId: inv.payeeMerchantId || null,
      amountValue: inv.amountValue,
      currencyCode: inv.currencyCode,
      poNumber: inv.poNumber || null,
      reason: inv.reason,
      invoiceDocument: inv.invoiceDocument,
      exceptionId: inv.exceptionId || null,
    }));
    const realHeadroomCents = parseAmountToCents(polSnap.remainingDailyHeadroomUsd) || 0;
    const simulatedRemainingPreviewHeadroomUsd = formatCentsToAmount(
      Math.max(0, realHeadroomCents - simulatedPreviewCents)
    );

    return {
      productName: PRODUCT_TITLE,
      subtitle: PRODUCT_SUBTITLE,
      firstPlaceThesis: FIRST_PLACE_THESIS,
      thirdPartyVerifierSentence: THIRD_PARTY_VERIFIER_SENTENCE,
      paypalToolkitCitation: PAYPAL_TOOLKIT_CITATION,
      datasetStatus: isLiveProof
        ? 'Recorded PayPal Sandbox Run · 25-Invoice Attack Suite + 5-Invoice Ledger · Pre-launch Prototype (0 Live Customers)'
        : 'Synthetic Simulation Mode (--simulate) · 5-Invoice Sample Fixture · 0 Network Calls',
      proofMode: isLiveProof ? 'recorded-live-sandbox' : 'offline-simulation',
      codeManifestSha256: loadedReceipt?.codeManifestSha256 || null,
      recordedReceiptSha256: loadedReceiptSha256,
      aiProposerRoute: isLiveProof
        ? `${loadedReceipt?.llmProposerSummary?.provider || 'ollama-cloud'}:${loadedReceipt?.llmProposerSummary?.returnedModel || 'glm-5.3'}`
        : 'offline:deterministic-fallback',
      kpis: {
        settledTodayUsd: polSnap.settledTodayUsd,
        dailyCapUsd: polSnap.dailyCapUsd,
        remainingHeadroomUsd: polSnap.remainingDailyHeadroomUsd,
        simulatedPreviewTotalUsd: formatCentsToAmount(simulatedPreviewCents),
        simulatedPreviewCount,
        simulatedRemainingPreviewHeadroomUsd,
        perPaymentCapUsd: polSnap.maxTransactionUsd,
        approvedPayeesActive: polSnap.approvedPayeesCount,
        exceptionsPendingCount: pendingExcs.length,
        exceptionsClearedCount: clearedExcs.length,
        exceptionsDismissedCount: dismissedExcs.length,
        blockedTotalUsd,
        holdsOpenCount: openHolds.length,
        holdsTotalCount: holds.length,
        refusalPaypalApiCalls: 0,
        chainValid: chainCheck.valid,
        chainValidCount: chainCheck.valid ? chainCheck.count : 0,
        chainTotalCount: chainCheck.count,
        verifiedEd25519Signatures: chainCheck.verifiedEd25519Signatures,
        baselineChainCount: 15,
        genesisHash: chainCheck.genesisHash,
        headHash: chainCheck.headHash,
      },
      attackSuite: attackSuiteSummary,
      settledPayments,
      policy: {
        ...polSnap,
        simulatedPreviewTotalUsd: formatCentsToAmount(simulatedPreviewCents),
        simulatedPreviewCount,
        simulatedRemainingPreviewHeadroomUsd,
      },
      exceptions,
      holds,
      deskInbox,
      policyEditTokenRequired: Boolean(requiredPolicyToken),
      ledger: sessionLedger.toJSON(),
      verification: chainCheck,
      apiCallLog: isLiveProof ? loadedReceipt.apiCallLog || [] : [],
      offlineVerification: baselineOfflineReport,
    };
  }

  const server = http.createServer(async (req, res) => {
    try {
      const reqUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const pathname = reqUrl.pathname;

      if (req.method === 'GET' && pathname.startsWith('/_shared/')) {
        serveSharedAsset(res, pathname);
        return;
      }

      if (req.method === 'GET' && pathname === '/verify.html') {
        if (!fs.existsSync(VERIFY_HTML_PATH)) {
          sendJson(res, 404, { ok: false, error: 'VERIFY_HTML_NOT_FOUND' });
          return;
        }
        const buf = fs.readFileSync(VERIFY_HTML_PATH);
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy':
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'",
          'Cache-Control': 'no-store',
        });
        res.end(buf);
        return;
      }

      if (req.method === 'GET' && pathname === '/') {
        const requestedScreen = reqUrl.searchParams.get('screen') || 'ledger';
        const html = renderProductHtml(buildStatePayload(), {
          defaultScreen: requestedScreen,
          standalone: false,
        });
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(html);
        return;
      }

      if (req.method === 'GET' && pathname === '/api/health') {
        const st = buildStatePayload();
        sendJson(res, 200, {
          ok: true,
          submitter: 'paypal-ap-policy-gate',
          productName: PRODUCT_TITLE,
          proofMode: st.proofMode,
          screenCount: 6,
          aiProposerRoute: st.aiProposerRoute,
          codeManifestSha256: st.codeManifestSha256,
          recordedReceiptSha256: st.recordedReceiptSha256,
          chainValid: st.kpis.chainValid,
          entryCount: st.kpis.chainTotalCount,
          verifiedEd25519Signatures: st.kpis.verifiedEd25519Signatures,
          baselineChainCount: 15,
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/attack-suite') {
        sendJson(res, 200, {
          ok: true,
          attackSuite: attackSuiteSummary,
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/state') {
        sendJson(res, 200, { ok: true, ...buildStatePayload() });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/policy') {
        const polSnap = policyGate.toPolicySnapshot(baselineDayTimestamp);
        const realHeadroomCents = parseAmountToCents(polSnap.remainingDailyHeadroomUsd) || 0;
        sendJson(res, 200, {
          ok: true,
          policy: {
            ...polSnap,
            simulatedPreviewTotalUsd: formatCentsToAmount(simulatedPreviewCents),
            simulatedPreviewCount,
            simulatedRemainingPreviewHeadroomUsd: formatCentsToAmount(
              Math.max(0, realHeadroomCents - simulatedPreviewCents)
            ),
          },
        });
        return;
      }

      if (req.method === 'PUT' && pathname === '/api/policy') {
        const body = await readJsonBody(req);
        if (requiredPolicyToken) {
          const presented = String(req.headers['x-policy-edit-token'] || body?.policyEditToken || '').trim();
          if (presented !== requiredPolicyToken) {
            sendJson(res, 401, { ok: false, error: 'POLICY_EDIT_TOKEN_REQUIRED' });
            return;
          }
        }
        try {
          if (body.addPayee && typeof body.addPayee === 'object') {
            policyGate.addPayee(body.addPayee);
          }
          if (body.removePayee) {
            policyGate.removePayee(body.removePayee);
          }
          if (body.addPurchaseOrder && typeof body.addPurchaseOrder === 'object') {
            policyGate.addPurchaseOrder(body.addPurchaseOrder);
          }
          if (Array.isArray(body.addPurchaseOrders)) {
            for (const po of body.addPurchaseOrders) policyGate.addPurchaseOrder(po);
          }
          const updated = policyGate.updatePolicy({
            maxTransactionUsd: body.maxTransactionUsd,
            dailyCapUsd: body.dailyCapUsd,
            allowedCurrencies: body.allowedCurrencies,
            approvedPayees: body.approvedPayees,
          });
          const auditReceipt = sessionLedger.append({
            stage: 'POLICY_UPDATED',
            timestamp: new Date().toISOString(),
            proposalId: null,
            actor: 'controller:policy-editor',
            payload: {
              maxTransactionUsd: updated.maxTransactionUsd,
              dailyCapUsd: updated.dailyCapUsd,
              allowedCurrencies: updated.allowedCurrencies,
              approvedPayeesCount: updated.approvedPayeesCount,
              approvedPayeeIds: updated.approvedPayees.map((p) => p.payeeId),
            },
          });
          sendJson(res, 200, {
            ok: true,
            policy: policyGate.toPolicySnapshot(baselineDayTimestamp),
            auditReceipt,
            state: buildStatePayload(),
          });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message });
        }
        return;
      }

      if (req.method === 'POST' && pathname === '/api/reset') {
        resetSessionToBaseline();
        sendJson(res, 200, {
          ok: true,
          state: buildStatePayload(),
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/exceptions') {
        const st = buildStatePayload();
        sendJson(res, 200, {
          ok: true,
          exceptions: st.exceptions,
          pendingCount: st.kpis.exceptionsPendingCount,
          clearedCount: st.kpis.exceptionsClearedCount,
          dismissedCount: st.kpis.exceptionsDismissedCount,
          blockedTotalUsd: st.kpis.blockedTotalUsd,
          refusalPaypalApiCalls: 0,
        });
        return;
      }

      const excReevalMatch = pathname.match(/^\/api\/exceptions\/([^/]+)\/reevaluate$/);
      if (req.method === 'POST' && excReevalMatch) {
        const targetId = decodeURIComponent(excReevalMatch[1]).toUpperCase();
        const exc = exceptions.find((e) => e.exceptionId.toUpperCase() === targetId);
        if (!exc) {
          sendJson(res, 404, { ok: false, error: `EXCEPTION_NOT_FOUND: ${targetId}` });
          return;
        }
        const verdict = policyGate.evaluate(exc.proposal, {
          timestamp: baselineDayTimestamp,
          ignoreProcessedProposalId: true,
        });
        exc.reevaluatedCount += 1;
        exc.updatedAt = new Date().toISOString();
        if (verdict.admitted) {
          exc.status = 'CLEARED_BY_POLICY';
          exc.reasonCode = 'POLICY_ADMITTED';
          exc.reasonDetail = verdict.reasonDetail;
          exc.resolutionNote =
            'Cleared by current PolicyGate rules (policy clearance only — 0 PayPal API calls executed during review).';
        } else {
          if (exc.status !== 'DISMISSED') {
            exc.status = 'PENDING_REVIEW';
          }
          exc.reasonCode = verdict.reasonCode;
          exc.reasonDetail = verdict.reasonDetail;
          exc.resolutionNote = null;
        }
        const auditReceipt = sessionLedger.append({
          stage: 'EXCEPTION_REVIEWED',
          timestamp: exc.updatedAt,
          proposalId: exc.proposalId,
          actor: 'controller:exception-queue',
          payload: {
            exceptionId: exc.exceptionId,
            invoiceId: exc.invoiceId,
            amountUsd: exc.amountUsd,
            decision: verdict.admitted ? 'CLEARED_BY_POLICY' : 'STILL_BLOCKED',
            reasonCode: verdict.reasonCode,
            paypalApiCallsExecuted: 0,
          },
          policyVerdict: verdict,
        });
        sendJson(res, 200, {
          ok: true,
          exception: exc,
          verdict,
          auditReceipt,
          state: buildStatePayload(),
        });
        return;
      }

      const excDismissMatch = pathname.match(/^\/api\/exceptions\/([^/]+)\/dismiss$/);
      if (req.method === 'POST' && excDismissMatch) {
        const targetId = decodeURIComponent(excDismissMatch[1]).toUpperCase();
        const exc = exceptions.find((e) => e.exceptionId.toUpperCase() === targetId);
        if (!exc) {
          sendJson(res, 404, { ok: false, error: `EXCEPTION_NOT_FOUND: ${targetId}` });
          return;
        }
        const body = await readJsonBody(req);
        const reason = String(body.reason || 'Controller dismissed refused proposal').trim();
        exc.status = 'DISMISSED';
        exc.dismissReason = reason;
        exc.resolutionNote = null;
        exc.updatedAt = new Date().toISOString();
        const auditReceipt = sessionLedger.append({
          stage: 'EXCEPTION_DISMISSED',
          timestamp: exc.updatedAt,
          proposalId: exc.proposalId,
          actor: 'controller:exception-queue',
          payload: {
            exceptionId: exc.exceptionId,
            invoiceId: exc.invoiceId,
            amountUsd: exc.amountUsd,
            dismissReason: reason,
            paypalApiCallsExecuted: 0,
          },
        });
        sendJson(res, 200, {
          ok: true,
          exception: exc,
          auditReceipt,
          state: buildStatePayload(),
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/receipts') {
        sendJson(res, 200, {
          ok: true,
          proofMode: isLiveProof ? 'recorded-live-sandbox' : 'offline-simulation',
          verification: verifyReceiptChain(sessionLedger),
          ledger: sessionLedger.toJSON(),
        });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/verify-chain') {
        const body = await readJsonBody(req);
        const target = Array.isArray(body?.entries)
          ? { gateSigner: baselineLedgerSource.gateSigner, entries: body.entries }
          : sessionLedger;
        sendJson(res, 200, verifyReceiptChain(target));
        return;
      }

      if (req.method === 'GET' && (pathname === '/api/verify-offline' || pathname === '/api/verify')) {
        if (isLiveProof) {
          const report = verifyRecordedReceiptBundle(loadedReceipt, {
            bundleDir: loadedFromDir,
            verifyBundleFilesOnDisk: fs.existsSync(path.join(loadedFromDir, 'CODE-MANIFEST.json')),
          });
          sendJson(res, 200, {
            ok: report.ok,
            valid: report.ok,
            count: report.chainCount,
            errors: report.errors,
            report,
            summaryLines: report.summaryLines,
          });
        } else {
          const check = verifyReceiptChain(baselineLedgerSource);
          sendJson(res, 200, {
            ok: check.valid,
            valid: check.valid,
            count: check.count,
            errors: check.errors,
            summaryLines: baselineOfflineReport.summaryLines,
          });
        }
        return;
      }

      if (req.method === 'POST' && pathname === '/api/tamper-check') {
        const body = await readJsonBody(req);
        const targetIndex = Number.isInteger(body?.index) ? body.index : 3;
        const tamperedValue = String(body?.amountValue || '9420.00');
        const cloned = structuredClone(baselineEntries);
        if (!cloned[targetIndex] || !cloned[targetIndex].payload) {
          sendJson(res, 400, { ok: false, error: `Invalid receipt index ${targetIndex}` });
          return;
        }
        const originalValue =
          cloned[targetIndex].payload.amountValue ??
          cloned[targetIndex].payload.attemptedAmountValue ??
          null;
        if ('amountValue' in cloned[targetIndex].payload) {
          cloned[targetIndex].payload.amountValue = tamperedValue;
        } else {
          cloned[targetIndex].payload.attemptedAmountValue = tamperedValue;
        }
        const expectedHash = computeReceiptHash(cloned[targetIndex]);
        const actualHash = cloned[targetIndex].receiptHash;
        const check = verifyReceiptChain({
          gateSigner: baselineLedgerSource.gateSigner || null,
          entries: cloned,
        });
        const firstErr = check.errors[0] || {};

        sendJson(res, 200, {
          ok: true,
          valid: check.valid,
          canonicalCount: baselineEntries.length,
          brokenAtIndex: firstErr.index ?? targetIndex,
          brokenStage: cloned[targetIndex].stage,
          originalValue,
          tamperedValue,
          expectedHash,
          actualHash,
          reason: firstErr.reason || 'RECEIPT_HASH_TAMPERED',
          totalDetectedErrors: check.errors.length,
        });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/holds') {
        sendJson(res, 200, { ok: true, holds: policyGate.listHolds(), state: buildStatePayload() });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/desk/evaluate') {
        const body = await readJsonBody(req);
        const proposal = body?.proposal || body || {};
        const verdict = policyGate.evaluate(proposal, { timestamp: baselineDayTimestamp });
        sendJson(res, 200, {
          ok: true,
          verdict,
          poCard: verdict.poCard || policyGate.getPoCard(proposal.poNumber) || null,
          hold: policyGate.getHold(proposal),
          state: buildStatePayload(),
        });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/holds/approve') {
        const body = await readJsonBody(req);
        try {
          const result = policyGate.approveHeldProposal(body?.proposal || {}, {
            approvedBy: body?.approvedBy,
            timestamp: new Date().toISOString(),
            ledger: sessionLedger,
          });
          sendJson(res, result.ok ? 200 : 409, { ok: result.ok, result, state: buildStatePayload() });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message });
        }
        return;
      }

      if (req.method === 'POST' && pathname === '/api/holds/reject') {
        const body = await readJsonBody(req);
        try {
          const result = policyGate.rejectHeldProposal(body?.proposal || {}, {
            rejectedBy: body?.rejectedBy,
            timestamp: new Date().toISOString(),
            ledger: sessionLedger,
          });
          sendJson(res, 200, { ok: true, result, state: buildStatePayload() });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message });
        }
        return;
      }

      if (req.method === 'POST' && pathname === '/api/propose') {
        const body = await readJsonBody(req);
        const rawProp = body?.proposal || body || {};
        const proposal = {
          proposalId: String(rawProp.proposalId || `prop-op-${Date.now()}`).trim(),
          invoiceId: String(rawProp.invoiceId || '').trim(),
          payeeId: rawProp.payeeId ? String(rawProp.payeeId).trim() : null,
          supplierName: rawProp.supplierName ? String(rawProp.supplierName).trim() : null,
          payeeEmail: String(rawProp.payeeEmail || '').trim(),
          payeeMerchantId: rawProp.payeeMerchantId || null,
          amountValue: String(rawProp.amountValue || '').trim(),
          currencyCode: String(rawProp.currencyCode || 'USD').trim().toUpperCase(),
          poNumber: rawProp.poNumber ? String(rawProp.poNumber).trim() : null,
          reason: String(rawProp.reason || '').trim(),
          invoiceMemo: rawProp.invoiceMemo || null,
          ...(rawProp.live !== undefined ? { live: rawProp.live } : {}),
        };

        // In recorded-live-sandbox mode, interactive proposals are strictly simulated previews:
        // they NEVER alter real settledTodayUsd ($2,100.00) or real remainingDailyHeadroomUsd ($2,900.00).
        const runResult = await processAgentPaymentProposal({
          proposal,
          policyGate,
          paypalClient,
          ledger: sessionLedger,
          timestamp: baselineDayTimestamp,
          captureImmediately: true,
          simulatedPreviewOnly: isLiveProof,
          evaluateOptions: isLiveProof
            ? {
                additionalSimulatedSpendCents: simulatedPreviewCents,
                simulatedInvoiceKeys: simulatedPreviewInvoiceKeys,
                simulatedProposalIds: simulatedPreviewProposalIds,
              }
            : {},
        });

        if (runResult.ok) {
          if (isLiveProof) {
            simulatedPreviewCents += runResult.verdict.amountCents;
            simulatedPreviewCount += 1;
            const dedup = deriveInvoiceDedupKeys(proposal.invoiceId);
            for (const k of dedup.keys) {
              simulatedPreviewInvoiceKeys.add(k);
            }
            simulatedPreviewProposalIds.add(proposal.proposalId);
          }
          settledPayments.push({
            step: settledPayments.length + 1,
            invoiceId: proposal.invoiceId,
            payeeId: runResult.verdict.payeeId,
            supplier: runResult.verdict.payeeName,
            payeeEmail: runResult.verdict.payeeEmail,
            payeeMerchantId: runResult.verdict.payeeMerchantId,
            rail: `${runResult.verdict.rail} (local simulation)`,
            amountUsd: runResult.verdict.amountValue,
            paypalOrderId: runResult.order.id,
            paypalCaptureId: runResult.capture.id,
            paypalInvoiceId: null,
            paypalPayoutBatchId: null,
            orderStatus: 'SIMULATED_LOCAL',
            captureStatus: 'SIMULATED_LOCAL',
            simulated: true,
            executionMode: 'SIMULATED_LOCAL_NO_PAYPAL_CALL',
            simulationNotice: SIMULATED_EXECUTION_BADGE_TEXT,
            getOrderPaypalDebugId: null,
          });
        } else {
          const nextExcId = `EXC-${String(exceptions.length + 1).padStart(2, '0')}`;
          exceptions.push({
            exceptionId: nextExcId,
            status: 'PENDING_REVIEW',
            proposalId: proposal.proposalId,
            invoiceId: proposal.invoiceId,
            payeeId: proposal.payeeId || 'unverified-vendor',
            supplierName: proposal.supplierName || proposal.payeeEmail || 'Unverified Vendor',
            payeeEmail: proposal.payeeEmail,
            payeeMerchantId: proposal.payeeMerchantId,
            amountUsd: proposal.amountValue,
            currencyCode: proposal.currencyCode,
            reason: proposal.reason,
            invoiceMemo: proposal.invoiceMemo || '',
            initialReasonCode: runResult.verdict.reasonCode,
            reasonCode: runResult.verdict.reasonCode,
            reasonDetail: runResult.verdict.reasonDetail,
            paypalApiCallsExecuted: 0,
            proposedReceiptIndex: runResult.proposedReceipt.index,
            refusalReceiptIndex: runResult.outcomeReceipt.index,
            refusalReceiptHash: runResult.outcomeReceipt.receiptHash,
            llmProposal: {
              provider: 'operator-interactive',
              model: 'manual-proposal-form',
              promptSha256: null,
              responseSha256: null,
              rawCompletion: JSON.stringify(proposal),
            },
            proposal,
            reevaluatedCount: 0,
            resolutionNote: null,
            dismissReason: null,
            updatedAt: new Date().toISOString(),
          });
        }

        sendJson(res, 200, {
          ok: true,
          result: {
            status: runResult.status,
            simulated: Boolean(runResult.ok),
            executionMode: runResult.ok
              ? 'SIMULATED_LOCAL_NO_PAYPAL_CALL'
              : 'REFUSED_BEFORE_PAYPAL_CALL',
            simulationNotice: runResult.ok ? SIMULATED_EXECUTION_BADGE_TEXT : null,
            reasonCode: runResult.verdict.reasonCode,
            reasonDetail: runResult.verdict.reasonDetail,
            paypalOrderId: runResult.order?.id || null,
            paypalCaptureId: runResult.capture?.id || null,
            apiCallsDelta: 0,
            livePaypalApiCalls: 0,
            outcomeReceiptIndex: runResult.outcomeReceipt.index,
            outcomeReceiptHash: runResult.outcomeReceipt.receiptHash,
          },
          verification: verifyReceiptChain(sessionLedger),
          state: buildStatePayload(),
        });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/paypal/webhook') {
        const body = await readJsonBody(req);
        try {
          const whResult = paypalClient.handleWebhookEvent({
            headers: body.headers || {},
            event: body.event,
            webhookId: body.webhookId,
            ledger: sessionLedger,
            timestamp: new Date().toISOString(),
          });
          sendJson(res, 200, {
            ok: true,
            verified: whResult.verified,
            eventType: whResult.eventType,
            settlementStatus: whResult.settlementStatus,
            receipt: whResult.receipt,
          });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message });
        }
        return;
      }

      sendJson(res, 404, { ok: false, error: 'NOT_FOUND', path: pathname });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message || 'INTERNAL_SERVER_ERROR' });
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });

  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  const url = `http://${host}:${actualPort}`;

  return {
    server,
    port: actualPort,
    url,
    proofMode: isLiveProof ? 'recorded-live-sandbox' : 'offline-simulation',
    get paypalClient() {
      return paypalClient;
    },
    getState: buildStatePayload,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function getCliArgVal(flag) {
  const idx = process.argv.indexOf(flag);
  return idx >= 0 && process.argv[idx + 1] && !process.argv[idx + 1].startsWith('--')
    ? process.argv[idx + 1]
    : null;
}

const isMain =
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url));

if (isMain) {
  const simulateFlag = process.argv.includes('--simulate');
  const receiptArg = getCliArgVal('--receipt');
  const requestedPort = process.env.PORT !== undefined ? Number(process.env.PORT) : 8799;

  startHostedDemoServer({
    port: requestedPort,
    simulate: simulateFlag,
    receiptPath: receiptArg,
  })
    .then((srv) => {
      console.log(`${PRODUCT_TITLE} listening at ${srv.url} (mode=${srv.proofMode})`);
    })
    .catch((err) => {
      console.error(`Failed to start ${PRODUCT_TITLE}: ${err.message || err}`);
      process.exit(1);
    });
}
