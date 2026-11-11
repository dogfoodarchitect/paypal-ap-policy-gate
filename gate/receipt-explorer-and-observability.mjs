/**
 * receipt-explorer-and-observability.mjs — Receipt Explorer & Structured Observability
 *
 * Provides:
 *   1. Receipt Explorer / Query Utility (`exploreReceipts`):
 *      Filters the SHA-256 hash-chained receipt ledger by `stage`, `payeeEmail`,
 *      `merchantId`, `reasonCode`, `invoiceId`, `proposalId`, and timestamp range
 *      (`fromTimestamp`, `toTimestamp`), while verifying each matched receipt's
 *      cryptographic hash and `prevHash` link against the full chain.
 *   2. Structured JSON Observability Logger (`AgentObservabilityLogger`):
 *      Emits structured JSON audit log events with `timestamp`, `eventType`,
 *      `correlationId`, `proposalId`, `idempotencyKey`, `stage`, `receiptHash`,
 *      and `paypalApiCallsDelta` for production auditability.
 *   3. Explicit Sandbox vs Production Payouts v1 Compliance Disclosure
 *      (`getSandboxComplianceDisclosure`):
 *      Documents Sandbox-only execution vs Production Payouts v1 KYC/AML
 *      business approval requirements.
 */
import {
  GENESIS_PREV_HASH,
  computeReceiptHash,
  verifyReceiptChain,
} from './receipt-ledger.mjs';
import { SANDBOX_ORIGIN } from './vendor/engines/payment-execution/client.mjs';

function extractEntries(ledgerOrEntries) {
  if (Array.isArray(ledgerOrEntries)) {
    return ledgerOrEntries;
  }
  if (typeof ledgerOrEntries?.getEntries === 'function') {
    return ledgerOrEntries.getEntries();
  }
  if (Array.isArray(ledgerOrEntries?.entries)) {
    return ledgerOrEntries.entries;
  }
  return [];
}

function getEntryPayeeEmail(entry) {
  return (
    entry?.payload?.payeeEmail ??
    entry?.policyVerdict?.payeeEmail ??
    entry?.payload?.proposal?.payeeEmail ??
    entry?.policyVerdict?.normalizedProposal?.payeeEmail ??
    null
  );
}

function getEntryMerchantId(entry) {
  return (
    entry?.payload?.payeeMerchantId ??
    entry?.policyVerdict?.payeeMerchantId ??
    entry?.payload?.proposal?.payeeMerchantId ??
    entry?.policyVerdict?.normalizedProposal?.payeeMerchantId ??
    null
  );
}

function getEntryInvoiceId(entry) {
  return (
    entry?.payload?.invoiceId ??
    entry?.policyVerdict?.invoiceId ??
    entry?.payload?.proposal?.invoiceId ??
    entry?.policyVerdict?.normalizedProposal?.invoiceId ??
    null
  );
}

function getEntryReasonCodes(entry) {
  const codes = new Set();
  if (typeof entry?.policyVerdict?.reasonCode === 'string') {
    codes.add(entry.policyVerdict.reasonCode);
  }
  if (typeof entry?.policyVerdict?.primaryReasonCode === 'string') {
    codes.add(entry.policyVerdict.primaryReasonCode);
  }
  if (Array.isArray(entry?.policyVerdict?.reasons)) {
    for (const r of entry.policyVerdict.reasons) {
      if (typeof r?.code === 'string') codes.add(r.code);
    }
  }
  if (typeof entry?.payload?.refusalCode === 'string') {
    codes.add(entry.payload.refusalCode);
  }
  if (typeof entry?.payload?.reasonCode === 'string') {
    codes.add(entry.payload.reasonCode);
  }
  return [...codes];
}

function getEntryAmountValue(entry) {
  const raw =
    entry?.payload?.amountValue ??
    entry?.payload?.attemptedAmountValue ??
    entry?.policyVerdict?.amountValue ??
    entry?.payload?.proposal?.amountValue ??
    entry?.policyVerdict?.normalizedProposal?.amountValue ??
    null;
  const num = raw !== null && raw !== undefined ? Number(raw) : NaN;
  return Number.isFinite(num) ? num : null;
}

/**
 * Queries a ReceiptLedger (or exported entries array), verifies cryptographic
 * chain integrity across the entire ledger and each matched entry, and returns
 * filtered receipts plus summary statistics.
 */
export function exploreReceipts(
  ledgerOrEntries,
  {
    stage = null,
    payeeEmail = null,
    merchantId = null,
    reasonCode = null,
    invoiceId = null,
    proposalId = null,
    fromTimestamp = null,
    toTimestamp = null,
  } = {}
) {
  const entries = extractEntries(ledgerOrEntries);
  const fullChainVerification = verifyReceiptChain(entries);

  const stageFilter = stage
    ? new Set(Array.isArray(stage) ? stage : [stage])
    : null;
  const normalizedEmail = payeeEmail ? String(payeeEmail).trim().toLowerCase() : null;
  const normalizedMerchant = merchantId ? String(merchantId).trim() : null;
  const normalizedReason = reasonCode ? String(reasonCode).trim() : null;
  const normalizedInvoice = invoiceId ? String(invoiceId).trim() : null;
  const normalizedProposal = proposalId ? String(proposalId).trim() : null;

  let fromMs = null;
  if (fromTimestamp !== null && fromTimestamp !== undefined) {
    fromMs = Date.parse(String(fromTimestamp));
    if (!Number.isFinite(fromMs)) {
      const err = new Error(`Invalid fromTimestamp filter: ${fromTimestamp}`);
      err.code = 'INVALID_TIMESTAMP_FILTER';
      err.failClosed = true;
      throw err;
    }
  }

  let toMs = null;
  if (toTimestamp !== null && toTimestamp !== undefined) {
    toMs = Date.parse(String(toTimestamp));
    if (!Number.isFinite(toMs)) {
      const err = new Error(`Invalid toTimestamp filter: ${toTimestamp}`);
      err.code = 'INVALID_TIMESTAMP_FILTER';
      err.failClosed = true;
      throw err;
    }
  }

  if (fromMs !== null && toMs !== null && fromMs > toMs) {
    const err = new Error(`fromTimestamp (${fromTimestamp}) exceeds toTimestamp (${toTimestamp})`);
    err.code = 'INVALID_TIMESTAMP_FILTER';
    err.failClosed = true;
    throw err;
  }

  const matchedEntries = [];
  const matchedVerifications = [];

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (stageFilter && !stageFilter.has(entry.stage)) continue;

    if (normalizedEmail) {
      const entryEmail = getEntryPayeeEmail(entry);
      if (!entryEmail || String(entryEmail).trim().toLowerCase() !== normalizedEmail) {
        continue;
      }
    }

    if (normalizedMerchant) {
      const entryMerchant = getEntryMerchantId(entry);
      if (entryMerchant !== normalizedMerchant) continue;
    }

    if (normalizedReason) {
      const codes = getEntryReasonCodes(entry);
      if (!codes.includes(normalizedReason)) continue;
    }

    if (normalizedInvoice) {
      const entryInvoice = getEntryInvoiceId(entry);
      if (entryInvoice !== normalizedInvoice) continue;
    }

    if (normalizedProposal && entry.proposalId !== normalizedProposal) {
      continue;
    }

    if (fromMs !== null && Number.isFinite(fromMs)) {
      const entryMs = Date.parse(entry.timestamp);
      if (!Number.isFinite(entryMs) || entryMs < fromMs) continue;
    }

    if (toMs !== null && Number.isFinite(toMs)) {
      const entryMs = Date.parse(entry.timestamp);
      if (!Number.isFinite(entryMs) || entryMs > toMs) continue;
    }

    const expectedPrevHash = i === 0 ? GENESIS_PREV_HASH : entries[i - 1]?.receiptHash;
    const computedHash = computeReceiptHash(entry);
    const hashValid = entry.receiptHash === computedHash;
    const prevLinkValid = entry.prevHash === expectedPrevHash;

    matchedEntries.push(entry);
    matchedVerifications.push({
      index: entry.index,
      receiptId: entry.receiptId,
      stage: entry.stage,
      receiptHash: entry.receiptHash,
      computedHash,
      hashValid,
      prevLinkValid,
    });
  }

  let executedUsdTotal = 0;
  let refusedUsdTotal = 0;
  const stageBreakdown = {};

  for (const entry of matchedEntries) {
    stageBreakdown[entry.stage] = (stageBreakdown[entry.stage] || 0) + 1;
    const amt = getEntryAmountValue(entry);
    if (amt !== null) {
      if (entry.stage === 'EXECUTED') executedUsdTotal += amt;
      if (entry.stage === 'REFUSED') refusedUsdTotal += amt;
    }
  }

  return Object.freeze({
    chainValid: fullChainVerification.valid,
    totalLedgerEntries: entries.length,
    matchedCount: matchedEntries.length,
    allMatchedCryptographicallyValid:
      fullChainVerification.valid &&
      matchedVerifications.every((v) => v.hashValid && v.prevLinkValid),
    stageBreakdown,
    executedUsdTotal: Number(executedUsdTotal.toFixed(2)),
    refusedUsdTotal: Number(refusedUsdTotal.toFixed(2)),
    matchedVerifications,
    entries: matchedEntries,
  });
}

/**
 * Structured JSON Observability Logger for audit correlation across AI proposal,
 * PolicyGate decision, PayPal Sandbox execution, and Webhook settlement stages.
 */
export class AgentObservabilityLogger {
  constructor({
    serviceName = 'paypal-receipted-agent',
    environment = 'paypal-sandbox',
    sink = null,
  } = {}) {
    this.serviceName = serviceName;
    this.environment = environment;
    this.sink = typeof sink === 'function' ? sink : null;
    this.events = [];
  }

  logEvent({
    timestamp = new Date().toISOString(),
    eventType,
    correlationId,
    proposalId = null,
    idempotencyKey = null,
    stage = null,
    receiptId = null,
    receiptHash = null,
    reasonCode = null,
    paypalOrderId = null,
    paypalCaptureId = null,
    paypalApiCallsDelta = 0,
    details = {},
  }) {
    if (!eventType || typeof eventType !== 'string') {
      throw new Error('AgentObservabilityLogger.logEvent requires a non-empty eventType');
    }
    if (!correlationId || typeof correlationId !== 'string') {
      throw new Error('AgentObservabilityLogger.logEvent requires a non-empty correlationId');
    }

    const structuredRecord = Object.freeze({
      schemaVersion: 'paypal-agent-observability/v1',
      timestamp,
      serviceName: this.serviceName,
      environment: this.environment,
      eventType,
      correlationId,
      proposalId,
      idempotencyKey,
      stage,
      receiptId,
      receiptHash,
      reasonCode,
      paypalOrderId,
      paypalCaptureId,
      paypalApiCallsDelta: Number(paypalApiCallsDelta) || 0,
      details: structuredClone(details),
    });

    this.events.push(structuredRecord);
    if (this.sink) {
      this.sink(JSON.stringify(structuredRecord));
    }
    return structuredRecord;
  }

  getEventsByCorrelationId(correlationId) {
    return this.events.filter((e) => e.correlationId === correlationId);
  }

  toJSONL() {
    return this.events.map((e) => JSON.stringify(e)).join('\n');
  }
}

/**
 * Returns explicit compliance and environment scope metadata distinguishing
 * PayPal Sandbox Orders v2 execution from Production Payouts v1 requirements.
 */
export function getSandboxComplianceDisclosure() {
  return Object.freeze({
    executionEnvironment: 'PAYPAL_SANDBOX_ONLY',
    apiBaseUrl: SANDBOX_ORIGIN,
    implementedApiSurface: [
      'POST /v1/oauth2/token',
      'POST /v2/checkout/orders',
      'POST /v2/checkout/orders/{id}/capture',
      'POST /v1/notifications/verify-webhook-signature',
    ],
    realMoneyMovement: false,
    productionPayoutsV1ReadinessNote:
      'This reference implementation executes exclusively against PayPal Sandbox Orders v2 (api-m.sandbox.paypal.com) with zero real-money movement. Transitioning to Production PayPal Payouts v1 (/v1/payments/payouts) requires live PayPal Business account onboarding, KYC/AML underwriting approval, Payouts API scope enablement, and hardware/KMS-backed webhook & OAuth2 credential rotation.',
  });
}
