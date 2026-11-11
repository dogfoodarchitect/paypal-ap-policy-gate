/**
 * paypal-receipted-agent.test.mjs — Core Engine & PolicyGate Test Suite
 *
 * Tests:
 *   1. SHA-256 ReceiptLedger genesis, canonical hashing, and chain verification
 *   2. Positive admitted payment flow (Orders v2 create + capture + getOrder)
 *   3. Negative Gate #1: Over per-transaction cap -> refused with 0 PayPal API calls
 *   4. Negative Gate #2: Over daily cumulative spend cap -> refused with 0 PayPal API calls
 *   5. Negative Gate #3: Unapproved supplier payee -> refused with 0 PayPal API calls
 *   6. Negative Gate #4: Duplicate invoice ID & duplicate proposal ID -> refused with 0 PayPal API calls
 *   7. Negative Gate #5 & #6: Invalid amounts, unsupported currencies, and live mode fail closed
 *   8. Webhook signature verification & settlement receipts (COMPLETED, REFUNDED, DENIED)
 *   9. Real HTTPS Sandbox transport wire contract (OAuth2 + Orders v2 headers/body)
 *  10. Tamper detection on SHA-256 receipt chain (payload edit, deleted entry)
 *  11. AIProcurementAgent live LLM proposer (ollama-cloud:glm-5.3) & offline deterministic fallback
 *  12. Full 5-invoice B2B supplier sample fixture executes 2 admitted orders + 3 refusals (15/15 links)
 *  13. PolicyGate.updatePolicy mutates live caps & allowedCurrencies while preserving settled spend
 *  14. PolicyGate.addPayee & removePayee dynamically manage Approved Payee Allowlist
 *  15. PolicyGate exception re-evaluation check ordering (DUPLICATE_INVOICE -> OVER_TRANSACTION_CAP -> OVER_DAILY_SPEND_CAP -> UNAPPROVED_PAYEE)
 *  16. ReceiptLedger.fromJSON & operational audit stages (POLICY_UPDATED, EXCEPTION_REVIEWED, EXCEPTION_DISMISSED)
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ReceiptLedger,
  verifyReceiptChain,
  computeReceiptHash,
  GENESIS_PREV_HASH,
} from './receipt-ledger.mjs';
import {
  PolicyGate,
  DEFAULT_AP_POLICY_GATE_CONFIG,
  processAgentPaymentProposal,
  parseAmountToCents,
  deriveInvoiceDedupKeys,
  replayPaidHistory,
} from './policy-gate.mjs';
import { testPolicyGate, fillProposal } from './b10-test-helpers.mjs';
import { PayPalSandboxClient } from './paypal-client.mjs';
import { AIProcurementAgent, SUPPORTED_AI_ROUTES } from './ai-procurement-agent.mjs';
import { runSampleFixtureDemo } from './demo-cli.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

test('1. ReceiptLedger initializes valid GENESIS entry and chains SHA-256 receipts deterministically', () => {
  const ledger = new ReceiptLedger({
    ledgerId: 'test-ledger-01',
    genesisTimestamp: '2026-11-09T00:00:00.000Z',
  });

  const entries = ledger.getEntries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].index, 0);
  assert.equal(entries[0].stage, 'GENESIS');
  assert.equal(entries[0].prevHash, GENESIS_PREV_HASH);
  assert.equal(entries[0].receiptHash, computeReceiptHash(entries[0]));

  const r1 = ledger.append({
    stage: 'PROPOSED',
    timestamp: '2026-11-09T00:01:00.000Z',
    proposalId: 'prop-1',
    payload: { b: 2, a: 1 },
  });
  assert.equal(r1.prevHash, entries[0].receiptHash);

  const check = verifyReceiptChain(ledger);
  assert.equal(check.valid, true);
  assert.equal(check.count, 2);
  assert.equal(check.errors.length, 0);
});

test('2. Admitted supplier proposal executes PayPal Sandbox Orders v2 createOrder, captureOrder, and getOrder', async () => {
  const ledger = new ReceiptLedger({ ledgerId: 'test-admitted' });
  const policyGate = testPolicyGate();
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-2' });

  const proposal = fillProposal({
    proposalId: 'prop-ok-100',
    invoiceId: 'INV-OK-100',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '1250.50',
    currencyCode: 'USD',
    reason: 'Washed Arabica green coffee wholesale lot #42',
  });

  const res = await processAgentPaymentProposal({
    proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-09T06:10:00.000Z',
  });

  assert.equal(res.ok, true);
  assert.equal(res.status, 'EXECUTED');
  assert.ok(res.order.id.startsWith('SIMULATED-ORDER-'));
  assert.ok(res.capture.id.startsWith('SIMULATED-CAPTURE-'));
  assert.equal(res.order.simulated, true);
  assert.equal(res.capture.simulated, true);
  assert.equal(res.capture.status, 'COMPLETED');
  assert.equal(res.capture.amount.value, '1250.50');
  assert.ok(res.apiCallsDelta >= 2);

  const fetchedOrder = await paypalClient.getOrder(res.order.id);
  assert.equal(fetchedOrder.id, res.order.id);
  assert.equal(fetchedOrder.status, 'COMPLETED');

  const chainCheck = verifyReceiptChain(ledger);
  assert.equal(chainCheck.valid, true);
  assert.equal(chainCheck.stageCounts.PROPOSED, 1);
  assert.equal(chainCheck.stageCounts.ADMITTED, 1);
  assert.equal(chainCheck.stageCounts.EXECUTED, 1);
});

test('3. Negative Gate #1: Over per-transaction cap fails closed with ZERO PayPal API calls and leaves REFUSED receipt', async () => {
  const ledger = new ReceiptLedger({ ledgerId: 'test-over-cap' });
  const policyGate = testPolicyGate();
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-3' });

  const res = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-over-cap',
      invoiceId: 'INV-OVER-999',
      payeeEmail: 'pay@colombia-direct-beans.example',
      amountValue: '2500.01',
      currencyCode: 'USD',
      reason: 'Over-limit raw-material shipment',
    },
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-09T06:15:00.000Z',
  });

  assert.equal(res.ok, false);
  assert.equal(res.status, 'REFUSED');
  assert.equal(res.verdict.reasonCode, 'OVER_TRANSACTION_CAP');
  assert.equal(res.order, null);
  assert.equal(res.capture, null);
  assert.equal(res.apiCallsDelta, 0);
  assert.equal(paypalClient.getApiCallCount(), 0);

  const chainCheck = verifyReceiptChain(ledger);
  assert.equal(chainCheck.valid, true);
  assert.equal(chainCheck.stageCounts.REFUSED, 1);
  assert.equal(chainCheck.stageCounts.EXECUTED, 0);
});

test('4. Negative Gate #2: Over daily cumulative spend cap fails closed with ZERO PayPal API calls on the breaching order', async () => {
  const ledger = new ReceiptLedger({ ledgerId: 'test-daily-cap' });
  const policyGate = testPolicyGate({
    ...DEFAULT_AP_POLICY_GATE_CONFIG,
    maxTransactionCents: 250000,
    maxDailySpendCents: 350000,
  });
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-4' });

  const first = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-day-1',
      invoiceId: 'INV-DAY-1',
      payeeEmail: 'pay@colombia-direct-beans.example',
      amountValue: '2200.00',
      currencyCode: 'USD',
      reason: 'Morning wholesale batch',
    },
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-09T08:00:00.000Z',
  });
  assert.equal(first.ok, true);
  const callsAfterFirst = paypalClient.getApiCallCount();

  const second = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-day-2',
      invoiceId: 'INV-DAY-2',
      payeeEmail: 'pay@colombia-direct-beans.example',
      amountValue: '1400.00',
      currencyCode: 'USD',
      reason: 'Afternoon batch exceeding daily cap',
    },
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-09T09:00:00.000Z',
  });

  assert.equal(second.ok, false);
  assert.equal(second.status, 'REFUSED');
  assert.equal(second.verdict.reasonCode, 'OVER_DAILY_SPEND_CAP');
  assert.equal(second.apiCallsDelta, 0);
  assert.equal(paypalClient.getApiCallCount(), callsAfterFirst);
});

test('5. Negative Gate #3: Unapproved payee & mismatched merchant ID fail closed with ZERO PayPal API calls', async () => {
  const ledger = new ReceiptLedger({ ledgerId: 'test-unapproved' });
  const policyGate = testPolicyGate();
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-5' });

  const unapprovedEmailRes = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-unapproved-1',
      invoiceId: 'INV-BAD-1',
      payeeEmail: 'wire@offshore-holdings.example',
      amountValue: '100.00',
      currencyCode: 'USD',
      reason: 'Unverified beneficiary invoice',
    },
    policyGate,
    paypalClient,
    ledger,
  });

  assert.equal(unapprovedEmailRes.ok, false);
  assert.equal(unapprovedEmailRes.verdict.reasonCode, 'UNAPPROVED_PAYEE');
  assert.equal(paypalClient.getApiCallCount(), 0);

  const mismatchedMerchantRes = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-unapproved-2',
      invoiceId: 'INV-BAD-2',
      payeeEmail: 'pay@colombia-direct-beans.example',
      payeeMerchantId: 'MCH-HIJACKED-99',
      amountValue: '100.00',
      currencyCode: 'USD',
      reason: 'Allowlisted email but hijacked merchant ID',
    },
    policyGate,
    paypalClient,
    ledger,
  });

  assert.equal(mismatchedMerchantRes.ok, false);
  assert.equal(mismatchedMerchantRes.verdict.reasonCode, 'UNAPPROVED_PAYEE');
  assert.equal(paypalClient.getApiCallCount(), 0);
});

test('6. Negative Gate #4: Duplicate invoice ID and duplicate proposal ID fail closed with ZERO PayPal API calls', async () => {
  const ledger = new ReceiptLedger({ ledgerId: 'test-duplicates' });
  const policyGate = testPolicyGate();
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-6' });

  const first = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-orig-1',
      invoiceId: 'INV-UNIQUE-500',
      payeeEmail: 'billing@cascade-packaging.example',
      amountValue: '300.00',
      currencyCode: 'USD',
      reason: 'Packaging order #500',
    },
    policyGate,
    paypalClient,
    ledger,
  });
  assert.equal(first.ok, true);
  const callsAfterFirst = paypalClient.getApiCallCount();

  const dupInvoice = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-replay-2',
      invoiceId: 'INV-UNIQUE-500',
      payeeEmail: 'billing@cascade-packaging.example',
      amountValue: '300.00',
      currencyCode: 'USD',
      reason: 'Duplicate invoice submission',
    },
    policyGate,
    paypalClient,
    ledger,
  });
  assert.equal(dupInvoice.ok, false);
  assert.equal(dupInvoice.verdict.reasonCode, 'DUPLICATE_INVOICE');
  assert.equal(dupInvoice.apiCallsDelta, 0);
  assert.equal(paypalClient.getApiCallCount(), callsAfterFirst);

  const dupProposal = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-orig-1',
      invoiceId: 'INV-UNIQUE-501',
      payeeEmail: 'billing@cascade-packaging.example',
      amountValue: '300.00',
      currencyCode: 'USD',
      reason: 'Duplicate proposal ID submission',
    },
    policyGate,
    paypalClient,
    ledger,
  });
  assert.equal(dupProposal.ok, false);
  assert.equal(dupProposal.verdict.reasonCode, 'DUPLICATE_PROPOSAL');
  assert.equal(dupProposal.apiCallsDelta, 0);
  assert.equal(paypalClient.getApiCallCount(), callsAfterFirst);
});

test('7. Negative Gate #5 & #6: Invalid amounts, unsupported currencies, and live mode fail closed', async () => {
  assert.equal(parseAmountToCents('-10.00'), null);
  assert.equal(parseAmountToCents('0.00'), null);
  assert.equal(parseAmountToCents('12.345'), null);
  assert.equal(parseAmountToCents('abc'), null);
  assert.equal(parseAmountToCents('45.50'), 4550);

  const ledger = new ReceiptLedger({ ledgerId: 'test-invalid-inputs' });
  const policyGate = testPolicyGate();
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-7' });

  const badCurrency = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-eur',
      invoiceId: 'INV-EUR-1',
      payeeEmail: 'pay@colombia-direct-beans.example',
      amountValue: '100.00',
      currencyCode: 'EUR',
      reason: 'Unsupported currency test',
    },
    policyGate,
    paypalClient,
    ledger,
  });
  assert.equal(badCurrency.ok, false);
  assert.equal(badCurrency.verdict.reasonCode, 'UNSUPPORTED_CURRENCY');

  const liveAttempt = await processAgentPaymentProposal({
    proposal: {
      proposalId: 'prop-live',
      invoiceId: 'INV-LIVE-1',
      payeeEmail: 'pay@colombia-direct-beans.example',
      amountValue: '100.00',
      currencyCode: 'USD',
      reason: 'Live flag test',
      live: true,
    },
    policyGate,
    paypalClient,
    ledger,
  });
  assert.equal(liveAttempt.ok, false);
  assert.equal(liveAttempt.verdict.reasonCode, 'LIVE_MODE_FORBIDDEN');
  assert.equal(paypalClient.getApiCallCount(), 0);

  assert.throws(
    () => new PayPalSandboxClient({ baseUrl: 'https://api-m.paypal.com' }),
    /PAYPAL_LIVE_ENDPOINT_FORBIDDEN/
  );
  assert.throws(
    () => new PayPalSandboxClient({ live: true }),
    /PAYPAL_LIVE_MODE_FORBIDDEN/
  );
});

test('8. Webhook signature verification and COMPLETED / REFUNDED / DENIED event chaining', () => {
  const ledger = new ReceiptLedger({ ledgerId: 'test-webhooks' });
  const paypalClient = new PayPalSandboxClient({ seed: 'test-seed-8' });

  for (const eventType of ['PAYMENT.CAPTURE.COMPLETED', 'PAYMENT.CAPTURE.REFUNDED', 'PAYMENT.CAPTURE.DENIED']) {
    const evt = {
      id: `WH-${eventType}`,
      event_type: eventType,
      resource: {
        id: 'SIMULATED-CAPTURE-123',
        custom_id: 'prop-wh-1',
        invoice_id: 'INV-WH-1',
        amount: { currency_code: 'USD', value: '250.00' },
        supplementary_data: { related_ids: { order_id: 'SIMULATED-ORDER-123' } },
      },
    };
    const signed = paypalClient.signWebhookEvent({ event: evt });
    const res = paypalClient.handleWebhookEvent({
      headers: signed.headers,
      event: evt,
      webhookId: signed.webhookId,
      ledger,
    });
    assert.equal(res.verified, true);
    assert.equal(res.eventType, eventType);
    assert.equal(res.receipt.stage, 'WEBHOOK_SETTLED');
  }

  assert.throws(
    () =>
      paypalClient.handleWebhookEvent({
        headers: {
          'paypal-transmission-id': 'tx-1',
          'paypal-transmission-time': '2026-11-09T06:00:00Z',
          'paypal-transmission-sig': 'forged-signature',
        },
        event: { id: 'WH-FORGED', event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: {} },
        ledger,
      }),
    /PAYPAL_WEBHOOK_REJECTED/
  );

  const check = verifyReceiptChain(ledger);
  assert.equal(check.valid, true);
  assert.equal(check.stageCounts.WEBHOOK_SETTLED, 3);
});

test('9. Real HTTPS Sandbox mode executes OAuth2 and Orders v2 against injected fetch transport', async () => {
  const requests = [];
  const mockFetch = async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith('/v1/oauth2/token')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'stub-tok', token_type: 'Bearer', expires_in: 32400 }),
      };
    }
    if (url.endsWith('/v2/checkout/orders') && options.method === 'POST') {
      const parsed = JSON.parse(options.body);
      return {
        ok: true,
        status: 201,
        json: async () => ({
          id: 'ORD-HTTPS-SBX-001',
          status: 'CREATED',
          purchase_units: parsed.purchase_units,
        }),
      };
    }
    if (url.endsWith('/v2/checkout/orders/ORD-HTTPS-SBX-001/capture')) {
      return {
        ok: true,
        status: 201,
        json: async () => ({
          id: 'CAP-HTTPS-SBX-001',
          status: 'COMPLETED',
        }),
      };
    }
    throw new Error(`Unexpected URL: ${url}`);
  };

  const client = new PayPalSandboxClient({
    clientId: 'sbx-id-123',
    clientSecret: 'sbx-sec-456',
    mode: 'sandbox-https',
    fetchImpl: mockFetch,
  });

  const order = await client.createOrder({
    proposalId: 'prop-https-1',
    invoiceId: 'INV-HTTPS-1',
    payeeEmail: 'pay@colombia-direct-beans.example',
    amountValue: '500.00',
    currencyCode: 'USD',
    description: 'HTTPS Sandbox test',
  });
  assert.equal(order.id, 'ORD-HTTPS-SBX-001');

  const capture = await client.captureOrder(order.id);
  assert.equal(capture.id, 'CAP-HTTPS-SBX-001');
  assert.equal(requests.length, 3);
  assert.equal(requests[1].options.headers.Authorization, 'Bearer stub-tok');
});

test('10. Tamper detection catches mutated payload and deleted entry in SHA-256 chain', async () => {
  const demo = await runSampleFixtureDemo();
  assert.equal(demo.chainVerification.valid, true);

  const tamperedAmountEntries = structuredClone(demo.ledger.entries);
  tamperedAmountEntries[1].payload.amountValue = '999999.00';
  const check1 = verifyReceiptChain(tamperedAmountEntries);
  assert.equal(check1.valid, false);
  assert.ok(check1.errors.some((e) => e.reason.includes('RECEIPT_HASH_TAMPERED')));

  const deletedEntryChain = structuredClone(demo.ledger.entries);
  deletedEntryChain.splice(7, 1);
  const check2 = verifyReceiptChain(deletedEntryChain);
  assert.equal(check2.valid, false);
  assert.ok(
    check2.errors.some((e) => e.reason.includes('PREV_HASH_CHAIN_BROKEN') || e.reason.includes('INDEX_MISMATCH'))
  );
});

test('11. AIProcurementAgent supports ollama-cloud:glm-5.3 live LLM proposer and offline deterministic fallback', async () => {
  const agent = new AIProcurementAgent({
    defaultRoute: 'ollama-cloud:glm-5.3',
    liveInferenceAdapter: async ({ model }) => ({
      rawCompletion: JSON.stringify({
        proposalId: 'prop-glm-01',
        invoiceId: 'INV-GLM-01',
        supplierName: 'Colombia Direct Beans Co.',
        payeeEmail: 'pay@colombia-direct-beans.example',
        payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
        amountValue: '950.00',
        currencyCode: 'USD',
        reason: `Drafted by ${model}`,
      }),
      returnedModel: model,
      tokensIn: 142,
      tokensOut: 64,
      elapsedMs: 812,
    }),
  });

  assert.ok(SUPPORTED_AI_ROUTES['ollama-cloud:glm-5.3']);
  assert.ok(SUPPORTED_AI_ROUTES['offline:deterministic-fallback']);
  assert.equal(Object.keys(SUPPORTED_AI_ROUTES).length, 2);

  const proposal = await agent.draftPaymentProposal('Invoice #INV-GLM-01 for $950.00', {
    route: 'ollama-cloud:glm-5.3',
    requireLiveLlm: true,
  });
  assert.equal(proposal.proposalId, 'prop-glm-01');
  assert.equal(proposal.amountValue, '950.00');
  assert.equal(proposal.aiModelRoute.mode, 'live-llm-proposer');
  assert.equal(proposal.aiModelRoute.provider, 'ollama-cloud');
  assert.equal(proposal.aiModelRoute.requestedModel, 'glm-5.3');
  assert.equal(proposal.aiModelRoute.returnedModel, 'glm-5.3');
  assert.equal(proposal.aiModelRoute.tokensIn, 142);
  assert.equal(proposal.aiModelRoute.tokensOut, 64);
  assert.equal(proposal.aiModelRoute.promptSha256.length, 64);
  assert.equal(proposal.aiModelRoute.responseSha256.length, 64);

  const offlineProposal = await agent.draftPaymentProposal(
    {
      proposalId: 'prop-offline-01',
      invoiceId: 'INV-OFFLINE-01',
      payeeEmail: 'pay@colombia-direct-beans.example',
      payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
      amountValue: '250.00',
      currencyCode: 'USD',
      reason: 'Offline fallback check',
    },
    { route: 'offline:deterministic-fallback' }
  );
  assert.equal(offlineProposal.aiModelRoute.mode, 'offline-deterministic-fallback');
});

test('12. Full 5-invoice B2B supplier sample fixture executes 2 admitted supplier orders + 3 refusals with 15/15 chain integrity', async () => {
  const report = await runSampleFixtureDemo();
  assert.equal(report.chainVerification.valid, true);
  assert.equal(report.chainVerification.count, 15);
  assert.equal(report.dailySpendCommittedUSD, '2100.00');
  assert.equal(report.scenarioResults.length, 5);

  const [step1, step2, step3, step4, step5] = report.scenarioResults;
  assert.equal(step1.outcome, 'EXECUTED');
  assert.equal(step1.invoiceId, 'INV-2026-1041');
  assert.equal(step2.outcome, 'EXECUTED');
  assert.equal(step2.invoiceId, 'INV-2026-1043');
  assert.equal(step3.outcome, 'REFUSED');
  assert.equal(step3.reasonCode, 'UNAPPROVED_PAYEE');
  assert.equal(step3.apiCallsDelta, 0);
  assert.equal(step4.outcome, 'REFUSED');
  assert.equal(step4.reasonCode, 'UNAPPROVED_PAYEE');
  assert.equal(step4.apiCallsDelta, 0);
  assert.equal(step5.outcome, 'REFUSED');
  assert.equal(step5.reasonCode, 'DUPLICATE_INVOICE');
  assert.equal(step5.apiCallsDelta, 0);
});

test('13. PolicyGate.updatePolicy mutates live caps & allowedCurrencies while preserving cumulative settled spend', () => {
  const gate = testPolicyGate();
  const ts = '2026-11-11T00:05:00.000Z';
  const v1 = gate.evaluate(
    {
      proposalId: 'prop-settle-1',
      invoiceId: 'INV-2026-1041',
      payeeEmail: 'pay@colombia-direct-beans.example',
      amountValue: '2100.00',
      currencyCode: 'USD',
      reason: 'Baseline settled spend',
    },
    { timestamp: ts }
  );
  assert.equal(v1.admitted, true);
  gate.commitAdmission({ proposalId: 'prop-settle-1', invoiceId: 'INV-2026-1041' }, v1);

  const updated = gate.updatePolicy({
    maxTransactionUsd: '3200.00',
    dailyCapUsd: '6000.00',
    allowedCurrencies: ['USD', 'EUR'],
  });
  assert.equal(updated.maxTransactionUsd, '3200.00');
  assert.equal(updated.dailyCapUsd, '6000.00');
  assert.deepEqual(updated.allowedCurrencies, ['USD', 'EUR']);

  const snap = gate.toPolicySnapshot(ts);
  assert.equal(snap.settledTodayUsd, '2100.00');
  assert.equal(snap.remainingDailyHeadroomUsd, '3900.00');

  assert.throws(() => gate.updatePolicy({ maxTransactionUsd: '-50' }), /INVALID_MAX_TRANSACTION_USD/);
  assert.throws(() => gate.updatePolicy({ allowedCurrencies: [] }), /INVALID_ALLOWED_CURRENCIES/);
});

test('14. PolicyGate.addPayee and removePayee dynamically manage Approved Payee Allowlist', () => {
  const gate = testPolicyGate();
  assert.equal(gate.listApprovedPayees().length, 3);

  const added = gate.addPayee({
    payeeId: 'offshore-holdings-ltd',
    displayName: 'Offshore Holdings Ltd.',
    paypalReceiver: 'wire@offshore-holdings.example',
    rail: 'Orders v2',
  });
  assert.equal(added.payeeId, 'offshore-holdings-ltd');
  assert.equal(gate.listApprovedPayees().length, 4);

  gate.addPurchaseOrder({
    poNumber: 'PO-2026-EXC-02',
    payeeId: 'offshore-holdings-ltd',
    payeeEmail: 'wire@offshore-holdings.example',
    currencyCode: 'USD',
    totalCents: 50000,
    open: true,
  });
  const evalAdded = gate.evaluate({
    proposalId: 'prop-allow-added',
    invoiceId: 'INV-2026-1044',
    payeeId: 'offshore-holdings-ltd',
    payeeEmail: 'wire@offshore-holdings.example',
    amountValue: '450.00',
    currencyCode: 'USD',
    poNumber: 'PO-2026-EXC-02',
    reason: 'Now allowlisted payee',
  });
  assert.equal(evalAdded.admitted, true, evalAdded.reasonCode);

  assert.equal(gate.removePayee('offshore-holdings-ltd'), true);
  assert.equal(gate.listApprovedPayees().length, 3);
});

test('15. PolicyGate exception re-evaluation enforces deterministic check precedence across cap & allowlist edits', () => {
  const gate = testPolicyGate();
  const ts = '2026-11-11T00:05:00.000Z';
  gate.commitAdmission(
    { proposalId: 'prop-ap-001', invoiceId: 'INV-2026-1041', payeeEmail: 'pay@colombia-direct-beans.example' },
    { admitted: true, amountCents: 210000, evaluatedAt: ts, payeeEmail: 'pay@colombia-direct-beans.example' }
  );

  const exc01Proposal = {
    proposalId: 'prop-ap-003-overcap',
    invoiceId: 'INV-2026-1042',
    payeeEmail: 'billing@pacific-roast-equip.example',
    amountValue: '4850.00',
    currencyCode: 'USD',
    reason: 'Spot equipment bundle',
  };

  // Rule 1 fires first: Pacific Roast is not a registered supplier, even before the $2,500 cap is considered.
  assert.equal(
    gate.evaluate(exc01Proposal, { timestamp: ts, ignoreProcessedProposalId: true }).reasonCode,
    'UNAPPROVED_PAYEE'
  );

  // Raising caps without allowlisting the supplier still returns UNAPPROVED_PAYEE
  gate.updatePolicy({ maxTransactionUsd: '5000.00', dailyCapUsd: '5000.00' });
  assert.equal(
    gate.evaluate(exc01Proposal, { timestamp: ts, ignoreProcessedProposalId: true }).reasonCode,
    'UNAPPROVED_PAYEE'
  );

  gate.updatePolicy({ dailyCapUsd: '8000.00' });
  assert.equal(
    gate.evaluate(exc01Proposal, { timestamp: ts, ignoreProcessedProposalId: true }).reasonCode,
    'UNAPPROVED_PAYEE'
  );

  // After the supplier is allowlisted and given an open PO, the $4,850 invoice hits the per-payment cap.
  gate.addPayee({
    payeeId: 'pacific-roast-equip',
    displayName: 'Pacific Roast Equipment Co.',
    paypalReceiver: 'billing@pacific-roast-equip.example',
    merchantId: 'MCH-PACIFIC-EQUIP-99',
    rail: 'Orders v2',
  });
  gate.addPurchaseOrder({
    poNumber: 'PO-2026-38-1042',
    payeeId: 'pacific-roast-equip',
    payeeEmail: 'billing@pacific-roast-equip.example',
    currencyCode: 'USD',
    totalCents: 600000,
    open: true,
  });
  const allowedExc01 = {
    ...exc01Proposal,
    payeeId: 'pacific-roast-equip',
    payeeMerchantId: 'MCH-PACIFIC-EQUIP-99',
    poNumber: 'PO-2026-38-1042',
  };
  gate.updatePolicy({ maxTransactionUsd: '2500.00', dailyCapUsd: '8000.00' });
  assert.equal(
    gate.evaluate(allowedExc01, { timestamp: ts, ignoreProcessedProposalId: true }).reasonCode,
    'OVER_TRANSACTION_CAP'
  );
  gate.updatePolicy({ maxTransactionUsd: '5000.00', dailyCapUsd: '5000.00' });
  assert.equal(
    gate.evaluate(allowedExc01, { timestamp: ts, ignoreProcessedProposalId: true }).reasonCode,
    'OVER_DAILY_SPEND_CAP'
  );

  // Duplicate invoice INV-2026-1041 is caught as DUPLICATE_INVOICE while the PO still has room
  assert.equal(
    gate.evaluate(
      {
        proposalId: 'prop-ap-005-duplicate-invoice',
        invoiceId: 'INV-2026-1041',
        payeeEmail: 'pay@colombia-direct-beans.example',
        amountValue: '1420.00',
        currencyCode: 'USD',
        reason: 'Duplicate replay',
      },
      { timestamp: ts, ignoreProcessedProposalId: true }
    ).reasonCode,
    'DUPLICATE_INVOICE'
  );
});

test('16. ReceiptLedger.fromJSON rehydrates verified chain and appends POLICY_UPDATED / EXCEPTION_REVIEWED / EXCEPTION_DISMISSED stages', async () => {
  const demo = await runSampleFixtureDemo();
  const rehydrated = ReceiptLedger.fromJSON(demo.ledger);
  assert.equal(rehydrated.getEntries().length, 15);

  rehydrated.append({
    stage: 'POLICY_UPDATED',
    proposalId: null,
    payload: { maxTransactionUsd: '3000.00' },
  });
  rehydrated.append({
    stage: 'EXCEPTION_REVIEWED',
    proposalId: 'prop-ap-004-unapproved-payee',
    payload: { exceptionId: 'EXC-02', decision: 'CLEARED_BY_POLICY', paypalApiCallsExecuted: 0 },
  });
  rehydrated.append({
    stage: 'EXCEPTION_DISMISSED',
    proposalId: 'prop-ap-003-overcap',
    payload: { exceptionId: 'EXC-01', dismissReason: 'Rejected adversarial over-cap invoice' },
  });

  const check = verifyReceiptChain(rehydrated);
  assert.equal(check.valid, true);
  assert.equal(check.count, 18);
  assert.equal(check.stageCounts.POLICY_UPDATED, 1);
  assert.equal(check.stageCounts.EXCEPTION_REVIEWED, 1);
  assert.equal(check.stageCounts.EXCEPTION_DISMISSED, 1);
});

test('17. Canonical duplicate-invoice normalization blocks all 18 adversarial invoice-ID variants while admitting distinct IDs', () => {
  const ts = '2026-11-11T12:00:00.000Z';
  const gate = testPolicyGate();
  const setupProposal = {
    proposalId: 'setup-atk08',
    invoiceId: 'INV-2026-2041',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '1420.00',
    currencyCode: 'USD',
    reason: 'Original Colombia Direct Beans invoice',
  };
  const setupVerdict = gate.evaluate(setupProposal, { timestamp: ts });
  assert.equal(setupVerdict.admitted, true);
  gate.commitAdmission(setupProposal, setupVerdict);

  const adversarialVariants = [
    'INV-2026-2041',
    'inv-2026-2041',
    ' INV-2026-2041',
    'INV-2026-2041 ',
    'INV-2026-2041\t',
    'INV - 2026-2041',
    'INV20262041',
    'INV_2026_2041',
    'INV\u20132026\u20132041',
    'INV\u20112026\u20112041',
    'INV\u22122026\u22122041',
    '\uFF29\uFF2E\uFF36-\uFF12\uFF10\uFF12\uFF16-\uFF12\uFF10\uFF14\uFF11',
    '\u0406NV-2026-2041',
    'INV\u200B-2026-2041',
    'INV\u00AD-2026-2041',
    'INV-2026-02041',
    '#INV-2026-2041',
    'INV.2026.2041',
  ];

  assert.equal(adversarialVariants.length, 18);
  adversarialVariants.forEach((variantId, idx) => {
    const verdict = gate.evaluate(
      {
        proposalId: `adv-dup-${idx + 1}`,
        invoiceId: variantId,
        payeeEmail: 'pay@colombia-direct-beans.example',
        payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
        amountValue: '1420.00',
        currencyCode: 'USD',
        reason: 'Duplicate invoice replay variant',
      },
      { timestamp: ts }
    );
    assert.equal(verdict.admitted, false, `Variant #${idx + 1} (${JSON.stringify(variantId)}) must be refused`);
    assert.equal(verdict.reasonCode, 'DUPLICATE_INVOICE', `Variant #${idx + 1} must refuse with DUPLICATE_INVOICE`);
  });

  // Distinct invoice IDs must still be admitted cleanly
  for (const [idx, distinctId] of ['INV-2026-2042', 'PO-2026-2041', 'INV-2027-2041'].entries()) {
    const verdict = gate.evaluate(
      {
        proposalId: `distinct-ok-${idx + 1}`,
        invoiceId: distinctId,
        payeeEmail: 'billing@cascade-packaging.example',
        payeeMerchantId: 'MCH-CASCADE-PKG-02',
        amountValue: '300.00',
        currencyCode: 'USD',
        reason: 'Distinct supplier invoice',
      },
      { timestamp: ts }
    );
    assert.equal(verdict.admitted, true, `Distinct ID ${distinctId} must be admitted`);
  }

  // Unsupported non-ASCII script fails closed with INVALID_INVOICE_ID
  assert.equal(deriveInvoiceDedupKeys('INV-2026-\u4E8C\u3007\u56DB\u4E00').valid, false);
});

test('18. Full 25-record attack-suite-pov4.json corpus refuses 20/20 obedient attacks with expected codes and admits 5/5 controls', () => {
  const suite = JSON.parse(fs.readFileSync(path.join(HERE, 'attack-suite-pov4.json'), 'utf8'));
  assert.equal(suite.records.length, 25);
  const ts = suite.fixedEvaluationTimestamp;

  let refusedAttacks = 0;
  let admittedControls = 0;
  for (const rec of suite.records) {
    const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
    replayPaidHistory(gate, rec.setup, ts);
    if (rec.kind === 'attack') {
      const v = gate.evaluate(rec.obedientProposal, { timestamp: ts });
      assert.equal(v.decision, 'DENY', `${rec.suiteId} obedient proposal must be denied`);
      assert.equal(v.reasonCode, rec.expectedReasonCode, `${rec.suiteId} reasonCode mismatch`);
      refusedAttacks += 1;
    } else {
      const v = gate.evaluate(rec.honestProposal || rec.proposal, { timestamp: ts });
      assert.equal(v.decision, 'ALLOW', `${rec.suiteId} control must be admitted`);
      admittedControls += 1;
    }
  }
  assert.equal(refusedAttacks, 20);
  assert.equal(admittedControls, 5);
});

test('19. AIProcurementAgent enclave isolation: proposer holds zero PayPal or Ed25519 signing secrets', async () => {
  const agentSrc = fs.readFileSync(path.join(HERE, 'ai-procurement-agent.mjs'), 'utf8');
  assert.doesNotMatch(agentSrc, /PAYPAL_CLIENT_ID|PAYPAL_CLIENT_SECRET|GATE_ED25519_PRIVATE_KEY_PEM/);
  assert.doesNotMatch(agentSrc, /from\s+['"]\.\/paypal-client\.mjs['"]/);
  assert.doesNotMatch(agentSrc, /from\s+['"]\.\/receipt-ledger\.mjs['"]/);

  const accessedEnvKeys = new Set();
  const envProxy = new Proxy(
    {},
    {
      get(_target, prop) {
        if (typeof prop === 'string') accessedEnvKeys.add(prop);
        return undefined;
      },
    }
  );
  const origEnv = process.env;
  process.env = envProxy;
  try {
    const agent = new AIProcurementAgent();
    const drafted = await agent.draftPaymentProposal({
      proposalId: 'prop-enclave-01',
      invoiceId: 'INV-ENCLAVE-01',
      supplierName: 'Colombia Direct Beans Co.',
      payeeEmail: 'pay@colombia-direct-beans.example',
      payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
      amountValue: '250.00',
      currencyCode: 'USD',
      reason: 'Enclave boundary check',
    });
    assert.equal(drafted.invoiceId, 'INV-ENCLAVE-01');
  } finally {
    process.env = origEnv;
  }
  assert.equal(accessedEnvKeys.has('PAYPAL_CLIENT_ID'), false);
  assert.equal(accessedEnvKeys.has('PAYPAL_CLIENT_SECRET'), false);
  assert.equal(accessedEnvKeys.has('GATE_ED25519_PRIVATE_KEY_PEM'), false);
});

test('20. ReceiptLedger RFC 8032 Ed25519 enclave signatures detect full re-hashed chain forgery without private key', () => {
  const ledger = new ReceiptLedger({
    ledgerId: 'ed25519-forgery-test',
    genesisTimestamp: '2026-11-11T00:00:00.000Z',
  });
  ledger.append({
    stage: 'PROPOSED',
    proposalId: 'prop-ed-01',
    payload: { invoiceId: 'INV-ED-01', amountValue: '500.00' },
  });
  ledger.append({
    stage: 'EXECUTED',
    proposalId: 'prop-ed-01',
    paypalOrderId: 'ORD-ED-01',
    paypalCaptureId: 'CAP-ED-01',
    payload: { invoiceId: 'INV-ED-01', amountValue: '500.00', captureStatus: 'COMPLETED' },
  });

  const cleanJson = ledger.toJSON();
  const cleanCheck = verifyReceiptChain(cleanJson);
  assert.equal(cleanCheck.valid, true);
  assert.equal(cleanCheck.verifiedEd25519Signatures, 3);

  // Attacker modifies amountValue on entry #2 AND recomputes SHA-256 receiptHash + headHash
  const forged = structuredClone(cleanJson);
  forged.entries[2].payload.amountValue = '9500.00';
  forged.entries[2].receiptHash = computeReceiptHash(forged.entries[2]);
  forged.headHash = forged.entries[2].receiptHash;

  const forgedCheck = verifyReceiptChain(forged);
  assert.equal(forgedCheck.valid, false);
  assert.match(forgedCheck.errors[0].reason, /ED25519_SIGNATURE_INVALID/);
});
