#!/usr/bin/env node
/**
 * demo-cli.mjs — Deterministic 5-Invoice B2B Supplier Sample Fixture CLI
 *
 * Runs the synthetic 5-invoice B2B supplier sample test fixture (0 live customers)
 * through an untrusted AI proposer, external deterministic PolicyGate, PayPal
 * Sandbox client, and SHA-256 hash-chained ReceiptLedger.
 *
 * Usage:
 *   node demo-cli.mjs
 *   node demo-cli.mjs --json
 */
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { ReceiptLedger, verifyReceiptChain } from './receipt-ledger.mjs';
import { PolicyGate, DEFAULT_AP_POLICY_GATE_CONFIG, processAgentPaymentProposal } from './policy-gate.mjs';
import { PayPalSandboxClient } from './paypal-client.mjs';
import { AIProcurementAgent, buildSampleSupplierInvoices } from './ai-procurement-agent.mjs';

export async function runSampleFixtureDemo({ mode = 'simulation' } = {}) {
  const ledger = new ReceiptLedger({
    ledgerId: 'ledger-paypal-ap-sample-fixture-2026-11',
    genesisTimestamp: '2026-11-11T00:00:00.000Z',
    protagonist: 'Synthetic 5-Invoice B2B Supplier Test Fixture (Pre-launch Prototype · 0 Live Customers)',
    metadata: {
      hackathon: 'PayPal AI Hackathon 2026',
      fixtureType: 'synthetic-5-invoice-b2b-ap-fixture',
      surfaces: ['Orders v2', 'Webhooks v1', 'Invoicing v2', 'Payouts v1'],
    },
  });

  const policyGate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const paypalClient = new PayPalSandboxClient({
    mode,
    seed: 'paypal-ap-policy-gate-seed-2026',
  });
  const aiAgent = new AIProcurementAgent({
    defaultRoute: 'offline:deterministic-fallback',
  });

  const invoices = buildSampleSupplierInvoices();
  const scenarioResults = [];

  // Step 1: Admitted Supplier Payment — Colombia Direct Beans Co. ($1,420.00, INV-2026-1041)
  const flow1Proposal = await aiAgent.draftPaymentProposal(invoices[0], {
    route: 'offline:deterministic-fallback',
  });
  const flow1Result = await processAgentPaymentProposal({
    proposal: flow1Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-11T00:01:00.000Z',
    captureImmediately: true,
    createInvoiceRecord: true,
  });

  const webhookEvent1 = {
    id: 'WH-EVT-SBX-1041',
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
      id: flow1Result.capture.id,
      custom_id: flow1Proposal.proposalId,
      invoice_id: flow1Proposal.invoiceId,
      status: 'COMPLETED',
      amount: { currency_code: 'USD', value: '1420.00' },
      supplementary_data: {
        related_ids: { order_id: flow1Result.order.id },
      },
    },
  };
  const signedWh1 = paypalClient.signWebhookEvent({
    transmissionId: 'tx-ap-1041',
    transmissionTime: '2026-11-11T00:01:05Z',
    event: webhookEvent1,
  });
  const flow1Webhook = paypalClient.handleWebhookEvent({
    headers: signedWh1.headers,
    event: webhookEvent1,
    webhookId: signedWh1.webhookId,
    ledger,
    timestamp: '2026-11-11T00:01:05.000Z',
  });

  scenarioResults.push({
    step: 1,
    title: 'Admitted Supplier Payment — Colombia Direct Beans Co. ($1,420.00 · INV-2026-1041)',
    aiRoute: flow1Proposal.aiModelRoute.routeKey,
    outcome: flow1Result.status,
    reasonCode: flow1Result.verdict.reasonCode,
    invoiceId: flow1Proposal.invoiceId,
    paypalOrderId: flow1Result.order.id,
    paypalCaptureId: flow1Result.capture.id,
    paypalInvoiceId: flow1Result.invoiceRecord.id,
    webhookReceiptHash: flow1Webhook.receipt.receiptHash,
    apiCallsDelta: flow1Result.apiCallsDelta + 1,
  });

  // Step 2: Admitted Packaging Supplier Payment — Cascade Packaging Co. ($680.00, INV-2026-1043)
  const flow2Proposal = await aiAgent.draftPaymentProposal(invoices[1], {
    route: 'offline:deterministic-fallback',
  });
  const flow2Result = await processAgentPaymentProposal({
    proposal: flow2Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-11T00:02:00.000Z',
    captureImmediately: true,
    createPayoutRecord: true,
  });

  const webhookEvent2 = {
    id: 'WH-EVT-SBX-1043',
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
      id: flow2Result.capture.id,
      custom_id: flow2Proposal.proposalId,
      invoice_id: flow2Proposal.invoiceId,
      status: 'COMPLETED',
      amount: { currency_code: 'USD', value: '680.00' },
      supplementary_data: {
        related_ids: { order_id: flow2Result.order.id },
      },
    },
  };
  const signedWh2 = paypalClient.signWebhookEvent({
    transmissionId: 'tx-ap-1043',
    transmissionTime: '2026-11-11T00:02:05Z',
    event: webhookEvent2,
  });
  const flow2Webhook = paypalClient.handleWebhookEvent({
    headers: signedWh2.headers,
    event: webhookEvent2,
    webhookId: signedWh2.webhookId,
    ledger,
    timestamp: '2026-11-11T00:02:05.000Z',
  });

  scenarioResults.push({
    step: 2,
    title: 'Admitted Packaging Payment — Cascade Packaging Co. ($680.00 · INV-2026-1043)',
    aiRoute: flow2Proposal.aiModelRoute.routeKey,
    outcome: flow2Result.status,
    reasonCode: flow2Result.verdict.reasonCode,
    invoiceId: flow2Proposal.invoiceId,
    paypalOrderId: flow2Result.order.id,
    paypalCaptureId: flow2Result.capture.id,
    paypalPayoutBatchId: flow2Result.payoutRecord.batch_header.payout_batch_id,
    webhookReceiptHash: flow2Webhook.receipt.receiptHash,
    apiCallsDelta: flow2Result.apiCallsDelta + 1,
  });

  // Step 3 (EXC-01): Refused Over-Cap Injected Invoice — Pacific Roast Equipment Co. ($4,850.00, INV-2026-1042)
  const flow3Proposal = await aiAgent.draftPaymentProposal(invoices[2], {
    route: 'offline:deterministic-fallback',
  });
  const flow3Result = await processAgentPaymentProposal({
    proposal: flow3Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-11T00:03:00.000Z',
  });

  scenarioResults.push({
    step: 3,
    exceptionId: 'EXC-01',
    title: 'Refused Over-Cap Injected Invoice — Pacific Roast Equipment Co. ($4,850.00 vs $2,500.00 cap · INV-2026-1042)',
    aiRoute: flow3Proposal.aiModelRoute.routeKey,
    outcome: flow3Result.status,
    reasonCode: flow3Result.verdict.reasonCode,
    invoiceId: flow3Proposal.invoiceId,
    paypalOrderId: flow3Result.order,
    paypalCaptureId: flow3Result.capture,
    refusalReceiptHash: flow3Result.outcomeReceipt.receiptHash,
    apiCallsDelta: flow3Result.apiCallsDelta,
  });

  // Step 4 (EXC-02): Refused Unapproved Payee — Offshore Holdings Ltd. ($450.00, INV-2026-1044)
  const flow4Proposal = await aiAgent.draftPaymentProposal(invoices[3], {
    route: 'offline:deterministic-fallback',
  });
  const flow4Result = await processAgentPaymentProposal({
    proposal: flow4Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-11T00:04:00.000Z',
  });

  scenarioResults.push({
    step: 4,
    exceptionId: 'EXC-02',
    title: 'Refused Unapproved Payee — Offshore Holdings Ltd. ($450.00 · INV-2026-1044)',
    aiRoute: flow4Proposal.aiModelRoute.routeKey,
    outcome: flow4Result.status,
    reasonCode: flow4Result.verdict.reasonCode,
    invoiceId: flow4Proposal.invoiceId,
    paypalOrderId: flow4Result.order,
    paypalCaptureId: flow4Result.capture,
    refusalReceiptHash: flow4Result.outcomeReceipt.receiptHash,
    apiCallsDelta: flow4Result.apiCallsDelta,
  });

  // Step 5 (EXC-03): Refused Duplicate Invoice Replay — Colombia Direct Beans Co. ($1,420.00, INV-2026-1041)
  const flow5Proposal = await aiAgent.draftPaymentProposal(invoices[4], {
    route: 'offline:deterministic-fallback',
  });
  const flow5Result = await processAgentPaymentProposal({
    proposal: flow5Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: '2026-11-11T00:05:00.000Z',
  });

  scenarioResults.push({
    step: 5,
    exceptionId: 'EXC-03',
    title: 'Refused Duplicate Invoice Replay — Colombia Direct Beans Co. ($1,420.00 · INV-2026-1041)',
    aiRoute: flow5Proposal.aiModelRoute.routeKey,
    outcome: flow5Result.status,
    reasonCode: flow5Result.verdict.reasonCode,
    invoiceId: flow5Proposal.invoiceId,
    paypalOrderId: flow5Result.order,
    paypalCaptureId: flow5Result.capture,
    refusalReceiptHash: flow5Result.outcomeReceipt.receiptHash,
    apiCallsDelta: flow5Result.apiCallsDelta,
  });

  const verification = verifyReceiptChain(ledger);

  return {
    protagonist: ledger.protagonist,
    policyId: policyGate.policyId,
    paypalMode: paypalClient.mode,
    supportedAiRoutesCount: aiAgent.listSupportedRoutes().length,
    totalApiCalls: paypalClient.getApiCallCount(),
    dailySpendCommittedUSD: (policyGate.getDailySpendCents('2026-11-11T00:05:00.000Z') / 100).toFixed(2),
    scenarioResults,
    chainVerification: verification,
    ledger: ledger.toJSON(),
  };
}

// Backwards-compatible alias
export const runApexCoffeeDemo = runSampleFixtureDemo;

const isMain =
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url));
if (isMain) {
  const jsonMode = process.argv.includes('--json');
  runSampleFixtureDemo().then((report) => {
    if (jsonMode) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    console.log('========================================================================');
    console.log(' PAYPAL AP POLICY GATE — SYNTHETIC 5-INVOICE B2B SAMPLE FIXTURE');
    console.log(` Fixture:  ${report.protagonist}`);
    console.log(` Policy:   ${report.policyId} (Mode: ${report.paypalMode})`);
    console.log('========================================================================\n');
    for (const step of report.scenarioResults) {
      console.log(`[Step ${step.step}] ${step.title}`);
      console.log(`  -> AI Route:     ${step.aiRoute}`);
      console.log(`  -> Outcome:      ${step.outcome} (${step.reasonCode})`);
      console.log(`  -> PayPal Calls: ${step.apiCallsDelta}`);
      if (step.paypalOrderId) {
        console.log(`  -> Order / Cap:  ${step.paypalOrderId} / ${step.paypalCaptureId}`);
      } else {
        console.log(`  -> Refusal Hash: ${step.refusalReceiptHash}`);
      }
      console.log('');
    }
    console.log('------------------------------------------------------------------------');
    console.log(`Receipt Chain Integrity: valid=${report.chainVerification.valid} (entries=${report.chainVerification.count})`);
    console.log(`Genesis Hash:            ${report.chainVerification.genesisHash}`);
    console.log(`Head Receipt Hash:       ${report.chainVerification.headHash}`);
    console.log(`Committed Spend Today:   $${report.dailySpendCommittedUSD} USD`);
    console.log('========================================================================');
  }).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
