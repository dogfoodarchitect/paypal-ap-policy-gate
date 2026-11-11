import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runSampleFixtureDemo } from './demo-cli.mjs';
import {
  exploreReceipts,
  AgentObservabilityLogger,
  getSandboxComplianceDisclosure,
} from './receipt-explorer-and-observability.mjs';

describe('PayPal AP Policy Gate — Receipt Explorer & Structured Observability', () => {
  it('filters the 5-invoice sample fixture receipt chain by stage, payeeEmail, reasonCode, and invoiceId with cryptographic verification', async () => {
    const demoResult = await runSampleFixtureDemo({ mode: 'simulation' });
    const ledger = demoResult.ledger;

    const refusedQuery = exploreReceipts(ledger, { stage: 'REFUSED' });
    assert.equal(refusedQuery.chainValid, true);
    assert.equal(refusedQuery.matchedCount, 3);
    assert.equal(refusedQuery.allMatchedCryptographicallyValid, true);
    assert.equal(refusedQuery.refusedUsdTotal, 6720.0);

    const payeeQuery = exploreReceipts(ledger, {
      payeeEmail: 'pay@colombia-direct-beans.example',
      stage: ['ADMITTED', 'EXECUTED'],
    });
    assert.equal(payeeQuery.matchedCount, 2);
    assert.equal(payeeQuery.executedUsdTotal, 1420.0);
    assert.equal(payeeQuery.allMatchedCryptographicallyValid, true);

    const capBreachQuery = exploreReceipts(ledger, {
      reasonCode: 'UNAPPROVED_PAYEE',
      invoiceId: 'INV-2026-1042',
    });
    assert.equal(capBreachQuery.matchedCount, 1);
    assert.equal(capBreachQuery.entries[0].proposalId, 'prop-ap-003-overcap');

    const allowlistRefusalQuery = exploreReceipts(ledger, {
      reasonCode: 'UNAPPROVED_PAYEE',
      invoiceId: 'INV-2026-1044',
    });
    assert.equal(allowlistRefusalQuery.matchedCount, 1);
    assert.equal(allowlistRefusalQuery.entries[0].proposalId, 'prop-ap-004-unapproved-payee');
  });

  it('detects tampered entries during receipt exploration and marks cryptographic validity false', async () => {
    const demoResult = await runSampleFixtureDemo({ mode: 'simulation' });
    const clonedEntries = structuredClone(demoResult.ledger.entries);
    clonedEntries[3].payload.amountValue = '10.00';

    const tamperedQuery = exploreReceipts(clonedEntries, { stage: 'REFUSED' });
    assert.equal(tamperedQuery.chainValid, false);
    assert.equal(tamperedQuery.allMatchedCryptographicallyValid, false);

    assert.throws(
      () => exploreReceipts(demoResult.ledger, { fromTimestamp: 'not-a-valid-iso-date' }),
      (err) => err.code === 'INVALID_TIMESTAMP_FILTER' && err.failClosed === true
    );
    assert.throws(
      () =>
        exploreReceipts(demoResult.ledger, {
          fromTimestamp: '2026-11-10T00:00:00Z',
          toTimestamp: '2026-11-08T00:00:00Z',
        }),
      (err) => err.code === 'INVALID_TIMESTAMP_FILTER' && err.failClosed === true
    );
  });

  it('emits structured JSON observability events linked by correlationId and exports valid JSONL', () => {
    const sinkLines = [];
    const logger = new AgentObservabilityLogger({
      sink: (line) => sinkLines.push(line),
    });

    const ev1 = logger.logEvent({
      timestamp: '2026-11-09T18:01:00.000Z',
      eventType: 'PROPOSAL_EVALUATED',
      correlationId: 'corr_ap_001',
      proposalId: 'prop_ap_001',
      idempotencyKey: 'idem_001',
      stage: 'ADMITTED',
      receiptId: 'rcpt_ledger-ap_0002',
      receiptHash: 'a'.repeat(64),
      reasonCode: 'ADMITTED_ALL_CHECKS_PASSED',
      paypalApiCallsDelta: 0,
    });

    const ev2 = logger.logEvent({
      timestamp: '2026-11-09T18:01:01.000Z',
      eventType: 'PAYPAL_ORDER_CAPTURED',
      correlationId: 'corr_ap_001',
      proposalId: 'prop_ap_001',
      idempotencyKey: 'idem_001',
      stage: 'EXECUTED',
      receiptId: 'rcpt_ledger-ap_0003',
      receiptHash: 'b'.repeat(64),
      paypalOrderId: 'ORDER-SANDBOX-1',
      paypalCaptureId: 'CAPTURE-SANDBOX-1',
      paypalApiCallsDelta: 2,
    });

    assert.equal(ev1.schemaVersion, 'paypal-agent-observability/v1');
    assert.equal(ev2.paypalApiCallsDelta, 2);
    assert.equal(logger.getEventsByCorrelationId('corr_ap_001').length, 2);
    assert.equal(sinkLines.length, 2);

    const parsedJsonl = logger
      .toJSONL()
      .split('\n')
      .map((line) => JSON.parse(line));
    assert.equal(parsedJsonl.length, 2);
    assert.equal(parsedJsonl[1].paypalOrderId, 'ORDER-SANDBOX-1');
  });

  it('provides explicit Sandbox-only compliance disclosure and Production Payouts v1 readiness notes', () => {
    const disclosure = getSandboxComplianceDisclosure();
    assert.equal(disclosure.executionEnvironment, 'PAYPAL_SANDBOX_ONLY');
    assert.equal(disclosure.realMoneyMovement, false);
    assert.ok(disclosure.productionPayoutsV1ReadinessNote.includes('KYC/AML'));
  });
});
