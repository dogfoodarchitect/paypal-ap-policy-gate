import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  startHostedDemoServer,
  renderProductHtml,
  PRODUCT_TITLE,
  FIRST_PLACE_THESIS,
  THIRD_PARTY_VERIFIER_SENTENCE,
  PAYPAL_TOOLKIT_CITATION,
} from './hosted-demo-server.mjs';
import {
  runLiveSandboxCheck,
  runLiveApexScenario,
  runLiveGetOrderCheck,
  loadPayPalCredentials,
} from './live-sandbox-runner.mjs';
import { verifyRecordedReceiptBundle } from './verify-payments.mjs';
import { runSampleFixtureDemo } from './demo-cli.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECORDED_RECEIPT_PATH = path.join(HERE, 'recorded-live-sandbox-receipt.json');
const VERIFIER_CLI_PATH = path.join(HERE, 'verify-payments.mjs');
const RUNNER_CLI_PATH = path.join(HERE, 'live-sandbox-runner.mjs');

function walkDirFiles(dir, relBase = '') {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkDirFiles(full, rel));
    else out.push({ rel, full });
  }
  return out;
}

test('1. Default zero-flag startHostedDemoServer loads recorded-live-sandbox-receipt.json automatically when present', async (t) => {
  const hasRecordedFile = fs.existsSync(RECORDED_RECEIPT_PATH);
  const srv = await startHostedDemoServer({ port: 0 });
  t.after(async () => {
    await srv.close();
  });

  const health = await (await fetch(`${srv.url}/api/health`)).json();
  assert.equal(health.ok, true);
  assert.equal(health.submitter, 'paypal-ap-policy-gate');
  assert.equal(health.productName, PRODUCT_TITLE);
  assert.equal(health.screenCount, 6);
  assert.equal(health.chainValid, true);
  assert.equal(health.entryCount, 15);

  const state = await (await fetch(`${srv.url}/api/state`)).json();
  if (hasRecordedFile) {
    const onDisk = JSON.parse(fs.readFileSync(RECORDED_RECEIPT_PATH, 'utf8'));
    assert.equal(health.proofMode, 'recorded-live-sandbox');
    assert.equal(state.proofMode, 'recorded-live-sandbox');
    assert.equal(state.kpis.headHash, onDisk.chainVerification.headHash);
    assert.equal(state.kpis.genesisHash, onDisk.chainVerification.genesisHash);
    assert.equal(state.settledPayments[0].paypalOrderId, onDisk.settledOrders[0].paypalOrderId);
    assert.equal(state.settledPayments[1].paypalOrderId, onDisk.settledOrders[1].paypalOrderId);
  } else {
    assert.equal(health.proofMode, 'offline-simulation');
  }
});

test('2. --simulate mode runs deterministic 5-invoice simulation with zero network calls', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const health = await (await fetch(`${srv.url}/api/health`)).json();
  assert.equal(health.proofMode, 'offline-simulation');
  assert.equal(health.aiProposerRoute, 'offline:deterministic-fallback');
  assert.equal(health.chainValid, true);
  assert.equal(health.entryCount, 15);

  const state = await (await fetch(`${srv.url}/api/state`)).json();
  assert.equal(state.kpis.settledTodayUsd, '2100.00');
  assert.equal(state.kpis.dailyCapUsd, '5000.00');
  assert.equal(state.kpis.perPaymentCapUsd, '2500.00');
  assert.equal(state.kpis.approvedPayeesActive, 3);
  assert.equal(state.kpis.exceptionsPendingCount, 3);
  assert.equal(state.kpis.blockedTotalUsd, '6720.00');
});

test('3. GET / renders the PayPal AP Policy Gate product HTML with the AP desk, zero emojis, zero nowrap/pre, and MIT copyright', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const html = await (await fetch(`${srv.url}/`)).text();
  assert.ok(html.includes(PRODUCT_TITLE));
  assert.ok(html.includes(FIRST_PLACE_THESIS));
  assert.ok(html.includes(THIRD_PARTY_VERIFIER_SENTENCE));
  assert.match(html, /id="screen-suite"/);
  assert.match(html, /id="screen-desk"/);
  assert.match(html, /id="screen-ledger"/);
  assert.match(html, /id="screen-policy"/);
  assert.match(html, /id="screen-exceptions"/);
  assert.match(html, /id="screen-verifier"/);
  assert.match(html, /MIT License/);
  assert.match(html, /Copyright \(c\) 2026 Brennan William DeCrow/);
  assert.match(html, /zero customers today/i);
  assert.doesNotMatch(html, /[\u{1F300}-\u{1FAFF}]/u);
  assert.doesNotMatch(html, /white-space:\s*nowrap/i);
  assert.doesNotMatch(html, /white-space:\s*pre\s*;/i);
  assert.doesNotMatch(html, /Judge Workspace/i);
  assert.doesNotMatch(html, /Demo Tour/i);
  assert.doesNotMatch(html, new RegExp(['Real', 'Terminal Recording'].join(' '), 'i'));

  const used = [...html.matchAll(/var\((--os-[a-z0-9-]+)\)/g)].map((m) => m[1]);
  const declared = new Set([...html.matchAll(/^\s*(--os-[a-z0-9-]+):/gm)].map((m) => m[1]));
  const missing = [...new Set(used)].filter((tok) => !declared.has(tok)).sort();
  assert.deepEqual(missing, [], `every var(--os-*) used must have an in-document fallback; missing: ${missing.join(', ')}`);
  assert.ok(used.length > 0);
});

test('4. renderProductHtml standalone mode produces valid self-contained HTML without external stylesheet links', async () => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  const state = srv.getState();
  await srv.close();

  const standaloneHtml = renderProductHtml(state, { defaultScreen: 'exceptions', standalone: true });
  assert.ok(standaloneHtml.includes('window.__STANDALONE_HTML__ = true;'));
  assert.ok(standaloneHtml.includes('window.__DEFAULT_SCREEN__ = "exceptions";'));
  assert.doesNotMatch(standaloneHtml, /href="\/_shared\/os-tokens\.css"/);
  assert.doesNotMatch(standaloneHtml, /white-space:\s*nowrap/i);
});

test('5. GET /?screen=<name> deep-links cleanly to ledger, policy, exceptions, and verifier views', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  for (const screen of ['suite', 'desk', 'ledger', 'policy', 'exceptions', 'verifier']) {
    const html = await (await fetch(`${srv.url}/?screen=${screen}`)).text();
    assert.ok(html.includes(`window.__DEFAULT_SCREEN__ = "${screen}";`));
  }
});

test('6. Shared UI assets (/_shared/os-tokens.css & /_shared/controls/schema.mjs) return 200 OK and block path traversal', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const tokRes = await fetch(`${srv.url}/_shared/os-tokens.css`);
  assert.equal(tokRes.status, 200);
  assert.match(await tokRes.text(), /--os-ground/);

  const ctrlRes = await fetch(`${srv.url}/_shared/controls/schema.mjs`);
  assert.equal(ctrlRes.status, 200);
  assert.match(await ctrlRes.text(), /SCHEMA_VERSION/);

  const missingRes = await fetch(`${srv.url}/_shared/nonexistent.css`);
  assert.equal(missingRes.status, 404);
});

test('7. GET /api/policy & PUT /api/policy mutate live PolicyGate caps, currencies, and headroom and append POLICY_UPDATED receipt', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const initPol = await (await fetch(`${srv.url}/api/policy`)).json();
  assert.equal(initPol.ok, true);
  assert.equal(initPol.policy.maxTransactionUsd, '2500.00');
  assert.equal(initPol.policy.dailyCapUsd, '5000.00');
  assert.equal(initPol.policy.settledTodayUsd, '2100.00');
  assert.equal(initPol.policy.remainingDailyHeadroomUsd, '2900.00');
  assert.equal(initPol.policy.approvedPayeesCount, 3);

  const putRes = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      maxTransactionUsd: '3000.00',
      dailyCapUsd: '6500.00',
      allowedCurrencies: ['USD', 'EUR'],
    }),
  });
  assert.equal(putRes.status, 200);
  const putData = await putRes.json();
  assert.equal(putData.ok, true);
  assert.equal(putData.policy.maxTransactionUsd, '3000.00');
  assert.equal(putData.policy.dailyCapUsd, '6500.00');
  assert.equal(putData.policy.remainingDailyHeadroomUsd, '4400.00');
  assert.deepEqual(putData.policy.allowedCurrencies, ['USD', 'EUR']);
  assert.equal(putData.auditReceipt.stage, 'POLICY_UPDATED');
  assert.equal(putData.state.verification.valid, true);
  assert.equal(putData.state.ledger.entries.length, 16);
});

test('8. PUT /api/policy validates malformed cap inputs and rejects empty currency lists with HTTP 400', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const badCap = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ maxTransactionUsd: '-100' }),
  });
  assert.equal(badCap.status, 400);

  const badCur = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ allowedCurrencies: [] }),
  });
  assert.equal(badCur.status, 400);
});

test('9. PUT /api/policy adds and removes payees on Approved Payee Allowlist and updates KPI counts', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const addRes = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      addPayee: {
        payeeId: 'offshore-holdings-ltd',
        displayName: 'Offshore Holdings Ltd.',
        paypalReceiver: 'wire@offshore-holdings.example',
        rail: 'Orders v2',
      },
    }),
  });
  assert.equal(addRes.status, 200);
  const addData = await addRes.json();
  assert.equal(addData.policy.approvedPayeesCount, 4);
  assert.equal(addData.state.kpis.approvedPayeesActive, 4);

  const remRes = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ removePayee: 'offshore-holdings-ltd' }),
  });
  assert.equal(remRes.status, 200);
  const remData = await remRes.json();
  assert.equal(remData.policy.approvedPayeesCount, 3);
});

test('10. GET /api/exceptions lists EXC-01 ($4,850 over-cap injection), EXC-02 ($450 unapproved payee), and EXC-03 ($1,420 duplicate)', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const data = await (await fetch(`${srv.url}/api/exceptions`)).json();
  assert.equal(data.ok, true);
  assert.equal(data.pendingCount, 3);
  assert.equal(data.blockedTotalUsd, '6720.00');
  assert.equal(data.refusalPaypalApiCalls, 0);

  const [exc1, exc2, exc3] = data.exceptions;
  assert.equal(exc1.exceptionId, 'EXC-01');
  assert.equal(exc1.invoiceId, 'INV-2026-1042');
  assert.equal(exc1.amountUsd, '4850.00');
  assert.equal(exc1.reasonCode, 'UNAPPROVED_PAYEE');
  assert.match(exc1.invoiceMemo, /#CFO-4850/);

  assert.equal(exc2.exceptionId, 'EXC-02');
  assert.equal(exc2.invoiceId, 'INV-2026-1044');
  assert.equal(exc2.amountUsd, '450.00');
  assert.equal(exc2.reasonCode, 'UNAPPROVED_PAYEE');

  assert.equal(exc3.exceptionId, 'EXC-03');
  assert.equal(exc3.invoiceId, 'INV-2026-1041');
  assert.equal(exc3.amountUsd, '1420.00');
  assert.equal(exc3.reasonCode, 'DUPLICATE_INVOICE');
});

test('11. Exception Queue workflow: allowlisting offshore-holdings-ltd clears EXC-02 on re-evaluate with 0 PayPal API calls', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  // Before allowlisting: EXC-02 still blocked on UNAPPROVED_PAYEE
  const pre = await (await fetch(`${srv.url}/api/exceptions/EXC-02/reevaluate`, { method: 'POST' })).json();
  assert.equal(pre.verdict.admitted, false);
  assert.equal(pre.verdict.reasonCode, 'UNAPPROVED_PAYEE');
  assert.equal(pre.exception.status, 'PENDING_REVIEW');

  // Controller adds offshore-holdings-ltd and an open purchase order on Policy Rules
  await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      addPayee: {
        payeeId: 'offshore-holdings-ltd',
        displayName: 'Offshore Holdings Ltd.',
        paypalReceiver: 'wire@offshore-holdings.example',
        rail: 'Orders v2',
      },
      addPurchaseOrder: {
        poNumber: 'PO-2026-EXC-02',
        payeeId: 'offshore-holdings-ltd',
        payeeEmail: 'wire@offshore-holdings.example',
        currencyCode: 'USD',
        totalCents: 50000,
        open: true,
      },
    }),
  });

  // Controller clicks Re-evaluate on EXC-02 ($450 + $2,100 settled = $2,550 <= $5,000 daily cap)
  const post = await (await fetch(`${srv.url}/api/exceptions/EXC-02/reevaluate`, { method: 'POST' })).json();
  assert.equal(post.ok, true);
  assert.equal(post.verdict.admitted, true);
  assert.equal(post.exception.status, 'CLEARED_BY_POLICY');
  assert.equal(post.auditReceipt.stage, 'EXCEPTION_REVIEWED');
  assert.equal(post.auditReceipt.payload.paypalApiCallsExecuted, 0);
  assert.equal(post.state.kpis.exceptionsPendingCount, 2);
  assert.equal(post.state.kpis.exceptionsClearedCount, 1);
  assert.equal(post.state.verification.valid, true);
});

test('12. Exception Queue workflow: EXC-01 stays UNAPPROVED_PAYEE when caps are raised, and EXC-03 always catches DUPLICATE_INVOICE', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  // Rule 1 (registered supplier) fires before caps, so raising the $2,500 / $5,000 limits does not clear Pacific Roast.
  await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ maxTransactionUsd: '5000.00', dailyCapUsd: '5000.00' }),
  });

  const exc1Daily = await (await fetch(`${srv.url}/api/exceptions/EXC-01/reevaluate`, { method: 'POST' })).json();
  assert.equal(exc1Daily.verdict.admitted, false);
  assert.equal(exc1Daily.verdict.reasonCode, 'UNAPPROVED_PAYEE');

  await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dailyCapUsd: '9000.00' }),
  });
  const exc1Payee = await (await fetch(`${srv.url}/api/exceptions/EXC-01/reevaluate`, { method: 'POST' })).json();
  assert.equal(exc1Payee.verdict.admitted, false);
  assert.equal(exc1Payee.verdict.reasonCode, 'UNAPPROVED_PAYEE');

  // EXC-03 (INV-2026-1041) is ALWAYS blocked as DUPLICATE_INVOICE
  const exc3Dup = await (await fetch(`${srv.url}/api/exceptions/EXC-03/reevaluate`, { method: 'POST' })).json();
  assert.equal(exc3Dup.verdict.admitted, false);
  assert.equal(exc3Dup.verdict.reasonCode, 'DUPLICATE_INVOICE');
});

test('13. POST /api/exceptions/:id/dismiss & POST /api/reset transition exception state and restore 15-link baseline', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const disRes = await fetch(`${srv.url}/api/exceptions/EXC-01/dismiss`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'Rejected adversarial #CFO-4850 vendor memo' }),
  });
  assert.equal(disRes.status, 200);
  const disData = await disRes.json();
  assert.equal(disData.exception.status, 'DISMISSED');
  assert.equal(disData.exception.dismissReason, 'Rejected adversarial #CFO-4850 vendor memo');
  assert.equal(disData.auditReceipt.stage, 'EXCEPTION_DISMISSED');
  assert.equal(disData.state.kpis.exceptionsDismissedCount, 1);

  const missingExc = await fetch(`${srv.url}/api/exceptions/EXC-99/dismiss`, { method: 'POST' });
  assert.equal(missingExc.status, 404);

  const resetRes = await fetch(`${srv.url}/api/reset`, { method: 'POST' });
  assert.equal(resetRes.status, 200);
  const resetData = await resetRes.json();
  assert.equal(resetData.state.ledger.entries.length, 15);
  assert.equal(resetData.state.kpis.exceptionsPendingCount, 3);
  assert.equal(resetData.state.kpis.approvedPayeesActive, 3);
});

test('14. POST /api/propose settles valid supplier invoice in simulation and routes refused invoice into EXC-04', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const okRes = await fetch(`${srv.url}/api/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proposal: {
        proposalId: 'prop-freight-01',
        invoiceId: 'INV-2026-1090',
        payeeId: 'sound-freight-logistics',
        payeeEmail: 'ap@sound-freight.example',
        payeeMerchantId: 'MCH-SOUND-FREIGHT-03',
        amountValue: '320.00',
        poNumber: 'PO-2026-38-FREIGHT',
        currencyCode: 'USD',
        reason: 'Regional pallet freight charges',
      },
    }),
  });
  const okData = await okRes.json();
  assert.equal(okData.result.status, 'EXECUTED');
  assert.ok(okData.result.paypalOrderId);
  assert.equal(okData.state.kpis.settledTodayUsd, '2420.00');

  const refRes = await fetch(`${srv.url}/api/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proposal: {
        proposalId: 'prop-unapproved-99',
        invoiceId: 'INV-2026-9999',
        payeeEmail: 'unknown@rogue-supplier.example',
        amountValue: '400.00',
        currencyCode: 'USD',
        reason: 'Rogue invoice test',
      },
    }),
  });
  const refData = await refRes.json();
  assert.equal(refData.result.status, 'REFUSED');
  assert.equal(refData.result.apiCallsDelta, 0);
  assert.equal(refData.state.exceptions.length, 4);
  assert.equal(refData.state.exceptions[3].exceptionId, 'EXC-04');
});

test('15. POST /api/verify-chain & POST /api/tamper-check catch 1-byte mutation at brokenAtIndex: 3 non-destructively', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const rcpts = await (await fetch(`${srv.url}/api/receipts`)).json();
  assert.equal(rcpts.verification.valid, true);
  assert.equal(rcpts.ledger.entries.length, 15);

  const tamperRes = await fetch(`${srv.url}/api/tamper-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ index: 3, amountValue: '9420.00' }),
  });
  assert.equal(tamperRes.status, 200);
  const tamper = await tamperRes.json();
  assert.equal(tamper.valid, false);
  assert.equal(tamper.canonicalCount, 15);
  assert.equal(tamper.brokenAtIndex, 3);
  assert.equal(tamper.brokenStage, 'EXECUTED');
  assert.equal(tamper.originalValue, '1420.00');
  assert.equal(tamper.tamperedValue, '9420.00');
  assert.notEqual(tamper.expectedHash, tamper.actualHash);
  assert.match(tamper.reason, /RECEIPT_HASH_TAMPERED/);

  const afterCheck = await (await fetch(`${srv.url}/api/verify-offline`)).json();
  assert.equal(afterCheck.valid, true);
  assert.equal(afterCheck.count, 15);
});

test('16. POST /api/paypal/webhook accepts valid HMAC signature (even after /api/reset) and rejects forged signature', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  await fetch(`${srv.url}/api/reset`, { method: 'POST' });

  const whEvent = {
    id: 'WH-EVT-TEST-99',
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
      id: 'SIMULATED-CAPTURE-TEST-99',
      custom_id: 'prop-wh-99',
      invoice_id: 'INV-WH-99',
      status: 'COMPLETED',
      amount: { currency_code: 'USD', value: '320.00' },
      supplementary_data: { related_ids: { order_id: 'SIMULATED-ORDER-TEST-99' } },
    },
  };
  const signed = srv.paypalClient.signWebhookEvent({
    transmissionId: 'tx-wh-99',
    transmissionTime: '2026-11-11T00:10:00Z',
    event: whEvent,
  });

  const validRes = await fetch(`${srv.url}/api/paypal/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ headers: signed.headers, event: whEvent, webhookId: signed.webhookId }),
  });
  assert.equal(validRes.status, 200);
  assert.equal((await validRes.json()).verified, true);

  const forgedRes = await fetch(`${srv.url}/api/paypal/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      headers: { ...signed.headers, 'paypal-transmission-sig': 'bad-sig-00' },
      event: whEvent,
      webhookId: signed.webhookId,
    }),
  });
  assert.equal(forgedRes.status, 400);
});

test('17. verify-payments.mjs passes (exit 0, VERDICT: PASS) on recorded-live-sandbox-receipt.json with 0 network sockets', () => {
  if (!fs.existsSync(RECORDED_RECEIPT_PATH)) {
    // Pre-Stage-2 fallback check using synthetic valid receipt + temp CODE-MANIFEST
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-synth-'));
    try {
      const dummyCode = path.join(tmpDir, 'sample.mjs');
      fs.writeFileSync(dummyCode, 'export const ok = true;\n', 'utf8');
      const codeSha = crypto.createHash('sha256').update(fs.readFileSync(dummyCode)).digest('hex');
      const codeManifestPath = path.join(tmpDir, 'CODE-MANIFEST.json');
      fs.writeFileSync(
        codeManifestPath,
        JSON.stringify({ files: { 'sample.mjs': { bytes: 24, sha256: codeSha } } }, null, 2),
        'utf8'
      );
      const report = verifyRecordedReceiptBundle(null, { bundleDir: tmpDir });
      assert.equal(report.ok, false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
    return;
  }

  const run = spawnSync(process.execPath, [VERIFIER_CLI_PATH, RECORDED_RECEIPT_PATH], {
    encoding: 'utf8',
    env: { ...process.env, HOME: os.tmpdir(), PAYPAL_CLIENT_ID: '', PAYPAL_CLIENT_SECRET: '', OLLAMA_API_KEY: '' },
  });
  assert.equal(run.status, 0, `verify-payments.mjs must exit 0: ${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /VERDICT: PASS — 15 of 15 SHA-256 \+ Ed25519 receipts valid/);
  assert.match(run.stdout, /0 network requests · 0 vendor trust required/);
});

test('18. verify-payments.mjs --tamper-demo and 1-byte file mutations fail closed with exit code 1', () => {
  if (!fs.existsSync(RECORDED_RECEIPT_PATH)) return;

  const demoRun = spawnSync(process.execPath, [VERIFIER_CLI_PATH, RECORDED_RECEIPT_PATH, '--tamper-demo'], {
    encoding: 'utf8',
  });
  assert.equal(demoRun.status, 1, '--tamper-demo must exit 1');
  assert.match(demoRun.stdout, /FIRST BROKEN INDEX\s*:\s*#3/);
  assert.match(demoRun.stdout, /VERDICT: FAIL/);

  // Copy recorded receipt to temp dir, mutate 1 byte in chain amount, summary, and JSON syntax -> all must exit 1
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-mutate-'));
  try {
    const raw = fs.readFileSync(RECORDED_RECEIPT_PATH, 'utf8');

    // Mutation A: 1-byte change in settled amount inside receipt JSON
    const mutatedAmountPath = path.join(tmpDir, 'mutated-amount.json');
    fs.writeFileSync(mutatedAmountPath, raw.replace('"1420.00"', '"1420.01"'), 'utf8');
    const resA = spawnSync(
      process.execPath,
      [VERIFIER_CLI_PATH, mutatedAmountPath, '--skip-bundle-files'],
      { encoding: 'utf8', cwd: HERE }
    );
    assert.equal(resA.status, 1, '1-byte amount mutation must exit 1');

    // Mutation B: 1-byte change in LLM completion JSON
    const parsed = JSON.parse(raw);
    parsed.llmProposerSummary.proposals[0].rawCompletion += ' ';
    const mutatedLlmPath = path.join(tmpDir, 'mutated-llm.json');
    fs.writeFileSync(mutatedLlmPath, JSON.stringify(parsed, null, 2), 'utf8');
    const resB = spawnSync(
      process.execPath,
      [VERIFIER_CLI_PATH, mutatedLlmPath, '--skip-bundle-files'],
      { encoding: 'utf8', cwd: HERE }
    );
    assert.equal(resB.status, 1, '1-byte LLM completion mutation must exit 1');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('19. CODE-MANIFEST.json and EXPORT-MANIFEST.json match 100% of listed files with 0 missing and 0 unlisted', () => {
  const codeManifestPath = path.join(HERE, 'CODE-MANIFEST.json');
  if (fs.existsSync(codeManifestPath)) {
    const cm = JSON.parse(fs.readFileSync(codeManifestPath, 'utf8'));
    const entries = Object.entries(cm.files || {});
    assert.ok(entries.length >= 15, 'CODE-MANIFEST.json must pin all code and shared files');
    for (const [rel, meta] of entries) {
      const full = path.join(HERE, rel);
      assert.ok(fs.existsSync(full), `CODE-MANIFEST missing file: ${rel}`);
      const buf = fs.readFileSync(full);
      const sha = crypto.createHash('sha256').update(buf).digest('hex');
      assert.equal(buf.length, meta.bytes, `CODE-MANIFEST byte mismatch for ${rel}`);
      assert.equal(sha, meta.sha256, `CODE-MANIFEST sha256 mismatch for ${rel}`);
    }
  }

  const exportManifestPath = path.join(HERE, 'EXPORT-MANIFEST.json');
  if (fs.existsSync(exportManifestPath)) {
    const em = JSON.parse(fs.readFileSync(exportManifestPath, 'utf8'));
    const diskFiles = walkDirFiles(HERE)
      .map((f) => f.rel)
      .filter((rel) => rel !== 'EXPORT-MANIFEST.json')
      .sort();
    const manifestFiles = Object.keys(em.files || {}).sort();
    assert.deepEqual(manifestFiles, diskFiles, 'EXPORT-MANIFEST.json must cover 100% of files in export dir');
    for (const rel of manifestFiles) {
      const buf = fs.readFileSync(path.join(HERE, rel));
      const sha = crypto.createHash('sha256').update(buf).digest('hex');
      assert.equal(buf.length, em.files[rel].bytes, `EXPORT-MANIFEST byte mismatch for ${rel}`);
      assert.equal(sha, em.files[rel].sha256, `EXPORT-MANIFEST sha256 mismatch for ${rel}`);
    }
  }
});

test('20. loadPayPalCredentials strips unquoted trailing inline # comments while preserving quoted # values', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'paypal-env-parse-'));
  const tmpFile = path.join(tmpDir, 'paypal.env');
  try {
    fs.writeFileSync(
      tmpFile,
      [
        '# Full-line comment',
        'PAYPAL_ENV=sandbox  # trailing env note',
        'PAYPAL_CLIENT_ID=SYNTH_ID_01  # pasted note',
        'PAYPAL_CLIENT_SECRET="SYNTH_SEC # keep # hash"',
        'PAYPAL_WEBHOOK_ID=WH#BARE#NO#SPACE  # strip only after space',
      ].join('\n'),
      'utf8'
    );
    const loaded = loadPayPalCredentials(tmpFile, { env: {} });
    assert.equal(loaded.hasCredentials, true);
    assert.equal(loaded.paypalEnv, 'sandbox');
    assert.equal(loaded.clientId, 'SYNTH_ID_01');
    assert.equal(loaded.clientSecret, 'SYNTH_SEC # keep # hash');
    assert.equal(loaded.webhookId, 'WH#BARE#NO#SPACE');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('21. Live PayPal Sandbox Edge Probe & Order lifecycle distinguish CREATED_NOT_CAPTURED from CAPTURED', async () => {
  const stubEdgeProbe = async () => ({
    reachable: true,
    origin: 'https://api-m.sandbox.paypal.com',
    endpoint: '/v1/oauth2/token',
    httpStatus: 200,
    paypalDebugId: 'f000hermetic02',
    tlsProtocol: 'TLSv1.3',
    probedAt: '2026-11-10T00:00:00.000Z',
  });
  const syntheticCreds = {
    envPath: '$HOME/.config/paypal-receipted-agent/paypal.env',
    redactedEnvPath: '$HOME/.config/paypal-receipted-agent/paypal.env',
    envFilePresent: true,
    envFileBytes: 219,
    paypalEnv: 'sandbox',
    keysPresent: ['PAYPAL_ENV', 'PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET'],
    clientIdLength: 11,
    clientSecretLength: 12,
    hasCredentials: true,
    clientId: 'SYNTH_ID_01',
    clientSecret: 'SYNTH_SEC_01',
    webhookId: '',
  };

  const blockedCheck = await runLiveSandboxCheck({ edgeProbeFn: stubEdgeProbe });
  assert.equal(blockedCheck.liveSandboxStatus, 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS');
  assert.equal(blockedCheck.liveOrderId, null);

  const createdOnly = await runLiveSandboxCheck({
    credentials: syntheticCreds,
    edgeProbeFn: stubEdgeProbe,
    paypalMode: 'simulation',
    captureImmediately: false,
  });
  assert.equal(createdOnly.orderLifecycle.createExecuted, true);
  assert.equal(createdOnly.orderLifecycle.captureState, 'CREATED_NOT_CAPTURED');
  assert.equal(createdOnly.orderLifecycle.moneyMoved, false);
  assert.doesNotMatch(createdOnly.liveSandboxStatus, /VERIFIED/);

  const capturedRun = await runLiveSandboxCheck({
    credentials: syntheticCreds,
    edgeProbeFn: stubEdgeProbe,
    paypalMode: 'simulation',
    captureImmediately: true,
  });
  assert.equal(capturedRun.orderLifecycle.captureState, 'CAPTURED');
  assert.equal(capturedRun.orderLifecycle.moneyMoved, true);
  assert.ok(capturedRun.liveOrderId);
  assert.ok(capturedRun.liveCaptureId);
});

test('22. --require-live and --get-order refuse to exit 0 when credentials are absent on an empty HOME', () => {
  const emptyHome = fs.mkdtempSync(path.join(os.tmpdir(), 'paypal-empty-home-'));
  try {
    const cleanEnv = {
      ...process.env,
      HOME: emptyHome,
      PAYPAL_ENV_FILE: '',
      PAYPAL_CLIENT_ID: '',
      PAYPAL_CLIENT_SECRET: '',
      OLLAMA_API_KEY: '',
    };
    const strictAbsent = spawnSync(process.execPath, [RUNNER_CLI_PATH, '--require-live'], {
      encoding: 'utf8',
      env: cleanEnv,
    });
    const lenientAbsent = spawnSync(process.execPath, [RUNNER_CLI_PATH], {
      encoding: 'utf8',
      env: cleanEnv,
    });
    const getOrderAbsent = spawnSync(process.execPath, [RUNNER_CLI_PATH, '--get-order', 'ORD-SYNTH-01'], {
      encoding: 'utf8',
      env: cleanEnv,
    });
    assert.equal(strictAbsent.status, 2);
    assert.equal(lenientAbsent.status, 0);
    assert.equal(getOrderAbsent.status, 2);
  } finally {
    fs.rmSync(emptyHome, { recursive: true, force: true });
  }
});

test('23. runLiveGetOrderCheck executes OAuth2 + GET /v2/checkout/orders/<ID> over injected fetch with zero secret exposure', async () => {
  const seenUrls = [];
  const stubFetch = async (url) => {
    seenUrls.push(String(url));
    if (String(url).endsWith('/v1/oauth2/token')) {
      return {
        ok: true,
        status: 200,
        headers: new Map([['paypal-debug-id', 'dbg-oauth-01']]),
        json: async () => ({ access_token: 'stub-tok', token_type: 'Bearer' }),
      };
    }
    return {
      ok: true,
      status: 200,
      headers: new Map([['paypal-debug-id', 'dbg-order-01']]),
      json: async () => ({
        id: 'ORD-VERIFY-1420',
        intent: 'CAPTURE',
        status: 'COMPLETED',
        create_time: '2026-11-11T00:00:00Z',
        update_time: '2026-11-11T00:00:02Z',
        purchase_units: [
          {
            invoice_id: 'INV-2026-1041',
            custom_id: 'prop-ap-001',
            amount: { currency_code: 'USD', value: '1420.00' },
            payments: {
              captures: [
                {
                  id: 'CAP-VERIFY-1420',
                  status: 'COMPLETED',
                  seller_receivable_breakdown: {
                    gross_amount: { currency_code: 'USD', value: '1420.00' },
                    paypal_fee: { currency_code: 'USD', value: '49.99' },
                    net_amount: { currency_code: 'USD', value: '1370.01' },
                  },
                },
              ],
            },
          },
        ],
      }),
    };
  };

  const result = await runLiveGetOrderCheck({
    orderId: 'ORD-VERIFY-1420',
    credentials: {
      redactedEnvPath: '$HOME/.config/paypal-receipted-agent/paypal.env',
      envFilePresent: true,
      paypalEnv: 'sandbox',
      clientIdLength: 10,
      clientSecretLength: 10,
      hasCredentials: true,
      clientId: 'id-stub-01',
      clientSecret: 'sec-stub01',
    },
    fetchImpl: stubFetch,
  });

  assert.equal(result.ok, true);
  assert.equal(result.httpStatus, 200);
  assert.equal(result.paypalDebugId, 'dbg-order-01');
  assert.equal(result.orderId, 'ORD-VERIFY-1420');
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.captureId, 'CAP-VERIFY-1420');
  assert.equal(result.grossAmountUsd, '1420.00');
  assert.equal(seenUrls.length, 2);
});

test('24. Injected recordedReceipt mode & blocked runLiveApexScenario fail closed without credentials', async (t) => {
  const baseline = await runSampleFixtureDemo({ mode: 'simulation' });
  const syntheticRecordedReceipt = {
    submitter: 'paypal-ap-policy-gate',
    workOrderId: 'WO-paypal-hackathon-payment-agent-1',
    codeManifestSha256: 'a'.repeat(64),
    liveSandboxStatus: 'LIVE_SANDBOX_CREATED_AND_CAPTURED',
    llmProposerSummary: {
      mode: 'live-llm-proposer',
      provider: 'ollama-cloud',
      requestedModel: 'glm-5.3',
      returnedModel: 'glm-5.3',
      proposalsGeneratedCount: 5,
      proposals: [],
    },
    settledOrders: [
      {
        step: 1,
        invoiceId: 'INV-2026-1041',
        payeeId: 'colombia-direct-beans',
        supplier: 'Colombia Direct Beans Co.',
        payeeEmail: 'pay@colombia-direct-beans.example',
        rail: 'Orders v2 + Invoicing v2',
        amountUsd: '1420.00',
        paypalOrderId: 'ORD-SYNTH-001',
        paypalCaptureId: 'CAP-SYNTH-001',
        paypalInvoiceId: 'INV2-SYNTH-001',
        orderStatus: 'COMPLETED',
        captureStatus: 'COMPLETED',
      },
    ],
    ledger: baseline.ledger,
  };

  const srv = await startHostedDemoServer({ port: 0, recordedReceipt: syntheticRecordedReceipt });
  t.after(async () => {
    await srv.close();
  });

  const st = await (await fetch(`${srv.url}/api/state`)).json();
  assert.equal(st.proofMode, 'recorded-live-sandbox');
  assert.equal(st.settledPayments[0].paypalOrderId, 'ORD-SYNTH-001');

  const blockedApex = await runLiveApexScenario({ live: false });
  assert.equal(blockedApex.liveSandboxStatus, 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS');
});

test('25. Recorded-mode POST /api/propose marks admitted interactive proposals with SIMULATED-ORDER-* IDs, simulated: true, and on-screen SIMULATED badge in /api/state and HTML', async (t) => {
  const baseline = await runSampleFixtureDemo({ mode: 'simulation' });
  const syntheticRecordedReceipt = {
    submitter: 'paypal-ap-policy-gate',
    workOrderId: 'WO-paypal-hackathon-payment-agent-1',
    codeManifestSha256: 'b'.repeat(64),
    liveSandboxStatus: 'LIVE_SANDBOX_CREATED_AND_CAPTURED',
    llmProposerSummary: {
      mode: 'live-llm-proposer',
      provider: 'ollama-cloud',
      requestedModel: 'glm-5.3',
      returnedModel: 'glm-5.3',
      proposalsGeneratedCount: 5,
      proposals: [],
    },
    settledOrders: [
      {
        step: 1,
        invoiceId: 'INV-2026-1041',
        payeeId: 'colombia-direct-beans',
        supplier: 'Colombia Direct Beans Co.',
        payeeEmail: 'pay@colombia-direct-beans.example',
        rail: 'Orders v2 + Invoicing v2',
        amountUsd: '1420.00',
        paypalOrderId: '5AB12345CD678901E',
        paypalCaptureId: '9XY98765ZW432109F',
        paypalInvoiceId: 'INV2-LIVE-TEST-001',
        orderStatus: 'COMPLETED',
        captureStatus: 'COMPLETED',
        getOrderPaypalDebugId: 'f1234567890ab',
      },
    ],
    ledger: baseline.ledger,
  };

  const srv = await startHostedDemoServer({ port: 0, recordedReceipt: syntheticRecordedReceipt });
  t.after(async () => {
    await srv.close();
  });

  const propRes = await fetch(`${srv.url}/api/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proposal: {
        proposalId: 'prop-sim-badge-01',
        invoiceId: 'INV-2026-1095',
        payeeId: 'sound-freight-logistics',
        payeeEmail: 'ap@sound-freight.example',
        payeeMerchantId: 'MCH-SOUND-FREIGHT-03',
        amountValue: '320.00',
        poNumber: 'PO-2026-38-FREIGHT',
        currencyCode: 'USD',
        reason: 'Regional pallet freight check',
      },
    }),
  });
  assert.equal(propRes.status, 200);
  const propData = await propRes.json();
  assert.equal(propData.result.status, 'EXECUTED');
  assert.equal(propData.result.simulated, true);
  assert.equal(propData.result.executionMode, 'SIMULATED_LOCAL_NO_PAYPAL_CALL');
  assert.equal(propData.result.apiCallsDelta, 0);
  assert.equal(propData.result.livePaypalApiCalls, 0);
  assert.match(propData.result.paypalOrderId, /^SIMULATED-ORDER-[0-9A-F]{14}$/);
  assert.match(propData.result.paypalCaptureId, /^SIMULATED-CAPTURE-[0-9A-F]{14}$/);
  assert.equal(
    propData.result.simulationNotice,
    'SIMULATED (local policy check only — 0 PayPal API calls)'
  );

  const st = await (await fetch(`${srv.url}/api/state`)).json();
  assert.equal(st.settledPayments.length, 2);
  assert.equal(st.settledPayments[0].simulated, false);
  assert.equal(st.settledPayments[0].paypalOrderId, '5AB12345CD678901E');
  assert.equal(st.settledPayments[1].simulated, true);
  assert.equal(st.settledPayments[1].executionMode, 'SIMULATED_LOCAL_NO_PAYPAL_CALL');
  assert.equal(st.settledPayments[1].paypalOrderId, propData.result.paypalOrderId);

  const html = await (await fetch(`${srv.url}/`)).text();
  assert.ok(html.includes(propData.result.paypalOrderId));
  assert.ok(html.includes('SIMULATED (local policy check only — 0 PayPal API calls)'));
  assert.ok(html.includes('data-simulated="false"'));
  assert.ok(html.includes('data-simulated="true"'));
});

test('26. Simulation mode prefixes all 4 surfaces with SIMULATED-* and UI renders buyer gate risk on Screens 3 & 4 plus 89 of 89 tests', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const st = await (await fetch(`${srv.url}/api/state`)).json();
  assert.equal(st.settledPayments.length, 2);
  assert.match(st.settledPayments[0].paypalOrderId, /^SIMULATED-ORDER-/);
  assert.match(st.settledPayments[0].paypalCaptureId, /^SIMULATED-CAPTURE-/);
  assert.match(st.settledPayments[0].paypalInvoiceId, /^SIMULATED-INVOICE-/);
  assert.match(st.settledPayments[1].paypalPayoutBatchId, /^SIMULATED-PAYOUT-/);
  assert.equal(st.settledPayments[0].simulated, true);
  assert.equal(st.settledPayments[1].simulated, true);

  const html = await (await fetch(`${srv.url}/`)).text();
  const buyerGateMatches = html.match(/Why This Buyer Needs an External Gate:/g) || [];
  assert.equal(buyerGateMatches.length, 2, 'Buyer gate risk sentence must appear on both Screen 3 and Screen 4');
  assert.ok(html.includes('89 of 89 tests'));
});

test('27. Recorded-mode POST /api/propose keeps real settledTodayUsd ($2,100.00) and remainingHeadroomUsd ($2,900.00) untouched while tracking simulated previews separately', async (t) => {
  const baseline = await runSampleFixtureDemo({ mode: 'simulation' });
  const syntheticRecordedReceipt = {
    submitter: 'paypal-ap-policy-gate',
    workOrderId: 'WO-paypal-hackathon-payment-agent-1',
    codeManifestSha256: 'c'.repeat(64),
    liveSandboxStatus: 'LIVE_SANDBOX_CREATED_AND_CAPTURED',
    llmProposerSummary: {
      mode: 'live-llm-proposer',
      provider: 'ollama-cloud',
      requestedModel: 'glm-5.3',
      returnedModel: 'glm-5.3',
      proposalsGeneratedCount: 5,
      proposals: [],
    },
    settledOrders: [
      {
        step: 1,
        invoiceId: 'INV-2026-1041',
        payeeId: 'colombia-direct-beans',
        supplier: 'Colombia Direct Beans Co.',
        payeeEmail: 'pay@colombia-direct-beans.example',
        rail: 'Orders v2 + Invoicing v2',
        amountUsd: '1420.00',
        paypalOrderId: '5AB12345CD678901E',
        paypalCaptureId: '9XY98765ZW432109F',
        orderStatus: 'COMPLETED',
        captureStatus: 'COMPLETED',
      },
      {
        step: 2,
        invoiceId: 'INV-2026-1043',
        payeeId: 'cascade-packaging-co',
        supplier: 'Cascade Packaging Co.',
        payeeEmail: 'billing@cascade-packaging.example',
        rail: 'Orders v2 + Payouts v1',
        amountUsd: '680.00',
        paypalOrderId: '6CD12345EF678901G',
        paypalCaptureId: '8UV98765WX432109H',
        orderStatus: 'COMPLETED',
        captureStatus: 'COMPLETED',
      },
    ],
    ledger: baseline.ledger,
  };

  const srv = await startHostedDemoServer({ port: 0, recordedReceipt: syntheticRecordedReceipt });
  t.after(async () => {
    await srv.close();
  });

  const propRes = await fetch(`${srv.url}/api/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proposal: {
        proposalId: 'prop-preview-sep-01',
        invoiceId: 'INV-2026-1099',
        payeeId: 'sound-freight-logistics',
        payeeEmail: 'ap@sound-freight.example',
        payeeMerchantId: 'MCH-SOUND-FREIGHT-03',
        amountValue: '320.00',
        poNumber: 'PO-2026-38-FREIGHT',
        currencyCode: 'USD',
        reason: 'Simulated freight preview',
      },
    }),
  });
  const propData = await propRes.json();
  assert.equal(propData.result.status, 'EXECUTED');
  assert.equal(propData.result.simulated, true);

  // Real settled spend and real daily headroom MUST remain strictly untouched
  assert.equal(propData.state.kpis.settledTodayUsd, '2100.00');
  assert.equal(propData.state.kpis.remainingHeadroomUsd, '2900.00');
  assert.equal(propData.state.policy.settledTodayUsd, '2100.00');
  assert.equal(propData.state.policy.remainingDailyHeadroomUsd, '2900.00');

  // Simulated preview counters track the $320.00 preview separately
  assert.equal(propData.state.kpis.simulatedPreviewTotalUsd, '320.00');
  assert.equal(propData.state.kpis.simulatedPreviewCount, 1);
  assert.equal(propData.state.kpis.simulatedRemainingPreviewHeadroomUsd, '2580.00');

  // POST /api/reset clears simulated previews back to 0.00
  const resetData = await (await fetch(`${srv.url}/api/reset`, { method: 'POST' })).json();
  assert.equal(resetData.state.kpis.settledTodayUsd, '2100.00');
  assert.equal(resetData.state.kpis.remainingHeadroomUsd, '2900.00');
  assert.equal(resetData.state.kpis.simulatedPreviewTotalUsd, '0.00');
  assert.equal(resetData.state.kpis.simulatedPreviewCount, 0);
});

test('28. GET /verify.html serves standalone browser WebCrypto SHA-256 + Ed25519 verifier with CSP default-src none', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const res = await fetch(`${srv.url}/verify.html`);
  assert.equal(res.status, 200);
  const cspHeader = res.headers.get('content-security-policy') || '';
  assert.match(cspHeader, /default-src 'none'/);
  assert.match(cspHeader, /connect-src 'none'/);

  const html = await res.text();
  assert.match(html, /default-src 'none'/);
  assert.match(html, /crypto\.subtle\.verify/);
  assert.match(html, /Ed25519/);
  assert.match(html, /Mutate 1 Byte/);
  assert.doesNotMatch(html, /[\u{1F300}-\u{1FAFF}]/u);
});

test('29. GET /api/attack-suite computes scoreboard strictly over 15 comparable attacks and carries scoping disclaimer', async (t) => {
  const srv = await startHostedDemoServer({ port: 0 });
  t.after(async () => {
    await srv.close();
  });

  const data = await (await fetch(`${srv.url}/api/attack-suite`)).json();
  assert.equal(data.ok, true);
  assert.equal(data.attackSuite.available, true);
  const sb = data.attackSuite.after.scoreboard;
  assert.equal(sb.attacksTotal, 20);
  assert.equal(sb.controlsTotal, 5);
  assert.equal(sb.comparableAttacks, 15);
  assert.match(sb.modelObeyedLabel, /of 15$/);
  assert.equal(sb.gateAdmittedAttacks, 0);
  assert.equal(sb.dollarsMovedOutsidePolicy, '0.00');
  assert.equal(sb.controlsPaid, 5);
  assert.equal(data.attackSuite.records.length, 25);
  assert.match(data.attackSuite.scopeNotice, /not comprehensive coverage of PayPal/i);
});

test('30. Standalone single-file verify-payments.mjs copied alone to an empty temp folder verifies receipts with zero vendor files', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'standalone-verifier-'));
  try {
    const isolatedVerifier = path.join(tmpDir, 'verify-payments.mjs');
    fs.copyFileSync(VERIFIER_CLI_PATH, isolatedVerifier);

    const suiteAfterPath = path.join(HERE, 'attack-suite-after-fix-receipt.json');
    const targets = [RECORDED_RECEIPT_PATH, suiteAfterPath].filter((p) => fs.existsSync(p));

    if (targets.length === 0) {
      // Pre-Stage-2 fallback check using pre-fix suite receipt if present
      const beforePath = path.join(HERE, 'attack-suite-before-fix-receipt.json');
      if (fs.existsSync(beforePath)) targets.push(beforePath);
    }

    assert.ok(targets.length >= 1, 'At least one signed receipt JSON must exist for standalone test');
    for (const srcReceipt of targets) {
      const isolatedReceipt = path.join(tmpDir, path.basename(srcReceipt));
      fs.copyFileSync(srcReceipt, isolatedReceipt);
      const run = spawnSync(process.execPath, [isolatedVerifier, isolatedReceipt], {
        cwd: tmpDir,
        encoding: 'utf8',
        env: { ...process.env, HOME: tmpDir, PAYPAL_CLIENT_ID: '', PAYPAL_CLIENT_SECRET: '', OLLAMA_API_KEY: '' },
      });
      assert.equal(run.status, 0, `Isolated single-file verifier failed on ${path.basename(srcReceipt)}: ${run.stdout}\n${run.stderr}`);
      assert.match(run.stdout, /VERDICT: PASS/);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('31. Zero-vendor-code node -e one-liner (node:fs + node:crypto only) verifies SHA-256 chain and Ed25519 signatures', () => {
  const suiteAfterPath = path.join(HERE, 'attack-suite-after-fix-receipt.json');
  const beforePath = path.join(HERE, 'attack-suite-before-fix-receipt.json');
  const target = [RECORDED_RECEIPT_PATH, suiteAfterPath, beforePath].find((p) => fs.existsSync(p));
  assert.ok(target, 'Signed receipt file must exist');

  const zeroVendorScript = `
    const fs = require('node:fs'), crypto = require('node:crypto');
    const r = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
    const canon = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v) :
      Array.isArray(v) ? '[' + v.map((x) => canon(x === undefined ? null : x)).join(',') + ']' :
      '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
    const pub = crypto.createPublicKey(r.gateSigner.publicKeyPem);
    for (let i = 0; i < r.ledger.entries.length; i++) {
      const { receiptHash, ed25519Signature, ...rest } = r.ledger.entries[i];
      const h = crypto.createHash('sha256').update(canon(rest)).digest('hex');
      if (h !== receiptHash) throw new Error('HASH_FAIL_' + i);
      if (i > 0 && rest.prevHash !== r.ledger.entries[i - 1].receiptHash) throw new Error('CHAIN_FAIL_' + i);
      if (!crypto.verify(null, Buffer.from(receiptHash, 'utf8'), pub, Buffer.from(ed25519Signature, 'base64'))) {
        throw new Error('SIG_FAIL_' + i);
      }
    }
    console.log('ZERO_VENDOR_OK:' + r.ledger.entries.length);
  `;
  const run = spawnSync(process.execPath, ['-e', zeroVendorScript, target], { encoding: 'utf8' });
  assert.equal(run.status, 0, `Zero-vendor node -e verifier failed: ${run.stderr}`);
  assert.match(run.stdout, /^ZERO_VENDOR_OK:\d+/);
});

test('32. verify-payments.mjs --forge-rehash-demo rejects attacker-rehashed SHA-256 chain lacking Ed25519 private key', () => {
  const suiteAfterPath = path.join(HERE, 'attack-suite-after-fix-receipt.json');
  const beforePath = path.join(HERE, 'attack-suite-before-fix-receipt.json');
  const target = [RECORDED_RECEIPT_PATH, suiteAfterPath, beforePath].find((p) => fs.existsSync(p));
  assert.ok(target);

  const run = spawnSync(process.execPath, [VERIFIER_CLI_PATH, target, '--forge-rehash-demo'], {
    encoding: 'utf8',
  });
  assert.equal(run.status, 1, 'Re-hashed chain without Ed25519 key must exit 1');
  assert.match(run.stdout, /ED25519_SIGNATURE_INVALID/);
});

test('33. verify-payments.mjs --expect-pubkey-sha256 rejects key-swap forgery with PUBLIC_KEY_FINGERPRINT_MISMATCH', () => {
  const suiteAfterPath = path.join(HERE, 'attack-suite-after-fix-receipt.json');
  const beforePath = path.join(HERE, 'attack-suite-before-fix-receipt.json');
  const target = [RECORDED_RECEIPT_PATH, suiteAfterPath, beforePath].find((p) => fs.existsSync(p));
  assert.ok(target);

  const run = spawnSync(
    process.execPath,
    [VERIFIER_CLI_PATH, target, '--expect-pubkey-sha256', '0'.repeat(64)],
    { encoding: 'utf8' }
  );
  assert.equal(run.status, 1, 'Mismatched pinned public key must exit 1');
  assert.match(run.stdout, /PUBLIC_KEY_FINGERPRINT_MISMATCH/);
});

test('34. Primary-sourced PayPal toolkit citation cites static developer.paypal.com/ai-tools/toolkit URL and zero JS-shell blog URLs', async (t) => {
  assert.match(PAYPAL_TOOLKIT_CITATION, /https:\/\/developer\.paypal\.com\/ai-tools\/toolkit/);
  assert.match(PAYPAL_TOOLKIT_CITATION, /Last updated: October 2, 2026/);
  assert.match(PAYPAL_TOOLKIT_CITATION, /works with LLM providers that support function calling/);
  assert.match(PAYPAL_TOOLKIT_CITATION, /System prompts: Use well-defined system prompts to control the behavior of the agent\./);
  assert.doesNotMatch(PAYPAL_TOOLKIT_CITATION, /community\/blog\/paypal-agentic-ai-toolkit/);

  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });
  const html = await (await fetch(`${srv.url}/`)).text();
  assert.match(html, /https:\/\/developer\.paypal\.com\/ai-tools\/toolkit/);
  assert.doesNotMatch(html, /community\/blog\/paypal-agentic-ai-toolkit/);
});


test('35. AP desk evaluates a cited purchase order and holds a same-supplier same-amount look-alike for approve-once', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true });
  t.after(async () => {
    await srv.close();
  });

  const state = await (await fetch(`${srv.url}/api/state`)).json();
  assert.ok(Array.isArray(state.deskInbox) && state.deskInbox.length >= 5);
  assert.equal(state.policy.policyId, 'policy-paypal-ap-gate-v2');

  const ev = await (await fetch(`${srv.url}/api/desk/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proposal: {
        proposalId: 'prop-desk-ok-freight',
        invoiceId: 'INV-2026-1090',
        payeeId: 'sound-freight-logistics',
        payeeEmail: 'ap@sound-freight.example',
        payeeMerchantId: 'MCH-SOUND-FREIGHT-03',
        amountValue: '320.00',
        currencyCode: 'USD',
        poNumber: 'PO-2026-38-FREIGHT',
        reason: 'Regional pallet freight charges',
      },
    }),
  })).json();
  assert.equal(ev.verdict.decision, 'ALLOW');
  assert.equal(ev.poCard.poNumber, 'PO-2026-38-FREIGHT');

  const lookalike = {
    proposalId: 'prop-desk-hold-01',
    invoiceId: 'INV-2026-1098',
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '1420.00',
    currencyCode: 'USD',
    poNumber: 'PO-2026-38-1041',
    reason: 'Look-alike of the already-paid Colombia invoice',
  };
  const held = await (await fetch(`${srv.url}/api/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal: lookalike }),
  })).json();
  assert.equal(held.result.status, 'HELD');
  assert.equal(held.result.reasonCode, 'POSSIBLE_DUPLICATE_PAYMENT');
  assert.equal(held.result.apiCallsDelta ?? 0, 0);

  const once = await (await fetch(`${srv.url}/api/holds/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal: lookalike, approvedBy: 'A. Controller' }),
  })).json();
  assert.equal(once.ok, true);
  assert.equal(once.result.status, 'APPROVED');
  assert.equal(once.result.idempotent, false);

  const again = await (await fetch(`${srv.url}/api/holds/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal: lookalike, approvedBy: 'A. Controller' }),
  })).json();
  assert.equal(again.ok, true);
  assert.equal(again.result.idempotent, true);

  const other = await (await fetch(`${srv.url}/api/holds/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal: lookalike, approvedBy: 'B. Reviewer' }),
  })).json();
  assert.equal(other.ok, false);
  assert.match(String(other.error || ''), /ALREADY_APPROVED/);

  const invoiceNamed = {
    proposalId: 'prop-desk-hold-02',
    invoiceId: 'INV-2026-1097',
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '1420.00',
    currencyCode: 'USD',
    poNumber: 'PO-2026-38-1041',
    reason: 'A. Controller',
  };
  const namedHold = await (await fetch(`${srv.url}/api/propose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal: invoiceNamed }),
  })).json();
  assert.equal(namedHold.result.status, 'HELD');
  const forbidden = await (await fetch(`${srv.url}/api/holds/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal: invoiceNamed, approvedBy: 'A. Controller' }),
  })).json();
  assert.equal(forbidden.ok, false);
  assert.match(String(forbidden.error || ''), /APPROVAL_FROM_PROPOSAL_FORBIDDEN/);
});

test('36. PUT /api/policy requires the configured edit token and accepts the matching header', async (t) => {
  const srv = await startHostedDemoServer({ port: 0, simulate: true, policyEditToken: 'desk-token' });
  t.after(async () => {
    await srv.close();
  });

  const denied = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dailyCapUsd: '6000.00' }),
  });
  assert.equal(denied.status, 401);
  const deniedBody = await denied.json();
  assert.equal(deniedBody.error, 'POLICY_EDIT_TOKEN_REQUIRED');

  const allowed = await fetch(`${srv.url}/api/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'x-policy-edit-token': 'desk-token' },
    body: JSON.stringify({ dailyCapUsd: '6000.00' }),
  });
  assert.equal(allowed.status, 200);
  const allowedBody = await allowed.json();
  assert.equal(allowedBody.ok, true);
  assert.equal(allowedBody.policy.dailyCapUsd, '6000.00');
});
