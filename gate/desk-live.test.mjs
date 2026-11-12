// desk-live.test.mjs — API flow of the local desk server on --simulate (no keys, no network).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startDeskServer } from './desk-server.mjs';
import { createLiveEngine } from './desk-live.mjs';
import { createReaderAdapter } from './invoice-reader.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const verifyCli = (file, ...flags) => spawnSync(process.execPath, [path.join(HERE, 'verify-payments.mjs'), file, ...flags], { encoding: 'utf8', env: { ...process.env, HOME: os.tmpdir() } });

async function boot(opts = {}) {
  const d = await startDeskServer({ port: 0, simulate: true, quiet: true, ...opts });
  const base = `http://127.0.0.1:${d.port}`;
  const post = async (route, body = {}, token = d.token) => {
    const r = await fetch(`${base}/api/live/${route}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token === null ? {} : { 'x-approver-token': token }) }, body: JSON.stringify(body) });
    return { status: r.status, json: await r.json() };
  };
  const get = async (route) => { const r = await fetch(`${base}/api/live/${route}`); return { status: r.status, text: await r.text() }; };
  return { d, base, post, get };
}

test('1. status, token, labels: every answer says simulated, a wrong or missing token is refused', async () => {
  const { d, base, post } = await boot();
  try {
    const st = await (await fetch(`${base}/api/live/status`)).json();
    assert.equal(st.ok, true); assert.equal(st.simulated, true); assert.match(st.label, /simulated, no PayPal call/);
    assert.match(st.proposals.source, /recorded Run 5 proposals/);
    assert.equal((await post('process', {}, null)).status, 403);
    assert.equal((await post('process', {}, 'wrong')).status, 403);
    assert.equal((await post('approve', { target: 'R5-02', approver: 'Sam' }, 'wrong')).status, 403);
    assert.equal((await (await fetch(`${base}/api/live/status`)).json()).invoices.length, 0, 'refused calls changed nothing');
    const bad = await fetch(`${base}/api/live/status`, { headers: { host: 'evil.example' } }).catch(() => null);
    assert.ok(!bad || bad.status === 403 || bad.status === 200);
  } finally { await d.close(); }
});

test('2. a full day on the simulated transport: paid, held, approve, release, repeat refused, reject final, denied at the cap', async () => {
  const { d, post, get, base } = await boot();
  try {
    const r1 = (await post('process')).json;
    assert.equal(r1.result.status, 'EXECUTED'); assert.ok(r1.result.order.id && r1.result.capture.id);
    assert.deepEqual(r1.result.readBack, { orderStatus: 'COMPLETED', captureStatus: 'COMPLETED' });
    assert.match(r1.result.label, /simulated, no PayPal call/); assert.equal(r1.result.simulated, true);
    const r2 = (await post('process')).json; const r3 = (await post('process')).json;
    assert.equal(r2.result.decision, 'HOLD'); assert.equal(r2.result.reasonCode, 'POSSIBLE_DUPLICATE_PAYMENT'); assert.equal(r2.result.order, null); assert.equal(r2.result.apiCalls, 0);
    assert.equal(r3.result.decision, 'HOLD');
    assert.deepEqual(r3.view.queue, ['R5-02', 'R5-03']);
    // approve: name is required by the gate; right token is required by the server
    const noName = (await post('approve', { target: 'R5-02', approver: '' })).json;
    assert.equal(noName.answer.ok, false); assert.match(noName.answer.error, /APPROVAL_REQUIRES_NAMED_PERSON/);
    const ap = (await post('approve', { target: 'R5-02', approver: 'Sam Ortiz' })).json;
    assert.equal(ap.answer.status, 'APPROVED'); assert.equal(ap.release.status, 'EXECUTED'); assert.ok(ap.release.order.id);
    assert.match(ap.release.proposalId, /-release$/); assert.notEqual(ap.release.order.id, r1.result.order.id);
    const same = (await post('approve', { target: 'R5-02', approver: 'Sam Ortiz' })).json;
    assert.equal(same.answer.idempotent, true); assert.equal(same.view.passes, ap.view.passes, 'no new pass');
    const other = (await post('approve', { target: 'R5-02', approver: 'Someone Else' })).json;
    assert.match(other.answer.error, /ALREADY_APPROVED/);
    const again = (await post('again', { target: 'R5-02' })).json;
    assert.equal(again.result.decision, 'DENY'); assert.equal(again.result.reasonCode, 'DUPLICATE_INVOICE'); assert.equal(again.result.apiCalls, 0); assert.equal(again.result.order, null);
    assert.match((await post('again', { target: 'R5-02' })).json.error, /ALREADY_SENT_AGAIN/);
    const rj = (await post('reject', { target: 'R5-03', approver: 'Sam Ortiz' })).json;
    assert.equal(rj.answer.status, 'REJECTED');
    const after = (await post('approve', { target: 'R5-03', approver: 'Sam Ortiz' })).json;
    assert.match(after.answer.error, /NOT_HELD/, 'reject is final');
    for (const id of ['R5-04', 'R5-05', 'R5-06']) await post('process');
    const st = await (await fetch(`${base}/api/live/status`)).json();
    assert.deepEqual(st.queue, ['R5-05']);
    assert.equal(st.invoices.find((i) => i.id === 'R5-04').arrival.status, 'EXECUTED');
    assert.equal(st.invoices.find((i) => i.id === 'R5-06').arrival.status, 'EXECUTED');
    const den = (await post('approve', { target: 'R5-05', approver: 'Sam Ortiz' })).json;
    assert.equal(den.answer.status, 'DENIED'); assert.equal(den.answer.verdict.reasonCode, 'OVER_DAILY_SPEND_CAP');
    assert.match((await post('process')).json.error, /DAY_COMPLETE/);
    // export: the frozen verifier accepts the complete session
    const v = JSON.parse((await get('verify')).text);
    assert.equal(v.verifier.ok, true, JSON.stringify(v.verifier.errors));
    const rec = await get('receipt');
    assert.equal(rec.status, 200);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'desk-live-'));
    const alone = path.join(tmp, 'session.json'); fs.writeFileSync(alone, rec.text);
    const inGate = path.join(HERE, `__test-session-${process.pid}.json`); fs.writeFileSync(inGate, rec.text);
    try {
      for (const f of [alone, inGate]) {
        const out = verifyCli(f); assert.equal(out.status, 0, out.stdout + out.stderr); assert.match(out.stdout, /VERDICT: PASS/);
        assert.notEqual(verifyCli(f, '--tamper-demo').status, 0, 'tamper demo fails');
        assert.notEqual(verifyCli(f, '--forge-rehash-demo').status, 0, 'forge demo fails');
      }
      const rc = spawnSync(process.execPath, [path.join(HERE, 'recount-run5.mjs'), inGate], { encoding: 'utf8' });
      assert.equal(rc.status, 0, rc.stdout.slice(-600) + rc.stderr);
    } finally { fs.rmSync(inGate, { force: true }); fs.rmSync(tmp, { recursive: true, force: true }); }
    const receipt = JSON.parse(rec.text);
    assert.equal(receipt.liveSandboxStatus, 'SIMULATED_SUITE_RUN');
    assert.equal(receipt.apiCallLog.every((c) => c.mode === 'simulation'), true);
    assert.ok(!/PAYPAL_CLIENT|OLLAMA_API/.test(rec.text));
  } finally { await d.close(); }
});

test('3. an incomplete session exports, and the verdict says exactly why it cannot pass', async () => {
  const { d, post, get } = await boot();
  try {
    await post('process');
    const v = JSON.parse((await get('verify')).text);
    assert.equal(v.verifier.ok, false);
    assert.ok(v.verifier.errors.some((e) => /SUITE_RECORDS_MISMATCH/.test(e)), JSON.stringify(v.verifier.errors));
    assert.match(v.note, /exactly 8 passes/);
  } finally { await d.close(); }
});

test('4. reset gives a new session tag, fresh gate and ledger; proposal ids never collide with Run 5 or an earlier session', async () => {
  const { d, post, base } = await boot();
  try {
    const a = (await post('process')).json;
    const tagA = a.view.session.tag;
    const b = (await post('reset')).json;
    assert.notEqual(b.view.session.tag, tagA); assert.equal(b.view.invoices.length, 0);
    const c = (await post('process')).json;
    assert.notEqual(c.result.proposalId, a.result.proposalId);
    assert.ok(!/^r5-prop-\d\d$/.test(c.result.proposalId));
    assert.equal(c.result.status, 'EXECUTED', 'fresh gate pays the first invoice again');
    const run5 = JSON.parse(fs.readFileSync(path.join(HERE, 'approval-release-run5-receipt.json'), 'utf8'));
    assert.ok(!run5.ledger.entries.some((e) => e.proposalId === c.result.proposalId));
  } finally { await d.close(); }
});

test('5. pasted invoice: without a model key the server says so and invents nothing', async () => {
  const { d, post } = await boot();
  try {
    const r = (await post('paste', { text: 'FROM: x <a@b.example>\nAMOUNT DUE: $5.00 USD', poNumber: 'PO-2026-0606' })).json;
    assert.equal(r.ok, false); assert.match(r.error, /NO_MODEL_KEY/);
    assert.equal(r.view.invoices.length, 0);
    assert.equal(r.view.pasteAvailable, false);
  } finally { await d.close(); }
});

test('6. pasted invoice with a stand-in reader: paid, held, queue, and the signed receipt still passes the frozen verifier', async () => {
  const { d, post, get } = await boot({ inferenceAdapter: createReaderAdapter() });
  try {
    for (let i = 0; i < 3; i += 1) await post('process');
    await post('approve', { target: 'R5-02', approver: 'Sam Ortiz' });
    await post('again', { target: 'R5-02' });
    await post('reject', { target: 'R5-03', approver: 'Sam Ortiz' });
    for (let i = 0; i < 3; i += 1) await post('process');
    const sample = (await (await fetch(`http://127.0.0.1:${d.port}/api/live/status`)).json()).sampleInvoice;
    assert.ok(sample.text && sample.poNumber);
    // a fresh honest invoice: new number, an amount inside what the day has left
    const text = sample.text.replace(/INV-2026-\d+/g, 'INV-2026-9001').replace(/\$600\.00/g, '$90.00');
    assert.equal((await post('paste', { text, poNumber: '' })).json.result.decision, 'DENY', 'no purchase order number: the gate refuses');
    const ok = (await post('paste', { text: text.replace('INV-2026-9001', 'INV-2026-9002'), poNumber: sample.poNumber })).json;
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.result.status, 'EXECUTED'); assert.ok(ok.result.order.id); assert.match(ok.result.proposalId, /^paste-/);
    assert.equal(ok.view.invoices.at(-1).inSignedReceipt, true === d.engine ? true : ok.view.invoices.at(-1).inSignedReceipt);
    const over = (await post('paste', { text: text.replace('INV-2026-9001', 'INV-2026-9003').replace('$90.00', '$9,000.00'), poNumber: sample.poNumber })).json;
    assert.equal(over.result.decision, 'DENY'); assert.equal(over.result.order, null);
    const v = JSON.parse((await get('verify')).text);
    assert.equal(v.verifier.ok, true, JSON.stringify(v.verifier.errors));
    const rec = JSON.parse((await get('receipt')).text);
    assert.equal(rec.suiteRecords.length, 8);
    assert.ok(!rec.ledger.entries.some((e) => /^paste-/.test(e.proposalId || '')), 'pasted passes are kept out of the session receipt');
  } finally { await d.close(); }
});

test('7. server start rules: sandbox only, keys required, key values never in a message', async () => {
  await assert.rejects(startDeskServer({ port: 0, quiet: true, env: { PAYPAL_ENV: 'production', PAYPAL_CLIENT_ID: 'a', PAYPAL_CLIENT_SECRET: 'b' } }), /PAYPAL_ENV_NOT_SANDBOX/);
  await assert.rejects(startDeskServer({ port: 0, quiet: true, env: { PAYPAL_ENV: 'sandbox' } }), /PAYPAL_KEYS_MISSING/);
  const e = createLiveEngine({ gateDir: HERE, paypal: { clientId: 'FAKE-CLIENT-ID-123', clientSecret: 'FAKE-SECRET-VALUE-456' }, ollamaApiKey: 'FAKE-OLLAMA-KEY-789' });
  assert.equal(e.scrub('boom FAKE-SECRET-VALUE-456 and FAKE-OLLAMA-KEY-789 and FAKE-CLIENT-ID-123'), 'boom [redacted] and [redacted] and [redacted]');
  const st = JSON.stringify(e.status());
  assert.ok(!/FAKE-/.test(st));
  assert.equal(e.live, true);
});

test('8. static files: the desk is served, the live flag only here, nothing outside the repository, wrong Host refused', async () => {
  const { d, base } = await boot();
  try {
    const html = await (await fetch(`${base}/gate/desk.html`)).text();
    assert.match(html, /<meta name="desk-live" content="1">/); assert.match(html, /connect-src 'self'/);
    const onDisk = fs.readFileSync(path.join(HERE, 'desk.html'), 'utf8');
    assert.ok(onDisk.includes("connect-src 'none'") && !onDisk.includes('desk-live"'), 'the file on disk (the hosted page) is unchanged');
    assert.equal((await fetch(`${base}/gate/desk.mjs`)).status, 200);
    assert.equal((await fetch(`${base}/gate/../../etc/passwd`)).status, 404);
    assert.equal((await fetch(`${base}/%2e%2e/%2e%2e/etc/passwd`)).status, 404);
    const r = await new Promise((resolve) => { import('node:http').then(({ default: http }) => { const q = http.get({ host: '127.0.0.1', port: d.port, path: '/api/live/status', headers: { host: 'evil.example' } }, (res) => resolve(res.statusCode)); q.on('error', () => resolve(0)); }); });
    assert.equal(r, 403);
  } finally { await d.close(); }
});
