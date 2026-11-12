#!/usr/bin/env node
// desk-server.mjs — a local desk where a click on Approve pays on the PayPal Sandbox.
//
//   node gate/desk-server.mjs [--port N] [--simulate]
//
// Binds 127.0.0.1 only. Serves this repository's static files and a small JSON API under /api/live/.
// With the Sandbox keys in the environment (PAYPAL_ENV=sandbox, PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET) the
// payments are real Sandbox payments. With --simulate nothing leaves the machine and every answer says so.
// Keys are read once from the environment, handed to the engine, and removed from process.env. They are never
// sent to a browser, never written to disk and never logged.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createLiveEngine } from './desk-live.mjs';

const GATE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(GATE_DIR, '..');
const MIME = { '.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.md': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2', '.mp4': 'video/mp4', '.jpg': 'image/jpeg' };

export async function startDeskServer({ port = 8787, simulate = false, env = process.env, inferenceAdapter = null, pasteInReceipt = false, quiet = false } = {}) {
  let paypal = null;
  let ollamaApiKey = '';
  if (!simulate) {
    if (String(env.PAYPAL_ENV || '').trim() !== 'sandbox') {
      throw new Error('PAYPAL_ENV_NOT_SANDBOX: refusing to start. Set PAYPAL_ENV=sandbox, or pass --simulate.');
    }
    const clientId = String(env.PAYPAL_CLIENT_ID || '').trim();
    const clientSecret = String(env.PAYPAL_CLIENT_SECRET || '').trim();
    if (!clientId || !clientSecret) throw new Error('PAYPAL_KEYS_MISSING: set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET (Sandbox), or pass --simulate.');
    paypal = { clientId, clientSecret };
    ollamaApiKey = String(env.OLLAMA_API_KEY || '').trim();
  }
  const engine = createLiveEngine({ gateDir: GATE_DIR, simulate, paypal, ollamaApiKey, inferenceAdapter, pasteInReceipt });
  if (env === process.env) { // the engine holds its own copies; nothing else in this process needs them
    for (const k of ['PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET', 'OLLAMA_API_KEY']) delete process.env[k];
  }
  const token = crypto.randomBytes(16).toString('hex');
  const tokenBuf = Buffer.from(token);

  let boundPort = port;
  const hostOk = (req) => { const h = String(req.headers.host || ''); return h === `127.0.0.1:${boundPort}` || h === `localhost:${boundPort}`; };
  const originOk = (req) => { const o = req.headers.origin; return !o || o === `http://127.0.0.1:${boundPort}` || o === `http://localhost:${boundPort}`; };
  const tokenOk = (req) => {
    const got = Buffer.from(String(req.headers['x-approver-token'] || ''));
    return got.length === tokenBuf.length && crypto.timingSafeEqual(got, tokenBuf);
  };
  const send = (res, code, body, headers = {}) => {
    const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
    res.writeHead(code, { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...(typeof body === 'object' && !Buffer.isBuffer(body) ? { 'content-type': 'application/json; charset=utf-8' } : {}), ...headers });
    res.end(data);
  };
  const readJson = (req) => new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => { n += c.length; if (n > 65536) { reject(new Error('BODY_TOO_LARGE')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(new Error('BAD_JSON')); } });
    req.on('error', reject);
  });

  async function api(req, res, url) {
    const route = url.pathname.replace(/^\/api\/live\//, '');
    if (req.method === 'GET') {
      if (route === 'status') return send(res, 200, engine.status());
      if (route === 'receipt') {
        const x = await engine.exportReceipt();
        return send(res, 200, JSON.stringify(x.receipt, null, 2) + '\n', { 'content-type': 'application/json; charset=utf-8', 'content-disposition': `attachment; filename="desk-live-session-receipt-${engine.tag}.json"` });
      }
      if (route === 'receipt-pasted') {
        const x = await engine.exportPasted();
        return send(res, 200, JSON.stringify(x, null, 2) + '\n', { 'content-type': 'application/json; charset=utf-8', 'content-disposition': `attachment; filename="desk-live-pasted-invoices-${engine.tag}.json"` });
      }
      if (route === 'verify') {
        const x = await engine.exportReceipt();
        return send(res, 200, { ok: true, verifier: x.verdict, passes: x.passes, expectedPasses: x.expectedPasses, note: x.note, label: engine.label() });
      }
      return send(res, 404, { ok: false, error: 'NO_SUCH_ROUTE' });
    }
    if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'METHOD_NOT_ALLOWED' });
    if (!tokenOk(req)) return send(res, 403, { ok: false, error: 'BAD_TOKEN: the session token is wrong or missing. It is printed in the terminal where this server was started.' });
    let body;
    try { body = await readJson(req); } catch (e) { return send(res, 400, { ok: false, error: e.message }); }
    const target = String(body.target ?? '');
    switch (route) {
      case 'process': return send(res, 200, await engine.processNext());
      case 'paste': return send(res, 200, await engine.processPasted(body.text, body.poNumber));
      case 'approve': return send(res, 200, await engine.approve(target, body.approver));
      case 'reject': return send(res, 200, await engine.reject(target, body.approver));
      case 'again': return send(res, 200, await engine.again(target));
      case 'reset': return send(res, 200, await engine.reset());
      default: return send(res, 404, { ok: false, error: 'NO_SUCH_ROUTE' });
    }
  }

  function serveStatic(req, res, url) {
    let rel;
    try { rel = decodeURIComponent(url.pathname); } catch { return send(res, 400, 'bad path'); }
    if (rel.endsWith('/')) rel += 'index.html';
    const file = path.resolve(ROOT, '.' + rel);
    if (!(file === ROOT || file.startsWith(ROOT + path.sep)) || rel.split('/').some((p) => p.startsWith('.'))) return send(res, 404, 'not found');
    let st; try { st = fs.statSync(file); } catch { return send(res, 404, 'not found'); }
    if (!st.isFile()) return send(res, 404, 'not found');
    const ext = path.extname(file).toLowerCase();
    if (file === path.join(GATE_DIR, 'desk.html')) {
      // Served by this server only: the page may call its own origin, and it knows a local server is here.
      let html = fs.readFileSync(file, 'utf8');
      html = html.replace("connect-src 'none'", "connect-src 'self'").replace('<head>', '<head>\n<meta name="desk-live" content="1">');
      return send(res, 200, html, { 'content-type': MIME['.html'] });
    }
    res.writeHead(200, { 'content-type': MIME[ext] || 'application/octet-stream', 'content-length': st.size, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    fs.createReadStream(file).pipe(res);
  }

  const server = http.createServer(async (req, res) => {
    try {
      if (!hostOk(req) || !originOk(req)) return send(res, 403, { ok: false, error: 'HOST_OR_ORIGIN_REFUSED' });
      const url = new URL(req.url, `http://127.0.0.1:${boundPort}`);
      if (url.pathname.startsWith('/api/live/')) return await api(req, res, url);
      if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'method not allowed');
      return serveStatic(req, res, url);
    } catch (err) {
      return send(res, 500, { ok: false, error: engine.scrub(err?.message || err) });
    }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  boundPort = server.address().port;
  const url = `http://127.0.0.1:${boundPort}/gate/desk.html#live`;
  if (!quiet) {
    console.log(`desk server: ${simulate ? 'SIMULATED, no PayPal call' : 'live on your PayPal Sandbox'}`);
    console.log(`open: ${url}`);
    console.log(`session token: ${token}`);
    console.log('The token is a local shared secret for this server start, not a login. It stops other web pages in your browser from calling this server.');
    console.log(`proposals: ${engine.proposalSource()}`);
  }
  return { server, port: boundPort, token, url, engine, close: () => new Promise((r) => server.close(() => r())) };
}

const isMain = process.argv[1] && fs.existsSync(process.argv[1]) && fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url));
if (isMain) {
  const args = process.argv.slice(2);
  const pi = args.indexOf('--port');
  const port = pi >= 0 ? Number(args[pi + 1]) : 8787;
  try {
    await startDeskServer({ port, simulate: args.includes('--simulate') });
  } catch (err) {
    console.error(String(err.message || err).split('\n')[0]);
    process.exit(1);
  }
}
