// Explicit Node HTTPS transport for the registered PayPal sandbox client.
import { request as httpsRequest } from 'node:https';
import { PaymentExecutionError } from './client.mjs';
const HOST = 'api-m.sandbox.paypal.com';
const CAP = 262144;
const PATH = /^https:\/\/api-m\.sandbox\.paypal\.com(?::443)?(\/v2\/checkout\/orders(?:\/[A-Z0-9]{1,36}(?:\/capture)?)?)$/;
const error = code => new PaymentExecutionError(code);
const readAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const addEvent = EventTarget.prototype.addEventListener;
const removeEvent = EventTarget.prototype.removeEventListener;
function timeoutOption(options) {
  try {
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw 0;
    const descriptors = Object.getOwnPropertyDescriptors(options);
    if (Object.getOwnPropertyNames(descriptors).concat(Object.getOwnPropertySymbols(descriptors)).some(k => k !== 'timeoutMs')) throw 0;
    const descriptor = descriptors.timeoutMs;
    if (descriptor && !('value' in descriptor)) throw 0;
    const timeout = descriptor ? descriptor.value : 10000;
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 120000) throw 0;
    return timeout;
  } catch { throw error('INVALID_TRANSPORT_OPTIONS'); }
}
function validate(input) {
  // Snapshot only data properties; no caller-controlled header reaches HTTPS unchecked.
  let result;
  try {
    const fields = Object.getOwnPropertyDescriptors(input);
    const read = key => { const d = fields[key]; if (d && !('value' in d)) throw 0; return d?.value; };
    const url = read('url'), method = read('method'), body = read('body'), signal = read('signal');
    const match = typeof url === 'string' && PATH.exec(url);
    if (!match) throw 0;
    if (signal !== undefined) readAborted.call(signal);
    const path = match[1];
    const permitted = path === '/v2/checkout/orders' ? method === 'POST' : path.endsWith('/capture') ? method === 'POST' : method === 'GET';
    if (!permitted || (method === 'GET' ? body !== undefined : typeof body !== 'string')) throw 0;
    const descriptors = Object.getOwnPropertyDescriptors(read('headers'));
    const headers = {};
    for (const key of Object.getOwnPropertyNames(descriptors).concat(Object.getOwnPropertySymbols(descriptors))) {
      if (!['Authorization','Accept','Content-Type','PayPal-Request-Id'].includes(key)) throw 0;
      const d = descriptors[key]; if (!('value' in d) || typeof d.value !== 'string' || /[\r\n\0]/.test(d.value)) throw 0;
      headers[key] = d.value;
    }
    if (!/^Bearer [^\s]+$/.test(headers.Authorization) || headers.Authorization.length > 8192 || headers.Accept !== 'application/json') throw 0;
    if (body !== undefined ? headers['Content-Type'] !== 'application/json' : Object.hasOwn(headers,'Content-Type')) throw 0;
    if (Object.hasOwn(headers,'PayPal-Request-Id') && (headers['PayPal-Request-Id'].length < 1 || headers['PayPal-Request-Id'].length > 10000)) throw 0;
    result = {path, method, headers, body, signal};
  } catch { throw error('INVALID_TRANSPORT_REQUEST'); }
  if (result.body !== undefined && Buffer.byteLength(result.body, 'utf8') > CAP) throw error('REQUEST_TOO_LARGE');
  return result;
}
function buildTransport(request, timeoutMs) {
  return async input => {
    const {path, method, headers, body, signal} = validate(input);
    if (signal !== undefined && readAborted.call(signal)) throw error('ABORTED');
    return new Promise((resolve, reject) => {
      let req, response, timer, settled = false;
      let received = 0;
      const chunks = [];
      const onRequestError = () => finish('TRANSPORT_ERROR');
      const onResponseError = () => finish('TRANSPORT_ERROR');
      const onAborted = () => finish('TRANSPORT_ERROR');
      const onAbort = () => finish('ABORTED');
      const cleanRequest = () => { req?.removeListener('error', onRequestError); req?.removeListener('close', onRequestClose); };
      const cleanResponse = () => {
        if (!response) return;
        response.removeListener('data', onData); response.removeListener('end', onEnd);
        response.removeListener('aborted', onAborted); response.removeListener('error', onResponseError);
        response.removeListener('close', onResponseClose);
      };
      const onRequestClose = () => { if (!settled) finish('TRANSPORT_ERROR'); cleanRequest(); };
      const onResponseClose = () => { if (!settled) finish('TRANSPORT_ERROR'); cleanResponse(); };
      function finish(code, value) {
        if (settled) return;
        settled = true; clearTimeout(timer); if (signal !== undefined) removeEvent.call(signal, 'abort', onAbort);
        chunks.length = 0;
        if (response) {
          response.removeListener('data', onData); response.removeListener('end', onEnd);
          response.removeListener('aborted', onAborted);
          // Keep error handlers until close, so delayed socket errors cannot escape.
          response.destroy(); if (response.closed) cleanResponse();
        }
        req?.destroy(); if (req?.closed) cleanRequest();
        if (code) reject(error(code)); else resolve(value);
      }
      function onData(chunk) {
        if (settled) return;
        if (!Buffer.isBuffer(chunk)) { finish('TRANSPORT_ERROR'); return; }
        received += chunk.length;
        if (received > CAP) { finish('RESPONSE_TOO_LARGE'); return; }
        chunks.push(chunk);
      }
      function onEnd() {
        if (settled) return;
        if (!response.complete) { finish('TRANSPORT_ERROR'); return; }
        let text;
        try { text = new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks, received)); }
        catch { finish('INVALID_RESPONSE_UTF8'); return; }
        finish(undefined, {status: response.statusCode, body: text});
      }
      function onResponse(res) {
        response = res;
        res.on('error', onResponseError); res.once('close', onResponseClose);
        if (settled) { res.destroy(); return; }
        if (!Number.isInteger(res.statusCode) || res.statusCode < 100 || res.statusCode > 599) { finish('INVALID_TRANSPORT_RESPONSE'); return; }
        if (res.statusCode >= 300 && res.statusCode < 400) { finish('REDIRECT_REFUSED'); return; }
        const encoding = res.headers['content-encoding'];
        if (encoding !== undefined && encoding !== 'identity') { finish('UNSUPPORTED_CONTENT_ENCODING'); return; }
        res.on('data', onData); res.once('end', onEnd); res.once('aborted', onAborted);
      }
      if (signal !== undefined) addEvent.call(signal, 'abort', onAbort, {once: true});
      timer = setTimeout(() => finish('TRANSPORT_TIMEOUT'), timeoutMs);
      if (signal !== undefined && readAborted.call(signal)) { finish('ABORTED'); return; }
      try {
        req = request({protocol: 'https:', hostname: HOST, port: 443, servername: HOST,
          path, method, headers: {...headers, Connection: 'close'}, agent: false,
          rejectUnauthorized: true, maxHeaderSize: 16384}, onResponse);
        req.on('error', onRequestError); req.once('close', onRequestClose);
        if (settled) { req.destroy(); return; }
        req.end(body);
      } catch { finish('TRANSPORT_ERROR'); }
    });
  };
}
/** No I/O until the returned function is called. TLS verification cannot be disabled. */
export function createSandboxTransport(options = {}) {
  return buildTransport(httpsRequest, timeoutOption(options));
}
// Test-only dependency seam, deliberately absent from index.mjs. Validation and
// production HTTPS options run unchanged; tests remap only the actual socket open.
export function __createSandboxTransportForTest(request, options = {}) {
  if (typeof request !== 'function') throw error('INVALID_TRANSPORT_OPTIONS');
  return buildTransport(request, timeoutOption(options));
}
