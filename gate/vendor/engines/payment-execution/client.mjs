// PayPal sandbox Orders v2. No network implementation or credential storage.
export const SANDBOX_ORIGIN = 'https://api-m.sandbox.paypal.com';
const ORDER_PATH = '/v2/checkout/orders';
const MAX_REQUEST_BYTES = 262144, MAX_RESPONSE_BYTES = 262144;
// Only private validation signals enter this map; public errors never do.
const FAILURES = new WeakMap();
export class PaymentExecutionError extends Error {
  constructor(code, status) { super(code); this.name = 'PaymentExecutionError'; this.code = code; if (status !== undefined) this.status = status; }
}
function internalFailure(code, status) {
  const signal = Object.freeze(Object.create(null));
  FAILURES.set(signal, Object.freeze({code, status}));
  return signal;
}
const fail = code => { throw internalFailure(code); };
const publicFail = code => { throw new PaymentExecutionError(code); };
function bounded(code, fn) {
  try { return fn(); }
  catch (e) {
    const failure = FAILURES.get(e);
    throw new PaymentExecutionError(failure ? failure.code : code, failure?.status);
  }
}
const ORDER_STATUS = new Set(['CREATED','SAVED','APPROVED','VOIDED','COMPLETED','PAYER_ACTION_REQUIRED']);
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x) && (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
function jsonData(x, seen = new Set(), state = {bytes:0}, depth = 0) {
  if (depth > 64) fail('INVALID_JSON_DATA');
  if (typeof x === 'string') { state.bytes += Buffer.byteLength(x,'utf8'); if (state.bytes > MAX_REQUEST_BYTES) fail('REQUEST_TOO_LARGE'); }
  if (x === null || typeof x === 'string' || typeof x === 'boolean') return;
  if (typeof x === 'number' && Number.isFinite(x)) return;
  if (!Array.isArray(x) && !plain(x)) fail('INVALID_JSON_DATA');
  if (seen.has(x)) fail('INVALID_JSON_DATA'); seen.add(x);
  if (Array.isArray(x)) for (let i=0;i<x.length;i++) if (!Object.hasOwn(x,i)) fail('INVALID_JSON_DATA');
  for (const k of Object.getOwnPropertyNames(x).concat(Object.getOwnPropertySymbols(x))) {
    if (typeof k !== 'string') fail('INVALID_JSON_DATA');
    const d = Object.getOwnPropertyDescriptor(x,k);
    if (!d || !('value' in d) || (!d.enumerable && k !== 'length')) fail('INVALID_JSON_DATA');
    if (k !== 'length') { state.bytes += Buffer.byteLength(k,'utf8'); if (state.bytes > MAX_REQUEST_BYTES) fail('REQUEST_TOO_LARGE'); jsonData(d.value,seen,state,depth+1); }
  }
  seen.delete(x);
}
function orderId(id) { if (typeof id !== 'string' || !/^[A-Z0-9]{1,36}$/.test(id)) fail('INVALID_ORDER_ID'); return id; }
function requestId(id) { if (id !== undefined && (typeof id !== 'string' || id.length < 1 || id.length > 10000 || /[\r\n\0]/.test(id))) fail('INVALID_REQUEST_ID'); return id; }
function amount(a) {
  if (!plain(a) || typeof a.currency_code !== 'string' || !/^[A-Z]{3}$/.test(a.currency_code) || typeof a.value !== 'string' || a.value.length > 32 || !/^(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)$/.test(a.value)) fail('INVALID_AMOUNT');
  const [integer='0',fraction=''] = a.value.split('.');
  if (integer.length > 15 || !/[1-9]/.test(integer+fraction)) fail('INVALID_AMOUNT');
}
function decimalEqual(a,b) {
  const norm = s => { const [i='', f=''] = s.split('.'); return [i.replace(/^0+/,'') || '0',f.replace(/0+$/,'')]; };
  const x=norm(a),y=norm(b); return x[0]===y[0] && x[1]===y[1];
}
function bodyForCreate(body) {
  jsonData(body);
  if (!plain(body) || body.intent !== 'CAPTURE' || !Array.isArray(body.purchase_units) || body.purchase_units.length !== 1 || !plain(body.purchase_units[0])) fail('INVALID_ORDER');
  if (Object.hasOwn(body,'payment_source') && !plain(body.payment_source)) fail('INVALID_PAYMENT_SOURCE');
  amount(body.purchase_units[0].amount);
  const text=JSON.stringify(body); if (Buffer.byteLength(text,'utf8') > MAX_REQUEST_BYTES) fail('REQUEST_TOO_LARGE'); return text;
}
export function createSandboxClient({transport, authorization, origin = SANDBOX_ORIGIN, timeoutMs = 10000} = {}) {
  if (origin !== SANDBOX_ORIGIN) publicFail('INVALID_ORIGIN');
  if (typeof transport !== 'function') publicFail('INVALID_TRANSPORT');
  if (typeof authorization !== 'string' || !/^Bearer [^\s\r\n]+$/.test(authorization) || authorization.length > 8192) publicFail('INVALID_AUTHORIZATION');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) publicFail('INVALID_TIMEOUT');
  async function request(method, path, body, idempotency, signal) {
    bounded('INVALID_REQUEST_ID', () => requestId(idempotency));
    if (signal !== undefined && !(signal instanceof AbortSignal)) publicFail('INVALID_SIGNAL');
    if (signal?.aborted) publicFail('ABORTED');
    const controller=new AbortController(); let timer, listener, interruptionCode;
    // A request-local signal identifies only this request's own cancellation.
    const interruption=Object.freeze(Object.create(null));
    const abortPromise=new Promise((_,reject)=>{
      const interrupt=code=>{
        if (interruptionCode !== undefined) return;
        interruptionCode=code; controller.abort(); reject(interruption);
      };
      listener=()=>interrupt('ABORTED');
      if (signal) signal.addEventListener('abort',listener,{once:true});
      timer=setTimeout(()=>interrupt('TIMEOUT'),timeoutMs);
    });
    const headers={'Authorization':authorization,'Accept':'application/json'};
    if (body !== undefined) headers['Content-Type']='application/json';
    if (idempotency !== undefined) headers['PayPal-Request-Id']=idempotency;
    try {
      let response;
      try { response=await Promise.race([Promise.resolve().then(()=>transport({url:SANDBOX_ORIGIN+path,method,headers,body,signal:controller.signal})),abortPromise]); }
      catch (e) { publicFail(e === interruption ? interruptionCode : 'TRANSPORT_ERROR'); }
      return bounded('INVALID_TRANSPORT_RESPONSE', () => {
        if (!plain(response) || !('value' in (Object.getOwnPropertyDescriptor(response,'status') || {})) || !('value' in (Object.getOwnPropertyDescriptor(response,'body') || {}))) fail('INVALID_TRANSPORT_RESPONSE');
        if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599 || typeof response.body !== 'string') fail('INVALID_TRANSPORT_RESPONSE');
        if (Buffer.byteLength(response.body,'utf8') > MAX_RESPONSE_BYTES) fail('RESPONSE_TOO_LARGE');
        if (response.status < 200 || response.status >= 300) throw internalFailure('PROVIDER_HTTP_ERROR',response.status);
        let data; try { data=JSON.parse(response.body); } catch { fail('MALFORMED_PROVIDER_JSON'); }
        if (!plain(data) || typeof data.id !== 'string' || !/^[A-Z0-9]{1,36}$/.test(data.id)) fail('INVALID_PROVIDER_RESPONSE');
        const requested = path.match(/^\/v2\/checkout\/orders\/([A-Z0-9]+)(?:\/capture)?$/);
        if (requested && data.id !== requested[1]) fail('PROVIDER_ID_MISMATCH');
        return data;
      });
    } finally { clearTimeout(timer); if (signal && listener) signal.removeEventListener('abort',listener); }
  }
  return Object.freeze({
    createOrder(body,{requestId:id,signal}={}) { const encoded=bounded('INVALID_JSON_DATA',()=>bodyForCreate(body)); return request('POST',ORDER_PATH,encoded,id,signal); },
    getOrder(id,{signal}={}) { return request('GET',ORDER_PATH+'/'+bounded('INVALID_ORDER_ID',()=>orderId(id)),undefined,undefined,signal); },
    captureOrder(id,{requestId:rid,signal}={}) { return request('POST',ORDER_PATH+'/'+bounded('INVALID_ORDER_ID',()=>orderId(id))+'/capture','{}',rid,signal); },
  });
}
// Single-capture consistency only. A caller's trust declaration is not authentication.
// No totals, receipt creation, or paid state is produced here.
export function assessCapture({order, expected, trustedProviderRepresentation} = {}) {
  try {
    if (trustedProviderRepresentation !== true || !plain(order) || !plain(expected)) return {status:'quarantined'};
    orderId(expected.orderId); orderId(expected.captureId); amount(expected.amount);
    if (expected.environment !== 'sandbox' || typeof expected.merchantId !== 'string' || !expected.merchantId || order.id !== expected.orderId) return {status:'quarantined'};
    if (!Array.isArray(order.purchase_units) || order.purchase_units.length !== 1) return {status:'quarantined'};
    const unit=order.purchase_units[0], captures=unit?.payments?.captures;
    if (unit?.payee?.merchant_id !== expected.merchantId || !Array.isArray(captures)) return {status:'quarantined'};
    const rows=captures.filter(c=>plain(c) && c.id===expected.captureId);
    if (rows.length !== 1) return {status:'quarantined'};
    const row=rows[0]; amount(row.amount);
    if (row.amount.currency_code !== expected.amount.currency_code || !decimalEqual(row.amount.value,expected.amount.value)) return {status:'quarantined'};
    if (typeof order.status !== 'string' || !ORDER_STATUS.has(order.status) || order.status !== 'COMPLETED') return {status:'quarantined'};
    if (row.status==='COMPLETED') return {status:'capture_consistent'};
    if (row.status==='PENDING') return {status:'pending'};
    if (row.status==='DECLINED' || row.status==='FAILED') return {status:'unpaid'};
    return {status:'quarantined'};
  } catch { return {status:'quarantined'}; }
}
