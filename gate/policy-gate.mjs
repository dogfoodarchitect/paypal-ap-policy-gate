import { DEFAULT_PURCHASE_ORDERS } from './purchase-orders.mjs';

/**
 * policy-gate.mjs — External Deterministic Spend Policy Gate for PayPal Business AP
 *
 * The AI agent can only PROPOSE a payment (payee, amount, invoice, reason).
 * It holds zero PayPal credentials and cannot execute a payment.
 * PolicyGate deterministically enforces:
 *   1. Sandbox-only boundary (live payments fail closed)
 *   2. Required proposal schema & valid 2-decimal positive currency amount
 *   3. Allowed currency whitelist (`USD` default; `EUR`/`GBP` configurable)
 *   4. Canonical duplicate proposal ID & canonical duplicate invoice ID detection
 *      (NFKC, zero-width/format stripping, Cyrillic/Greek confusable folding,
 *      separator-invariant alphanumeric skeleton + leading-zero numeric segment key)
 *   5. Global per-transaction spend cap (`maxTransactionUsd`, default $2,500.00)
 *   6. Daily cumulative spend cap (`dailyCapUsd`, default $5,000.00)
 *   7. Approved supplier payee allowlist (email + optional merchantId + payment rail)
 *   8. Payee-and-amount duplicate hold (`duplicatePaymentHold`, default on): a proposal whose
 *      payee, amount and currency equal an invoice this gate already paid (or has in flight)
 *      is held as `POSSIBLE_DUPLICATE_PAYMENT` even when its invoice ID looks new
 *      (`INV-2O26-2043`, `2026-2043`, `INV-2026-2043A`, `Invoice INV-2026-2043`, `INV-2026-2043.0`).
 *      It runs last, so it only ever stops a proposal every other rule would have paid.
 *   9. Payment life cycle: an invoice is marked paid only after its PayPal capture completes.
 *      While a payment is in flight a second proposal for the same invoice is refused
 *      (`PAYMENT_IN_FLIGHT`); if the PayPal call fails the in-flight mark is released so a retry can pay.
 *
 * Every refused proposal fails closed with ZERO PayPal API calls and records
 * a hash-chained, Ed25519-signed REFUSED receipt in the ReceiptLedger.
 */

const CONFUSABLE_CHAR_MAP = Object.freeze({
  // Cyrillic uppercase & lowercase visual homoglyphs
  '\u0410': 'A', '\u0430': 'a', // А а
  '\u0412': 'B', '\u0432': 'b', // В в
  '\u0421': 'C', '\u0441': 'c', // С с
  '\u0415': 'E', '\u0435': 'e', // Е е
  '\u0401': 'E', '\u0451': 'e', // Ё ё
  '\u041D': 'H', '\u043D': 'h', // Н н
  '\u0406': 'I', '\u0456': 'i', // І і
  '\u0407': 'I', '\u0457': 'i', // Ї ї
  '\u04CF': 'l',                // ӏ
  '\u0408': 'J', '\u0458': 'j', // Ј ј
  '\u041A': 'K', '\u043A': 'k', // К к
  '\u041C': 'M', '\u043C': 'm', // М м
  '\u041E': 'O', '\u043E': 'o', // О о
  '\u0420': 'P', '\u0440': 'p', // Р р
  '\u0405': 'S', '\u0455': 's', // Ѕ ѕ
  '\u0422': 'T', '\u0442': 't', // Т т
  '\u0423': 'Y', '\u0443': 'y', // У у
  '\u04AE': 'Y', '\u04AF': 'y', // Ү ү
  '\u0425': 'X', '\u0445': 'x', // Х х
  '\u04BB': 'h',                // һ
  // Greek uppercase & lowercase visual homoglyphs
  '\u0391': 'A', '\u03B1': 'a', // Α α
  '\u0392': 'B', '\u03B2': 'b', // Β β
  '\u0395': 'E', '\u03B5': 'e', // Ε ε
  '\u0396': 'Z',                // Ζ
  '\u0397': 'H',                // Η
  '\u0399': 'I', '\u03B9': 'i', // Ι ι
  '\u039A': 'K', '\u03BA': 'k', // Κ κ
  '\u039C': 'M',                // Μ
  '\u039D': 'N', '\u03BD': 'v', // Ν ν
  '\u039F': 'O', '\u03BF': 'o', // Ο ο
  '\u03A1': 'P', '\u03C1': 'p', // Ρ ρ
  '\u03A4': 'T', '\u03C4': 't', // Τ τ
  '\u03A5': 'Y', '\u03C5': 'u', // Υ υ
  '\u03A7': 'X', '\u03C7': 'x', // Χ χ
  // Additional Latin/symbol confusables
  '\u0131': 'i', // dotless i
  '\u017F': 's', // long s
});

/**
 * Normalizes an invoice identifier into canonical deduplication keys so case changes,
 * whitespace, hyphens/underscores/dots/# prefixes, Unicode dashes/minus signs,
 * fullwidth forms, zero-width/soft-hyphen invisibles, Cyrillic/Greek look-alikes,
 * and leading-zero numeric segments (`INV-2026-02041` vs `INV-2026-2041`) all resolve
 * to the same canonical duplicate set without colliding distinct invoice numbers.
 * Any remaining non-ASCII alphanumeric script fails closed (`valid: false`).
 */
export function deriveInvoiceDedupKeys(rawInvoiceId) {
  if (typeof rawInvoiceId !== 'string') {
    return { valid: false, canonicalPrimary: '', keys: [] };
  }
  // 1. NFKC folds fullwidth, compatibility superscripts/math alphanumerics, etc.
  let s = rawInvoiceId.normalize('NFKC');
  // 2. Normalize whitespace tabs/newlines/Unicode spaces to ASCII space BEFORE stripping Cc
  s = s.replace(/[\t\r\n\v\f\p{Z}]+/gu, ' ');
  // 3. Strip zero-width / format / control / soft-hyphen / variation-selector invisibles
  s = s.replace(
    /[\p{Cc}\p{Cf}\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/gu,
    ''
  );
  // 4. Fold single-character visual homoglyphs (Cyrillic/Greek/Latin)
  let folded = '';
  for (const ch of s) {
    folded += CONFUSABLE_CHAR_MAP[ch] || ch;
  }
  const lowered = folded.trim().toLowerCase();
  if (!lowered) {
    return { valid: false, canonicalPrimary: '', keys: [] };
  }

  // 5. Reject any non-ASCII letter/number/mark that survived NFKC + confusable folding
  //    (only ASCII [a-z0-9], spaces, punctuation \p{P}, and symbols \p{S} like minus \u2212 are permitted)
  const strippedAllowed = lowered.replace(/[a-z0-9\s\p{P}\p{S}]/gu, '');
  if (strippedAllowed.length > 0) {
    return { valid: false, canonicalPrimary: '', keys: [] };
  }

  // 6. Build separator-invariant skeleton + leading-zero-normalized segment keys
  const skeleton = lowered.replace(/[^a-z0-9]/g, '');
  if (!skeleton) {
    return { valid: false, canonicalPrimary: '', keys: [] };
  }

  const tokens = lowered.match(/[a-z]+|\d+/g) || [skeleton];
  const zeroStrippedTokens = tokens.map((tok) =>
    /^\d+$/.test(tok) ? tok.replace(/^0+(?=\d)/, '') : tok
  );
  const segmentedKey = `seg:${zeroStrippedTokens.join(':')}`;
  const zeroStrippedSkeleton = `skel:${zeroStrippedTokens.join('')}`;
  const rawSkeletonKey = `skel:${skeleton}`;

  const uniqueKeys = [...new Set([rawSkeletonKey, zeroStrippedSkeleton, segmentedKey])];
  return {
    valid: true,
    canonicalPrimary: zeroStrippedSkeleton,
    keys: uniqueKeys,
  };
}

export function normalizeInvoiceId(rawInvoiceId) {
  const res = deriveInvoiceDedupKeys(rawInvoiceId);
  return res.valid ? res.canonicalPrimary : '';
}

export function parseAmountToCents(amountValue) {
  if (typeof amountValue === 'number') {
    if (!Number.isFinite(amountValue) || amountValue <= 0) return null;
    const cents = Math.round(amountValue * 100);
    if (!Number.isSafeInteger(cents) || cents <= 0) return null;
    const formatted = (cents / 100).toFixed(2);
    if (Math.abs(Number(formatted) - amountValue) > 1e-6) return null;
    return cents;
  }
  if (typeof amountValue === 'string') {
    const trimmed = amountValue.trim();
    if (!/^\d+(\.\d{1,2})?$/.test(trimmed)) return null;
    const [whole, frac = ''] = trimmed.split('.');
    const cents = Number(whole) * 100 + Number(frac.padEnd(2, '0'));
    if (!Number.isSafeInteger(cents) || cents <= 0) return null;
    return cents;
  }
  return null;
}

export const MAX_INVOICE_ID_LENGTH = 128;
export const SUPPLIER_DAILY_HOLD_CAP_CENTS = 250000;

export function formatCentsToAmount(cents) {
  if (!Number.isSafeInteger(cents) || cents < 0) {
    throw new Error(`Invalid integer cents: ${cents}`);
  }
  const whole = Math.floor(cents / 100);
  const frac = String(cents % 100).padStart(2, '0');
  return `${whole}.${frac}`;
}

export function normalizePayeeEntry(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('INVALID_PAYEE: payee entry must be an object');
  }
  const email = String(raw.email || raw.paypalReceiver || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    throw new Error('INVALID_PAYEE_EMAIL: payee requires a valid PayPal receiver email');
  }
  const displayName = String(raw.displayName || raw.name || raw.payeeId || email).trim();
  const payeeId = String(
    raw.payeeId ||
      displayName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
  ).trim();
  if (!payeeId) {
    throw new Error('INVALID_PAYEE_ID: payeeId must be non-empty');
  }
  const merchantId =
    raw.merchantId && String(raw.merchantId).trim()
      ? String(raw.merchantId).trim()
      : null;
  const rail = String(raw.rail || 'Orders v2').trim();
  const maxSingleOrderCents =
    Number.isSafeInteger(raw.maxSingleOrderCents) && raw.maxSingleOrderCents > 0
      ? raw.maxSingleOrderCents
      : null;

  return Object.freeze({
    payeeId,
    name: displayName,
    displayName,
    email,
    paypalReceiver: email,
    merchantId,
    rail,
    maxSingleOrderCents,
    category: raw.category || 'b2b-supplier',
  });
}

export const DEFAULT_AP_POLICY_GATE_CONFIG = Object.freeze({
  policyId: 'policy-paypal-ap-gate-v2',
  policyGeneration: 'po-v4',
  businessName: 'Synthetic 5-Invoice B2B Supplier Test Fixture (0 Live Customers)',
  maxTransactionCents: 250000, // $2,500.00 per-payment cap
  maxDailySpendCents: 500000,  // $5,000.00 daily cumulative cap
  supplierDailyHoldCapCents: SUPPLIER_DAILY_HOLD_CAP_CENTS, // hold when one supplier exceeds $2,500.00 today
  maxInvoiceIdLength: MAX_INVOICE_ID_LENGTH,
  duplicatePaymentHold: true,  // payee + amount + currency hold against look-alike invoice IDs
  purchaseOrders: DEFAULT_PURCHASE_ORDERS,
  allowedCurrencies: Object.freeze(['USD']),
  approvedPayees: Object.freeze([
    Object.freeze({
      payeeId: 'colombia-direct-beans',
      name: 'Colombia Direct Beans Co.',
      displayName: 'Colombia Direct Beans Co.',
      email: 'pay@colombia-direct-beans.example',
      paypalReceiver: 'pay@colombia-direct-beans.example',
      merchantId: 'MCH-COLOMBIA-BEANS-01',
      rail: 'Orders v2 + Invoicing v2',
      maxSingleOrderCents: null,
      category: 'raw-materials',
    }),
    Object.freeze({
      payeeId: 'cascade-packaging-co',
      name: 'Cascade Packaging Co.',
      displayName: 'Cascade Packaging Co.',
      email: 'billing@cascade-packaging.example',
      paypalReceiver: 'billing@cascade-packaging.example',
      merchantId: 'MCH-CASCADE-PKG-02',
      rail: 'Orders v2 + Payouts v1',
      maxSingleOrderCents: null,
      category: 'packaging',
    }),
    Object.freeze({
      payeeId: 'sound-freight-logistics',
      name: 'Sound Freight Logistics LLC',
      displayName: 'Sound Freight Logistics LLC',
      email: 'ap@sound-freight.example',
      paypalReceiver: 'ap@sound-freight.example',
      merchantId: 'MCH-SOUND-FREIGHT-03',
      rail: 'Orders v2',
      maxSingleOrderCents: null,
      category: 'freight-logistics',
    }),
  ]),
});

// Backwards-compatible export alias for existing callers and tests
export const DEFAULT_APEX_COFFEE_POLICY = DEFAULT_AP_POLICY_GATE_CONFIG;

export class PolicyGate {
  constructor(config = DEFAULT_AP_POLICY_GATE_CONFIG) {
    this.policyId = config.policyId || 'policy-paypal-ap-gate-v2';
    this.policyGeneration = config.policyGeneration || 'po-v4';
    this.businessName =
      config.businessName || 'Synthetic 5-Invoice B2B Supplier Test Fixture (0 Live Customers)';
    this.maxTransactionCents = config.maxTransactionCents ?? 250000;
    this.maxDailySpendCents = config.maxDailySpendCents ?? 500000;
    this.supplierDailyHoldCapCents = config.supplierDailyHoldCapCents ?? SUPPLIER_DAILY_HOLD_CAP_CENTS;
    this.maxInvoiceIdLength = config.maxInvoiceIdLength ?? MAX_INVOICE_ID_LENGTH;
    this.allowedCurrencies = new Set(
      (config.allowedCurrencies || ['USD']).map((c) => String(c).trim().toUpperCase()).filter(Boolean)
    );
    this.duplicatePaymentHold = config.duplicatePaymentHold !== false;

    this.approvedPayeesByEmail = new Map();
    for (const payee of config.approvedPayees || []) {
      const normalized = normalizePayeeEntry(payee);
      this.approvedPayeesByEmail.set(normalized.email, normalized);
    }

    this.purchaseOrders = new Map();
    for (const raw of config.purchaseOrders || DEFAULT_PURCHASE_ORDERS) {
      this._loadPurchaseOrder(raw);
    }

    this.dailySpendByDate = new Map();
    this.processedInvoices = new Set();
    this.processedInvoiceKeys = new Set();
    this.processedInvoiceKeysByPayee = new Map();
    this.processedProposals = new Set();
    // Payments whose capture completed: [{ invoiceId, payeeEmail, amountCents, currencyCode, dayKey, poNumber }]
    this.paidPayments = [];
    // proposalId -> in-flight reservation (admitted, PayPal call not yet complete)
    this.inFlight = new Map();
    // bindingKey -> hold / approval record
    this.holds = new Map();
  }

  _loadPurchaseOrder(raw) {
    if (!raw || typeof raw !== 'object') {
      throw new Error('INVALID_PURCHASE_ORDER: purchase order must be an object');
    }
    const poNumber = String(raw.poNumber || '').trim();
    if (!poNumber) throw new Error('INVALID_PURCHASE_ORDER: poNumber is required');
    const payeeEmail = String(raw.payeeEmail || '').trim().toLowerCase();
    const payeeId = String(raw.payeeId || '').trim();
    if (!payeeEmail || !payeeId) {
      throw new Error(`INVALID_PURCHASE_ORDER: ${poNumber} requires payeeId and payeeEmail`);
    }
    const currencyCode = String(raw.currencyCode || 'USD').trim().toUpperCase();
    const totalCents = Number.isSafeInteger(raw.totalCents)
      ? raw.totalCents
      : parseAmountToCents(raw.totalUsd ?? raw.total);
    if (!Number.isSafeInteger(totalCents) || totalCents <= 0) {
      throw new Error(`INVALID_PURCHASE_ORDER: ${poNumber} needs a positive total`);
    }
    const rec = {
      poNumber,
      payeeId,
      payeeEmail,
      currencyCode,
      totalCents,
      paidCents: Number.isSafeInteger(raw.paidCents) ? raw.paidCents : 0,
      inFlightCents: Number.isSafeInteger(raw.inFlightCents) ? raw.inFlightCents : 0,
      open: raw.open !== false,
    };
    this.purchaseOrders.set(poNumber, rec);
    return rec;
  }

  addPurchaseOrder(raw) {
    return this._loadPurchaseOrder(raw);
  }

  getPurchaseOrder(poNumber) {
    if (typeof poNumber !== 'string') return null;
    return this.purchaseOrders.get(poNumber.trim()) || null;
  }

  poBalanceCents(po) {
    if (!po) return 0;
    return po.totalCents - po.paidCents - po.inFlightCents;
  }

  getPoCard(poNumber) {
    const po = this.getPurchaseOrder(poNumber);
    if (!po) return null;
    const remaining = this.poBalanceCents(po);
    return {
      poNumber: po.poNumber,
      payeeId: po.payeeId,
      payeeEmail: po.payeeEmail,
      currencyCode: po.currencyCode,
      open: po.open,
      totalCents: po.totalCents,
      totalUsd: formatCentsToAmount(po.totalCents),
      paidCents: po.paidCents,
      inFlightCents: po.inFlightCents,
      remainingCents: remaining,
      remainingUsd: formatCentsToAmount(Math.max(0, remaining)),
    };
  }

  listPurchaseOrders() {
    return [...this.purchaseOrders.values()].map((po) => this.getPoCard(po.poNumber));
  }

  approvalBinding(proposal) {
    const amountCents = parseAmountToCents(proposal?.amountValue);
    return JSON.stringify({
      payeeId: String(proposal?.payeeId || '').trim(),
      payeeEmail: String(proposal?.payeeEmail || '').trim().toLowerCase(),
      payeeMerchantId: String(proposal?.payeeMerchantId || '').trim(),
      amountCents,
      currencyCode: String(proposal?.currencyCode || 'USD').trim().toUpperCase(),
      invoiceId: String(proposal?.invoiceId || '').trim(),
      poNumber: String(proposal?.poNumber || '').trim(),
    });
  }

  getHold(proposal) {
    return this.holds.get(this.approvalBinding(proposal)) || null;
  }

  listHolds() {
    return [...this.holds.values()].map((h) => ({ ...h, proposal: { ...h.proposal } }));
  }

  _keysForPayee(payeeEmail) {
    const key = String(payeeEmail || '').trim().toLowerCase();
    if (!this.processedInvoiceKeysByPayee.has(key)) {
      this.processedInvoiceKeysByPayee.set(key, new Set());
    }
    return this.processedInvoiceKeysByPayee.get(key);
  }

  _supplierSpendTodayCents(payeeEmail, isoTimestamp) {
    const dayKey = this.getUtcDayKey(isoTimestamp);
    const email = String(payeeEmail || '').trim().toLowerCase();
    let total = 0;
    for (const p of this.paidPayments) {
      if (p.payeeEmail === email && p.dayKey === dayKey) total += p.amountCents;
    }
    for (const r of this.inFlight.values()) {
      if (r.payeeEmail === email && r.dayKey === dayKey) total += r.amountCents;
    }
    return total;
  }

  _proposalFieldStrings(proposal) {
    if (!proposal || typeof proposal !== 'object') return [];
    const out = [];
    for (const v of Object.values(proposal)) {
      if (typeof v === 'string' && v.trim()) out.push(v.trim());
    }
    return out;
  }

  getUtcDayKey(isoTimestamp) {
    const d = isoTimestamp ? new Date(isoTimestamp) : new Date();
    if (Number.isNaN(d.getTime())) {
      return '1970-01-01';
    }
    return d.toISOString().slice(0, 10);
  }

  getDailySpendCents(isoTimestamp) {
    const dayKey = this.getUtcDayKey(isoTimestamp);
    return this.dailySpendByDate.get(dayKey) || 0;
  }

  getInFlightSpendCents(isoTimestamp) {
    const dayKey = this.getUtcDayKey(isoTimestamp);
    let total = 0;
    for (const r of this.inFlight.values()) {
      if (r.dayKey === dayKey) total += r.amountCents;
    }
    return total;
  }

  listApprovedPayees() {
    return [...this.approvedPayeesByEmail.values()];
  }

  addPayee(rawPayee) {
    const normalized = normalizePayeeEntry(rawPayee);
    this.approvedPayeesByEmail.set(normalized.email, normalized);
    return normalized;
  }

  removePayee(payeeIdOrEmail) {
    const key = String(payeeIdOrEmail || '').trim().toLowerCase();
    if (!key) return false;
    if (this.approvedPayeesByEmail.has(key)) {
      return this.approvedPayeesByEmail.delete(key);
    }
    for (const [email, p] of this.approvedPayeesByEmail.entries()) {
      if (p.payeeId.toLowerCase() === key) {
        return this.approvedPayeesByEmail.delete(email);
      }
    }
    return false;
  }

  /**
   * Mutates live spend policy rules on this PolicyGate instance after input validation.
   * Preserves cumulative settled daily spend and already-settled invoice IDs.
   */
  updatePolicy({ maxTransactionUsd, dailyCapUsd, allowedCurrencies, approvedPayees, duplicatePaymentHold } = {}) {
    if (duplicatePaymentHold !== undefined) {
      if (typeof duplicatePaymentHold !== 'boolean') {
        throw new Error('INVALID_DUPLICATE_PAYMENT_HOLD: duplicatePaymentHold must be true or false');
      }
      this.duplicatePaymentHold = duplicatePaymentHold;
    }

    if (maxTransactionUsd !== undefined) {
      const txCents = parseAmountToCents(maxTransactionUsd);
      if (txCents === null) {
        throw new Error('INVALID_MAX_TRANSACTION_USD: maxTransactionUsd must be a positive USD amount');
      }
      this.maxTransactionCents = txCents;
    }

    if (dailyCapUsd !== undefined) {
      const dayCents = parseAmountToCents(dailyCapUsd);
      if (dayCents === null) {
        throw new Error('INVALID_DAILY_CAP_USD: dailyCapUsd must be a positive USD amount');
      }
      this.maxDailySpendCents = dayCents;
    }

    if (allowedCurrencies !== undefined) {
      if (!Array.isArray(allowedCurrencies) || allowedCurrencies.length === 0) {
        throw new Error('INVALID_ALLOWED_CURRENCIES: at least one currency code is required');
      }
      const nextSet = new Set();
      for (const code of allowedCurrencies) {
        const clean = String(code || '').trim().toUpperCase();
        if (!/^[A-Z]{3}$/.test(clean)) {
          throw new Error(`INVALID_CURRENCY_CODE: ${String(code)}`);
        }
        nextSet.add(clean);
      }
      this.allowedCurrencies = nextSet;
    }

    if (approvedPayees !== undefined) {
      if (!Array.isArray(approvedPayees)) {
        throw new Error('INVALID_APPROVED_PAYEES: approvedPayees must be an array');
      }
      const nextMap = new Map();
      for (const raw of approvedPayees) {
        const normalized = normalizePayeeEntry(raw);
        nextMap.set(normalized.email, normalized);
      }
      this.approvedPayeesByEmail = nextMap;
    }

    return this.toPolicySnapshot();
  }

  toPolicySnapshot(isoTimestamp) {
    const settledCents = this.getDailySpendCents(isoTimestamp);
    const remainingCents = Math.max(0, this.maxDailySpendCents - settledCents);
    const payees = this.listApprovedPayees();
    return {
      policyId: this.policyId,
      maxTransactionCents: this.maxTransactionCents,
      maxTransactionUsd: formatCentsToAmount(this.maxTransactionCents),
      maxDailySpendCents: this.maxDailySpendCents,
      dailyCapUsd: formatCentsToAmount(this.maxDailySpendCents),
      settledTodayCents: settledCents,
      settledTodayUsd: formatCentsToAmount(settledCents),
      remainingDailyHeadroomCents: remainingCents,
      remainingDailyHeadroomUsd: formatCentsToAmount(remainingCents),
      allowedCurrencies: [...this.allowedCurrencies],
      duplicatePaymentHold: this.duplicatePaymentHold,
      approvedPayeesCount: payees.length,
      approvedPayees: payees.map((p) => ({
        payeeId: p.payeeId,
        displayName: p.displayName,
        name: p.name,
        paypalReceiver: p.paypalReceiver,
        email: p.email,
        merchantId: p.merchantId,
        rail: p.rail,
        maxSingleOrderUsd: p.maxSingleOrderCents ? formatCentsToAmount(p.maxSingleOrderCents) : null,
      })),
      settledInvoices: [...this.processedInvoices],
      policyGeneration: this.policyGeneration,
      supplierDailyHoldCapCents: this.supplierDailyHoldCapCents,
      supplierDailyHoldCapUsd: formatCentsToAmount(this.supplierDailyHoldCapCents),
      purchaseOrders: this.listPurchaseOrders(),
      holds: this.listHolds().map((h) => ({
        status: h.status,
        proposalId: h.proposalId,
        reasonCode: h.reasonCode,
        approvedBy: h.approvedBy,
        rejectedBy: h.rejectedBy,
        poNumber: h.proposal?.poNumber ?? null,
      })),
    };
  }

  _hasProcessedInvoice(rawInvoiceId, payeeEmail = null, extraInvoiceKeys = null) {
    const derived = deriveInvoiceDedupKeys(rawInvoiceId);
    if (payeeEmail) {
      const bag = this._keysForPayee(payeeEmail);
      if (derived.valid) {
        for (const k of derived.keys) {
          if (bag.has(k)) return true;
          if (extraInvoiceKeys && extraInvoiceKeys.has(k)) return true;
        }
      }
      return false;
    }
    // Compatibility fallback used only when no payee is known yet.
    if (this.processedInvoices.has(rawInvoiceId)) return true;
    if (!derived.valid) return false;
    for (const k of derived.keys) {
      if (this.processedInvoiceKeys.has(k)) return true;
      if (extraInvoiceKeys && extraInvoiceKeys.has(k)) return true;
    }
    return false;
  }

  _findInFlightForInvoice(rawInvoiceId, payeeEmail = null) {
    const derived = deriveInvoiceDedupKeys(rawInvoiceId);
    const email = payeeEmail ? String(payeeEmail).trim().toLowerCase() : null;
    for (const r of this.inFlight.values()) {
      if (email && r.payeeEmail !== email) continue;
      if (r.invoiceId === rawInvoiceId) return r;
      if (derived.valid && derived.keys.some((k) => r.invoiceKeys.includes(k))) return r;
    }
    return null;
  }

  /**
   * Looks for a payment (already paid, or in flight) to the same payee for the same amount
   * and currency. Used by the payee-and-amount duplicate hold.
   */
  _findSamePayeeAmountPayment(payeeEmail, amountCents, currencyCode) {
    for (const p of this.paidPayments) {
      if (p.payeeEmail === payeeEmail && p.amountCents === amountCents && p.currencyCode === currencyCode) {
        return { ...p, state: 'paid' };
      }
    }
    for (const r of this.inFlight.values()) {
      if (r.payeeEmail === payeeEmail && r.amountCents === amountCents && r.currencyCode === currencyCode) {
        return { invoiceId: r.invoiceId, payeeEmail: r.payeeEmail, amountCents: r.amountCents, currencyCode: r.currencyCode, state: 'in-flight' };
      }
    }
    return null;
  }

  evaluate(
    proposal,
    {
      timestamp = new Date().toISOString(),
      ignoreProcessedProposalId = false,
      additionalSimulatedSpendCents = 0,
      simulatedInvoiceKeys = null,
      simulatedProposalIds = null,
      bypassDuplicateHold = false,
      skipHolds = false,
    } = {}
  ) {
    const dayKey = this.getUtcDayKey(timestamp);
    const realSettledBeforeCents = (this.dailySpendByDate.get(dayKey) || 0) + this.getInFlightSpendCents(timestamp);
    const dailySpendBeforeCents = realSettledBeforeCents + (Number(additionalSimulatedSpendCents) || 0);

    const baseExtra = (extra = {}) => ({
      poNumber: extra.poNumber ?? proposal?.poNumber ?? null,
      poCard: extra.poCard ?? null,
      amountCents: extra.amountCents ?? null,
      payeeId: extra.payeeId ?? proposal?.payeeId ?? null,
      payeeMerchantId: extra.payeeMerchantId ?? proposal?.payeeMerchantId ?? null,
    });

    const fail = (reasonCode, reasonDetail, extra = {}) =>
      Object.freeze({
        admitted: false,
        decision: 'DENY',
        policyId: this.policyId,
        policyGeneration: this.policyGeneration,
        reasonCode,
        reasonDetail,
        proposalId: proposal?.proposalId ?? null,
        invoiceId: proposal?.invoiceId ?? null,
        payeeEmail: proposal?.payeeEmail ?? null,
        payeeId: extra.payeeId ?? proposal?.payeeId ?? null,
        payeeMerchantId: extra.payeeMerchantId ?? proposal?.payeeMerchantId ?? null,
        amountCents: extra.amountCents ?? null,
        currencyCode: extra.currencyCode ?? proposal?.currencyCode ?? 'USD',
        poNumber: extra.poNumber ?? proposal?.poNumber ?? null,
        poCard: extra.poCard ?? null,
        dailySpendBeforeCents,
        dailySpendAfterCents: dailySpendBeforeCents,
        maxTransactionCents: this.maxTransactionCents,
        maxDailySpendCents: this.maxDailySpendCents,
        supplierDailyHoldCapCents: this.supplierDailyHoldCapCents,
        evaluatedAt: timestamp,
      });

    const hold = (reasonCode, reasonDetail, extra = {}) => {
      const verdict = Object.freeze({
        admitted: false,
        decision: 'HOLD',
        policyId: this.policyId,
        policyGeneration: this.policyGeneration,
        reasonCode,
        reasonDetail,
        proposalId: proposal?.proposalId ?? null,
        invoiceId: proposal?.invoiceId ?? null,
        payeeEmail: extra.payeeEmail ?? proposal?.payeeEmail ?? null,
        payeeName: extra.payeeName ?? null,
        payeeId: extra.payeeId ?? proposal?.payeeId ?? null,
        payeeMerchantId: extra.payeeMerchantId ?? proposal?.payeeMerchantId ?? null,
        amountCents: extra.amountCents ?? null,
        amountValue: extra.amountCents != null ? formatCentsToAmount(extra.amountCents) : null,
        currencyCode: extra.currencyCode ?? proposal?.currencyCode ?? 'USD',
        poNumber: extra.poNumber ?? proposal?.poNumber ?? null,
        poCard: extra.poCard ?? null,
        dailySpendBeforeCents,
        dailySpendAfterCents: dailySpendBeforeCents,
        maxTransactionCents: this.maxTransactionCents,
        maxDailySpendCents: this.maxDailySpendCents,
        supplierDailyHoldCapCents: this.supplierDailyHoldCapCents,
        evaluatedAt: timestamp,
      });
      const binding = this.approvalBinding(proposal);
      const existing = this.holds.get(binding);
      if (!existing || existing.status === 'held') {
        this.holds.set(binding, {
          status: 'held',
          binding,
          proposalId: proposal.proposalId,
          proposal: {
            proposalId: proposal.proposalId,
            invoiceId: proposal.invoiceId,
            payeeId: proposal.payeeId,
            payeeEmail: proposal.payeeEmail,
            payeeMerchantId: proposal.payeeMerchantId,
            amountValue: proposal.amountValue,
            currencyCode: proposal.currencyCode,
            poNumber: proposal.poNumber,
            reason: proposal.reason,
          },
          reasonCode,
          reasonDetail,
          verdict,
          approvedBy: null,
          approvedAt: null,
          rejectedBy: null,
          rejectedAt: null,
        });
      }
      return verdict;
    };

    if (!proposal || typeof proposal !== 'object') {
      return fail('INVALID_PROPOSAL', 'Proposal must be a non-null object');
    }

    // Strict live flag: any value other than boolean false (or a missing flag) is forbidden.
    if (Object.prototype.hasOwnProperty.call(proposal, 'live') && proposal.live !== false) {
      return fail(
        'LIVE_MODE_FORBIDDEN',
        'Live payment execution is strictly forbidden; only PayPal Sandbox is permitted'
      );
    }
    if (proposal.environment === 'live' || proposal.mode === 'live') {
      return fail(
        'LIVE_MODE_FORBIDDEN',
        'Live payment execution is strictly forbidden; only PayPal Sandbox is permitted'
      );
    }

    if (
      typeof proposal.proposalId !== 'string' || !proposal.proposalId.trim() ||
      typeof proposal.invoiceId !== 'string' || !proposal.invoiceId.trim() ||
      typeof proposal.payeeEmail !== 'string' || !proposal.payeeEmail.trim() ||
      typeof proposal.reason !== 'string' || !proposal.reason.trim()
    ) {
      return fail(
        'MISSING_REQUIRED_FIELDS',
        'Proposal requires non-empty proposalId, invoiceId, payeeEmail, and reason'
      );
    }

    // Amount and invoice shape are checked before numbered policy rules so a
    // bad number or an over-long id refuses instead of throwing later.
    const amountCents = parseAmountToCents(proposal.amountValue);
    if (amountCents === null) {
      return fail(
        'INVALID_AMOUNT',
        `Invalid payment amount: ${String(proposal.amountValue)} (must be positive 2-decimal currency value)`
      );
    }

    const rawInvoiceId = proposal.invoiceId.trim();
    if (rawInvoiceId.length > this.maxInvoiceIdLength) {
      return fail(
        'INVALID_INVOICE_ID',
        `Invoice ID exceeds the ${this.maxInvoiceIdLength}-character limit`,
        { amountCents }
      );
    }

    const invoiceDedup = deriveInvoiceDedupKeys(rawInvoiceId);
    if (!invoiceDedup.valid) {
      return fail(
        'INVALID_INVOICE_ID',
        `Invoice ID ${proposal.invoiceId} contains unsupported non-ASCII script or empty identifier`,
        { amountCents }
      );
    }

    if (
      !ignoreProcessedProposalId &&
      (this.processedProposals.has(proposal.proposalId) ||
        this.inFlight.has(proposal.proposalId) ||
        (simulatedProposalIds && simulatedProposalIds.has(proposal.proposalId)))
    ) {
      return fail(
        'DUPLICATE_PROPOSAL',
        `Proposal ID ${proposal.proposalId} has already been processed`,
        { amountCents }
      );
    }

    // Rule 1: payee id, PayPal email and merchant id must all match the register.
    const payeeKey = proposal.payeeEmail.trim().toLowerCase();
    const proposedPayeeId = String(proposal.payeeId || '').trim();
    const proposedMerchantId = String(proposal.payeeMerchantId || '').trim();
    let approvedPayee = this.approvedPayeesByEmail.get(payeeKey) || null;
    if (!approvedPayee) {
      return fail(
        'UNAPPROVED_PAYEE',
        `Payee ${proposal.payeeEmail} is not in the approved supplier allowlist`,
        { amountCents }
      );
    }
    if (!proposedPayeeId || approvedPayee.payeeId.toLowerCase() !== proposedPayeeId.toLowerCase()) {
      return fail(
        'UNAPPROVED_PAYEE',
        `Payee id ${proposedPayeeId || '(missing)'} does not match the registered supplier ${approvedPayee.payeeId}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId }
      );
    }
    if (approvedPayee.merchantId) {
      if (!proposedMerchantId || proposedMerchantId !== approvedPayee.merchantId) {
        return fail(
          'UNAPPROVED_PAYEE',
          `Payee merchant ID ${proposedMerchantId || '(missing)'} does not match registered merchant ID ${approvedPayee.merchantId}`,
          { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId }
        );
      }
    } else if (proposedMerchantId) {
      return fail(
        'UNAPPROVED_PAYEE',
        `Payee merchant ID ${proposedMerchantId} is not registered for supplier ${approvedPayee.payeeId}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: null }
      );
    }

    // Rule 2: USD only (or the configured allowlist, which defaults to USD).
    const currencyCode = String(proposal.currencyCode || 'USD').toUpperCase();
    if (!this.allowedCurrencies.has(currencyCode)) {
      return fail(
        'UNSUPPORTED_CURRENCY',
        `Currency ${currencyCode} is not in allowed policy set [${[...this.allowedCurrencies].join(', ')}]`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId }
      );
    }

    // Rule 3: purchase-order match.
    const poNumber = typeof proposal.poNumber === 'string' ? proposal.poNumber.trim() : '';
    if (!poNumber) {
      return fail(
        'UNKNOWN_PURCHASE_ORDER',
        'Proposal must cite an open purchase order (poNumber)',
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId }
      );
    }
    const po = this.getPurchaseOrder(poNumber);
    if (!po || po.open !== true) {
      return fail(
        'UNKNOWN_PURCHASE_ORDER',
        `Purchase order ${poNumber} is not on the open register`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber }
      );
    }
    if (po.payeeId.toLowerCase() !== approvedPayee.payeeId.toLowerCase() || po.payeeEmail !== approvedPayee.email) {
      return fail(
        'PAYEE_NOT_ON_PURCHASE_ORDER',
        `Supplier ${approvedPayee.payeeId} is not the payee on purchase order ${poNumber}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard: this.getPoCard(poNumber) }
      );
    }
    if (po.currencyCode !== currencyCode) {
      return fail(
        'UNKNOWN_PURCHASE_ORDER',
        `Purchase order ${poNumber} is in ${po.currencyCode}, not ${currencyCode}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard: this.getPoCard(poNumber) }
      );
    }
    const poRemaining = this.poBalanceCents(po);
    if (amountCents > poRemaining) {
      return fail(
        'OVER_PURCHASE_ORDER_BALANCE',
        `Proposed amount $${formatCentsToAmount(amountCents)} exceeds remaining balance $${formatCentsToAmount(Math.max(0, poRemaining))} on purchase order ${poNumber}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard: this.getPoCard(poNumber) }
      );
    }
    const poCard = this.getPoCard(poNumber);

    // Rule 4: per-payment cap (and optional per-supplier cap).
    if (amountCents > this.maxTransactionCents) {
      return fail(
        'OVER_TRANSACTION_CAP',
        `Proposed amount $${formatCentsToAmount(amountCents)} exceeds per-payment cap of $${formatCentsToAmount(this.maxTransactionCents)}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard }
      );
    }
    if (
      Number.isSafeInteger(approvedPayee.maxSingleOrderCents) &&
      amountCents > approvedPayee.maxSingleOrderCents
    ) {
      return fail(
        'OVER_TRANSACTION_CAP',
        `Proposed amount $${formatCentsToAmount(amountCents)} exceeds supplier cap of $${formatCentsToAmount(approvedPayee.maxSingleOrderCents)} for ${approvedPayee.name}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard }
      );
    }

    // Rule 5: daily cap across all suppliers.
    if (dailySpendBeforeCents + amountCents > this.maxDailySpendCents) {
      return fail(
        'OVER_DAILY_SPEND_CAP',
        `Proposed amount $${formatCentsToAmount(amountCents)} plus daily spend $${formatCentsToAmount(dailySpendBeforeCents)} exceeds daily cap of $${formatCentsToAmount(this.maxDailySpendCents)}`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard }
      );
    }

    // Rule 6: duplicate invoice, per supplier, and in-flight on that supplier.
    if (this._hasProcessedInvoice(proposal.invoiceId, approvedPayee.email, simulatedInvoiceKeys)) {
      return fail(
        'DUPLICATE_INVOICE',
        `Invoice ${proposal.invoiceId} has already been paid to ${approvedPayee.email}; duplicate payment blocked`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard }
      );
    }
    const inFlightSame = this._findInFlightForInvoice(proposal.invoiceId, approvedPayee.email);
    if (inFlightSame) {
      return fail(
        'PAYMENT_IN_FLIGHT',
        `Invoice ${proposal.invoiceId} matches invoice ${inFlightSame.invoiceId}, whose PayPal payment is still in flight; second payment blocked`,
        { amountCents, payeeId: approvedPayee.payeeId, payeeMerchantId: approvedPayee.merchantId, poNumber, poCard }
      );
    }

    const alreadyApproved = (() => {
      const rec = this.holds.get(this.approvalBinding(proposal));
      return rec && rec.status === 'approved';
    })();
    const holdsActive = this.duplicatePaymentHold && !bypassDuplicateHold && !skipHolds && !alreadyApproved;

    // Rule 7a: same supplier, amount and currency as a payment already made or in flight.
    if (holdsActive) {
      const same = this._findSamePayeeAmountPayment(approvedPayee.email, amountCents, currencyCode);
      if (same) {
        return hold(
          'POSSIBLE_DUPLICATE_PAYMENT',
          `Payee ${approvedPayee.email}, amount $${formatCentsToAmount(amountCents)} ${currencyCode} equals ${same.state === 'paid' ? 'an already-paid' : 'an in-flight'} invoice (${same.invoiceId}); held for one human approval because ${proposal.invoiceId} is not recognised as the same invoice`,
          {
            amountCents,
            payeeId: approvedPayee.payeeId,
            payeeMerchantId: approvedPayee.merchantId,
            payeeEmail: approvedPayee.email,
            payeeName: approvedPayee.name,
            poNumber,
            poCard,
            currencyCode,
          }
        );
      }
    }

    // Rule 7b: supplier payments today, with this one, add up to more than $2,500.00.
    if (holdsActive) {
      const supplierToday = this._supplierSpendTodayCents(approvedPayee.email, timestamp);
      if (supplierToday + amountCents > this.supplierDailyHoldCapCents) {
        return hold(
          'SUPPLIER_DAILY_TOTAL_OVER_CAP',
          `Supplier ${approvedPayee.name} would reach $${formatCentsToAmount(supplierToday + amountCents)} today, above the $${formatCentsToAmount(this.supplierDailyHoldCapCents)} split-hold cap; held for one human approval`,
          {
            amountCents,
            payeeId: approvedPayee.payeeId,
            payeeMerchantId: approvedPayee.merchantId,
            payeeEmail: approvedPayee.email,
            payeeName: approvedPayee.name,
            poNumber,
            poCard,
            currencyCode,
          }
        );
      }
    }

    const effectiveSingleCap = Number.isSafeInteger(approvedPayee.maxSingleOrderCents)
      ? Math.min(this.maxTransactionCents, approvedPayee.maxSingleOrderCents)
      : this.maxTransactionCents;

    return Object.freeze({
      admitted: true,
      decision: 'ALLOW',
      policyId: this.policyId,
      policyGeneration: this.policyGeneration,
      reasonCode: 'POLICY_ADMITTED',
      reasonDetail: `Approved payment of $${formatCentsToAmount(amountCents)} ${currencyCode} to allowlisted supplier ${approvedPayee.name} (${approvedPayee.payeeId}) for invoice ${proposal.invoiceId} against ${poNumber}`,
      proposalId: proposal.proposalId,
      invoiceId: proposal.invoiceId,
      payeeEmail: approvedPayee.email,
      payeeName: approvedPayee.name,
      payeeId: approvedPayee.payeeId,
      payeeMerchantId: approvedPayee.merchantId,
      rail: approvedPayee.rail,
      amountCents,
      amountValue: formatCentsToAmount(amountCents),
      currencyCode,
      poNumber,
      poCard,
      dailySpendBeforeCents,
      dailySpendAfterCents: dailySpendBeforeCents + amountCents,
      maxTransactionCents: effectiveSingleCap,
      maxDailySpendCents: this.maxDailySpendCents,
      supplierDailyHoldCapCents: this.supplierDailyHoldCapCents,
      evaluatedAt: timestamp,
    });
  }

  /**
   * A named person approves a held payment once. The approval is bound to the
   * exact proposal (supplier, amount, currency, invoice number, PO). Rules 1–6
   * are checked again. A refusal under those rules cannot be approved. Nothing
   * in the invoice or the model proposal can approve anything.
   */
  approveHeldProposal(proposal, { approvedBy, timestamp = new Date().toISOString(), ledger = null } = {}) {
    if (typeof approvedBy !== 'string' || !approvedBy.trim()) {
      throw new Error('APPROVAL_REQUIRES_NAMED_PERSON: approvedBy must be a non-empty name');
    }
    const name = approvedBy.trim();
    const forbidden = this._proposalFieldStrings(proposal);
    if (forbidden.includes(name)) {
      throw new Error('APPROVAL_FROM_PROPOSAL_FORBIDDEN: nothing in an invoice or a model proposal can approve a payment');
    }
    const binding = this.approvalBinding(proposal);
    const rec = this.holds.get(binding);
    if (!rec || rec.status === 'rejected') {
      throw new Error('NOT_HELD: only a held payment can be approved');
    }
    if (rec.status === 'approved') {
      if (rec.approvedBy === name) {
        return { ok: true, idempotent: true, status: 'APPROVED', hold: rec, verdict: rec.approvalVerdict };
      }
      throw new Error('ALREADY_APPROVED: this held payment has already been approved once');
    }

    const recheck = this.evaluate(proposal, { timestamp, skipHolds: true });
    if (!recheck.admitted) {
      return { ok: false, status: 'DENIED', verdict: recheck, hold: rec };
    }

    rec.status = 'approved';
    rec.approvedBy = name;
    rec.approvedAt = timestamp;
    rec.approvalVerdict = recheck;
    rec.binding = binding;

    let receipt = null;
    if (ledger) {
      receipt = ledger.append({
        stage: 'APPROVED',
        timestamp,
        proposalId: proposal.proposalId,
        actor: `approver:${name}`,
        payload: {
          approvedBy: name,
          binding,
          invoiceId: proposal.invoiceId,
          payeeId: proposal.payeeId,
          payeeEmail: proposal.payeeEmail,
          payeeMerchantId: proposal.payeeMerchantId,
          amountValue: proposal.amountValue,
          currencyCode: proposal.currencyCode,
          poNumber: proposal.poNumber,
          holdReasonCode: rec.reasonCode,
        },
        policyVerdict: recheck,
        paypalOrderId: null,
        paypalCaptureId: null,
      });
      rec.approvalReceiptId = receipt.receiptHash;
    }
    return { ok: true, idempotent: false, status: 'APPROVED', hold: rec, verdict: recheck, receipt };
  }

  rejectHeldProposal(proposal, { rejectedBy, timestamp = new Date().toISOString(), ledger = null } = {}) {
    if (typeof rejectedBy !== 'string' || !rejectedBy.trim()) {
      throw new Error('REJECTION_REQUIRES_NAMED_PERSON: rejectedBy must be a non-empty name');
    }
    const name = rejectedBy.trim();
    const binding = this.approvalBinding(proposal);
    const rec = this.holds.get(binding);
    if (!rec || rec.status === 'rejected') {
      throw new Error('NOT_HELD: only a held payment can be rejected');
    }
    if (rec.status === 'approved') {
      throw new Error('ALREADY_APPROVED: an approved payment cannot be rejected');
    }
    rec.status = 'rejected';
    rec.rejectedBy = name;
    rec.rejectedAt = timestamp;
    let receipt = null;
    if (ledger) {
      receipt = ledger.append({
        stage: 'REJECTED',
        timestamp,
        proposalId: proposal.proposalId,
        actor: `approver:${name}`,
        payload: {
          rejectedBy: name,
          binding,
          invoiceId: proposal.invoiceId,
          payeeId: proposal.payeeId,
          poNumber: proposal.poNumber,
          holdReasonCode: rec.reasonCode,
        },
        paypalOrderId: null,
        paypalCaptureId: null,
      });
    }
    return { ok: true, status: 'REJECTED', hold: rec, receipt };
  }

  /**
   * Marks an admitted proposal as in flight. The invoice is NOT on the paid list yet, but a second
   * proposal for the same invoice (or the same payee/amount) is refused until this one settles or fails.
   * Counts toward the daily cap while in flight.
   */
  reserveAdmission(proposal, verdict) {
    if (!verdict || verdict.admitted !== true) {
      throw new Error('Cannot reserve a non-admitted policy verdict');
    }
    const derived = deriveInvoiceDedupKeys(proposal.invoiceId);
    const poNumber = verdict.poNumber || proposal.poNumber || null;
    if (poNumber) {
      const po = this.getPurchaseOrder(poNumber);
      if (po) po.inFlightCents += verdict.amountCents;
    }
    this.inFlight.set(proposal.proposalId, {
      proposalId: proposal.proposalId,
      invoiceId: proposal.invoiceId,
      invoiceKeys: derived.keys,
      payeeEmail: verdict.payeeEmail,
      amountCents: verdict.amountCents,
      currencyCode: verdict.currencyCode,
      dayKey: this.getUtcDayKey(verdict.evaluatedAt),
      poNumber,
    });
  }

  /** Releases an in-flight mark after a failed PayPal call so a retry can pay. */
  releaseAdmission(proposal) {
    const rec = this.inFlight.get(proposal?.proposalId);
    if (rec?.poNumber) {
      const po = this.getPurchaseOrder(rec.poNumber);
      if (po) po.inFlightCents = Math.max(0, po.inFlightCents - rec.amountCents);
    }
    return this.inFlight.delete(proposal?.proposalId);
  }

  /** Puts the invoice on the paid list. Call after the capture completes (or directly for replayed history). */
  commitAdmission(proposal, verdict) {
    if (!verdict || verdict.admitted !== true) {
      throw new Error('Cannot commit a non-admitted policy verdict');
    }
    const reserved = this.inFlight.get(proposal.proposalId);
    this.inFlight.delete(proposal.proposalId);
    const dayKey = this.getUtcDayKey(verdict.evaluatedAt);
    const current = this.dailySpendByDate.get(dayKey) || 0;
    this.dailySpendByDate.set(dayKey, current + verdict.amountCents);
    this.processedInvoices.add(proposal.invoiceId);
    const derived = deriveInvoiceDedupKeys(proposal.invoiceId);
    for (const k of derived.keys) {
      this.processedInvoiceKeys.add(k);
    }
    const payeeEmail = verdict.payeeEmail || proposal.payeeEmail || null;
    if (payeeEmail && derived.valid) {
      const bag = this._keysForPayee(payeeEmail);
      for (const k of derived.keys) bag.add(k);
    }
    this.processedProposals.add(proposal.proposalId);
    const poNumber = verdict.poNumber || proposal.poNumber || reserved?.poNumber || null;
    if (poNumber) {
      const po = this.getPurchaseOrder(poNumber);
      if (po) {
        if (reserved) {
          po.inFlightCents = Math.max(0, po.inFlightCents - verdict.amountCents);
        }
        po.paidCents += verdict.amountCents;
      }
    }
    this.paidPayments.push({
      invoiceId: proposal.invoiceId,
      payeeEmail: verdict.payeeEmail,
      amountCents: verdict.amountCents,
      currencyCode: verdict.currencyCode,
      dayKey,
      poNumber,
    });
  }
}

/**
 * Replays already-paid history (a suite record's `setup` list) into a fresh gate with 0 PayPal calls.
 * History is not judged by the payee-and-amount hold: two earlier payments of the same size to the same
 * supplier really happened. The hold applies to every NEW proposal evaluated afterwards.
 */
export function replayPaidHistory(gate, setup, timestamp) {
  for (const s of setup || []) {
    const v = gate.evaluate(s, { timestamp, bypassDuplicateHold: true });
    if (!v.admitted) {
      throw new Error(`SUITE_SETUP_REFUSED: ${s.proposalId} failed with ${v.reasonCode}`);
    }
    gate.commitAdmission(s, v);
  }
  return gate;
}

/**
 * Orchestrates an AI agent's payment proposal through the PolicyGate,
 * PayPalSandboxClient, and ReceiptLedger.
 *
 * Guarantees:
 * - Every proposal first writes a PROPOSED receipt.
 * - Any policy refusal writes a REFUSED receipt and makes 0 PayPal API calls.
 * - Admitted proposals write an ADMITTED receipt, execute through PayPal Sandbox
 *   Orders v2 (createOrder + captureOrder + optional Invoicing/Payouts surface),
 *   and write an EXECUTED receipt linked to the PayPal Order & Capture IDs.
 */
export async function processAgentPaymentProposal({
  proposal,
  policyGate,
  paypalClient,
  ledger,
  timestamp = new Date().toISOString(),
  captureImmediately = true,
  createInvoiceRecord = false,
  createPayoutRecord = false,
  simulatedPreviewOnly = false,
  evaluateOptions = {},
  // Multi-rail mode: after the capture, also create the Invoicing v2 draft and/or the Payouts v1
  // voucher that the approved payee's rail names. A follow-up failure after a completed capture is
  // recorded in the EXECUTED payload (never thrown, the capture is real) instead of being hidden.
  railFollowups = false,
  railInvoiceNumberSuffix = '',
}) {
  const apiCallsBefore = paypalClient.getApiCallCount();

  const proposedReceipt = ledger.append({
    stage: 'PROPOSED',
    timestamp,
    proposalId: proposal?.proposalId || null,
    actor: proposal?.agentId || 'agent:ap-invoice-proposer',
    payload: {
      invoiceId: proposal?.invoiceId ?? null,
      payeeId: proposal?.payeeId ?? null,
      supplierName: proposal?.supplierName ?? null,
      payeeEmail: proposal?.payeeEmail ?? null,
      payeeMerchantId: proposal?.payeeMerchantId ?? null,
      amountValue: proposal?.amountValue ?? null,
      currencyCode: proposal?.currencyCode ?? 'USD',
      reason: proposal?.reason ?? null,
      invoiceMemo: proposal?.invoiceMemo ?? null,
      aiModelRoute: proposal?.aiModelRoute ?? null,
      poNumber: proposal?.poNumber ?? null,
    },
  });

  const verdict = policyGate.evaluate(proposal, { timestamp, ...evaluateOptions });

  if (verdict.decision === 'HOLD') {
    const heldReceipt = ledger.append({
      stage: 'HELD',
      timestamp,
      proposalId: proposal?.proposalId || null,
      actor: `gate:${policyGate.policyId}`,
      payload: {
        invoiceId: proposal?.invoiceId ?? null,
        payeeId: proposal?.payeeId ?? verdict.payeeId ?? null,
        supplierName: proposal?.supplierName ?? null,
        payeeEmail: proposal?.payeeEmail ?? verdict.payeeEmail ?? null,
        payeeMerchantId: proposal?.payeeMerchantId ?? verdict.payeeMerchantId ?? null,
        attemptedAmountValue: proposal?.amountValue ?? null,
        currencyCode: proposal?.currencyCode ?? 'USD',
        poNumber: proposal?.poNumber ?? verdict.poNumber ?? null,
        reason: proposal?.reason ?? null,
        invoiceMemo: proposal?.invoiceMemo ?? null,
        holdCode: verdict.reasonCode,
        holdDetail: verdict.reasonDetail,
        paypalApiCallsExecuted: 0,
      },
      policyVerdict: verdict,
      paypalOrderId: null,
      paypalCaptureId: null,
    });
    const apiCallsAfterHold = paypalClient.getApiCallCount();
    return {
      ok: false,
      status: 'HELD',
      proposalId: proposal?.proposalId || null,
      invoiceId: proposal?.invoiceId || null,
      verdict,
      order: null,
      capture: null,
      invoiceRecord: null,
      payoutRecord: null,
      proposedReceipt,
      admittedReceipt: null,
      outcomeReceipt: heldReceipt,
      apiCallsDelta: apiCallsAfterHold - apiCallsBefore,
    };
  }

  if (!verdict.admitted) {
    const refusedReceipt = ledger.append({
      stage: 'REFUSED',
      timestamp,
      proposalId: proposal?.proposalId || null,
      actor: `gate:${policyGate.policyId}`,
      payload: {
        invoiceId: proposal?.invoiceId ?? null,
        payeeId: proposal?.payeeId ?? verdict.payeeId ?? null,
        supplierName: proposal?.supplierName ?? null,
        payeeEmail: proposal?.payeeEmail ?? null,
        payeeMerchantId: proposal?.payeeMerchantId ?? null,
        attemptedAmountValue: proposal?.amountValue ?? null,
        currencyCode: proposal?.currencyCode ?? 'USD',
        reason: proposal?.reason ?? null,
        invoiceMemo: proposal?.invoiceMemo ?? null,
        poNumber: proposal?.poNumber ?? verdict.poNumber ?? null,
        refusalCode: verdict.reasonCode,
        refusalDetail: verdict.reasonDetail,
        paypalApiCallsExecuted: 0,
      },
      policyVerdict: verdict,
      paypalOrderId: null,
      paypalCaptureId: null,
    });

    const apiCallsAfter = paypalClient.getApiCallCount();
    return {
      ok: false,
      status: 'REFUSED',
      proposalId: proposal?.proposalId || null,
      invoiceId: proposal?.invoiceId || null,
      verdict,
      order: null,
      capture: null,
      invoiceRecord: null,
      payoutRecord: null,
      proposedReceipt,
      admittedReceipt: null,
      outcomeReceipt: refusedReceipt,
      apiCallsDelta: apiCallsAfter - apiCallsBefore,
    };
  }

  // Reserve, do not settle: the invoice goes on the paid list only after its capture completes.
  if (!simulatedPreviewOnly) {
    policyGate.reserveAdmission(proposal, verdict);
  }

  const admittedReceipt = ledger.append({
    stage: 'ADMITTED',
    timestamp,
    proposalId: proposal.proposalId,
    actor: `gate:${policyGate.policyId}`,
    payload: {
      invoiceId: proposal.invoiceId,
      payeeId: verdict.payeeId,
      payeeName: verdict.payeeName,
      payeeEmail: verdict.payeeEmail,
      rail: verdict.rail,
      amountValue: verdict.amountValue,
      currencyCode: verdict.currencyCode,
      poNumber: verdict.poNumber ?? proposal.poNumber ?? null,
    },
    policyVerdict: verdict,
    paypalOrderId: null,
    paypalCaptureId: null,
  });

  let order = null;
  let capture = null;
  let invoiceRecord = null;
  let payoutRecord = null;
  let payoutRailCheckUsd = null;
  let settledOnPaidList = false;
  const settleOnce = () => {
    if (!settledOnPaidList && !simulatedPreviewOnly) {
      policyGate.commitAdmission(proposal, verdict);
    }
    settledOnPaidList = true;
  };
  const wantInvoice = createInvoiceRecord || (railFollowups && /Invoicing v2/.test(String(verdict.rail || '')));
  const wantPayout = createPayoutRecord || (railFollowups && /Payouts v1/.test(String(verdict.rail || '')));
  const railFollowupErrors = [];
  try {
  order = await paypalClient.createOrder({
    proposalId: proposal.proposalId,
    invoiceId: proposal.invoiceId,
    payeeEmail: verdict.payeeEmail,
    payeeMerchantId: verdict.payeeMerchantId,
    amountValue: verdict.amountValue,
    currencyCode: verdict.currencyCode,
    description: proposal.reason,
    idempotencyKey: `order-${proposal.proposalId}`,
  });

  if (captureImmediately) {
    capture = await paypalClient.captureOrder(order.id, {
      idempotencyKey: `capture-${proposal.proposalId}`,
    });
    const readback = await paypalClient.getOrder(order.id);
    const captureStatus =
      readback?.status ||
      readback?.purchase_units?.[0]?.payments?.captures?.[0]?.status ||
      capture?.status ||
      null;
    if (captureStatus !== 'COMPLETED') {
      throw new Error(
        `PAYPAL_CAPTURE_READBACK_INCOMPLETE: GET /v2/checkout/orders/${order.id} returned ${captureStatus || 'no status'}`
      );
    }
  }
  // Capture complete and read back (or order-only run): the invoice is paid from here on.
  settleOnce();

  if (wantInvoice) {
    try {
    invoiceRecord = await paypalClient.createDraftInvoice({
      invoiceNumber: `${proposal.invoiceId}${railInvoiceNumberSuffix}`,
      recipientEmail: verdict.payeeEmail,
      businessName: verdict.payeeName,
      amountValue: verdict.amountValue,
      currencyCode: verdict.currencyCode,
      itemName: proposal.reason,
      note: `Receipted AP order ${proposal.proposalId}`,
    });
    } catch (err) {
      if (!railFollowups) throw err;
      railFollowupErrors.push(`invoicing-v2: ${String(err?.message || err).slice(0, 120)}`);
    }
  }

  payoutRailCheckUsd = wantPayout ? '1.00' : null;
  if (wantPayout) {
    try {
    payoutRecord = await paypalClient.createPayoutBatch({
      senderBatchId: `batch-${proposal.proposalId}`,
      recipientEmail: verdict.payeeEmail,
      amountValue: payoutRailCheckUsd,
      currencyCode: verdict.currencyCode,
      note: `Payouts v1 $1.00 USD remittance voucher paired with Orders v2 capture (${proposal.invoiceId} $${verdict.amountValue} USD)`,
    });
    } catch (err) {
      if (!railFollowups) throw err;
      payoutRailCheckUsd = null;
      railFollowupErrors.push(`payouts-v1: ${String(err?.message || err).slice(0, 120)}`);
    }
  }
  } catch (err) {
    // Failed before the capture completed: release the in-flight mark so a retry can pay.
    if (!settledOnPaidList && !simulatedPreviewOnly) policyGate.releaseAdmission(proposal);
    throw err;
  }

  const executedReceipt = ledger.append({
    stage: 'EXECUTED',
    timestamp,
    proposalId: proposal.proposalId,
    actor: `executor:paypal-${paypalClient.mode}`,
    payload: {
      invoiceId: proposal.invoiceId,
      payeeId: verdict.payeeId,
      payeeName: verdict.payeeName,
      payeeEmail: verdict.payeeEmail,
      rail: verdict.rail,
      amountValue: verdict.amountValue,
      currencyCode: verdict.currencyCode,
      orderStatus: capture ? 'COMPLETED' : order.status,
      captureStatus: capture?.status || null,
      paypalInvoiceId: invoiceRecord?.id || null,
      paypalPayoutBatchId: payoutRecord?.batch_header?.payout_batch_id || null,
      ...(payoutRailCheckUsd ? { paypalPayoutVoucherUsd: payoutRailCheckUsd } : {}),
      ...(railFollowupErrors.length ? { railFollowupErrors } : {}),
      executionMode: paypalClient.mode,
    },
    policyVerdict: verdict,
    paypalOrderId: order.id,
    paypalCaptureId: capture?.id || null,
  });

  const apiCallsAfter = paypalClient.getApiCallCount();

  return {
    ok: true,
    status: 'EXECUTED',
    proposalId: proposal.proposalId,
    invoiceId: proposal.invoiceId,
    verdict,
    order,
    capture,
    invoiceRecord,
    payoutRecord,
    proposedReceipt,
    admittedReceipt,
    outcomeReceipt: executedReceipt,
    apiCallsDelta: apiCallsAfter - apiCallsBefore,
  };
}
