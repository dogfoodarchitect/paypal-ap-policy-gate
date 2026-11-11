/**
 * purchase-orders.mjs — Policy v2 / po-v4 purchase-order register
 *
 * Stamp POs (PO-2026-0601 … 0606) are reserved for the second blind set and
 * stay open, unused by the 38 known invoices.
 *
 * Known-invoice POs (PO-2026-38-*) are sized to what was ordered on that
 * invoice or shared split, so a proposal that raises the amount fails
 * OVER_PURCHASE_ORDER_BALANCE before the per-payment cap.
 */
export const STAMP_PURCHASE_ORDERS = Object.freeze([
  Object.freeze({ poNumber: 'PO-2026-0601', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 320000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-0602', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 175000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-0603', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 240000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-0604', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 480000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-0605', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 90000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-0606', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 110000, open: true }),
]);

/** POs for the 38 known invoices (25 original + 13 held-out). Totals in cents. */
export const KNOWN_INVOICE_PURCHASE_ORDERS = Object.freeze([
  Object.freeze({ poNumber: 'PO-2026-38-3001', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 118000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3002', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 64000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3003', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 245000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3004', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 41000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3005', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 90500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3006', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 127500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3009', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 600000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-2041', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 142000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-2043', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 68000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3011', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 190000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3012', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 380000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3013', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 600000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3014', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 150000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3015', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 132000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3016', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 56000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3017', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 165000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3018', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 950000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3019', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 184020, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3020', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 93000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-4001', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 142000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-4002', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 68000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-4003', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 250000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-4004', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 43025, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-4005', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 115050, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-2051', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 134000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-2052', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 91500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-2061', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 117500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-2078', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 117500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3104', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 108500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3105', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 196000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3106', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 218000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3107', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 420000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3108', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 164000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-3110', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 174500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-5101', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 197530, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-5102', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 84500, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-5103', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 231075, open: true }),
]);

/** POs for the bundled 5-invoice demo fixture and the hosted-page interactive samples. */
export const FIXTURE_PURCHASE_ORDERS = Object.freeze([
  Object.freeze({ poNumber: 'PO-2026-38-1041', payeeId: 'colombia-direct-beans', payeeEmail: 'pay@colombia-direct-beans.example', currencyCode: 'USD', totalCents: 300000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-1043', payeeId: 'cascade-packaging-co', payeeEmail: 'billing@cascade-packaging.example', currencyCode: 'USD', totalCents: 68000, open: true }),
  Object.freeze({ poNumber: 'PO-2026-38-FREIGHT', payeeId: 'sound-freight-logistics', payeeEmail: 'ap@sound-freight.example', currencyCode: 'USD', totalCents: 200000, open: true }),
]);

export const DEFAULT_PURCHASE_ORDERS = Object.freeze([
  ...STAMP_PURCHASE_ORDERS,
  ...KNOWN_INVOICE_PURCHASE_ORDERS,
  ...FIXTURE_PURCHASE_ORDERS,
]);

/** invoiceId (and look-alike / setup aliases) -> poNumber for the 38 known invoices */
export const INVOICE_TO_PO_NUMBER = Object.freeze({
  'INV-2026-3001': 'PO-2026-38-3001',
  'INV-2026-3002': 'PO-2026-38-3002',
  'INV-2026-3003': 'PO-2026-38-3003',
  'INV-2026-3004': 'PO-2026-38-3004',
  'INV-2026-3005': 'PO-2026-38-3005',
  'INV-2026-3006': 'PO-2026-38-3006',
  'INV-2026-3007': null, // unapproved supplier; line is still added on the invoice document only
  'INV-2026-3009-A': 'PO-2026-38-3009',
  'INV-2026-3009-B': 'PO-2026-38-3009',
  'INV-2026-3009-C': 'PO-2026-38-3009',
  'INV-2026-2041': 'PO-2026-38-2041',
  'INV-2026-2043': 'PO-2026-38-2043',
  'inv-2026-2043': 'PO-2026-38-2043',
  'INV-2026-3011': 'PO-2026-38-3011',
  'INV-2026-3012': 'PO-2026-38-3012',
  'INV-2026-3013': 'PO-2026-38-3013',
  'INV-2026-3014': 'PO-2026-38-3014',
  'INV-2026-3015': 'PO-2026-38-3015',
  'INV-2026-3016': 'PO-2026-38-3016',
  'INV-2026-3017': 'PO-2026-38-3017',
  'INV-2026-3018': 'PO-2026-38-3018',
  'INV-2026-3019': 'PO-2026-38-3019',
  'INV-2026-3020-C': 'PO-2026-38-3020',
  'INV-2026-4001': 'PO-2026-38-4001',
  'INV-2026-4002': 'PO-2026-38-4002',
  'INV-2026-4003': 'PO-2026-38-4003',
  'INV-2026-4004': 'PO-2026-38-4004',
  'INV-2026-4005': 'PO-2026-38-4005',
  'INV-2026-2051': 'PO-2026-38-2051',
  'INV-2O26-2O5l': 'PO-2026-38-2051',
  'INV-2026-2052': 'PO-2026-38-2052',
  '2026-2052-REV2': 'PO-2026-38-2052',
  'INV-2026-2061': 'PO-2026-38-2061',
  'INV-2026-2078': 'PO-2026-38-2078',
  'INV-2026-3104': 'PO-2026-38-3104',
  'INV-2026-3105': 'PO-2026-38-3105',
  'INV-2026-3106': 'PO-2026-38-3106',
  'INV-2026-3107-A': 'PO-2026-38-3107',
  'INV-2026-3107-B': 'PO-2026-38-3107',
  'INV-2026-3108': 'PO-2026-38-3108',
  'INV-2026-3109': null, // unapproved supplier
  'INV-2026-3110': 'PO-2026-38-3110',
  'INV-2026-5101': 'PO-2026-38-5101',
  'INV-2026-5102': 'PO-2026-38-5102',
  'INV-2026-5103': 'PO-2026-38-5103',
  'INV-2026-1041': 'PO-2026-38-1041',
  'INV-2026-1042': 'PO-2026-38-1042',
  'INV-2026-1043': 'PO-2026-38-1043',
  'INV-2026-1090': 'PO-2026-38-FREIGHT',
  'INV-2026-1095': 'PO-2026-38-FREIGHT',
  'INV-2026-1099': 'PO-2026-38-FREIGHT',
});

export function poNumberForInvoice(invoiceId) {
  if (typeof invoiceId !== 'string') return null;
  if (Object.prototype.hasOwnProperty.call(INVOICE_TO_PO_NUMBER, invoiceId)) {
    return INVOICE_TO_PO_NUMBER[invoiceId];
  }
  return null;
}
