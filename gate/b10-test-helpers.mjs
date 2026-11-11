/**
 * Test-only purchase orders and proposal defaults for B.10 unit tests.
 * These blankets are not in the public default register.
 */
import { PolicyGate, DEFAULT_AP_POLICY_GATE_CONFIG } from './policy-gate.mjs';

export const TEST_BLANKET_ORDERS = Object.freeze([
  Object.freeze({
    poNumber: 'PO-2026-TEST-COLOMBIA',
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    currencyCode: 'USD',
    totalCents: 5_000_000,
    open: true,
  }),
  Object.freeze({
    poNumber: 'PO-2026-TEST-CASCADE',
    payeeId: 'cascade-packaging-co',
    payeeEmail: 'billing@cascade-packaging.example',
    currencyCode: 'USD',
    totalCents: 5_000_000,
    open: true,
  }),
  Object.freeze({
    poNumber: 'PO-2026-TEST-SOUND',
    payeeId: 'sound-freight-logistics',
    payeeEmail: 'ap@sound-freight.example',
    currencyCode: 'USD',
    totalCents: 5_000_000,
    open: true,
  }),
]);

export const PO_BY_PAYEE_EMAIL = Object.freeze({
  'pay@colombia-direct-beans.example': 'PO-2026-TEST-COLOMBIA',
  'billing@cascade-packaging.example': 'PO-2026-TEST-CASCADE',
  'ap@sound-freight.example': 'PO-2026-TEST-SOUND',
});

export const PAYEE_ID_BY_EMAIL = Object.freeze({
  'pay@colombia-direct-beans.example': 'colombia-direct-beans',
  'billing@cascade-packaging.example': 'cascade-packaging-co',
  'ap@sound-freight.example': 'sound-freight-logistics',
});

export const MERCHANT_BY_EMAIL = Object.freeze({
  'pay@colombia-direct-beans.example': 'MCH-COLOMBIA-BEANS-01',
  'billing@cascade-packaging.example': 'MCH-CASCADE-PKG-02',
  'ap@sound-freight.example': 'MCH-SOUND-FREIGHT-03',
});

export function testPolicyGate(config = DEFAULT_AP_POLICY_GATE_CONFIG) {
  const gate = new PolicyGate(config);
  for (const po of TEST_BLANKET_ORDERS) gate.addPurchaseOrder(po);
  const originalEvaluate = gate.evaluate.bind(gate);
  gate.evaluate = (proposal, options) => originalEvaluate(fillProposal(proposal || {}), options);
  return gate;
}

export function fillProposal(proposal) {
  const email = String(proposal.payeeEmail || '').trim().toLowerCase();
  const out = { ...proposal };
  const expectedId = PAYEE_ID_BY_EMAIL[email];
  const knownIds = new Set(Object.values(PAYEE_ID_BY_EMAIL));
  if (expectedId) {
    // Fill a missing id, or replace a leftover id from another known test payee.
    // Leave an explicit unknown id so unapproved-payee tests can fire.
    if (!out.payeeId || knownIds.has(String(out.payeeId).toLowerCase())) {
      if (String(out.payeeId || '').toLowerCase() !== expectedId) out.payeeId = expectedId;
    }
  }
  if (MERCHANT_BY_EMAIL[email]) {
    const knownMerchants = new Set(Object.values(MERCHANT_BY_EMAIL));
    if (!out.payeeMerchantId) {
      out.payeeMerchantId = MERCHANT_BY_EMAIL[email];
    } else if (knownMerchants.has(out.payeeMerchantId) && out.payeeMerchantId !== MERCHANT_BY_EMAIL[email]) {
      // Caller changed the email but left the previous approved merchant id.
      out.payeeMerchantId = MERCHANT_BY_EMAIL[email];
    }
  }
  if (PO_BY_PAYEE_EMAIL[email]) {
    const expectedPo = PO_BY_PAYEE_EMAIL[email];
    const known = new Set(Object.values(PO_BY_PAYEE_EMAIL));
    if (!out.poNumber || known.has(out.poNumber)) out.poNumber = expectedPo;
  }
  return out;
}

export function testPolicyGateRaw(config = DEFAULT_AP_POLICY_GATE_CONFIG) {
  const gate = new PolicyGate(config);
  for (const po of TEST_BLANKET_ORDERS) gate.addPurchaseOrder(po);
  return gate;
}
