// invoice-reader.mjs — the simple field reader that stands in for the AI model where no model is available.
// It is the plain-pattern reader that the Run 5 runner uses in its --simulate mode (run-approval-release.mjs,
// createSimulationExtractorAdapter), ported as its own browser-safe module. It reads the fields of an invoice
// that follows the layout of the suite's invoices (FROM, VENDOR, INVOICE NUMBER, LINE ITEM, AMOUNT DUE).
// It is not a model and it does not understand free text. Whatever it cannot find stays empty.
export function readInvoiceFields(text) {
  const t = String(text ?? '');
  const grab = (re) => (t.match(re) || [])[1]?.trim() ?? null;
  const amountRaw = grab(/AMOUNT DUE:\s*\$?([\d,]+(?:\.\d{1,2})?)/);
  return {
    invoiceId: grab(/INVOICE NUMBER:\s*(\S+)/),
    supplierName: grab(/VENDOR:\s*(.+?)\s*\(/),
    payeeEmail: grab(/FROM:[^<\n]*<([^>]+)>/),
    payeeMerchantId: grab(/Merchant ID:\s*([A-Z0-9-]+)\)/),
    amountValue: amountRaw ? Number(amountRaw.replace(/,/g, '')).toFixed(2) : null,
    currencyCode: grab(/AMOUNT DUE:[^\n]*\s([A-Z]{3})\b/) || 'USD',
    reason: grab(/LINE ITEM:\s*(.+)/),
  };
}

// The same reader in the shape the agent's inference adapter has (used by tests as a stand-in model).
export function createReaderAdapter() {
  return async ({ prompt }) => {
    const text = String(prompt);
    const proposalId = (text.match(/Use exact "proposalId": "([^"]+)"/) || [])[1]?.trim() || 'reader-prop';
    const doc = text.split('--- INCOMING SUPPLIER INVOICE DOCUMENT ---')[1] ?? text;
    return {
      rawCompletion: JSON.stringify({ proposalId, ...readInvoiceFields(doc.split('--- END INVOICE DOCUMENT ---')[0]) }),
      returnedModel: 'simulation-regex-extractor',
      tokensIn: 0, tokensOut: 0, doneReason: 'stop', httpStatus: 200, elapsedMs: 0,
    };
  };
}
