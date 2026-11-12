# Desk live session summary
Receipt `desk-live-session-receipt.json`: one session of the local desk (`node gate/desk-server.mjs`) on the PayPal Sandbox, session tag `lv-mwczbh0pa9f4`, 2026-11-12 03:19 UTC, model `glm-5.3` through Ollama Cloud (a live model call for each of the six invoices and for the pasted one).
**The clicks in this session were made by a script (Playwright) driving the page, not by a person.** The approver name typed into the page was "Proof script (Playwright)". The receipt does not record who or what drives the page.
## What was paid
- Signed session receipt: 4 payments, $4,300.00 (R5-01 $1,000.00, R5-02 released after the approval click $1,000.00, R5-04 $1,700.00, R5-06 $600.00). Each has an order id, a capture id and a COMPLETED read-back.
- R5-02 and R5-03 were held, R5-05 was held. R5-02 was approved on the page and paid. The same payment sent again was REFUSED `DUPLICATE_INVOICE`. R5-03 was rejected. The approval of R5-05 was DENIED `OVER_DAILY_SPEND_CAP` ($4300.00 plus $900.00 over $5000.00).
- One pasted invoice, P-01 (Sound Freight Logistics LLC, INV-2026-9101, $90.00, PO-2026-0606): read by the model, admitted by the gate, paid. PayPal order `9AC0767659251753T`. It is kept out of the signed session receipt (the frozen verifier counts PROPOSED entries against the suite file) and has its own signed ledger.
## PayPal calls (all HTTPS to the Sandbox, each with a Paypal-Debug-Id)
Session receipt: 13 (OAuth2 1, Orders v2 12: 4 create, 4 capture, 4 read-back). Held, rejected, refused and denied passes made 0 calls. Pasted ledger: 4 (OAuth2 1, create, capture, read-back). Total 17.
## Checks
`node verify-payments.mjs desk-live-session-receipt.json`: PASS (23 of 23 entries, 8 of 8 suite records, 13 of 13 calls). `--tamper-demo` and `--forge-rehash-demo` exit 1. `node recount-run5.mjs desk-live-session-receipt.json`: agrees, 31 of 31.
Not shown by this summary: the page's own label "live on your PayPal Sandbox" is text the server sends with each answer; it is true only for a server started with Sandbox keys.
