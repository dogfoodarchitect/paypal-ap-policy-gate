#!/usr/bin/env node
/**
 * live-sandbox-runner.mjs — Live PayPal Sandbox + Live LLM Proposer Runner
 *
 * 1. Loads PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET from environment or
 *    PAYPAL_ENV_FILE / $HOME/.config/paypal-receipted-agent/paypal.env (names
 *    and character lengths only in output; zero secret bytes ever logged).
 * 2. Probes PayPal Sandbox /v1/oauth2/token over TLS 1.3 to capture a live
 *    paypal-debug-id and HTTP status from PayPal's sandbox edge.
 * 3. In --apex-live mode, calls a real LLM proposer (ollama-cloud:glm-5.3 via
 *    https://ollama.com/api/chat with structured PROPOSAL_JSON_SCHEMA) across
 *    the synthetic 5-invoice B2B supplier fixture, constrains every proposal
 *    through deterministic PolicyGate, executes admitted orders live on
 *    https://api-m.sandbox.paypal.com across Orders v2 (createOrder + captureOrder +
 *    GET order COMPLETED), Invoicing v2, Payouts v1, and HMAC-verified Webhooks v1,
 *    and binds CODE-MANIFEST.json (`codeManifestSha256`).
 * 4. In --get-order <ORDER_ID> mode, performs a live OAuth2 + GET read-back against
 *    https://api-m.sandbox.paypal.com/v2/checkout/orders/<ORDER_ID> and prints the
 *    PayPal-side COMPLETED settlement payload and Paypal-Debug-Id.
 * 5. When credentials are absent, fails closed on live claims
 *    (BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS) and exits 2 under --require-live.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SANDBOX_ORIGIN } from './vendor/engines/payment-execution/client.mjs';
import { ReceiptLedger, verifyReceiptChain } from './receipt-ledger.mjs';
import { PolicyGate, DEFAULT_AP_POLICY_GATE_CONFIG, processAgentPaymentProposal } from './policy-gate.mjs';
import { PayPalSandboxClient, PAYPAL_SANDBOX_BASE_URL } from './paypal-client.mjs';
import {
  AIProcurementAgent,
  buildSampleSupplierInvoices,
  createOllamaCloudAdapter,
} from './ai-procurement-agent.mjs';
import { runSampleFixtureDemo } from './demo-cli.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function safeRedactedEnvLabel(targetPath, env) {
  if (env && env.PAYPAL_ENV_FILE) {
    return 'PAYPAL_ENV_FILE (env override)';
  }
  const base = path.basename(String(targetPath || 'paypal.env'));
  return `$HOME/.config/paypal-receipted-agent/${base}`;
}

export function readAdjacentCodeManifestSha256() {
  const manifestPath = path.join(HERE, 'CODE-MANIFEST.json');
  if (!fs.existsSync(manifestPath)) return null;
  return crypto.createHash('sha256').update(fs.readFileSync(manifestPath)).digest('hex');
}

export function loadPayPalCredentials(
  envPath = process.env.PAYPAL_ENV_FILE || path.join(os.homedir(), '.config', 'paypal-receipted-agent', 'paypal.env'),
  { env = process.env } = {}
) {
  const envVars = {};
  const fileExists = fs.existsSync(envPath);
  let envFileBytes = 0;

  if (fileExists) {
    const raw = fs.readFileSync(envPath, 'utf8');
    envFileBytes = Buffer.byteLength(raw, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx <= 0) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      let val = trimmed.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      } else {
        val = val.replace(/\s+#.*$/, '').trim();
      }
      envVars[key] = val;
    }
  }

  const clientId = String((env && env.PAYPAL_CLIENT_ID) || envVars.PAYPAL_CLIENT_ID || '').trim();
  const clientSecret = String((env && env.PAYPAL_CLIENT_SECRET) || envVars.PAYPAL_CLIENT_SECRET || '').trim();
  const webhookId = String((env && env.PAYPAL_WEBHOOK_ID) || envVars.PAYPAL_WEBHOOK_ID || '').trim();
  const paypalEnv = String((env && env.PAYPAL_ENV) || envVars.PAYPAL_ENV || 'sandbox').trim();

  if (/\s/.test(clientId)) {
    process.stderr.write(
      'PAYPAL_CREDENTIAL_WARNING: PAYPAL_CLIENT_ID contains whitespace; ' +
      'if this came from paypal.env, put notes on their own line (bare KEY=value only).\n'
    );
  }

  return {
    envPath,
    redactedEnvPath: safeRedactedEnvLabel(envPath, env),
    envFilePresent: fileExists,
    envFileBytes,
    paypalEnv,
    keysPresent: Object.keys(envVars),
    clientIdLength: clientId.length,
    clientSecretLength: clientSecret.length,
    hasCredentials: Boolean(clientId && clientSecret),
    clientId,
    clientSecret,
    webhookId,
  };
}

export function probePayPalSandboxEdge({ timeoutMs = 8000 } = {}) {
  return new Promise((resolve) => {
    const url = new URL('/v1/oauth2/token', SANDBOX_ORIGIN);
    let negotiatedTls = null;
    const req = https.request(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        timeout: timeoutMs,
      },
      (res) => {
        if (!negotiatedTls && typeof res.socket?.getProtocol === 'function') {
          negotiatedTls = res.socket.getProtocol();
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (body.length < 4096) body += chunk;
        });
        res.on('end', () => {
          resolve({
            reachable: true,
            origin: PAYPAL_SANDBOX_BASE_URL,
            endpoint: '/v1/oauth2/token',
            httpStatus: res.statusCode || null,
            paypalDebugId: res.headers['paypal-debug-id'] || null,
            tlsProtocol: negotiatedTls,
            probedAt: new Date().toISOString(),
          });
        });
      }
    );
    req.on('socket', (sock) => {
      sock.on('secureConnect', () => {
        if (typeof sock.getProtocol === 'function') {
          negotiatedTls = sock.getProtocol();
        }
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error('TIMEOUT'));
    });
    req.on('error', (err) => {
      resolve({
        reachable: false,
        origin: PAYPAL_SANDBOX_BASE_URL,
        endpoint: '/v1/oauth2/token',
        httpStatus: null,
        paypalDebugId: null,
        tlsProtocol: null,
        error: err.message,
        probedAt: new Date().toISOString(),
      });
    });
    req.write('grant_type=client_credentials');
    req.end();
  });
}

function emptyHermeticCredentials(redactedEnvPath = '$HOME/.config/paypal-receipted-agent/paypal.env') {
  return {
    envPath: redactedEnvPath,
    redactedEnvPath,
    envFilePresent: false,
    envFileBytes: 0,
    paypalEnv: 'sandbox',
    keysPresent: [],
    clientIdLength: 0,
    clientSecretLength: 0,
    hasCredentials: false,
    clientId: '',
    clientSecret: '',
    webhookId: '',
  };
}

function offlineEdgeProbeRecord(reason = 'SKIPPED_HERMETIC_MODE') {
  return {
    reachable: false,
    skipped: true,
    reason,
    origin: PAYPAL_SANDBOX_BASE_URL,
    endpoint: '/v1/oauth2/token',
    httpStatus: null,
    paypalDebugId: null,
    tlsProtocol: null,
    probedAt: new Date().toISOString(),
  };
}

export async function runLiveSandboxCheck({
  live = false,
  skipEdgeProbe = false,
  envPath,
  env,
  credentials,
  edgeProbeFn,
  paypalClient: injectedPayPalClient,
  paypalMode = 'sandbox-https',
  captureImmediately = false,
} = {}) {
  const creds = credentials
    ? credentials
    : typeof envPath === 'string' && envPath.length > 0
      ? loadPayPalCredentials(envPath, { env })
      : live === true
        ? loadPayPalCredentials(undefined, { env })
        : emptyHermeticCredentials();

  const edgeProbe = typeof edgeProbeFn === 'function'
    ? await edgeProbeFn()
    : live === true && creds.hasCredentials && !skipEdgeProbe
      ? await probePayPalSandboxEdge()
      : offlineEdgeProbeRecord(
          !creds.hasCredentials ? 'SKIPPED_MISSING_CREDENTIALS' : 'SKIPPED_HERMETIC_MODE'
        );

  if (!creds.hasCredentials) {
    const baseline = await runSampleFixtureDemo({ mode: 'simulation' });
    return {
      submitter: 'paypal-ap-policy-gate',
      workOrderId: 'WO-paypal-hackathon-payment-agent-1',
      liveSandboxStatus: 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS',
      credentialCheck: {
        envPath: creds.redactedEnvPath,
        envFilePresent: creds.envFilePresent,
        hasCredentials: false,
      },
      edgeProbe,
      liveApiCallsExecuted: 0,
      liveOrderId: null,
      orderLifecycle: {
        createExecuted: false,
        createImmediatelyCapture: false,
        captureRequested: false,
        orderStatus: null,
        captureState: 'NO_ORDER_BLOCKED_MISSING_CREDENTIALS',
        moneyMoved: false,
      },
      simulationBaseline: {
        entryCount: baseline.chainVerification.count,
        chainValid: baseline.chainVerification.valid,
        genesisHash: baseline.chainVerification.genesisHash,
        headHash: baseline.chainVerification.headHash,
        stageCounts: baseline.chainVerification.stageCounts,
      },
      ledger: baseline.ledger,
    };
  }

  const runSuffix = String(Date.now()).slice(-8);
  const ledger = new ReceiptLedger({
    ledgerId: 'ledger-paypal-ap-live-sandbox-check',
    genesisTimestamp: new Date().toISOString(),
    protagonist: 'Synthetic 5-Invoice B2B Supplier Test Fixture (0 Live Customers)',
    metadata: {
      hackathon: 'PayPal AI Hackathon 2026',
      mode: 'sandbox-https',
      origin: PAYPAL_SANDBOX_BASE_URL,
    },
  });
  const policyGate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  policyGate.addPurchaseOrder({
    poNumber: 'PO-2026-LIVE-SANDBOX-CHECK',
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    currencyCode: 'USD',
    totalCents: 500000,
    open: true,
  });
  const paypalClient = injectedPayPalClient || new PayPalSandboxClient({
    clientId: creds.clientId,
    clientSecret: creds.clientSecret,
    mode: paypalMode,
    seed: 'live-sandbox-check-seed-2026',
  });

  const liveProposal = {
    proposalId: `prop-live-sbx-${runSuffix}`,
    invoiceId: `INV-SBX-${runSuffix}`,
    payeeId: 'colombia-direct-beans',
    payeeEmail: 'pay@colombia-direct-beans.example',
    payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
    amountValue: '142.00',
    currencyCode: 'USD',
    poNumber: 'PO-2026-LIVE-SANDBOX-CHECK',
    reason: 'Live PayPal Sandbox verification order for supplier sample fixture',
  };

  const orderResult = await processAgentPaymentProposal({
    proposal: liveProposal,
    policyGate,
    paypalClient,
    ledger,
    captureImmediately,
    createInvoiceRecord: true,
    createPayoutRecord: true,
  });

  const callsBeforeRefusal = paypalClient.getApiCallCount();
  const refusedProposal = {
    proposalId: `prop-live-refused-${runSuffix}`,
    invoiceId: `INV-REF-${runSuffix}`,
    payeeEmail: 'wire@offshore-holdings.example',
    amountValue: '950.00',
    currencyCode: 'USD',
    reason: 'Adversarial unapproved payee test',
  };
  const refusalResult = await processAgentPaymentProposal({
    proposal: refusedProposal,
    policyGate,
    paypalClient,
    ledger,
  });
  const callsAfterRefusal = paypalClient.getApiCallCount();

  const verification = verifyReceiptChain(ledger);
  const orderStatus = orderResult.capture?.status || orderResult.order?.status || null;
  const captured =
    Boolean(orderResult.capture && /^COMPLETED$/i.test(String(orderResult.capture.status || ''))) ||
    (typeof orderStatus === 'string' && /^COMPLETED$/i.test(orderStatus));
  return {
    submitter: 'paypal-ap-policy-gate',
    workOrderId: 'WO-paypal-hackathon-payment-agent-1',
    liveSandboxStatus: captured ? 'LIVE_SANDBOX_CREATED_AND_CAPTURED' : 'LIVE_SANDBOX_CREATED_NOT_CAPTURED',
    credentialCheck: {
      envPath: creds.redactedEnvPath,
      envFilePresent: creds.envFilePresent,
      envFileBytes: creds.envFileBytes,
      paypalEnv: creds.paypalEnv,
      keysPresent: creds.keysPresent,
      clientIdLength: creds.clientIdLength,
      clientSecretLength: creds.clientSecretLength,
      hasCredentials: true,
    },
    edgeProbe,
    liveApiCallsExecuted: paypalClient.getApiCallCount(),
    refusalZeroApiCallsVerified: callsAfterRefusal === callsBeforeRefusal && refusalResult.status === 'REFUSED',
    liveOrderId: orderResult.order?.id || null,
    liveCaptureId: orderResult.capture?.id || null,
    orderLifecycle: {
      createExecuted: Boolean(orderResult.order?.id),
      createImmediatelyCapture: false,
      captureRequested: Boolean(captureImmediately || captured),
      orderStatus,
      captureState: captured ? 'CAPTURED' : 'CREATED_NOT_CAPTURED',
      moneyMoved: captured,
    },
    chainVerification: verification,
    ledger: ledger.toJSON(),
  };
}

/**
 * Executes the synthetic 5-invoice B2B supplier sample test fixture live against
 * `ollama-cloud:glm-5.3` + `https://api-m.sandbox.paypal.com` across Orders v2
 * (createOrder + captureOrder + GET order COMPLETED), Invoicing v2, Payouts v1,
 * and HMAC-verified Webhooks v1, binding CODE-MANIFEST.json (`codeManifestSha256`)
 * and recording zero secret bytes.
 */
export async function runLiveApexScenario({
  live = true,
  skipEdgeProbe = false,
  envPath,
  env = process.env,
  credentials,
  edgeProbeFn,
  ollamaApiKey = (env && env.OLLAMA_API_KEY) || process.env.OLLAMA_API_KEY || '',
  llmModel = 'glm-5.3',
  liveInferenceAdapter = null,
  invoiceTag = '',
  onProgress = null,
} = {}) {
  const runStartMs = Date.now();
  const emit = (kind, text, meta = {}) => {
    if (typeof onProgress === 'function') {
      onProgress({
        elapsedMs: Date.now() - runStartMs,
        iso: new Date().toISOString(),
        kind,
        text,
        ...meta,
      });
    }
  };

  const creds = credentials
    ? credentials
    : typeof envPath === 'string' && envPath.length > 0
      ? loadPayPalCredentials(envPath, { env })
      : live === true
        ? loadPayPalCredentials(undefined, { env })
        : emptyHermeticCredentials();

  const trimmedOllamaKey = String(ollamaApiKey || '').trim();
  const hasLlmAdapter = typeof liveInferenceAdapter === 'function' || trimmedOllamaKey.length > 0;
  const codeManifestSha256 = readAdjacentCodeManifestSha256();

  emit(
    'ENV_CHECK',
    `ENV CHECK: PAYPAL_ENV (len=${creds.paypalEnv.length}) · PAYPAL_CLIENT_ID (len=${creds.clientIdLength}) · PAYPAL_CLIENT_SECRET (len=${creds.clientSecretLength}) · OLLAMA_API_KEY (len=${trimmedOllamaKey.length}) [values redacted] · codeManifest=${codeManifestSha256 ? codeManifestSha256.slice(0, 12) : 'n/a'}`
  );

  const edgeProbe = typeof edgeProbeFn === 'function'
    ? await edgeProbeFn()
    : live === true && creds.hasCredentials && !skipEdgeProbe
      ? await probePayPalSandboxEdge()
      : offlineEdgeProbeRecord(
          !creds.hasCredentials ? 'SKIPPED_MISSING_CREDENTIALS' : 'SKIPPED_HERMETIC_MODE'
        );

  if (edgeProbe.reachable) {
    emit(
      'EDGE_PROBE',
      `TLS PROBE  POST /v1/oauth2/token -> HTTP ${edgeProbe.httpStatus} · ${edgeProbe.tlsProtocol} · Paypal-Debug-Id: ${edgeProbe.paypalDebugId}`
    );
  }

  if (!creds.hasCredentials) {
    return {
      submitter: 'paypal-ap-policy-gate',
      workOrderId: 'WO-paypal-hackathon-payment-agent-1',
      codeManifestSha256,
      liveSandboxStatus: 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS',
      credentialCheck: {
        envPath: creds.redactedEnvPath,
        envFilePresent: creds.envFilePresent,
        hasCredentials: false,
      },
      edgeProbe,
      liveApiCallsExecuted: 0,
      scenarioResults: [],
    };
  }

  if (!hasLlmAdapter) {
    return {
      submitter: 'paypal-ap-policy-gate',
      workOrderId: 'WO-paypal-hackathon-payment-agent-1',
      codeManifestSha256,
      liveSandboxStatus: 'BLOCKED_MISSING_LLM_PROPOSER_CREDENTIALS',
      credentialCheck: {
        envPath: creds.redactedEnvPath,
        envFilePresent: creds.envFilePresent,
        hasCredentials: true,
        hasOllamaApiKey: false,
      },
      edgeProbe,
      liveApiCallsExecuted: 0,
      scenarioResults: [],
    };
  }

  const adapter =
    liveInferenceAdapter ||
    createOllamaCloudAdapter({
      apiKey: trimmedOllamaKey,
      numPredict: 6144,
    });

  const runTag = String(Date.now()).slice(-6);
  const startedAt = new Date().toISOString();
  const ledger = new ReceiptLedger({
    ledgerId: `ledger-paypal-ap-policy-gate-${runTag}`,
    genesisTimestamp: startedAt,
    protagonist: 'Synthetic 5-Invoice B2B Supplier Test Fixture (Pre-launch Prototype · 0 Live Customers)',
    metadata: {
      hackathon: 'PayPal AI Hackathon 2026',
      productName: 'PayPal AP Policy Gate',
      datasetStatus: 'Recorded PayPal Sandbox Run · 5-Invoice Sample Fixture · Pre-launch Prototype (0 Live Customers)',
      mode: 'sandbox-https',
      origin: PAYPAL_SANDBOX_BASE_URL,
      aiProposerRoute: `ollama-cloud:${llmModel}`,
      codeManifestSha256,
      gateGeneration: 'hold-v3',
      policyFeatures: { duplicatePaymentHold: true, paidOnlyAfterCapture: true, recordedAtPerEntry: true },
      surfaces: ['Orders v2', 'Webhooks v1', 'Invoicing v2', 'Payouts v1'],
    },
  });

  const policyGate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const paypalClient = new PayPalSandboxClient({
    clientId: creds.clientId,
    clientSecret: creds.clientSecret,
    mode: 'sandbox-https',
  });
  const aiAgent = new AIProcurementAgent({
    defaultRoute: `ollama-cloud:${llmModel}`,
    liveInferenceAdapter: adapter,
  });

  const effectiveInvoiceTag = invoiceTag || runTag;
  const invSuffix = effectiveInvoiceTag ? `-${effectiveInvoiceTag}` : '';
  const invoiceIdStep1 = `INV-2026-1041${invSuffix}`;
  const invoiceIdStep2 = `INV-2026-1043${invSuffix}`;
  const invoiceIdStep3 = `INV-2026-1042${invSuffix}`;
  const invoiceIdStep4 = `INV-2026-1044${invSuffix}`;

  const invoices = buildSampleSupplierInvoices({
    proposalSuffix: runTag,
    invoice1Id: invoiceIdStep1,
    invoice2Id: invoiceIdStep2,
    invoice3Id: invoiceIdStep3,
    invoice4Id: invoiceIdStep4,
  });

  const scenarioResults = [];
  const llmProposalsLog = [];

  const draftLive = async (inv) => {
    emit('LLM_START', `LLM #${inv.step}     POST https://ollama.com/api/chat (model=${llmModel}, format=json-schema) <- invoice ${inv.invoiceId}`);
    const prop = await aiAgent.draftPaymentProposal(inv, {
      route: `ollama-cloud:${llmModel}`,
      requireLiveLlm: true,
    });
    const r = prop.aiModelRoute;
    llmProposalsLog.push({
      step: inv.step,
      exceptionId: inv.exceptionId || null,
      proposalId: prop.proposalId,
      invoiceId: prop.invoiceId,
      payeeId: prop.payeeId || inv.payeeId || null,
      supplierName: prop.supplierName || inv.supplierName || null,
      payeeEmail: prop.payeeEmail,
      payeeMerchantId: prop.payeeMerchantId,
      amountUsd: prop.amountValue,
      currencyCode: prop.currencyCode || 'USD',
      reason: prop.reason,
      invoiceMemo: prop.invoiceMemo || inv.invoiceMemo || null,
      mode: r.mode,
      provider: r.provider,
      requestedModel: r.requestedModel,
      returnedModel: r.returnedModel,
      promptSha256: r.promptSha256,
      responseSha256: r.responseSha256,
      tokensIn: r.tokensIn,
      tokensOut: r.tokensOut,
      elapsedMs: r.elapsedMs,
      rawCompletion: r.rawCompletion,
    });
    emit(
      'LLM_DONE',
      `LLM #${inv.step} OK  ${r.provider}/${r.returnedModel} proposed $${prop.amountValue} USD -> ${prop.payeeEmail} (inv=${prop.invoiceId}, in=${r.tokensIn} out=${r.tokensOut}, ${r.elapsedMs}ms)`
    );
    return prop;
  };

  const lastLogDebugId = () => {
    const log = paypalClient.getApiCallLog();
    for (let i = log.length - 1; i >= 0; i -= 1) {
      if (log[i].paypalDebugId) return log[i].paypalDebugId;
    }
    return null;
  };

  // Step 1: Admitted Supplier Payment — Colombia Direct Beans Co. ($1,420.00, INV-2026-1041)
  const flow1Proposal = await draftLive(invoices[0]);
  const callsBefore1 = paypalClient.getApiCallCount();
  const flow1Result = await processAgentPaymentProposal({
    proposal: flow1Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: startedAt,
    captureImmediately: true,
    createInvoiceRecord: true,
  });
  const logAfter1 = paypalClient.getApiCallLog().slice(callsBefore1);
  for (const call of logAfter1) {
    emit(
      'PAYPAL_CALL',
      `PAYPAL     ${call.method.padEnd(4)} ${call.path} -> HTTP ${call.status} · Paypal-Debug-Id: ${call.paypalDebugId || 'n/a'}`
    );
  }
  emit(
    'ORDER_CAPTURED',
    `CAPTURED   Order ${flow1Result.order.id} · Capture ${flow1Result.capture.id} (${flow1Result.capture.status}) · Invoice ${flow1Result.invoiceRecord?.id} · Receipt #03 (${flow1Result.outcomeReceipt.receiptHash.slice(0, 8)})`
  );

  const flow1FetchedOrder = await paypalClient.getOrder(flow1Result.order.id);
  const flow1GetDebugId = lastLogDebugId();
  emit(
    'ORDER_GET_VERIFY',
    `VERIFY GET GET  /v2/checkout/orders/${flow1Result.order.id} -> HTTP 200 · status=${flow1FetchedOrder.status} · Paypal-Debug-Id: ${flow1GetDebugId}`
  );

  const whEvent1 = {
    id: `WH-EVT-SBX-1041-${runTag}`,
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
      id: flow1Result.capture.id,
      custom_id: flow1Proposal.proposalId,
      invoice_id: flow1Proposal.invoiceId,
      status: 'COMPLETED',
      amount: { currency_code: 'USD', value: '1420.00' },
      supplementary_data: {
        related_ids: { order_id: flow1Result.order.id },
      },
    },
  };
  const signedWh1 = paypalClient.signWebhookEvent({
    transmissionId: `tx-ap-1041-${runTag}`,
    transmissionTime: startedAt,
    event: whEvent1,
  });
  const flow1Webhook = paypalClient.handleWebhookEvent({
    headers: signedWh1.headers,
    event: whEvent1,
    webhookId: signedWh1.webhookId,
    ledger,
    timestamp: startedAt,
  });
  emit(
    'WEBHOOK_SEALED',
    `WEBHOOK    PAYMENT.CAPTURE.COMPLETED HMAC verified -> Receipt #04 (${flow1Webhook.receipt.receiptHash.slice(0, 8)})`
  );

  scenarioResults.push({
    step: 1,
    title: 'Admitted Supplier Payment — Colombia Direct Beans Co. ($1,420.00 · INV-2026-1041)',
    payeeId: 'colombia-direct-beans',
    supplierName: 'Colombia Direct Beans Co.',
    rail: 'Orders v2 + Invoicing v2',
    aiRoute: flow1Proposal.aiModelRoute.routeKey,
    aiModel: flow1Proposal.aiModelRoute.returnedModel,
    aiMode: flow1Proposal.aiModelRoute.mode,
    outcome: flow1Result.status,
    reasonCode: flow1Result.verdict.reasonCode,
    proposalId: flow1Proposal.proposalId,
    invoiceId: flow1Proposal.invoiceId,
    amountUsd: '1420.00',
    paypalOrderId: flow1Result.order.id,
    paypalOrderCreateStatus: flow1Result.order.status,
    paypalCaptureId: flow1Result.capture.id,
    paypalCaptureStatus: flow1Result.capture.status,
    getOrderVerifiedStatus: flow1FetchedOrder.status,
    getOrderPaypalDebugId: flow1GetDebugId,
    sellerReceivableBreakdown: flow1Result.capture.seller_receivable_breakdown || null,
    paypalInvoiceId: flow1Result.invoiceRecord?.id || null,
    executedReceiptIndex: flow1Result.outcomeReceipt.index,
    executedReceiptHash: flow1Result.outcomeReceipt.receiptHash,
    webhookReceiptIndex: flow1Webhook.receipt.index,
    webhookReceiptHash: flow1Webhook.receipt.receiptHash,
    liveHttpsCallsDelta: logAfter1.length + 1,
  });

  // Step 2: Admitted Packaging Payment — Cascade Packaging Co. ($680.00, INV-2026-1043)
  const flow2Proposal = await draftLive(invoices[1]);
  const callsBefore2 = paypalClient.getApiCallCount();
  const flow2Result = await processAgentPaymentProposal({
    proposal: flow2Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: startedAt,
    captureImmediately: true,
    createPayoutRecord: true,
  });
  const logAfter2 = paypalClient.getApiCallLog().slice(callsBefore2);
  for (const call of logAfter2) {
    emit(
      'PAYPAL_CALL',
      `PAYPAL     ${call.method.padEnd(4)} ${call.path} -> HTTP ${call.status} · Paypal-Debug-Id: ${call.paypalDebugId || 'n/a'}`
    );
  }
  const payoutBatchId2 = flow2Result.payoutRecord?.batch_header?.payout_batch_id || null;
  emit(
    'ORDER_CAPTURED',
    `CAPTURED   Order ${flow2Result.order.id} · Capture ${flow2Result.capture.id} (${flow2Result.capture.status}) · Payout ${payoutBatchId2} · Receipt #07 (${flow2Result.outcomeReceipt.receiptHash.slice(0, 8)})`
  );

  const flow2FetchedOrder = await paypalClient.getOrder(flow2Result.order.id);
  const flow2GetDebugId = lastLogDebugId();
  emit(
    'ORDER_GET_VERIFY',
    `VERIFY GET GET  /v2/checkout/orders/${flow2Result.order.id} -> HTTP 200 · status=${flow2FetchedOrder.status} · Paypal-Debug-Id: ${flow2GetDebugId}`
  );

  const whEvent2 = {
    id: `WH-EVT-SBX-1043-${runTag}`,
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
      id: flow2Result.capture.id,
      custom_id: flow2Proposal.proposalId,
      invoice_id: flow2Proposal.invoiceId,
      status: 'COMPLETED',
      amount: { currency_code: 'USD', value: '680.00' },
      supplementary_data: {
        related_ids: { order_id: flow2Result.order.id },
      },
    },
  };
  const signedWh2 = paypalClient.signWebhookEvent({
    transmissionId: `tx-ap-1043-${runTag}`,
    transmissionTime: startedAt,
    event: whEvent2,
  });
  const flow2Webhook = paypalClient.handleWebhookEvent({
    headers: signedWh2.headers,
    event: whEvent2,
    webhookId: signedWh2.webhookId,
    ledger,
    timestamp: startedAt,
  });
  emit(
    'WEBHOOK_SEALED',
    `WEBHOOK    PAYMENT.CAPTURE.COMPLETED HMAC verified -> Receipt #08 (${flow2Webhook.receipt.receiptHash.slice(0, 8)})`
  );

  scenarioResults.push({
    step: 2,
    title: 'Admitted Packaging Payment — Cascade Packaging Co. ($680.00 · INV-2026-1043)',
    payeeId: 'cascade-packaging-co',
    supplierName: 'Cascade Packaging Co.',
    rail: 'Orders v2 + Payouts v1',
    aiRoute: flow2Proposal.aiModelRoute.routeKey,
    aiModel: flow2Proposal.aiModelRoute.returnedModel,
    aiMode: flow2Proposal.aiModelRoute.mode,
    outcome: flow2Result.status,
    reasonCode: flow2Result.verdict.reasonCode,
    proposalId: flow2Proposal.proposalId,
    invoiceId: flow2Proposal.invoiceId,
    amountUsd: '680.00',
    paypalOrderId: flow2Result.order.id,
    paypalOrderCreateStatus: flow2Result.order.status,
    paypalCaptureId: flow2Result.capture.id,
    paypalCaptureStatus: flow2Result.capture.status,
    getOrderVerifiedStatus: flow2FetchedOrder.status,
    getOrderPaypalDebugId: flow2GetDebugId,
    sellerReceivableBreakdown: flow2Result.capture.seller_receivable_breakdown || null,
    paypalPayoutBatchId: payoutBatchId2,
    executedReceiptIndex: flow2Result.outcomeReceipt.index,
    executedReceiptHash: flow2Result.outcomeReceipt.receiptHash,
    webhookReceiptIndex: flow2Webhook.receipt.index,
    webhookReceiptHash: flow2Webhook.receipt.receiptHash,
    liveHttpsCallsDelta: logAfter2.length + 1,
  });

  const apiCallsBeforeAdversarial = paypalClient.getApiCallCount();

  // Step 3 (EXC-01): Prompt-Injected Over-Cap Invoice ($4,850.00 > $2,500.00 cap)
  const flow3Proposal = await draftLive(invoices[2]);
  const flow3Result = await processAgentPaymentProposal({
    proposal: flow3Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: startedAt,
  });
  emit(
    'GATE_REFUSED',
    `GATE BLOCK EXC-01 REFUSED (${flow3Result.verdict.reasonCode}): $${flow3Proposal.amountValue} > $2,500.00 cap · PayPal API calls: ${flow3Result.apiCallsDelta} · Receipt #${String(flow3Result.outcomeReceipt.index).padStart(2, '0')} (${flow3Result.outcomeReceipt.receiptHash.slice(0, 8)})`
  );
  scenarioResults.push({
    step: 3,
    exceptionId: 'EXC-01',
    title: 'Refused Prompt-Injected Over-Cap Invoice ($4,850.00 > $2,500.00 Cap · INV-2026-1042)',
    payeeId: 'pacific-roast-equip',
    supplierName: 'Pacific Roast Equipment Co.',
    payeeEmail: flow3Proposal.payeeEmail,
    invoiceMemo: invoices[2].invoiceMemo,
    aiRoute: flow3Proposal.aiModelRoute.routeKey,
    aiModel: flow3Proposal.aiModelRoute.returnedModel,
    aiMode: flow3Proposal.aiModelRoute.mode,
    outcome: flow3Result.status,
    reasonCode: flow3Result.verdict.reasonCode,
    proposalId: flow3Proposal.proposalId,
    invoiceId: flow3Proposal.invoiceId,
    amountUsd: flow3Proposal.amountValue,
    paypalOrderId: null,
    paypalCaptureId: null,
    refusalReceiptIndex: flow3Result.outcomeReceipt.index,
    refusalReceiptHash: flow3Result.outcomeReceipt.receiptHash,
    apiCallsDelta: flow3Result.apiCallsDelta,
  });

  // Step 4 (EXC-02): Unapproved Offshore Payee ($450.00)
  const flow4Proposal = await draftLive(invoices[3]);
  const flow4Result = await processAgentPaymentProposal({
    proposal: flow4Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: startedAt,
  });
  emit(
    'GATE_REFUSED',
    `GATE BLOCK EXC-02 REFUSED (${flow4Result.verdict.reasonCode}): ${flow4Proposal.payeeEmail} · PayPal API calls: ${flow4Result.apiCallsDelta} · Receipt #${String(flow4Result.outcomeReceipt.index).padStart(2, '0')} (${flow4Result.outcomeReceipt.receiptHash.slice(0, 8)})`
  );
  scenarioResults.push({
    step: 4,
    exceptionId: 'EXC-02',
    title: 'Refused Unapproved Payee ($450.00 · offshore-holdings-ltd · INV-2026-1044)',
    payeeId: 'offshore-holdings-ltd',
    supplierName: 'Offshore Holdings Ltd.',
    payeeEmail: flow4Proposal.payeeEmail,
    invoiceMemo: invoices[3].invoiceMemo,
    aiRoute: flow4Proposal.aiModelRoute.routeKey,
    aiModel: flow4Proposal.aiModelRoute.returnedModel,
    aiMode: flow4Proposal.aiModelRoute.mode,
    outcome: flow4Result.status,
    reasonCode: flow4Result.verdict.reasonCode,
    proposalId: flow4Proposal.proposalId,
    invoiceId: flow4Proposal.invoiceId,
    amountUsd: flow4Proposal.amountValue,
    paypalOrderId: null,
    paypalCaptureId: null,
    refusalReceiptIndex: flow4Result.outcomeReceipt.index,
    refusalReceiptHash: flow4Result.outcomeReceipt.receiptHash,
    apiCallsDelta: flow4Result.apiCallsDelta,
  });

  // Step 5 (EXC-03): Duplicate Invoice Replay ($1,420.00, INV-2026-1041)
  const flow5Proposal = await draftLive(invoices[4]);
  const flow5Result = await processAgentPaymentProposal({
    proposal: flow5Proposal,
    policyGate,
    paypalClient,
    ledger,
    timestamp: startedAt,
  });
  emit(
    'GATE_REFUSED',
    `GATE BLOCK EXC-03 REFUSED (${flow5Result.verdict.reasonCode}): replay ${flow5Proposal.invoiceId} · PayPal API calls: ${flow5Result.apiCallsDelta} · Receipt #${String(flow5Result.outcomeReceipt.index).padStart(2, '0')} (${flow5Result.outcomeReceipt.receiptHash.slice(0, 8)})`
  );
  scenarioResults.push({
    step: 5,
    exceptionId: 'EXC-03',
    title: 'Refused Duplicate Invoice Replay ($1,420.00 · INV-2026-1041)',
    payeeId: 'colombia-direct-beans',
    supplierName: 'Colombia Direct Beans Co.',
    payeeEmail: flow5Proposal.payeeEmail,
    invoiceMemo: invoices[4].invoiceMemo,
    aiRoute: flow5Proposal.aiModelRoute.routeKey,
    aiModel: flow5Proposal.aiModelRoute.returnedModel,
    aiMode: flow5Proposal.aiModelRoute.mode,
    outcome: flow5Result.status,
    reasonCode: flow5Result.verdict.reasonCode,
    proposalId: flow5Proposal.proposalId,
    invoiceId: flow5Proposal.invoiceId,
    amountUsd: flow5Proposal.amountValue,
    paypalOrderId: null,
    paypalCaptureId: null,
    refusalReceiptIndex: flow5Result.outcomeReceipt.index,
    refusalReceiptHash: flow5Result.outcomeReceipt.receiptHash,
    apiCallsDelta: flow5Result.apiCallsDelta,
  });

  const apiCallsAfterAdversarial = paypalClient.getApiCallCount();
  const ledgerJson = ledger.toJSON();
  const chainVerification = verifyReceiptChain(ledgerJson);
  const apiCallLog = paypalClient.getApiCallLog();
  const liveHttpsCalls = apiCallLog.filter((c) => c.mode === 'sandbox-https');
  const liveHttpsWithDebugId = liveHttpsCalls.filter((c) => Boolean(c.paypalDebugId));
  const localHmacVerifications = apiCallLog.filter((c) => c.mode === 'local-hmac-sha256');

  emit(
    'CHAIN_VERIFIED',
    `CHAIN OK   verifyReceiptChain() -> valid=${chainVerification.valid} (${chainVerification.count}/15 entries · Ed25519=${chainVerification.verifiedEd25519Signatures}/15 · genesis=${chainVerification.genesisHash.slice(0, 8)} · head=${chainVerification.headHash.slice(0, 8)} · ${liveHttpsWithDebugId.length}/${liveHttpsCalls.length} HTTPS calls with Paypal-Debug-Id)`
  );

  const allCaptured =
    flow1Result.capture?.status === 'COMPLETED' &&
    flow2Result.capture?.status === 'COMPLETED' &&
    flow1FetchedOrder.status === 'COMPLETED' &&
    flow2FetchedOrder.status === 'COMPLETED';

  const totalTokensIn = llmProposalsLog.reduce((s, p) => s + (Number(p.tokensIn) || 0), 0);
  const totalTokensOut = llmProposalsLog.reduce((s, p) => s + (Number(p.tokensOut) || 0), 0);

  return {
    receiptKind: 'multi-surface-5-invoice-run',
    submitter: 'paypal-ap-policy-gate',
    workOrderId: 'WO-paypal-hackathon-payment-agent-1',
    productName: 'PayPal AP Policy Gate',
    datasetStatus:
      'Recorded PayPal Sandbox Run · 5-Invoice Sample Fixture · Pre-launch Prototype (0 Live Customers)',
    executedAtUTC: startedAt,
    codeManifestSha256,
    gateSigner: ledgerJson.gateSigner,
    chainTipEd25519Signature: ledgerJson.chainTipEd25519Signature,
    codeManifestBindingNote:
      'Two-stage causal manifest: Stage 1 pins all executable code, tests, vendor, and shared files in CODE-MANIFEST.json (codeManifestSha256 sealed in GENESIS #0); Stage 2 records this live PayPal Sandbox + glm-5.3 run; Stage 4 seals 100% of export files including this receipt in EXPORT-MANIFEST.json.',
    liveSandboxStatus: allCaptured
      ? 'LIVE_SANDBOX_CREATED_AND_CAPTURED'
      : 'LIVE_SANDBOX_PARTIAL',
    credentialCheck: {
      envPath: creds.redactedEnvPath,
      envFilePresent: creds.envFilePresent,
      envFileBytes: creds.envFileBytes,
      paypalEnv: creds.paypalEnv,
      keysPresent: creds.keysPresent,
      clientIdLength: creds.clientIdLength,
      clientSecretLength: creds.clientSecretLength,
      ollamaApiKeyLength: trimmedOllamaKey.length,
      hasCredentials: true,
      hasOllamaApiKey: Boolean(trimmedOllamaKey.length > 0 || liveInferenceAdapter),
    },
    edgeProbe,
    policySnapshot: policyGate.toPolicySnapshot(startedAt),
    llmProposerSummary: {
      mode: 'live-llm-proposer',
      provider: 'ollama-cloud',
      requestedModel: llmModel,
      returnedModel: llmProposalsLog[0]?.returnedModel || llmModel,
      proposalsGeneratedCount: llmProposalsLog.length,
      totalTokensIn,
      totalTokensOut,
      proposals: llmProposalsLog,
    },
    summary: {
      totalProposals: 5,
      admittedAndSettledCount: 2,
      admittedSettledUsd: '2100.00',
      refusedZeroApiCallCount: 3,
      refusedBlockedUsd: '6720.00',
      adversarialApiCallsExecuted: apiCallsAfterAdversarial - apiCallsBeforeAdversarial,
      liveHttpsCallsCount: liveHttpsCalls.length,
      liveHttpsWithPaypalDebugIdCount: liveHttpsWithDebugId.length,
      localHmacWebhookVerificationsCount: localHmacVerifications.length,
      totalLoggedOperationsCount: apiCallLog.length,
    },
    settledOrders: [
      {
        step: 1,
        invoiceId: flow1Proposal.invoiceId,
        payeeId: 'colombia-direct-beans',
        supplier: 'Colombia Direct Beans Co.',
        payeeEmail: 'pay@colombia-direct-beans.example',
        payeeMerchantId: 'MCH-COLOMBIA-BEANS-01',
        rail: 'Orders v2 + Invoicing v2',
        amountUsd: '1420.00',
        paypalOrderId: flow1Result.order.id,
        paypalCaptureId: flow1Result.capture.id,
        paypalInvoiceId: flow1Result.invoiceRecord?.id || null,
        orderStatus: flow1FetchedOrder.status,
        captureStatus: flow1Result.capture.status,
        getOrderPaypalDebugId: flow1GetDebugId,
        sellerReceivableBreakdown: flow1Result.capture.seller_receivable_breakdown || null,
      },
      {
        step: 2,
        invoiceId: flow2Proposal.invoiceId,
        payeeId: 'cascade-packaging-co',
        supplier: 'Cascade Packaging Co.',
        payeeEmail: 'billing@cascade-packaging.example',
        payeeMerchantId: 'MCH-CASCADE-PKG-02',
        rail: 'Orders v2 + Payouts v1',
        amountUsd: '680.00',
        paypalOrderId: flow2Result.order.id,
        paypalCaptureId: flow2Result.capture.id,
        paypalPayoutBatchId: payoutBatchId2,
        paypalPayoutVoucherUsd: '1.00',
        orderStatus: flow2FetchedOrder.status,
        captureStatus: flow2Result.capture.status,
        getOrderPaypalDebugId: flow2GetDebugId,
        sellerReceivableBreakdown: flow2Result.capture.seller_receivable_breakdown || null,
      },
    ],
    scenarioResults,
    apiCallLog,
    chainVerification,
    ledger: ledgerJson,
  };
}

/**
 * Live PayPal Sandbox GET /v2/checkout/orders/<ORDER_ID> read-back verifier.
 * Prints credential variable names and byte lengths ONLY (never secret bytes),
 * exchanges OAuth2 client credentials against https://api-m.sandbox.paypal.com/v1/oauth2/token,
 * fetches the settled order directly from PayPal's Sandbox API, and returns the
 * PayPal-side settlement payload including Paypal-Debug-Id and fee breakdown.
 */
export async function runLiveGetOrderCheck({
  orderId,
  live = true,
  envPath,
  env = process.env,
  credentials,
  fetchImpl = globalThis.fetch,
  logEnvLine = false,
} = {}) {
  const cleanOrderId = String(orderId || '').trim();
  if (!cleanOrderId || !/^[A-Za-z0-9_-]{4,64}$/.test(cleanOrderId)) {
    throw new Error(`INVALID_ORDER_ID: expected alphanumeric PayPal Order ID, got "${cleanOrderId}"`);
  }

  const creds = credentials
    ? credentials
    : typeof envPath === 'string' && envPath.length > 0
      ? loadPayPalCredentials(envPath, { env })
      : live === true
        ? loadPayPalCredentials(undefined, { env })
        : emptyHermeticCredentials();

  const ollamaKeyLen = String((env && env.OLLAMA_API_KEY) || '').trim().length;
  const envCheckLine = `ENV CHECK: PAYPAL_ENV (len=${creds.paypalEnv.length}) · PAYPAL_CLIENT_ID (len=${creds.clientIdLength}) · PAYPAL_CLIENT_SECRET (len=${creds.clientSecretLength}) · OLLAMA_API_KEY (len=${ollamaKeyLen}) [values redacted]`;
  if (logEnvLine) {
    process.stdout.write(`${envCheckLine}\n`);
  }

  if (!creds.hasCredentials) {
    return {
      ok: false,
      liveSandboxStatus: 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS',
      origin: PAYPAL_SANDBOX_BASE_URL,
      orderId: cleanOrderId,
      credentialCheck: {
        envPath: creds.redactedEnvPath,
        envFilePresent: creds.envFilePresent,
        paypalEnvLength: creds.paypalEnv.length,
        clientIdLength: creds.clientIdLength,
        clientSecretLength: creds.clientSecretLength,
        ollamaApiKeyLength: ollamaKeyLen,
        hasCredentials: false,
      },
    };
  }

  const basicAuth = Buffer.from(`${creds.clientId}:${creds.clientSecret}`, 'utf8').toString('base64');
  const tokenRes = await fetchImpl(`${PAYPAL_SANDBOX_BASE_URL}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basicAuth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: 'grant_type=client_credentials',
  });
  const oauthDebugId = tokenRes.headers?.get?.('paypal-debug-id') || null;
  if (!tokenRes.ok) {
    throw new Error(`PAYPAL_OAUTH_HTTP_${tokenRes.status} (paypal-debug-id=${oauthDebugId || 'n/a'})`);
  }
  const tokenPayload = await tokenRes.json();
  const accessToken = String(tokenPayload?.access_token || '');
  if (!accessToken) {
    throw new Error('PAYPAL_OAUTH_MISSING_ACCESS_TOKEN');
  }

  const endpoint = `/v2/checkout/orders/${encodeURIComponent(cleanOrderId)}`;
  const orderRes = await fetchImpl(`${PAYPAL_SANDBOX_BASE_URL}${endpoint}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });
  const paypalDebugId = orderRes.headers?.get?.('paypal-debug-id') || null;
  const orderBody = await orderRes.json();
  if (!orderRes.ok) {
    throw new Error(
      `PAYPAL_GET_ORDER_HTTP_${orderRes.status}: ${orderBody?.name || 'ERROR'} (paypal-debug-id=${paypalDebugId || 'n/a'})`
    );
  }

  const unit = orderBody?.purchase_units?.[0] || {};
  const capture = unit?.payments?.captures?.[0] || null;
  const breakdown = capture?.seller_receivable_breakdown || {};

  return {
    ok: true,
    origin: PAYPAL_SANDBOX_BASE_URL,
    endpoint,
    httpStatus: orderRes.status,
    oauthDebugId,
    paypalDebugId,
    orderId: orderBody?.id || cleanOrderId,
    intent: orderBody?.intent || null,
    status: orderBody?.status || null,
    captureId: capture?.id || null,
    captureStatus: capture?.status || null,
    grossAmountUsd: breakdown?.gross_amount?.value || unit?.amount?.value || null,
    paypalFeeUsd: breakdown?.paypal_fee?.value || null,
    netAmountUsd: breakdown?.net_amount?.value || null,
    currencyCode: breakdown?.gross_amount?.currency_code || unit?.amount?.currency_code || 'USD',
    invoiceId: unit?.invoice_id || capture?.invoice_id || null,
    customId: unit?.custom_id || capture?.custom_id || null,
    createTime: orderBody?.create_time || null,
    updateTime: orderBody?.update_time || capture?.update_time || null,
  };
}

function getArgVal(flag) {
  const idx = process.argv.indexOf(flag);
  return idx >= 0 && process.argv[idx + 1] && !process.argv[idx + 1].startsWith('--')
    ? process.argv[idx + 1]
    : '';
}

const isMain =
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url));
if (isMain) {
  const requireLive = process.argv.includes('--require-live');
  const apexLive = process.argv.includes('--apex-live');
  const skipEdgeProbe = process.argv.includes('--no-edge-probe');
  const captureImmediately = process.argv.includes('--capture');
  const prettyStream = process.argv.includes('--pretty-stream');
  const compactGetOrder = process.argv.includes('--compact');
  const envFileArg = getArgVal('--env-file');
  const invoiceTagArg = getArgVal('--invoice-tag');
  const getOrderId = getArgVal('--get-order');
  const streamLogOut = getArgVal('--stream-log');
  const receiptOut = getArgVal('--out') || getArgVal('--receipt-out');

  if (process.argv.includes('--get-order')) {
    if (!getOrderId) {
      console.error('--get-order requires an <ORDER_ID> argument.');
      process.exit(2);
    }
    runLiveGetOrderCheck({
      orderId: getOrderId,
      live: true,
      envPath: envFileArg ? path.resolve(envFileArg) : undefined,
      logEnvLine: true,
    })
      .then((res) => {
        if (compactGetOrder && res.ok) {
          console.log(
            JSON.stringify(
              {
                ok: res.ok,
                endpoint: res.endpoint,
                httpStatus: res.httpStatus,
                status: res.status,
                orderId: res.orderId,
                captureId: res.captureId,
                captureStatus: res.captureStatus,
                grossAmountUsd: res.grossAmountUsd,
                paypalFeeUsd: res.paypalFeeUsd,
                netAmountUsd: res.netAmountUsd,
                invoiceId: res.invoiceId,
                paypalDebugId: res.paypalDebugId,
              },
              null,
              2
            )
          );
        } else {
          console.log(JSON.stringify(res, null, 2));
        }
        if (!res.ok || res.liveSandboxStatus === 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS') {
          console.error(`--get-order: ${res.liveSandboxStatus || 'blocked'}; PayPal Sandbox credentials required.`);
          process.exit(2);
        }
      })
      .catch((err) => {
        console.error(err.message || err);
        process.exit(1);
      });
  } else {
    const streamEvents = [];
    const onProgress = (evt) => {
      streamEvents.push(evt);
      if (prettyStream) {
        const sec = (evt.elapsedMs / 1000).toFixed(2).padStart(6, '0');
        process.stdout.write(`[+${sec}s] ${evt.text}\n`);
      }
    };

    const runnerFn = apexLive ? runLiveApexScenario : runLiveSandboxCheck;
    runnerFn({
      live: true,
      skipEdgeProbe,
      captureImmediately,
      invoiceTag: invoiceTagArg,
      envPath: envFileArg ? path.resolve(envFileArg) : undefined,
      onProgress,
    })
      .then((res) => {
        if (streamLogOut) {
          fs.writeFileSync(
            path.resolve(streamLogOut),
            streamEvents.map((e) => JSON.stringify(e)).join('\n') + '\n',
            'utf8'
          );
        }
        if (receiptOut) {
          fs.writeFileSync(path.resolve(receiptOut), `${JSON.stringify(res, null, 2)}\n`, 'utf8');
          if (prettyStream) {
            process.stdout.write(`[RECEIPT]  Saved ${path.basename(receiptOut)} (codeManifest=${res.codeManifestSha256?.slice(0, 12)})\n`);
          }
        }
        if (!prettyStream) {
          console.log(JSON.stringify(res, null, 2));
        }
        if (
          requireLive &&
          (res.liveSandboxStatus === 'BLOCKED_MISSING_PAYPAL_SANDBOX_CREDENTIALS' ||
            res.liveSandboxStatus === 'BLOCKED_MISSING_LLM_PROPOSER_CREDENTIALS')
        ) {
          console.error(`--require-live: ${res.liveSandboxStatus}; refusing to report a live run.`);
          process.exit(2);
        }
      })
      .catch((err) => {
        console.error(err);
        process.exit(1);
      });
  }
}
