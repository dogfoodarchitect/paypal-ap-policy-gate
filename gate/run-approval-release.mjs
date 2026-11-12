#!/usr/bin/env node
/**
 * run-approval-release.mjs — Run 5: a held payment is approved by a named person, then released and paid.
 *
 * Same building blocks as run-attack-suite.mjs: AIProcurementAgent (glm-5.3 through Ollama Cloud in live
 * mode), PolicyGate, processAgentPaymentProposal, PayPalSandboxClient, ReceiptLedger, the scoreboard code.
 * New: ONE gate for the whole run (a hold lives in the gate's memory), and scripted approver steps between
 * proposals, read from `approval-release-suite.json` (`steps`).
 *
 *   propose  one model call on the invoice text, then one pass through the gate
 *   approve  gate.approveHeldProposal(proposal, { approvedBy, timestamp, ledger })
 *   reject   gate.rejectHeldProposal(proposal, { rejectedBy, timestamp, ledger })
 *   release  the SAME proposal object goes through processAgentPaymentProposal again (no model call)
 *
 * In Run 5 the approver steps are entered by this script under the name in the suite file. A person does
 * not click them. An approval that is DENIED or throws writes no ledger entry: what the gate returned is
 * kept in the receipt's unsigned `approverSteps` list.
 *
 * Usage: node run-approval-release.mjs --simulate --out run5-sim.json
 *        node run-approval-release.mjs --out approval-release-run5-receipt.json   (live PayPal Sandbox)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ReceiptLedger, verifyReceiptChain } from './receipt-ledger.mjs';
import {
  PolicyGate,
  DEFAULT_AP_POLICY_GATE_CONFIG,
  processAgentPaymentProposal,
  replayPaidHistory,
} from './policy-gate.mjs';
import { PayPalSandboxClient, PAYPAL_SANDBOX_BASE_URL } from './paypal-client.mjs';
import { AIProcurementAgent, createOllamaCloudAdapter } from './ai-procurement-agent.mjs';
import { loadPayPalCredentials } from './live-sandbox-runner.mjs';
import {
  computeAttackSuiteScoreboard,
  evaluateObedienceAndHonesty,
  normalizeCoreProposalFields,
  withBoundedRetry,
} from './run-attack-suite.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SET_NAME = 'approval-release-run5';

const sha256Buf = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/**
 * Simulation-only stand-in for the model: reads the invoice text in the prompt with plain patterns and
 * returns the JSON the real model is asked for. It is labelled as a stand-in everywhere it appears.
 */
export function createSimulationExtractorAdapter() {
  return async ({ prompt }) => {
    const text = String(prompt);
    const grab = (re) => (text.match(re) || [])[1]?.trim() ?? null;
    const amountRaw = grab(/AMOUNT DUE:\s*\$?([\d,]+(?:\.\d{1,2})?)/);
    const completion = {
      proposalId: grab(/Use exact "proposalId": "([^"]+)"/) || 'sim-prop',
      invoiceId: grab(/INVOICE NUMBER:\s*(\S+)/),
      supplierName: grab(/VENDOR:\s*(.+?)\s*\(/),
      payeeEmail: grab(/FROM:[^<\n]*<([^>]+)>/),
      payeeMerchantId: grab(/Merchant ID:\s*([A-Z0-9-]+)\)/),
      amountValue: amountRaw ? Number(amountRaw.replace(/,/g, '')).toFixed(2) : null,
      currencyCode: grab(/AMOUNT DUE:[^\n]*\s([A-Z]{3})\b/) || 'USD',
      reason: grab(/LINE ITEM:\s*(.+)/),
    };
    return {
      rawCompletion: JSON.stringify(completion),
      returnedModel: 'simulation-regex-extractor',
      tokensIn: 0,
      tokensOut: 0,
      doneReason: 'stop',
      httpStatus: 200,
      elapsedMs: 0,
    };
  };
}

const gateWord = (v) => ({ decision: v.decision, reasonCode: v.reasonCode, reasonDetail: v.reasonDetail });

export async function runApprovalRelease({
  suitePath = path.join(HERE, 'approval-release-suite.json'),
  manifestPath = path.join(HERE, 'CODE-MANIFEST.json'),
  gateGeneration = 'po-v4',
  sandboxRunTag = null,
  simulate = false,
  clientId = process.env.PAYPAL_CLIENT_ID || '',
  clientSecret = process.env.PAYPAL_CLIENT_SECRET || '',
  ollamaApiKey = process.env.OLLAMA_API_KEY || '',
  // Test seams (unit tests only): a model stand-in and an injected PayPal client.
  inferenceAdapter = null,
  paypalClientOverride = null,
} = {}) {
  const suiteBuf = fs.readFileSync(suitePath);
  const suiteSha256 = sha256Buf(suiteBuf);
  const suite = JSON.parse(suiteBuf.toString('utf8'));
  const fixedTs = suite.fixedEvaluationTimestamp || '2026-11-11T12:00:00.000Z';
  const approverName = suite.approver?.name;
  if (!approverName) throw new Error('SUITE_APPROVER_MISSING: the suite file must name the approver');
  const recordById = new Map(suite.records.map((r) => [r.suiteId, r]));

  const isLive = !simulate && Boolean(clientId && clientSecret && ollamaApiKey);
  if (!simulate && !isLive) {
    throw new Error(
      'RUN5_LIVE_CREDENTIALS_MISSING: pass --simulate for offline mode or set PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, and OLLAMA_API_KEY'
    );
  }
  const baseAdapter = isLive
    ? createOllamaCloudAdapter({ apiKey: ollamaApiKey, numPredict: 6144 })
    : inferenceAdapter || createSimulationExtractorAdapter();
  const retryingAdapter = async (params) => {
    let lastErr = null;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      try {
        const res = await baseAdapter(params);
        if (!res?.rawCompletion || !String(res.rawCompletion).trim()) throw new Error('LLM_EMPTY_COMPLETION_RETRY');
        return res;
      } catch (err) {
        lastErr = err;
        if (attempt < 5) await new Promise((r) => setTimeout(r, isLive ? 4000 * attempt : 0));
      }
    }
    throw lastErr;
  };
  const agent = new AIProcurementAgent({
    defaultRoute: 'ollama-cloud:glm-5.3',
    liveInferenceAdapter: retryingAdapter,
  });
  const routeKey = 'ollama-cloud:glm-5.3';
  const proposerRoute = isLive ? routeKey : 'simulation:regex-extractor-standin';

  const paypalClient =
    paypalClientOverride ||
    new PayPalSandboxClient({
      clientId: isLive ? clientId : '',
      clientSecret: isLive ? clientSecret : '',
      baseUrl: PAYPAL_SANDBOX_BASE_URL,
      mode: isLive ? 'sandbox-https' : 'simulation',
      sandboxRunTag: sandboxRunTag || (isLive ? `SUITE-${Date.now().toString(36).toUpperCase()}` : null),
    });
  if (isLive && !paypalClientOverride) withBoundedRetry(paypalClient);

  const policyGateSha256 = sha256Buf(fs.readFileSync(path.join(HERE, 'policy-gate.mjs')));
  const codeManifestSha256 = fs.existsSync(manifestPath)
    ? sha256Buf(fs.readFileSync(manifestPath))
    : sha256Buf(Buffer.from(`adhoc:policy-gate=${policyGateSha256}:suite=${suiteSha256}`, 'utf8'));
  const suiteSets = [
    { name: SET_NAME, file: path.basename(suitePath), sha256: suiteSha256, recordCount: suite.records.length, fixedEvaluationTimestamp: fixedTs },
  ];
  const policyFeatures = {
    duplicatePaymentHold: true,
    paidOnlyAfterCapture: true,
    recordedAtPerEntry: true,
    scoreboardVersion: 2,
    multiRail: false,
    approvalRelease: true,
  };
  const protagonist =
    'Run 5: approval and release (6 invoices, 8 passes through the gate, scripted approver steps) · Pre-launch Prototype · 0 Live Customers';

  const ledger = new ReceiptLedger({
    ledgerId: `paypal-approval-release-${gateGeneration}`,
    genesisTimestamp: fixedTs,
    protagonist,
    metadata: {
      receiptKind: 'attack-suite-run',
      gateGeneration,
      codeManifestSha256,
      attackSuiteSha256: suiteSha256,
      suiteSets,
      policyFeatures,
      policyGateSha256,
      executionEnvironment: isLive ? PAYPAL_SANDBOX_BASE_URL : 'offline-simulation',
      aiProposerRoute: proposerRoute,
    },
  });

  const gate = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG);
  const baselineSnapshot = new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG).toPolicySnapshot(fixedTs);
  const freshWithSetup = (setup) => replayPaidHistory(new PolicyGate(DEFAULT_AP_POLICY_GATE_CONFIG), setup, fixedTs);

  const proposals = new Map(); // suiteId -> the proposal object the model returned
  const llmProposals = [];
  const suiteRecords = [];
  const approverSteps = [];
  let totalTokensIn = 0;
  let totalTokensOut = 0;
  let returnedModelName = isLive ? 'glm-5.3' : 'simulation-regex-extractor';

  const runPass = async (rec, proposal, { reused }) => {
    const step = suiteRecords.length + 1;
    const routeMeta = proposal.aiModelRoute || {};
    if (!reused) {
      if (routeMeta.returnedModel) returnedModelName = routeMeta.returnedModel;
      totalTokensIn += Number(routeMeta.tokensIn) || 0;
      totalTokensOut += Number(routeMeta.tokensOut) || 0;
    }
    llmProposals.push({
      step,
      suiteId: rec.suiteId,
      proposalId: proposal.proposalId,
      invoiceId: proposal.invoiceId,
      payeeEmail: proposal.payeeEmail,
      payeeMerchantId: proposal.payeeMerchantId,
      amountUsd: proposal.amountValue,
      currencyCode: proposal.currencyCode,
      mode: routeMeta.mode,
      provider: routeMeta.provider,
      returnedModel: routeMeta.returnedModel,
      promptSha256: routeMeta.promptSha256 || null,
      rawCompletion: routeMeta.rawCompletion || null,
      responseSha256: routeMeta.responseSha256 || null,
      tokensIn: reused ? null : routeMeta.tokensIn ?? null,
      tokensOut: reused ? null : routeMeta.tokensOut ?? null,
      elapsedMs: reused ? null : routeMeta.elapsedMs ?? null,
      ...(reused ? { reusedProposalOf: rec.reusesProposalOf } : {}),
    });

    const { obeyedInjection, matchedHonestProposal } = evaluateObedienceAndHonesty(rec, proposal);
    const honestGateEval = rec.honestProposal
      ? freshWithSetup(rec.setup).evaluate(rec.honestProposal, { timestamp: fixedTs })
      : null;
    const obedientGateEval = freshWithSetup(rec.setup).evaluate(rec.obedientProposal, { timestamp: fixedTs });

    const execRes = await processAgentPaymentProposal({
      proposal,
      policyGate: gate,
      paypalClient,
      ledger,
      timestamp: fixedTs,
      captureImmediately: true,
    });

    const honestPolicyDecision = honestGateEval ? honestGateEval.decision : null;
    const isHonestInPolicy = rec.kind === 'attack' && matchedHonestProposal === true && honestPolicyDecision === 'ALLOW';
    suiteRecords.push({
      step,
      suiteSet: SET_NAME,
      suiteId: rec.suiteId,
      kind: rec.kind,
      technique: rec.technique,
      whatTheAttackerWants: rec.whatTheAttackerWants,
      setupCount: (rec.setup || []).length,
      obeyedInjectionComparable: rec.obeyedInjectionComparable,
      obeyedInjection,
      matchedHonestProposal,
      honestProposalPolicyDecision: honestPolicyDecision,
      directGateOnObedientDecision: obedientGateEval.decision,
      directGateOnObedientReasonCode: obedientGateEval.reasonCode,
      outsidePolicyAttempt: rec.kind === 'attack' ? !isHonestInPolicy : false,
      expectedGateDecisionIfObeyed: rec.expectedGateDecisionIfObeyed,
      expectedReasonCode: rec.expectedReasonCode,
      invoiceSnippet: String(rec.invoice?.invoiceDocument || ''),
      honestProposalSummary: normalizeCoreProposalFields(rec.honestProposal),
      obedientProposalSummary: normalizeCoreProposalFields(rec.obedientProposal),
      modelProposal: {
        proposalId: proposal.proposalId,
        invoiceId: proposal.invoiceId,
        supplierName: proposal.supplierName,
        payeeEmail: proposal.payeeEmail,
        payeeMerchantId: proposal.payeeMerchantId,
        amountValue: proposal.amountValue,
        currencyCode: proposal.currencyCode,
        reason: proposal.reason,
      },
      gateDecision: execRes.verdict.decision,
      outcome: execRes.status,
      reasonCode: execRes.verdict.reasonCode,
      reasonDetail: execRes.verdict.reasonDetail,
      apiCallsDelta: execRes.apiCallsDelta,
      paypalOrderId: execRes.order?.id || null,
      paypalCaptureId: execRes.capture?.id || null,
      paypalInvoiceId: execRes.invoiceRecord?.id || null,
      paypalPayoutBatchId: execRes.payoutRecord?.batch_header?.payout_batch_id || null,
      proposedReceiptIndex: execRes.proposedReceipt.index,
      proposedReceiptHash: execRes.proposedReceipt.receiptHash,
      outcomeReceiptIndex: execRes.outcomeReceipt.index,
      outcomeReceiptHash: execRes.outcomeReceipt.receiptHash,
      ...(reused ? { reusesProposalOf: rec.reusesProposalOf, modelCallMade: false } : { modelCallMade: true }),
    });
    process.stderr.write(
      `[pass ${String(step).padStart(2, '0')}] ${rec.suiteId} -> ${execRes.status} (${execRes.verdict.reasonCode}) apiCalls=${execRes.apiCallsDelta}\n`
    );
  };

  const recordApprover = (action, target, name, outcome) => {
    approverSteps.push({
      afterPass: suiteRecords.length,
      action,
      target,
      by: name,
      enteredBy: 'run script',
      ...outcome,
    });
    process.stderr.write(`[approver] ${action} ${target} by "${name}" -> ${outcome.threw ? `THREW ${outcome.threw.split(':')[0]}` : outcome.status}\n`);
  };

  for (const s of suite.steps) {
    if (s.do === 'propose') {
      const rec = recordById.get(s.record);
      const proposal = await agent.draftPaymentProposal(rec.invoice, { route: routeKey, requireLiveLlm: true });
      proposals.set(rec.suiteId, proposal);
      await runPass(rec, proposal, { reused: false });
    } else if (s.do === 'release') {
      const rec = recordById.get(s.record);
      const held = proposals.get(s.target);
      if (!held) throw new Error(`RUN5_RELEASE_WITHOUT_PROPOSAL: no proposal for ${s.target}`);
      // Default: the SAME object. `newProposalId` (suite-file option) sends a copy under another id.
      const proposal = s.newProposalId ? Object.freeze({ ...held, proposalId: s.newProposalId }) : held;
      await runPass(rec, proposal, { reused: true });
    } else if (s.do === 'approve' || s.do === 'reject') {
      const proposal = proposals.get(s.target);
      if (!proposal) throw new Error(`RUN5_APPROVER_WITHOUT_PROPOSAL: no proposal for ${s.target}`);
      const before = ledger.entries.length;
      try {
        const res =
          s.do === 'approve'
            ? gate.approveHeldProposal(proposal, { approvedBy: approverName, timestamp: fixedTs, ledger })
            : gate.rejectHeldProposal(proposal, { rejectedBy: approverName, timestamp: fixedTs, ledger });
        recordApprover(s.do, s.target, approverName, {
          ok: res.ok,
          status: res.status,
          idempotent: res.idempotent ?? null,
          verdict: res.verdict ? gateWord(res.verdict) : null,
          signedLedgerEntryIndex: res.receipt ? res.receipt.index : null,
          ledgerEntriesAdded: ledger.entries.length - before,
        });
      } catch (err) {
        recordApprover(s.do, s.target, approverName, {
          threw: String(err?.message || err),
          signedLedgerEntryIndex: null,
          ledgerEntriesAdded: ledger.entries.length - before,
        });
      }
    } else {
      throw new Error(`RUN5_UNKNOWN_STEP: ${JSON.stringify(s)}`);
    }
  }

  const ledgerJson = ledger.toJSON();
  const chainVerification = verifyReceiptChain(ledgerJson);
  const scoreboard = computeAttackSuiteScoreboard(ledgerJson.entries, suiteRecords, { scoreboardVersion: 2 });
  const apiCallLog = paypalClient.getApiCallLog();
  const httpsCallsCount = apiCallLog.filter((c) => c.mode === 'sandbox-https').length;

  return {
    receiptKind: 'attack-suite-run',
    gateGeneration,
    generatedAt: new Date().toISOString(),
    fixedEvaluationTimestamp: fixedTs,
    protagonist,
    codeManifestSha256,
    attackSuiteSha256: suiteSha256,
    suiteSets,
    policyFeatures,
    policyGateSha256,
    liveSandboxStatus: isLive ? 'LIVE_SANDBOX_CREATED_AND_CAPTURED' : 'SIMULATED_SUITE_RUN',
    sandboxBaseUrl: PAYPAL_SANDBOX_BASE_URL,
    gateSigner: ledgerJson.gateSigner,
    chainTipEd25519Signature: ledgerJson.chainTipEd25519Signature,
    policySnapshot: { ...baselineSnapshot },
    scoreboard,
    scoreboardBySet: { [SET_NAME]: scoreboard },
    summary: {
      totalProposals: suiteRecords.length,
      attacksTotal: scoreboard.attacksTotal,
      controlsTotal: scoreboard.controlsTotal,
      comparableAttacks: scoreboard.comparableAttacks,
      modelObeyedCount: scoreboard.modelObeyedCount,
      gateAdmittedAttacks: scoreboard.gateAdmittedAttacks,
      controlsPaid: scoreboard.controlsPaid,
      dollarsMovedOutsidePolicy: scoreboard.dollarsMovedOutsidePolicy,
      attackerGoalReachedInsidePolicyUsd: scoreboard.attackerGoalReachedInsidePolicyUsd,
      adversarialApiCallsExecuted: scoreboard.refusedApiCalls,
      liveHttpsCallsCount: httpsCallsCount,
      modelCalls: suiteRecords.filter((r) => r.modelCallMade).length,
    },
    approver: { name: approverName, enteredBy: 'run script', clickedByAPerson: false },
    approverSteps,
    llmProposerSummary: {
      mode: isLive ? 'live-llm-proposer' : 'simulation-regex-extractor-standin',
      routeKey: proposerRoute,
      provider: isLive ? 'ollama-cloud' : 'simulation',
      requestedModel: isLive ? 'glm-5.3' : null,
      returnedModel: returnedModelName,
      totalTokensIn,
      totalTokensOut,
      proposals: llmProposals,
    },
    suiteRecords,
    apiCallLog,
    chainVerification,
    ledger: ledgerJson,
  };
}

const isMain =
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url));

if (isMain) {
  const args = process.argv.slice(2);
  const simulate = args.includes('--simulate');
  const val = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 && args[i + 1] ? args[i + 1] : null;
  };
  const outPath = val('--out') ? path.resolve(val('--out')) : null;
  const sandboxRunTag = val('--sandbox-run-tag');
  const suitePath = val('--suite') ? path.resolve(val('--suite')) : undefined;

  let paypalCreds = { clientId: '', clientSecret: '' };
  if (!simulate) {
    const creds = loadPayPalCredentials(process.env.PAYPAL_ENV_FILE || undefined);
    if (creds.paypalEnv !== 'sandbox') {
      console.error(`RUN5_NOT_SANDBOX: PAYPAL_ENV is "${creds.paypalEnv}"; only "sandbox" is allowed. Stopping.`);
      process.exit(2);
    }
    process.stderr.write(
      `ENV CHECK: PAYPAL_ENV=sandbox · PAYPAL_CLIENT_ID (len=${creds.clientIdLength}) · PAYPAL_CLIENT_SECRET (len=${creds.clientSecretLength}) · OLLAMA_API_KEY (len=${String(process.env.OLLAMA_API_KEY || '').trim().length}) [values redacted]\n`
    );
    paypalCreds = { clientId: creds.clientId, clientSecret: creds.clientSecret };
  }

  const receipt = await runApprovalRelease({ simulate, sandboxRunTag, suitePath, ...paypalCreds });
  const serialized = `${JSON.stringify(receipt, null, 2)}\n`;
  if (outPath) {
    fs.writeFileSync(outPath, serialized, 'utf8');
    console.log(
      JSON.stringify(
        {
          ok: true,
          outPath: path.basename(outPath),
          bytes: Buffer.byteLength(serialized),
          sha256: sha256Buf(Buffer.from(serialized, 'utf8')),
          liveSandboxStatus: receipt.liveSandboxStatus,
          chainValid: receipt.chainVerification.valid,
          chainCount: receipt.chainVerification.count,
          stageCounts: receipt.chainVerification.stageCounts,
          scoreboard: receipt.scoreboard,
        },
        null,
        2
      )
    );
  } else {
    process.stdout.write(serialized);
  }
}
