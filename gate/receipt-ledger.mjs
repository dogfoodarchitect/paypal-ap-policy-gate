/**
 * receipt-ledger.mjs — Tamper-Evident SHA-256 + Ed25519 Signed Receipt Ledger
 *
 * Every AI payment proposal, policy gate decision, PayPal Sandbox execution,
 * webhook settlement event, and operational policy/exception review action is
 * recorded as an immutable, canonically serialized JSON receipt chained via
 * SHA-256 (`prevHash` -> `receiptHash`) and signed inside the gate enclave
 * with RFC 8032 `Ed25519` asymmetric signatures (`ed25519Signature`).
 *
 * Zero external dependencies — Node.js built-in `node:crypto` only.
 */
import crypto from 'node:crypto';

export const GENESIS_PREV_HASH = '0'.repeat(64);
export const ISO_8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

export const RECEIPT_STAGES = Object.freeze([
  'GENESIS',
  'PROPOSED',
  'ADMITTED',
  'REFUSED',
  'HELD',
  'APPROVED',
  'REJECTED',
  'EXECUTED',
  'WEBHOOK_SETTLED',
  'POLICY_UPDATED',
  'EXCEPTION_REVIEWED',
  'EXCEPTION_DISMISSED',
]);

/**
 * Deterministic RFC-8785-style canonical JSON serializer so SHA-256 hashes
 * are 100% reproducible regardless of JS object property insertion order.
 */
export function canonicalize(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'boolean' || typeof value === 'number') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new TypeError('Receipt canonicalize() rejects non-finite numbers');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item === undefined ? null : item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
    return `{${pairs.join(',')}}`;
  }
  throw new TypeError(`Unsupported receipt value type: ${typeof value}`);
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Computes the SHA-256 hash of a receipt entry excluding its `receiptHash`
 * and `ed25519Signature` fields.
 */
export function computeReceiptHash(entryWithoutHash) {
  const { receiptHash: _ignoredHash, ed25519Signature: _ignoredSig, ...rest } = entryWithoutHash;
  return sha256Hex(canonicalize(rest));
}

function createEd25519EnclaveSigner(privateKeyPem = null) {
  let privateKeyObj;
  if (privateKeyPem) {
    privateKeyObj = crypto.createPrivateKey(privateKeyPem);
  } else {
    const generated = crypto.generateKeyPairSync('ed25519');
    privateKeyObj = generated.privateKey;
  }
  const publicKeyObj = crypto.createPublicKey(privateKeyObj);
  const publicKeyPem = publicKeyObj.export({ type: 'spki', format: 'pem' }).toString();
  const publicKeySpkiBase64 = publicKeyObj.export({ type: 'spki', format: 'der' }).toString('base64');
  const publicKeySha256 = sha256Hex(publicKeyPem);
  return {
    privateKeyObj,
    signerMeta: Object.freeze({
      algorithm: 'Ed25519',
      publicKeyPem,
      publicKeySpkiBase64,
      publicKeySha256,
    }),
  };
}

function resolvePublicKeyObject({ pem = null, spkiBase64 = null } = {}) {
  if (pem && typeof pem === 'string') {
    return crypto.createPublicKey(pem);
  }
  if (spkiBase64 && typeof spkiBase64 === 'string') {
    return crypto.createPublicKey({
      key: Buffer.from(spkiBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
  }
  return null;
}

export class ReceiptLedger {
  #privateKey;

  constructor({
    ledgerId = 'paypal-ap-policy-gate-ledger',
    genesisTimestamp = '2026-11-11T00:00:00.000Z',
    protagonist = 'Synthetic 5-Invoice B2B Supplier Test Fixture (Pre-launch Prototype · 0 Live Customers)',
    metadata = {},
    privateKeyPem = process.env.GATE_ED25519_PRIVATE_KEY_PEM || null,
    skipGenesis = false,
    recordedClock = () => new Date().toISOString(),
  } = {}) {
    this.ledgerId = ledgerId;
    this.protagonist = protagonist;
    this.entries = [];
    this.recordedClock = recordedClock;

    const enclave = createEd25519EnclaveSigner(privateKeyPem);
    this.#privateKey = enclave.privateKeyObj;
    this.gateSigner = enclave.signerMeta;
    this.sessionSigner = null;
    this.baselineSignedCount = null;

    if (!skipGenesis) {
      this._appendRaw({
        stage: 'GENESIS',
        timestamp: genesisTimestamp,
        proposalId: null,
        actor: 'system:receipt-ledger',
        payload: {
          ledgerId,
          protagonist,
          hashAlgorithm: 'SHA-256',
          signatureAlgorithm: 'Ed25519',
          gatePublicKeySha256: this.gateSigner.publicKeySha256,
          gatePublicKeySpkiBase64: this.gateSigner.publicKeySpkiBase64,
          ...metadata,
        },
        policyVerdict: null,
        paypalOrderId: null,
        paypalCaptureId: null,
      });
    }
  }

  static fromJSON(snapshot) {
    if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.entries) || snapshot.entries.length === 0) {
      throw new Error('ReceiptLedger.fromJSON requires a snapshot with at least a GENESIS entry');
    }
    const check = verifyReceiptChain(snapshot);
    if (!check.valid) {
      throw new Error(`ReceiptLedger.fromJSON refused invalid chain: ${check.errors[0]?.reason || 'INVALID_CHAIN'}`);
    }
    const instance = new ReceiptLedger({
      ledgerId: snapshot.ledgerId || 'paypal-ap-policy-gate-ledger',
      protagonist: snapshot.protagonist || 'Synthetic 5-Invoice B2B Supplier Test Fixture',
      skipGenesis: true,
    });
    // Preserve original enclave public key metadata for baseline entries,
    // while using the ephemeral session signer for operational appends (#N+).
    const sessionEnclaveSigner = instance.gateSigner;
    if (snapshot.gateSigner && snapshot.gateSigner.publicKeyPem) {
      instance.gateSigner = Object.freeze({ ...snapshot.gateSigner });
    } else if (snapshot.entries[0]?.payload?.gatePublicKeySpkiBase64) {
      const pubObj = resolvePublicKeyObject({ spkiBase64: snapshot.entries[0].payload.gatePublicKeySpkiBase64 });
      const pem = pubObj.export({ type: 'spki', format: 'pem' }).toString();
      instance.gateSigner = Object.freeze({
        algorithm: 'Ed25519',
        publicKeyPem: pem,
        publicKeySpkiBase64: snapshot.entries[0].payload.gatePublicKeySpkiBase64,
        publicKeySha256: snapshot.entries[0].payload.gatePublicKeySha256 || sha256Hex(pem),
      });
    }
    instance.baselineSignedCount = snapshot.entries.length;
    instance.sessionSigner = Object.freeze({
      ...sessionEnclaveSigner,
      startIndex: snapshot.entries.length,
    });
    instance.entries = snapshot.entries.map((entry) => Object.freeze(structuredClone(entry)));
    return instance;
  }

  _appendRaw({
    stage,
    timestamp = new Date().toISOString(),
    proposalId = null,
    actor = 'agent:ap-proposer',
    payload = {},
    policyVerdict = null,
    paypalOrderId = null,
    paypalCaptureId = null,
  }) {
    if (!RECEIPT_STAGES.includes(stage)) {
      throw new Error(`Invalid receipt stage: ${stage}`);
    }
    const index = this.entries.length;
    const prevHash = index === 0 ? GENESIS_PREV_HASH : this.entries[index - 1].receiptHash;
    const receiptId = `rcpt_${this.ledgerId}_${String(index).padStart(4, '0')}`;

    const isOperationalSessionEntry =
      this.baselineSignedCount !== null && index >= this.baselineSignedCount && this.sessionSigner !== null;

    // `timestamp` is the fixed evaluation clock the policy uses for its daily window.
    // `recordedAt` is the real wall-clock time this entry was signed (ISO 8601, inside the signed hash).
    // It never moves backwards inside one ledger: a clock step is clamped to the previous entry.
    const prevRecorded = index === 0 ? null : this.entries[index - 1].recordedAt || null;
    let recordedAt = String(this.recordedClock());
    if (prevRecorded && Date.parse(recordedAt) < Date.parse(prevRecorded)) recordedAt = prevRecorded;

    const draft = {
      receiptId,
      ledgerId: this.ledgerId,
      index,
      stage,
      timestamp,
      recordedAt,
      proposalId,
      actor,
      payload: isOperationalSessionEntry
        ? {
            ...payload,
            sessionPublicKeySpkiBase64: this.sessionSigner.publicKeySpkiBase64,
            sessionPublicKeySha256: this.sessionSigner.publicKeySha256,
          }
        : payload,
      policyVerdict,
      paypalOrderId,
      paypalCaptureId,
      prevHash,
    };

    const receiptHash = computeReceiptHash(draft);
    const ed25519Signature = crypto
      .sign(null, Buffer.from(receiptHash, 'utf8'), this.#privateKey)
      .toString('base64');
    const sealed = Object.freeze({ ...draft, receiptHash, ed25519Signature });
    this.entries.push(sealed);
    return sealed;
  }

  append(record) {
    if (record?.stage === 'GENESIS') {
      throw new Error('GENESIS receipt cannot be appended after ledger initialization');
    }
    return this._appendRaw(record);
  }

  getHead() {
    return this.entries[this.entries.length - 1] || null;
  }

  getEntries() {
    return this.entries.slice();
  }

  getByProposalId(proposalId) {
    return this.entries.filter((e) => e.proposalId === proposalId);
  }

  toJSON() {
    const head = this.getHead();
    return {
      ledgerId: this.ledgerId,
      protagonist: this.protagonist,
      entryCount: this.entries.length,
      headHash: head?.receiptHash || null,
      chainTipEd25519Signature: head?.ed25519Signature || null,
      gateSigner: structuredClone(this.gateSigner),
      ...(this.sessionSigner ? { sessionSigner: structuredClone(this.sessionSigner) } : {}),
      entries: structuredClone(this.entries),
    };
  }
}

/**
 * Verifies an entire receipt chain (either a ReceiptLedger instance, a ledger JSON snapshot,
 * or a plain JSON array of entries).
 * Detects:
 *  - Missing or invalid GENESIS root
 *  - Non-contiguous index sequence
 *  - Any mutated payload, policyVerdict, timestamp, or PayPal ID (`receiptHash` mismatch)
 *  - Any deleted, reordered, or spliced entry (`prevHash` mismatch)
 *  - Any forged or re-hashed entry lacking a valid enclave `Ed25519` signature (`ED25519_SIGNATURE_INVALID`)
 *  - Refused payment invariant violation (a REFUSED entry must never carry a PayPal Order/Capture ID)
 *  - A malformed or backwards `recordedAt` (entries written by this generation carry a real recorded time)
 */
export function verifyReceiptChain(ledgerOrEntries) {
  const entries = Array.isArray(ledgerOrEntries)
    ? ledgerOrEntries
    : ledgerOrEntries?.entries || [];

  const errors = [];

  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      valid: false,
      count: 0,
      headHash: null,
      errors: [{ index: 0, reason: 'EMPTY_LEDGER: at least GENESIS entry is required' }],
    };
  }

  let baselinePubKey = null;
  let baselinePubSha256 = null;
  try {
    const gateSigner = !Array.isArray(ledgerOrEntries) ? ledgerOrEntries?.gateSigner : null;
    const genesisPayload = entries[0]?.payload || {};
    baselinePubKey = resolvePublicKeyObject({
      pem: gateSigner?.publicKeyPem || null,
      spkiBase64: gateSigner?.publicKeySpkiBase64 || genesisPayload.gatePublicKeySpkiBase64 || null,
    });
    if (baselinePubKey) {
      const exportedPem = baselinePubKey.export({ type: 'spki', format: 'pem' }).toString();
      baselinePubSha256 = sha256Hex(exportedPem);
      if (
        genesisPayload.gatePublicKeySha256 &&
        genesisPayload.gatePublicKeySha256 !== baselinePubSha256
      ) {
        errors.push({
          index: 0,
          receiptId: entries[0]?.receiptId,
          reason: `PUBLIC_KEY_FINGERPRINT_MISMATCH: GENESIS pins ${genesisPayload.gatePublicKeySha256}, gateSigner is ${baselinePubSha256}`,
        });
      }
    }
  } catch (err) {
    errors.push({
      index: 0,
      receiptId: entries[0]?.receiptId,
      reason: `INVALID_GATE_PUBLIC_KEY: ${err.message}`,
    });
  }

  const sessionSignerMeta = !Array.isArray(ledgerOrEntries) ? ledgerOrEntries?.sessionSigner : null;
  let sessionPubKey = null;
  try {
    if (sessionSignerMeta) {
      sessionPubKey = resolvePublicKeyObject({
        pem: sessionSignerMeta.publicKeyPem || null,
        spkiBase64: sessionSignerMeta.publicKeySpkiBase64 || null,
      });
    }
  } catch {
    sessionPubKey = null;
  }

  let verifiedSignatures = 0;

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (!entry || typeof entry !== 'object') {
      errors.push({ index: i, reason: 'MALFORMED_ENTRY: receipt is not an object' });
      continue;
    }

    if (entry.index !== i) {
      errors.push({
        index: i,
        receiptId: entry.receiptId,
        reason: `INDEX_MISMATCH: expected index ${i}, found ${entry.index}`,
      });
    }

    if (!RECEIPT_STAGES.includes(entry.stage)) {
      errors.push({
        index: i,
        receiptId: entry.receiptId,
        reason: `UNKNOWN_STAGE: ${String(entry.stage)}`,
      });
    }

    if (i === 0) {
      if (entry.stage !== 'GENESIS') {
        errors.push({
          index: 0,
          receiptId: entry.receiptId,
          reason: `INVALID_GENESIS_STAGE: expected GENESIS, found ${entry.stage}`,
        });
      }
      if (entry.prevHash !== GENESIS_PREV_HASH) {
        errors.push({
          index: 0,
          receiptId: entry.receiptId,
          reason: 'INVALID_GENESIS_PREV_HASH: genesis prevHash must be 64 zeros',
        });
      }
    } else {
      const expectedPrev = entries[i - 1]?.receiptHash;
      if (entry.prevHash !== expectedPrev) {
        errors.push({
          index: i,
          receiptId: entry.receiptId,
          reason: `PREV_HASH_CHAIN_BROKEN: expected ${expectedPrev}, found ${entry.prevHash}`,
        });
      }
    }

    const recomputed = computeReceiptHash(entry);
    if (entry.receiptHash !== recomputed) {
      errors.push({
        index: i,
        receiptId: entry.receiptId,
        reason: `RECEIPT_HASH_TAMPERED: expected ${recomputed}, found ${entry.receiptHash}`,
      });
    }

    // Verify RFC 8032 Ed25519 signature over canonical receiptHash
    let entryPubKey = baselinePubKey;
    if (entry.payload?.sessionPublicKeySpkiBase64) {
      try {
        entryPubKey =
          sessionPubKey ||
          resolvePublicKeyObject({ spkiBase64: entry.payload.sessionPublicKeySpkiBase64 });
      } catch {
        entryPubKey = null;
      }
    }

    if (entryPubKey) {
      if (!entry.ed25519Signature || typeof entry.ed25519Signature !== 'string') {
        errors.push({
          index: i,
          receiptId: entry.receiptId,
          reason: 'ED25519_SIGNATURE_MISSING: receipt entry lacks ed25519Signature',
        });
      } else {
        try {
          const sigBuf = Buffer.from(entry.ed25519Signature, 'base64');
          const sigOk = crypto.verify(
            null,
            Buffer.from(String(entry.receiptHash || ''), 'utf8'),
            entryPubKey,
            sigBuf
          );
          if (!sigOk) {
            errors.push({
              index: i,
              receiptId: entry.receiptId,
              reason: `ED25519_SIGNATURE_INVALID: RFC 8032 Ed25519 signature check failed at index ${i}`,
            });
          } else {
            verifiedSignatures += 1;
          }
        } catch (err) {
          errors.push({
            index: i,
            receiptId: entry.receiptId,
            reason: `ED25519_SIGNATURE_INVALID: ${err.message}`,
          });
        }
      }
    }

    if (
      (entry.stage === 'REFUSED' || entry.stage === 'HELD' || entry.stage === 'APPROVED' || entry.stage === 'REJECTED') &&
      (entry.paypalOrderId || entry.paypalCaptureId)
    ) {
      errors.push({
        index: i,
        receiptId: entry.receiptId,
        reason: `${entry.stage}_INVARIANT_VIOLATION: ${entry.stage} receipt must not carry PayPal Order or Capture IDs`,
      });
    }

    if (entry.recordedAt !== undefined) {
      const t = Date.parse(entry.recordedAt);
      if (typeof entry.recordedAt !== 'string' || !ISO_8601_UTC.test(entry.recordedAt) || Number.isNaN(t)) {
        errors.push({
          index: i,
          receiptId: entry.receiptId,
          reason: `RECORDED_TIME_INVALID: ${String(entry.recordedAt)} is not an ISO 8601 UTC time`,
        });
      } else if (i > 0 && entries[i - 1].recordedAt !== undefined && Date.parse(entries[i - 1].recordedAt) > t) {
        errors.push({
          index: i,
          receiptId: entry.receiptId,
          reason: 'RECORDED_TIME_BACKWARDS: recordedAt is earlier than the previous entry',
        });
      }
    }
  }

  const stageCounts = Object.fromEntries(RECEIPT_STAGES.map((s) => [s, 0]));
  for (const e of entries) {
    if (e && typeof e.stage === 'string') {
      stageCounts[e.stage] = (stageCounts[e.stage] || 0) + 1;
    }
  }

  return {
    valid: errors.length === 0,
    count: entries.length,
    verifiedEd25519Signatures: verifiedSignatures,
    gatePublicKeySha256: baselinePubSha256,
    genesisHash: entries[0]?.receiptHash || null,
    headHash: entries[entries.length - 1]?.receiptHash || null,
    stageCounts,
    errors,
  };
}
