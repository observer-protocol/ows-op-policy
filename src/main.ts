import { readFileSync } from 'node:fs';
import { parseConfig } from './config.js';
import { validateStructure, checkValidityWindow } from './schema.js';
import { resolveDidDocument, findAssertionMethodKey } from './resolve.js';
import { verifyEddsaJcs2022, decodeEd25519Multibase } from './proof.js';
import { checkStatusEntry } from './revocation.js';
import { evaluateMandate } from './mandate.js';
import { appendAudit } from './audit.js';
import { sha256 } from './crypto.js';
import type {
  AuditEntry,
  ObserverDelegationCredential,
  PolicyContext,
  PolicyResult,
  VerifierConfig,
} from './types.js';

// ows-op-verify — Observer Protocol delegation-credential verifier for the
// Open Wallet Standard policy engine.
//
// OWS exec contract (core docs/03-policy-engine.md): PolicyContext JSON on
// stdin; exactly one PolicyResult JSON on stdout; non-zero exit, malformed
// output, or a 5s timeout all deny. We therefore always emit well-formed
// JSON and exit 0 — deny is expressed in the payload, and any unexpected
// crash is converted into an explicit deny.

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

interface Verdict {
  allow: boolean;
  reason: string;
  notes: string[];
}

async function evaluate(ctx: PolicyContext, config: VerifierConfig): Promise<Verdict> {
  const notes: string[] = [];

  // 1. Load the delegation credential — re-read on every call (ratified:
  // rotation/re-issue is picked up immediately; credentials are small).
  let cred: ObserverDelegationCredential;
  try {
    cred = JSON.parse(readFileSync(config.credentialPath, 'utf8')) as ObserverDelegationCredential;
  } catch (e) {
    return { allow: false, reason: `op-verify: [credential] cannot read ${config.credentialPath}: ${(e as Error).message}`, notes };
  }

  // 2. Structure (v2.1 body), pinned issuer, schema allowlist, agent pin.
  const structure = validateStructure(cred, config);
  if (!structure.ok) return { allow: false, reason: `op-verify: [schema] ${structure.reason}`, notes };

  // 3. Validity window.
  const nowMs = Date.parse(ctx.timestamp) || Date.now();
  const window = checkValidityWindow(cred, nowMs);
  if (!window.ok) return { allow: false, reason: `op-verify: ${window.reason}`, notes };

  // 4. Proof: resolve issuer DID document, demand an assertionMethod-valid
  // key, verify eddsa-jcs-2022.
  try {
    const { doc, note } = await resolveDidDocument(cred.issuer, {
      cacheDir: config.cacheDir,
      timeoutMs: config.revocation.fetchTimeoutMs,
      maxStalenessHours: config.didCache.maxStalenessHours,
      offlinePath: config.offline?.didDocumentPath,
    });
    if (note) notes.push(note);
    if (doc.id !== cred.issuer) {
      return { allow: false, reason: `op-verify: [did] resolved DID document id ${doc.id} does not match issuer ${cred.issuer}`, notes };
    }
    const vmId = cred.proof?.verificationMethod;
    if (!vmId) return { allow: false, reason: 'op-verify: [proof] proof.verificationMethod missing', notes };
    if (!vmId.startsWith(cred.issuer + '#')) {
      return { allow: false, reason: `op-verify: [proof] verificationMethod ${vmId} is not a key of the issuer ${cred.issuer}`, notes };
    }
    const { entry } = findAssertionMethodKey(doc, vmId);
    if (!entry.publicKeyMultibase) {
      return { allow: false, reason: `op-verify: [did] verification method ${entry.id} has no publicKeyMultibase`, notes };
    }
    const { key, note: keyNote } = decodeEd25519Multibase(entry.publicKeyMultibase);
    if (keyNote) notes.push(keyNote);
    const proofResult = verifyEddsaJcs2022(cred as unknown as Record<string, unknown>, key);
    notes.push(...proofResult.notes);
    if (!proofResult.ok) {
      return { allow: false, reason: `op-verify: [proof] ${proofResult.reason}`, notes };
    }
  } catch (e) {
    return { allow: false, reason: `op-verify: [proof] ${(e as Error).message}`, notes };
  }

  // 5. Revocation / suspension — refresh-first; cache under the configured
  // staleness window; deny beyond it. A missing credentialStatus is allowed
  // (not every issuance carries one) and noted.
  if (cred.credentialStatus && cred.credentialStatus.length > 0) {
    for (const entry of cred.credentialStatus) {
      try {
        const outcome = await checkStatusEntry(entry, config);
        notes.push(...outcome.notes);
        if (outcome.revoked) {
          return { allow: false, reason: `op-verify: [revocation] ${outcome.detail}`, notes };
        }
      } catch (e) {
        return { allow: false, reason: `op-verify: [revocation] status could not be established: ${(e as Error).message}`, notes };
      }
    }
  } else {
    notes.push('credential carries no credentialStatus entry — revocation not checkable for this credential');
  }

  // 6. Mandate enforcement.
  const mandate = evaluateMandate(ctx, cred, config);
  notes.push(...mandate.notes);
  if (!mandate.ok) return { allow: false, reason: `op-verify: ${mandate.reason}`, notes };

  return {
    allow: true,
    reason: `op-verify: delegation ${cred.id} verified (issuer ${cred.issuer}); ${mandate.reason}`,
    notes,
  };
}

async function main(): Promise<void> {
  let ctx: PolicyContext | undefined;
  let config: VerifierConfig | undefined;
  let verdict: Verdict;
  let credentialForAudit: { id?: string; hash?: string } = {};

  try {
    const input = await readStdin();
    ctx = JSON.parse(input) as PolicyContext;
    config = parseConfig(ctx.policy_config);
    try {
      const raw = readFileSync(config.credentialPath, 'utf8');
      credentialForAudit = {
        id: (JSON.parse(raw) as { id?: string }).id,
        hash: sha256(raw).toString('hex'),
      };
    } catch {
      // unreadable credential is handled (denied) inside evaluate()
    }
    verdict = await evaluate(ctx, config);
  } catch (e) {
    verdict = { allow: false, reason: `op-verify: [internal] ${(e as Error).message}`, notes: [] };
  }

  if (config && ctx) {
    const entry: AuditEntry = {
      ts: new Date().toISOString(),
      decision: verdict.allow ? 'allow' : 'deny',
      reason: verdict.reason,
      notes: verdict.notes,
      chain_id: ctx.chain_id,
      wallet_id: ctx.wallet_id,
      api_key_id: ctx.api_key_id,
      credential_id: credentialForAudit.id,
      credential_sha256: credentialForAudit.hash,
      tx_sha256: ctx.transaction?.raw_hex ? sha256(ctx.transaction.raw_hex).toString('hex') : undefined,
    };
    const auditError = appendAudit(config.auditLog, entry);
    if (auditError) verdict.notes.push(auditError);
  }

  const result: PolicyResult = { allow: verdict.allow, reason: verdict.reason };
  process.stdout.write(JSON.stringify(result));
  process.exit(0);
}

void main();
