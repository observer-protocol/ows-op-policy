#!/usr/bin/env node
// Installer / setup ceremony for the Observer Protocol OWS policy.
//
// Deliberately walks the same path a user walks by hand, so a successful
// install doubles as an integration test of that path:
//   1. copy the verifier executable into ~/.ows/plugins/policies/
//   2. generate the OWS policy JSON (declarative mirror rules + executable
//      + fully-explicit config — staleness window and behavior included)
//   3. self-test the executable offline
//   4. print the exact `ows` commands that register the policy and bind it
//      to an API key
//
// Usage:
//   node installer/install.mjs --credential <path-to-delegation.json>
//        [--issuer did:web:...] [--agent did:...] [--name op-delegation]
//        [--direct]   write the policy file straight into ~/.ows/policies/
//                     instead of the current directory
import { copyFileSync, chmodSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const EXE_SRC = join(ROOT, 'dist', 'ows-op-verify.cjs');

const args = process.argv.slice(2);
function flag(name) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}
const hasFlag = (name) => args.includes(`--${name}`);

const credentialArg = flag('credential');
if (!credentialArg) {
  console.error('Required: --credential <path to the agent ObserverDelegationCredential JSON>');
  process.exit(1);
}
const credentialPath = resolve(credentialArg);
const policyName = flag('name') ?? 'op-delegation';

if (!existsSync(EXE_SRC)) {
  console.error(`Verifier not built — run \`npm run build\` first (expected ${EXE_SRC})`);
  process.exit(1);
}

// Read the credential to derive issuer pin + declarative mirror rules.
let cred;
try {
  cred = JSON.parse(readFileSync(credentialPath, 'utf8'));
} catch (e) {
  console.error(`Cannot read credential at ${credentialPath}: ${e.message}`);
  process.exit(1);
}
const issuerDid = flag('issuer') ?? cred.issuer;
if (!issuerDid || !String(issuerDid).startsWith('did:')) {
  console.error('Could not determine the issuer DID — pass --issuer did:web:...');
  process.exit(1);
}

// Reverse rail map for the allowed_chains declarative mirror (must match
// DEFAULT_RAILS in src/config.ts; override cases write their own rule).
const RAIL_TO_CHAIN = {
  'ethereum-mainnet': 'eip155:1',
  'base-mainnet': 'eip155:8453',
  'polygon-mainnet': 'eip155:137',
  'arbitrum-one': 'eip155:42161',
  'optimism-mainnet': 'eip155:10',
  'solana-mainnet': 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  'bitcoin-mainnet': 'bip122:000000000019d6689c085ae165831e93',
  'usdt-trc20': 'tron:mainnet',
};

const rules = [];
const allowedRails = cred.credentialSubject?.actionScope?.allowed_rails;
if (Array.isArray(allowedRails) && allowedRails.length > 0) {
  const chainIds = allowedRails.map((r) => RAIL_TO_CHAIN[r] ?? r).filter((c) => /^[a-z0-9-]+:/.test(c));
  if (chainIds.length > 0) rules.push({ type: 'allowed_chains', chain_ids: chainIds });
}
if (typeof cred.validUntil === 'string') {
  rules.push({ type: 'expires_at', timestamp: cred.validUntil });
}

const owsDir = join(homedir(), '.ows');
const pluginDir = join(owsDir, 'plugins', 'policies');
const exeDest = join(pluginDir, 'ows-op-verify.cjs');

// 1. Install the executable.
mkdirSync(pluginDir, { recursive: true });
copyFileSync(EXE_SRC, exeDest);
chmodSync(exeDest, 0o755);
console.log(`✓ verifier installed → ${exeDest}`);

// 2. Generate the policy file. Every behavioral knob is written explicitly —
// in particular the revocation staleness window and unreachable behavior.
const policy = {
  id: policyName,
  name: 'Observer Protocol delegation verification',
  version: 1,
  created_at: new Date().toISOString(),
  rules,
  executable: exeDest,
  action: 'deny',
  config: {
    credentialPath,
    issuerDid,
    ...(flag('agent') ? { agentDid: flag('agent') } : {}),
    schemaAllowlist: ['https://observerprotocol.org/schemas/delegation/v2.1.json'],
    revocation: {
      maxStalenessHours: 24,
      onUnreachable: 'cache-then-deny',
      fetchTimeoutMs: 1500,
    },
    didCache: { maxStalenessHours: 24 },
    cacheDir: join(homedir(), '.cache', 'ows-op-policy'),
    auditLog: join(homedir(), '.cache', 'ows-op-policy', 'decisions.jsonl'),
    allowContractCalls: false,
  },
};

const direct = hasFlag('direct');
const policyDest = direct ? join(owsDir, 'policies', `${policyName}.json`) : resolve(`${policyName}.json`);
if (direct) mkdirSync(join(owsDir, 'policies'), { recursive: true });
writeFileSync(policyDest, JSON.stringify(policy, null, 2) + '\n');
console.log(`✓ policy file written → ${policyDest}`);

// 3. Offline self-test: the executable must produce a verdict for a probe
// context. A deny is fine here (no real chain context); a crash is not.
const probe = {
  chain_id: 'eip155:1',
  wallet_id: '00000000-0000-4000-8000-00000000probe',
  api_key_id: '00000000-0000-4000-8000-00000000probe',
  transaction: { to: '0x0000000000000000000000000000000000000000', value: '0', data: '0x' },
  spending: { daily_total: '0' },
  timestamp: new Date().toISOString(),
  policy_config: policy.config,
};
const selfTest = spawnSync('node', [exeDest], { input: JSON.stringify(probe), encoding: 'utf8', timeout: 8000 });
let verdict;
try {
  verdict = JSON.parse(selfTest.stdout);
} catch {
  console.error(`✗ self-test FAILED — executable did not emit valid JSON.\nstdout: ${selfTest.stdout}\nstderr: ${selfTest.stderr}`);
  process.exit(1);
}
console.log(`✓ self-test: executable responded (${verdict.allow ? 'allow' : 'deny'}: ${verdict.reason})`);

// 4. The remaining ceremony — the user's own path.
console.log(`
Next steps (run these yourself — they bind the policy to your agent key):
`);
if (!direct) {
  console.log(`  ows policy create --file ${policyDest}`);
}
console.log(`  ows key create --name "my-agent" --wallet <your-wallet> --policy ${policyName}
  # hand the ows_key_... token to your agent; every signing call is now
  # gated on the Observer Protocol delegation credential at ${credentialPath}

Decision log: ${policy.config.auditLog}
Revocation behavior (explicit in the policy config): refresh-first; on
refresh failure a cached status list under ${policy.config.revocation.maxStalenessHours}h is honored; older than
that the verifier DENIES until connectivity returns.`);
