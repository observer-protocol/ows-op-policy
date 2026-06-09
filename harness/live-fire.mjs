#!/usr/bin/env node
// Live-fire harness: proves the verifier end-to-end against a REAL, freshly
// installed Open Wallet Standard release — not against unit fixtures.
//
// Path-green over component-green: the deny must manifest as `policy denied`
// from an actual `ows sign tx` call in agent mode, and the allow must return
// real signature bytes. Both sides are asserted, plus the owner-tier bypass
// (passphrase auth skips policies by OWS design — that distinction is the
// point of the two credential tiers).
//
// Everything runs in an isolated sandbox: OWS is npm-installed into
// harness/.tmp and HOME is overridden, so the user's real ~/.ows is never
// touched. Fixture issuer keys are generated fresh; no production
// credentials are involved (and must not be — see the repository gate).
//
// Usage: npm run livefire   (add --keep to retain the sandbox)
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TMP = join(ROOT, 'harness', '.tmp');
const SANDBOX_HOME = join(TMP, 'home');
const EXE = join(ROOT, 'dist', 'ows-op-verify.cjs');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'out');
const keep = process.argv.includes('--keep');

let step = 0;
const say = (msg) => console.log(`\n[${++step}] ${msg}`);
const die = (msg) => {
  console.error(`\n✗ LIVE-FIRE FAILED: ${msg}`);
  process.exit(1);
};

function ows(args, { token, allowFail = false } = {}) {
  try {
    return execFileSync(join(TMP, 'node_modules', '.bin', 'ows'), args, {
      encoding: 'utf8',
      timeout: 30_000,
      // OWS v1.3.2 reads OWS_PASSPHRASE at signing time (agent tokens are
      // detected by prefix in the passphrase position); wallet/key creation
      // on a non-TTY proceeds without one, so the sandbox wallet is
      // passphrase-less — fine for throwaway test keys, never for real ones.
      env: { ...process.env, HOME: SANDBOX_HOME, ...(token ? { OWS_PASSPHRASE: token } : {}) },
    });
  } catch (e) {
    if (allowFail) return `${e.stdout ?? ''}${e.stderr ?? ''}`;
    die(`ows ${args.join(' ')} → ${e.stderr || e.message}`);
  }
}

if (!existsSync(EXE)) die('dist/ows-op-verify.cjs not built — run `npm run build` first');

say('regenerating conformance fixtures (fresh keys)');
execFileSync('node', [join(ROOT, 'test', 'fixtures', 'gen.mjs')], { stdio: 'inherit' });

say('installing current OWS release into an isolated sandbox');
rmSync(TMP, { recursive: true, force: true });
mkdirSync(SANDBOX_HOME, { recursive: true });
writeFileSync(join(TMP, 'package.json'), '{"name":"livefire-sandbox","private":true}');
execFileSync('npm', ['install', '@open-wallet-standard/core', '--no-fund', '--no-audit'], {
  cwd: TMP,
  stdio: 'pipe',
  timeout: 180_000,
});
const version = ows(['--version']).trim();
console.log(`    installed: ${version}`);

say('creating wallet (sandbox, passphrase-less)');
const walletOut = ows(['wallet', 'create', '--name', 'livefire-treasury']);
if (!walletOut.includes('Wallet created')) die('wallet creation failed');

say('registering the Observer Protocol policy');
const { cases } = JSON.parse(readFileSync(join(FIXTURES, 'cases.json'), 'utf8'));
const config = cases[0].ctx.policy_config; // fixture-driven offline config
const policy = {
  id: 'op-delegation-livefire',
  name: 'Observer Protocol delegation verification (live-fire)',
  version: 1,
  created_at: new Date().toISOString(),
  rules: [],
  executable: EXE,
  action: 'deny',
  config,
};
const policyPath = join(TMP, 'op-delegation-livefire.json');
writeFileSync(policyPath, JSON.stringify(policy, null, 2));
ows(['policy', 'create', '--file', policyPath]);

say('creating agent API key bound to the policy');
const keyOut = ows(['key', 'create', '--name', 'livefire-agent', '--wallet', 'livefire-treasury', '--policy', 'op-delegation-livefire']);
const token = keyOut.split('\n').find((l) => l.trim().startsWith('ows_key_'))?.trim();
if (!token) die(`could not parse API token from key create output:\n${keyOut}`);

const { buildEip1559Tx } = await import('../test/fixtures/lib.mjs');
const MERCHANT = '0xA11CE00000000000000000000000000000000001';
const overTx = buildEip1559Tx({ to: MERCHANT, valueWei: 2_000_000_000_000_000_000n }); // 2 ETH > 1.0 ceiling
const underTx = buildEip1559Tx({ to: MERCHANT, valueWei: 500_000_000_000_000_000n }); // 0.5 ETH

say('DENY side: agent signs 2 ETH against a 1.0 ETH mandate ceiling');
const denyOut = ows(['sign', 'tx', '--chain', 'eip155:1', '--wallet', 'livefire-treasury', '--tx', overTx], { token, allowFail: true });
if (!/policy denied/i.test(denyOut) || !denyOut.includes('per_transaction_ceiling')) {
  die(`expected POLICY_DENIED with the ceiling reason, got:\n${denyOut}`);
}
console.log(`    ✓ real signing call denied: ${denyOut.trim().split('\n')[0]}`);

say('ALLOW side: agent signs 0.5 ETH within the mandate');
const allowOut = ows(['sign', 'tx', '--chain', 'eip155:1', '--wallet', 'livefire-treasury', '--tx', underTx], { token });
if (!/^[0-9a-f]{120,}/m.test(allowOut.trim())) die(`expected signature bytes, got:\n${allowOut}`);
console.log(`    ✓ signature returned (${allowOut.trim().length} hex chars)`);

say('owner tier sanity: non-token auth bypasses policies (OWS two-tier design)');
const ownerOut = ows(['sign', 'tx', '--chain', 'eip155:1', '--wallet', 'livefire-treasury', '--tx', overTx]);
if (!/^[0-9a-f]{120,}/m.test(ownerOut.trim())) die(`owner-tier signing failed:\n${ownerOut}`);
console.log('    ✓ owner signs regardless of agent policies, as specified');

say('decision log: verify both verdicts were recorded');
const audit = readFileSync(config.auditLog, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const denies = audit.filter((e) => e.decision === 'deny' && e.reason.includes('per_transaction_ceiling'));
const allows = audit.filter((e) => e.decision === 'allow');
if (denies.length === 0 || allows.length === 0) die('audit log missing the live-fire decisions');
console.log(`    ✓ JSONL log has the deny and the allow (${audit.length} entries total)`);

if (!keep) rmSync(TMP, { recursive: true, force: true });
console.log(`\n✓ LIVE-FIRE PASSED against ${version} — deny and allow both proven through real signing calls.`);
