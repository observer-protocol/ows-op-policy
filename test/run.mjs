// Conformance runner. Pipes each fixture PolicyContext through the BUILT
// executable (dist/ows-op-verify.cjs) exactly as the OWS engine would —
// stdin JSON in, stdout JSON out — and asserts the verdict. Also exercises
// the live refresh-first / stale-cache revocation behavior against a local
// HTTP server.
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync, rmSync, mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'test', 'fixtures', 'out');
const EXE = join(ROOT, 'dist', 'ows-op-verify.cjs');

let pass = 0;
let fail = 0;
const failures = [];

// Async spawn — a synchronous spawn would block the event loop and starve
// the local HTTP server used by the staleness scenarios.
function runExecutable(input) {
  return new Promise((resolve) => {
    const child = spawn('node', [EXE], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('close', () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(stdout));
      } catch {
        resolve({ allow: false, reason: `UNPARSEABLE STDOUT: ${stdout.slice(0, 200)} / stderr: ${stderr.slice(0, 200)}` });
      }
    });
    child.stdin.end(input);
  });
}

function check(name, result, expectAllow, reasonIncludes) {
  const allowOk = result.allow === expectAllow;
  const reasonOk = !reasonIncludes || (result.reason ?? '').toLowerCase().includes(reasonIncludes.toLowerCase());
  if (allowOk && reasonOk) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    failures.push({ name, expected: { expectAllow, reasonIncludes }, got: result });
    console.log(`  FAIL  ${name}`);
    console.log(`        expected allow=${expectAllow} reason~"${reasonIncludes}"`);
    console.log(`        got      allow=${result.allow} reason="${result.reason}"`);
  }
}

// ---- fixture-driven cases ---------------------------------------------------
const { cases } = JSON.parse(readFileSync(join(OUT, 'cases.json'), 'utf8'));
console.log(`\nConformance cases (${cases.length}):`);
for (const c of cases) {
  const input = c.raw !== undefined ? c.raw : JSON.stringify(c.ctx);
  const result = await runExecutable(input);
  check(c.name, result, c.expectAllow, c.reasonIncludes);
}

// ---- live revocation behavior: refresh-first / cache fallback / stale deny --
console.log('\nRevocation staleness behavior (ratified: refresh-first; cache <window; deny older):');

const netCache = join(OUT, 'net-cache');
rmSync(netCache, { recursive: true, force: true });
mkdirSync(netCache, { recursive: true });

const statusBody = readFileSync(join(OUT, 'status-clean.json'), 'utf8');
const server = createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(statusBody);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const statusUrl = `http://127.0.0.1:${port}/status/1`;

// The status URL is signed into the credential, so the network scenarios use
// a fresh self-contained issuer + credential pointing at the live server.
const { signEddsaJcs2022, newIssuerKeys, makeDidDocument, makeStatusList } = await import('./fixtures/lib.mjs');
const nk = newIssuerKeys();
const NET_ISSUER = 'did:web:issuer.example';
const NET_VM = `${NET_ISSUER}#key-1`;
const netDidDoc = makeDidDocument(NET_ISSUER, [{ fragment: 'key-1', multikey: nk.multikey, assertion: true }]);
writeFileSync(join(OUT, 'net-issuer-did.json'), JSON.stringify(netDidDoc));
const netStatus = makeStatusList({ issuer: NET_ISSUER, privateKey: nk.privateKey, verificationMethod: NET_VM, setBits: [], url: statusUrl });
writeFileSync(join(OUT, 'net-status.json'), JSON.stringify(netStatus));
// live server should serve the re-signed list
const netStatusBody = JSON.stringify(netStatus);
server.removeAllListeners('request');
server.on('request', (req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(netStatusBody);
});

const netCredUnsigned = JSON.parse(readFileSync(join(OUT, 'cred-valid-policy.json'), 'utf8'));
delete netCredUnsigned.proof;
netCredUnsigned.credentialStatus = [
  {
    id: `${statusUrl}#7`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '7',
    statusListCredential: statusUrl,
  },
];
const netCred = signEddsaJcs2022(netCredUnsigned, nk.privateKey, NET_VM);
writeFileSync(join(OUT, 'cred-net.json'), JSON.stringify(netCred));

const SCHEMA_URL = 'https://observerprotocol.org/schemas/delegation/v2.1.json';
const SCHEMA_URL_V24 = 'https://observerprotocol.org/schemas/delegation/v2.4.json';
const netCtx = (overrides = {}) => ({
  chain_id: 'eip155:1',
  wallet_id: '00000000-0000-4000-8000-000000000001',
  api_key_id: '00000000-0000-4000-8000-000000000002',
  transaction: { to: '0xA11CE00000000000000000000000000000000001', value: '500000000000000000', data: '0x' },
  spending: { daily_total: '0', date: '2026-06-09' },
  timestamp: '2026-06-09T12:00:00Z',
  policy_config: {
    credentialPath: join(OUT, 'cred-net.json'),
    issuerDid: NET_ISSUER,
    schemaAllowlist: [SCHEMA_URL, SCHEMA_URL_V24],
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    didCache: { maxStalenessHours: 24 },
    cacheDir: netCache,
    auditLog: join(OUT, 'decisions.jsonl'),
    offline: { didDocumentPath: join(OUT, 'net-issuer-did.json') }, // DID offline; status list over the network
    ...overrides,
  },
});

// 1. Server up: fresh fetch, allow.
check('allow: status list fetched fresh from live server', await runExecutable(JSON.stringify(netCtx())), true, 'verified');

// 2. Server down, cache fresh: allow with cache-served note.
await new Promise((resolve) => server.close(resolve));
check('allow: server down, cache under staleness window', await runExecutable(JSON.stringify(netCtx())), true, 'verified');

// 3. Server down, cache backdated beyond the window: deny.
for (const f of readdirSync(netCache)) {
  const p = join(netCache, f);
  const obj = JSON.parse(readFileSync(p, 'utf8'));
  obj.fetchedAt = new Date(Date.now() - 25 * 3_600_000).toISOString();
  writeFileSync(p, JSON.stringify(obj));
}
check('deny: server down, cache older than 24h window', await runExecutable(JSON.stringify(netCtx())), false, 'staleness window');

// 4. Tighter window honored from config: 1h window, cache aged 25h → deny.
check(
  'deny: config-tightened staleness window honored',
  await runExecutable(JSON.stringify(netCtx({ revocation: { maxStalenessHours: 1, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 } }))),
  false,
  'staleness window',
);

// ---- audit log sanity --------------------------------------------------------
const auditLines = readFileSync(join(OUT, 'decisions.jsonl'), 'utf8').trim().split('\n');
const lastEntry = JSON.parse(auditLines[auditLines.length - 1]);
if (auditLines.length >= cases.length && lastEntry.decision && lastEntry.reason) {
  pass++;
  console.log(`\n  PASS  audit log: ${auditLines.length} JSONL decision entries recorded`);
} else {
  fail++;
  console.log('\n  FAIL  audit log incomplete');
}

console.log(`\n${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log('\nFailures:');
  for (const f of failures) console.log(JSON.stringify(f, null, 2));
}
process.exit(fail === 0 ? 0 : 1);
