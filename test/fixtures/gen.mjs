// Conformance fixture generator. Produces a self-contained fixture tree in
// test/fixtures/out/: issuer keys + DID document, status lists, delegation
// credentials (valid and each failure mode), PolicyContext per case, and a
// cases.json manifest binding fixtures to expected verdicts.
//
// All keys are generated here, on the fly. NOTHING in this tree derives
// from production credentials, production keys, or any deployment.
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { newIssuerKeys, signEddsaJcs2022, makeDidDocument, makeStatusList } from './lib.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), 'out');
rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, 'cache'), { recursive: true });

const ISSUER = 'did:web:issuer.example';
const AGENT = 'did:web:issuer.example:agents:fixture-agent';
const MERCHANT_DID = 'did:web:merchant.example';
const MERCHANT_ADDR = '0xA11CE00000000000000000000000000000000001';
const OTHER_ADDR = '0xB0B0000000000000000000000000000000000002';
const BLOCKED_ADDR = '0xBAD0000000000000000000000000000000000003';
const SCHEMA_URL = 'https://observerprotocol.org/schemas/delegation/v2.1.json';

const key1 = newIssuerKeys(); // assertionMethod-valid
const key2 = newIssuerKeys(); // present but NOT in assertionMethod
const didDoc = makeDidDocument(ISSUER, [
  { fragment: 'key-1', multikey: key1.multikey, assertion: true },
  { fragment: 'key-2', multikey: key2.multikey, assertion: false },
]);
writeFileSync(join(OUT, 'issuer-did.json'), JSON.stringify(didDoc, null, 2));

const VM1 = `${ISSUER}#key-1`;
const VM2 = `${ISSUER}#key-2`;

const statusClean = makeStatusList({
  issuer: ISSUER, privateKey: key1.privateKey, verificationMethod: VM1,
  setBits: [], url: 'https://issuer.example/status/1',
});
const statusRevoked = makeStatusList({
  issuer: ISSUER, privateKey: key1.privateKey, verificationMethod: VM1,
  setBits: [7], url: 'https://issuer.example/status/1',
});
writeFileSync(join(OUT, 'status-clean.json'), JSON.stringify(statusClean, null, 2));
writeFileSync(join(OUT, 'status-revoked.json'), JSON.stringify(statusRevoked, null, 2));

function baseCredential(overrides = {}) {
  const { subject = {}, top = {} } = overrides;
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer: ISSUER,
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2027-01-01T00:00:00Z',
    credentialSchema: { id: SCHEMA_URL, type: 'JsonSchema' },
    credentialStatus: [
      {
        id: 'https://issuer.example/status/1#7',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '7',
        statusListCredential: 'https://issuer.example/status/1',
      },
    ],
    ...top,
    credentialSubject: {
      id: AGENT,
      authorizationLevel: 'policy',
      authorizationConfig: {
        policy: {
          policy_id: 'fixture-policy-001',
          rail_preference: ['ethereum-mainnet'],
          per_rail_caps: {
            'ethereum-mainnet': { per_transaction: '1.0', aggregate: '5.0', period: 'P1D', currency: 'ETH' },
          },
        },
      },
      actionScope: {
        allowed_rails: ['ethereum-mainnet', 'tron:mainnet'],
        per_transaction_ceiling: { amount: '1.0', currency: 'ETH' },
        cumulative_budget: { amount: '10.0', currency: 'ETH', window: 'credential_validity' },
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check',
      tradingMandate: {
        maxNotionalPerOrder: 2,
        unit: 'ETH',
        counterparty: { blockList: [BLOCKED_ADDR] },
      },
      ...subject,
    },
  };
}

const sign = (cred, key = key1.privateKey, vm = VM1) => signEddsaJcs2022(cred, key, vm);

const credentials = {
  'valid-policy': sign(baseCredential()),
  expired: sign(baseCredential({ top: { validUntil: '2026-02-01T00:00:00Z' } })),
  'not-yet-valid': sign(baseCredential({ top: { validFrom: '2026-12-01T00:00:00Z' } })),
  'bad-schema': sign(
    baseCredential({ top: { credentialSchema: { id: 'https://observerprotocol.org/schemas/delegation/v2.json', type: 'JsonSchema' } } }),
  ),
  'key2-signed': sign(baseCredential(), key2.privateKey, VM2),
  'no-status': sign((() => { const c = baseCredential(); delete c.credentialStatus; return c; })()),
  'counterparty-allowlist': sign(
    baseCredential({
      subject: {
        tradingMandate: {
          maxNotionalPerOrder: 2,
          unit: 'ETH',
          counterparty: { allowList: [MERCHANT_DID, OTHER_ADDR] },
        },
      },
    }),
  ),
  temporal: sign(
    baseCredential({
      subject: {
        tradingMandate: {
          temporal: { allowedTimeWindows: [{ start: '09:00', end: '17:00', timezone: 'UTC' }] },
        },
      },
    }),
  ),
  'one-time': sign(
    baseCredential({
      subject: {
        authorizationLevel: 'one-time',
        authorizationConfig: {
          oneTime: {
            counterparty_did: MERCHANT_DID,
            amount: '0.5',
            currency: 'ETH',
            rail: 'ethereum-mainnet',
            execution_deadline: '2026-06-10T00:00:00Z',
            purchase_description: 'fixture purchase',
          },
        },
        tradingMandate: undefined,
        actionScope: { allowed_rails: ['ethereum-mainnet'] },
      },
    }),
  ),
  velocity: sign(
    baseCredential({
      subject: {
        tradingMandate: { unit: 'ETH', velocity: { dailyVolumeCap: 2 } },
        actionScope: { allowed_rails: ['ethereum-mainnet'] },
      },
    }),
  ),
  'currency-mismatch': sign(
    baseCredential({
      subject: { actionScope: { per_transaction_ceiling: { amount: '100', currency: 'USDT' } } },
    }),
  ),
  'identity-only': sign(
    baseCredential({
      subject: {
        actionScope: { allowed_rails: ['usdt-trc20'] },
        tradingMandate: undefined,
        authorizationLevel: undefined,
        authorizationConfig: undefined,
      },
    }),
  ),
  'tron-with-ceiling': sign(
    baseCredential({
      subject: {
        actionScope: { allowed_rails: ['usdt-trc20'], per_transaction_ceiling: { amount: '50', currency: 'TRX' } },
        tradingMandate: undefined,
        authorizationLevel: undefined,
        authorizationConfig: undefined,
      },
    }),
  ),
  'issuer-class': sign(
    baseCredential({
      subject: {
        tradingMandate: { counterparty: { requireIssuerClassIn: ['op_first_party'] } },
      },
    }),
  ),
  'geo-allowonly': sign(
    baseCredential({
      subject: { tradingMandate: { geographic: { allowedJurisdictionsOnly: ['US'] } } },
    }),
  ),
};

// Tampered: valid signature, then mutate a binding field post-signing.
const tampered = JSON.parse(JSON.stringify(credentials['valid-policy']));
tampered.credentialSubject.actionScope.per_transaction_ceiling.amount = '1000.0';
credentials['tampered'] = tampered;

// Legacy proof suite: same body, proof.type from the pre-migration era.
const legacy = JSON.parse(JSON.stringify(credentials['valid-policy']));
legacy.proof = {
  type: 'Ed25519Signature2026',
  created: '2026-06-01T00:00:00Z',
  verificationMethod: VM1,
  proofPurpose: 'assertionMethod',
  proofValue: legacy.proof.proofValue.slice(1),
};
credentials['legacy-suite'] = legacy;

// Wrong issuer: full credential under a different (self-consistent) issuer —
// the verifier must reject on the issuer pin, not on signature mechanics.
const evilKeys = newIssuerKeys();
const EVIL = 'did:web:evil.example';
const evilCred = baseCredential();
evilCred.issuer = EVIL;
credentials['wrong-issuer'] = signEddsaJcs2022(evilCred, evilKeys.privateKey, `${EVIL}#key-1`);

for (const [name, cred] of Object.entries(credentials)) {
  writeFileSync(join(OUT, `cred-${name}.json`), JSON.stringify(cred, null, 2));
}

// --- PolicyContext + expectations ------------------------------------------

const baseConfig = {
  credentialPath: join(OUT, 'cred-valid-policy.json'),
  issuerDid: ISSUER,
  schemaAllowlist: [SCHEMA_URL],
  agentDid: AGENT,
  revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
  didCache: { maxStalenessHours: 24 },
  cacheDir: join(OUT, 'cache'),
  auditLog: join(OUT, 'decisions.jsonl'),
  counterpartyAddressMap: { [MERCHANT_DID]: [MERCHANT_ADDR] },
  offline: {
    didDocumentPath: join(OUT, 'issuer-did.json'),
    statusListPath: join(OUT, 'status-clean.json'),
  },
};

const baseCtx = {
  chain_id: 'eip155:1',
  wallet_id: '00000000-0000-4000-8000-000000000001',
  api_key_id: '00000000-0000-4000-8000-000000000002',
  transaction: { to: MERCHANT_ADDR, value: '500000000000000000', data: '0x' }, // 0.5 ETH
  spending: { daily_total: '0', date: '2026-06-09' },
  timestamp: '2026-06-09T12:00:00Z', // a Tuesday, 12:00 UTC
};

const ctx = (configOverrides = {}, ctxOverrides = {}) => ({
  ...baseCtx,
  ...ctxOverrides,
  policy_config: { ...baseConfig, ...configOverrides },
});
const withCred = (name, configOverrides = {}, ctxOverrides = {}) =>
  ctx({ credentialPath: join(OUT, `cred-${name}.json`), ...configOverrides }, ctxOverrides);

const cases = [
  // -------- pass side --------
  { name: 'allow: valid credential, in-scope transaction', ctx: withCred('valid-policy'), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: counterparty allowList match via DID map', ctx: withCred('counterparty-allowlist'), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: counterparty allowList match via raw address', ctx: withCred('counterparty-allowlist', {}, { transaction: { ...baseCtx.transaction, to: OTHER_ADDR } }), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: inside temporal window', ctx: withCred('temporal'), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: one-time exact match', ctx: withCred('one-time'), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: velocity under cap', ctx: withCred('velocity', {}, { spending: { daily_total: '1000000000000000000', date: '2026-06-09' } }), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: identity-only mandate on unparsed rail (tron)', ctx: withCred('identity-only', {}, { chain_id: 'tron:mainnet', transaction: { raw_hex: '0a02bb8e' } }), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: no credentialStatus (noted, not fatal)', ctx: withCred('no-status'), expectAllow: true, reasonIncludes: 'verified' },
  { name: 'allow: contract call permitted when explicitly configured', ctx: withCred('valid-policy', { allowContractCalls: true }, { transaction: { ...baseCtx.transaction, data: '0xa9059cbb' } }), expectAllow: true, reasonIncludes: 'verified' },

  // -------- fail side: credential integrity --------
  { name: 'deny: expired credential', ctx: withCred('expired'), expectAllow: false, reasonIncludes: 'expired' },
  { name: 'deny: not-yet-valid credential', ctx: withCred('not-yet-valid'), expectAllow: false, reasonIncludes: 'not yet valid' },
  { name: 'deny: tampered credential (signature mismatch)', ctx: withCred('tampered'), expectAllow: false, reasonIncludes: 'does not verify' },
  { name: 'deny: legacy proof suite rejected', ctx: withCred('legacy-suite'), expectAllow: false, reasonIncludes: 'legacy suites are not accepted' },
  { name: 'deny: issuer not the pinned issuer', ctx: withCred('wrong-issuer'), expectAllow: false, reasonIncludes: 'pinned trusted issuer' },
  { name: 'deny: schema not in allowlist (v2 excluded)', ctx: withCred('bad-schema'), expectAllow: false, reasonIncludes: 'allowlist' },
  { name: 'deny: signing key not in assertionMethod', ctx: withCred('key2-signed'), expectAllow: false, reasonIncludes: 'assertionMethod' },
  { name: 'deny: revoked credential', ctx: withCred('valid-policy', { offline: { ...baseConfig.offline, statusListPath: join(OUT, 'status-revoked.json') } }), expectAllow: false, reasonIncludes: 'revoked' },
  { name: 'deny: credential file missing', ctx: withCred('does-not-exist'), expectAllow: false, reasonIncludes: 'cannot read' },
  { name: 'deny: agent DID pin mismatch', ctx: withCred('valid-policy', { agentDid: 'did:web:issuer.example:agents:someone-else' }), expectAllow: false, reasonIncludes: 'pinned agent DID' },

  // -------- fail side: mandate enforcement --------
  { name: 'deny: over per_transaction_ceiling', ctx: withCred('valid-policy', {}, { transaction: { ...baseCtx.transaction, value: '1500000000000000000' } }), expectAllow: false, reasonIncludes: 'per_transaction_ceiling' },
  { name: 'deny: rail not in allowed_rails', ctx: withCred('valid-policy', {}, { chain_id: 'eip155:8453' }), expectAllow: false, reasonIncludes: 'allowed_rails' },
  { name: 'deny: unmapped chain', ctx: withCred('valid-policy', {}, { chain_id: 'eip155:999999' }), expectAllow: false, reasonIncludes: 'no rail mapping' },
  { name: 'deny: counterparty on blockList', ctx: withCred('valid-policy', {}, { transaction: { ...baseCtx.transaction, to: BLOCKED_ADDR } }), expectAllow: false, reasonIncludes: 'blockList' },
  { name: 'deny: counterparty not on allowList', ctx: withCred('counterparty-allowlist', {}, { transaction: { ...baseCtx.transaction, to: BLOCKED_ADDR } }), expectAllow: false, reasonIncludes: 'not on the mandate allowList' },
  { name: 'deny: outside temporal window', ctx: withCred('temporal', {}, { timestamp: '2026-06-09T22:00:00Z' }), expectAllow: false, reasonIncludes: 'allowedTimeWindows' },
  { name: 'deny: one-time wrong amount', ctx: withCred('one-time', {}, { transaction: { ...baseCtx.transaction, value: '600000000000000000' } }), expectAllow: false, reasonIncludes: 'exactly' },
  { name: 'deny: one-time wrong counterparty', ctx: withCred('one-time', {}, { transaction: { ...baseCtx.transaction, to: OTHER_ADDR } }), expectAllow: false, reasonIncludes: 'counterparty' },
  { name: 'deny: one-time past execution_deadline', ctx: withCred('one-time', {}, { timestamp: '2026-06-11T00:00:00Z' }), expectAllow: false, reasonIncludes: 'execution_deadline' },
  { name: 'deny: velocity cap exceeded', ctx: withCred('velocity', {}, { spending: { daily_total: '1800000000000000000', date: '2026-06-09' } }), expectAllow: false, reasonIncludes: 'dailyVolumeCap' },
  { name: 'deny: ceiling currency mismatch (no FX)', ctx: withCred('currency-mismatch'), expectAllow: false, reasonIncludes: 'same-currency' },
  { name: 'deny: binding ceiling on unparsed rail (tron)', ctx: withCred('tron-with-ceiling', {}, { chain_id: 'tron:mainnet', transaction: { raw_hex: '0a02bb8e' } }), expectAllow: false, reasonIncludes: 'support matrix' },
  { name: 'deny: requireIssuerClassIn with no attestation source', ctx: withCred('issuer-class'), expectAllow: false, reasonIncludes: 'issuer class' },
  { name: 'deny: allowedJurisdictionsOnly fail-closed', ctx: withCred('geo-allowonly'), expectAllow: false, reasonIncludes: 'allowedJurisdictionsOnly' },
  { name: 'deny: contract call under binding ceiling', ctx: withCred('valid-policy', {}, { transaction: { ...baseCtx.transaction, data: '0xa9059cbb' } }), expectAllow: false, reasonIncludes: 'calldata' },
  { name: 'deny: per-rail aggregate cap exceeded (deny-side state)', ctx: withCred('valid-policy', {}, { spending: { daily_total: '4800000000000000000', date: '2026-06-09' } }), expectAllow: false, reasonIncludes: 'aggregate cap' },

  // -------- fail side: configuration --------
  { name: 'deny: missing policy_config', ctx: { ...baseCtx, policy_config: undefined }, expectAllow: false, reasonIncludes: 'policy_config missing' },
  { name: 'deny: config without issuerDid', ctx: ctx({ issuerDid: undefined }), expectAllow: false, reasonIncludes: 'issuerDid' },
  { name: 'deny: malformed stdin handled as deny', raw: '{not json', expectAllow: false, reasonIncludes: 'internal' },
];

writeFileSync(join(OUT, 'cases.json'), JSON.stringify({ cases }, null, 2));
console.log(`fixtures written: ${Object.keys(credentials).length} credentials, ${cases.length} cases → ${OUT}`);
