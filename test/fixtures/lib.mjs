// Fixture-side signing/encoding helpers. Mirrors the verifier's wire
// formats so fixtures are produced independently of the bundled code.
import { createHash, sign as cryptoSign, generateKeyPairSync } from 'node:crypto';
import { gzipSync } from 'node:zlib';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(buf) {
  let acc = 0n;
  for (const b of buf) acc = (acc << 8n) + BigInt(b);
  let out = '';
  while (acc > 0n) {
    out = B58[Number(acc % 58n)] + out;
    acc /= 58n;
  }
  for (const b of buf) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

export function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => jcs(v ?? null)).join(',') + ']';
  const keys = Object.keys(value).sort();
  return (
    '{' +
    keys
      .filter((k) => value[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + jcs(value[k]))
      .join(',') +
    '}'
  );
}

const sha256 = (data) => createHash('sha256').update(data).digest();

export function newIssuerKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const raw = spki.subarray(spki.length - 32);
  const multikey = 'z' + base58Encode(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
  return { privateKey, raw, multikey };
}

export function signEddsaJcs2022(document, privateKey, verificationMethod) {
  const docNoProof = {};
  for (const [k, v] of Object.entries(document)) if (k !== 'proof') docNoProof[k] = v;
  const proofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2026-06-01T00:00:00Z',
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };
  if ('@context' in docNoProof) proofOptions['@context'] = docNoProof['@context'];
  const hashData = Buffer.concat([
    sha256(Buffer.from(jcs(proofOptions), 'utf8')),
    sha256(Buffer.from(jcs(docNoProof), 'utf8')),
  ]);
  const sig = cryptoSign(null, hashData, privateKey);
  return { ...docNoProof, proof: { ...proofOptions, proofValue: 'z' + base58Encode(sig) } };
}

export function makeDidDocument(did, keys) {
  // keys: [{fragment, multikey, assertion: bool}]
  return {
    id: did,
    verificationMethod: keys.map((k) => ({
      id: `${did}#${k.fragment}`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: k.multikey,
    })),
    assertionMethod: keys.filter((k) => k.assertion).map((k) => `${did}#${k.fragment}`),
  };
}

export function makeStatusList({ issuer, privateKey, verificationMethod, setBits = [], url }) {
  const raw = Buffer.alloc(2048); // 16384 bits
  for (const i of setBits) raw[i >> 3] |= 1 << (7 - (i % 8));
  const encodedList = 'u' + gzipSync(raw).toString('base64url');
  const cred = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: url,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer,
    validFrom: '2026-01-01T00:00:00Z',
    credentialSubject: {
      id: url + '#list',
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList,
    },
  };
  return signEddsaJcs2022(cred, privateKey, verificationMethod);
}
