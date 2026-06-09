# ows-op-policy

**Observer Protocol delegation verification for Open Wallet Standard wallets.**

> **Status: pre-release.** Built and conformance-tested against fixtures; not yet
> published or validated against production Observer Protocol credentials.

A single-file policy executable for the [OWS policy engine](https://github.com/open-wallet-standard/core/blob/main/docs/03-policy-engine.md)
that gates every agent signing request on a **signed, revocable, scope-limited
mandate** — an `ObserverDelegationCredential` issued under
[AIP v0.8](https://github.com/observer-protocol/aip). The agent holds an OWS API
key; the principal holds the mandate; the wallet refuses to sign anything the
mandate doesn't cover.

OWS evaluates policies **before** the wallet secret's decryption key is derived,
so a deny here means key material is never touched. OWS provides the local
key-custody and gating machinery; Observer Protocol provides the verifiable
**authorization provenance** — who authorized this agent, for what scope, and
whether that authority has been revoked.

```
agent calls ows sign (API key in the passphrase position)
  → OWS policy engine (AND of all policies on the key)
      → declarative rules: allowed_chains, expires_at   (mirror of mandate scope)
      → executable: ows-op-verify                       (this project)
           verifies   eddsa-jcs-2022 proof · issuer did:web + assertionMethod
                      schema allowlist · validity window · revocation status
           enforces   rails · amount ceilings · counterparty lists · time windows
                      velocity caps (deny-side) · authorization levels 1/2/3
  → deny  ⇒ POLICY_DENIED — the wallet's HKDF key is never derived
  → allow ⇒ decrypt → sign → zeroize
```

## Quickstart

```bash
npm install && npm run build          # produces dist/ows-op-verify.cjs (zero runtime deps)
npm test                              # 43 conformance checks, pass AND fail sides

node installer/install.mjs --credential /path/to/delegation-credential.json
ows policy create --file op-delegation.json
ows key create --name "my-agent" --wallet <wallet> --policy op-delegation
```

The installer copies the executable to `~/.ows/plugins/policies/`, derives the
declarative mirror rules (`allowed_chains` from the mandate's rails,
`expires_at` from `validUntil`), writes every behavioral knob into the policy
`config` explicitly, and self-tests the executable before telling you the exact
`ows` commands to finish with. A reference policy file is in
[`policy/op-delegation.template.json`](./policy/op-delegation.template.json).

## What gets verified (credential plane)

> **Proof-suite note (deliberate, not an oversight):** this verifier
> implements the **eddsa-jcs-2022 surface as deployed by the Observer
> Protocol issuance pipeline** — the production signing reality. The AIP
> v0.6–v0.8 draft *texts* still cite the older `Ed25519Signature2026` suite
> name; aligning the draft language is tracked separately in the
> [AIP repository](https://github.com/observer-protocol/aip) and is
> intentionally **not** part of this project. Where draft text and deployed
> surface disagree, this verifier follows the deployed surface.

| Check | Behavior |
|---|---|
| Proof suite | `DataIntegrityProof` / `eddsa-jcs-2022` (W3C VC Data Integrity). Legacy Ed25519Signature20xx suites are **rejected** |
| Issuer | Pinned in config; resolved via `did:web`; the signing key **must** be listed in `assertionMethod` — a key merely present on the DID document is refused |
| Schema | `credentialSchema.id` must be on the configured allowlist (default: `delegation/v2.1.json` only) |
| Validity | `validFrom` ≤ now ≤ `validUntil` |
| Revocation | W3C Bitstring Status List. **Refresh-first**: the list is re-fetched on every evaluation; on fetch failure a cached copy younger than `revocation.maxStalenessHours` (default **24, always written explicitly by the installer**) is honored; anything older **denies** until connectivity returns. The status list credential's own signature is verified against the same pinned issuer |

## What gets enforced (transaction plane)

Binding mandate fields deny; advisory fields (per AIP v0.8: `cumulative_budget`,
`allowed_counterparty_types`, `actionScope.geographic_restriction`) are surfaced
in the decision log but never ground a deny. A **binding constraint the verifier
cannot establish from the signing context is a deny** — wrongful acceptance is
treated as categorically worse than wrongful rejection.

- `actionScope.allowed_rails`, `per_transaction_ceiling` (same-currency only —
  **no FX conversion, ever**), `allowed_transaction_categories` (against the
  category declared in config for this key)
- Authorization levels: `one-time` (exact amount/counterparty/rail/deadline),
  `recurring` (per-transaction max, validity, counterparty; period ceilings
  enforced deny-side via the per-key daily counter), `policy` (per-rail caps)
- `tradingMandate`: `maxNotionalPerOrder` + `unit`, counterparty
  `allowList`/`blockList` (raw addresses, or DIDs via
  `config.counterpartyAddressMap`), `temporal.allowedTimeWindows` (IANA
  timezones), velocity caps (deny-side, see Limitations), geographic
  (`allowedJurisdictionsOnly` fails closed; `blockedJurisdictions` fails open
  per AIP v0.8 §2.3 — both surfaced in the log)

## Per-rail support matrix

The released OWS engine (v1.3.2) hands executables `transaction.raw_hex` only
(the parsed `to`/`value`/`data` fields described in main-branch docs are newer
than the latest release — discovered live-fire, not from docs). This verifier
therefore decodes EVM payloads itself: EIP-1559, EIP-2930, and legacy RLP, with
a chain-id cross-check against the signing context. Parsed fields are used
as-is when a newer engine provides them. Other chains' payloads remain
undecoded, and the verifier does not silently skip what it cannot read:

| Rail (CAIP-2) | Credential plane¹ | Amount ceilings | Counterparty lists | Net effect |
|---|---|---|---|---|
| EVM (`eip155:*`) | ✅ | ✅ native value² (decoded from `raw_hex`) | ✅ `to` address | **Full enforcement** |
| Solana, Bitcoin, Tron, TON, Cosmos, Sui, XRPL, … | ✅ | ✗ payload unparsed | ✗ payload unparsed | **Verified-identity only**: mandates carrying binding amount/counterparty constraints **deny** on these rails; identity/temporal/revocation-scoped mandates work |

¹ proof, issuer, schema, validity, revocation, time windows, rail allowlists — chain-independent.
² Native value only. Transactions with calldata (token transfers, contract
calls) **deny** under a binding amount constraint unless
`allowContractCalls: true` is set deliberately — the native value is not a
reliable measure of a contract call's spend. ERC-20 `transfer` parsing is a
planned extension.

**Contributing a rail:** implement payload parsing for the chain (amount +
recipient from `raw_hex`), add the CAIP-2 → rail/currency/decimals mapping to
`DEFAULT_RAILS`, and add pass/fail fixtures for every rule the parser enables.
PRs are welcome — the conformance runner (`test/run.mjs`) is the gate.

## Configuration

Everything arrives through the OWS policy file's `config` object (injected by
the engine as `policy_config`). No quiet defaults: the installer writes every
behavioral value out loud; the table is the contract.

| Key | Required | Meaning |
|---|---|---|
| `credentialPath` | ✅ | Delegation credential JSON. **Re-read on every call** — rotation/re-issue takes effect immediately |
| `issuerDid` | ✅ | Pinned trusted issuer. Credentials from any other issuer deny |
| `schemaAllowlist` | ✅ | Accepted `credentialSchema.id` URLs (frozen-URL schema policy; default v2.1 only) |
| `agentDid` | — | Pin `credentialSubject.id`; mismatch denies |
| `revocation.maxStalenessHours` | written explicitly (24) | Cache window for status lists when refresh fails. Older ⇒ deny |
| `revocation.onUnreachable` | written explicitly | `cache-then-deny` (the only implemented behavior, on purpose) |
| `revocation.fetchTimeoutMs` | written explicitly (1500) | Per-fetch budget inside OWS's hard 5s executable timeout |
| `didCache.maxStalenessHours` | written explicitly (24) | Same refresh-first policy for issuer DID documents |
| `rails` | defaults built in | CAIP-2 → `{rail, currency, decimals}` map; extend/override per deployment |
| `allowContractCalls` | default `false` | Permit EVM calldata under binding amount constraints (read the footnote first) |
| `transactionCategory` | — | Category this key's transactions are declared as, matched against `allowed_transaction_categories` |
| `counterpartyAddressMap` | — | DID → addresses, for mandates that pin counterparties by DID |
| `cacheDir` / `auditLog` | written explicitly | Cache location; JSONL decision log |
| `offline.didDocumentPath` / `offline.statusListPath` | — | Air-gapped/test overrides; bypass network entirely |

## Decision log

Every evaluation appends one JSON line — timestamp, verdict, reason, advisory
notes, chain, wallet/key ids, credential id + SHA-256, transaction hash — to
`auditLog` (0600). The log is unsigned in this release; emission of signed
`PolicyEvaluationCredential`s with a published per-instance key is a planned
extension (see `docs/SCOPE.md`).

## Limitations (read these — they are load-bearing)

- **Counterparty DIDs need a mapping.** The wallet sees addresses, not DIDs. A
  mandate pinning a counterparty DID with no `counterpartyAddressMap` entry
  **denies** (the binding cannot be established). 
- **`requireIssuerClassIn` denies.** Verifying a counterparty's attested issuer
  class needs an attestation source this executable doesn't have yet.
- **Velocity/period ceilings are deny-side only.** The only state OWS provides
  is a per-API-key, per-calendar-day, native-value counter — a lower bound on
  any rolling window. An overshoot it can see is a real overshoot (deny); full
  allow-side accounting needs a stateful evaluator.
- **One-time credentials aren't consumed.** Single-use semantics can't be
  tracked at this layer; revoke the credential after settlement.
- **Order-plane constraints are not enforced here.** `allowedVenues`,
  `allowedInstruments`, `dailyDrawdownCap` require order context and belong to
  an order-aware evaluator; they are surfaced as NOT-ENFORCED notes.
- **Schema note:** the frozen v2.1 schema's `proof` block predates the
  eddsa-jcs-2022 migration; the credential **body** is validated against v2.1
  structure while the proof is verified per W3C VC Data Integrity. Tracked as a
  spec-alignment item in the AIP repository.

## Development

```bash
npm run typecheck   # strict TS
npm run build       # esbuild → dist/ows-op-verify.cjs (single file, node:* only)
npm test            # fixtures regenerated fresh (keys generated on the fly), 43 checks
npm run livefire    # end-to-end against a real local OWS install (see harness/)
```

MIT. Spec surface: [observer-protocol/op-policy-engine](https://github.com/observer-protocol/op-policy-engine) · [observer-protocol/aip](https://github.com/observer-protocol/aip).
