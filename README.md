# ows-op-policy

> **SUPPORT TIER — REFERENCE IMPLEMENTATION, NO CONSUMER FOUND.** Not under active maintenance.
> Read it, run it, copy from it; do not assume support.
>
> **What backs the tier, stated as an absence with its scope.** No import or require of
> `@observer-protocol/ows-op-verify` was found anywhere in the Observer Protocol estate — not in any
> service, and not even in our own conformance harness, which does exercise four of the other
> adapters. It is not installed on the production host. **That search covered our own estate and
> that host only. An external adopter running this against a real Open Wallet Standard Solana wallet
> would be invisible to us, and this adapter is built for someone else's stack, so that is a live
> possibility rather than a technicality.** This says we found no consumer; it does not say nobody
> uses it.
>
> The rail registry in the Observer Protocol API names this package at `transports[7].enforcer`.
> **That field is read only by the registry's own validator and its tests** — `api-server-v2.py`
> consumes only `registerable_rail_ids()`, so the registry declares this adapter and never installs
> or calls it. A registry entry is not a consumer.
>
> **Versions.** Published `@observer-protocol/ows-op-verify@0.3.0`.
> The Observer Protocol API's rail registry no longer carries a pin. **Ruled 2026-08-05:** the
> field was named `version` and read as "these versions are known to work together", while
> nothing enforced or checked it — the running server never reads it. It is now
> `published_version_recorded` with a required `recorded_on` date: what was published when
> someone last looked. It does not track publication and is not automated to. **It is not a
> statement that these versions have been verified together** — no such verification exists,
> and a real compatibility matrix would be a separate artifact.
>
> Tiers for all seven Observer Protocol adapters are listed together in
> [`op-policy-engine`](https://github.com/observer-protocol/op-policy-engine#adapter-support-tiers).

**Observer Protocol delegation verification for Open Wallet Standard wallets.**

> **Published.** `@observer-protocol/ows-op-verify@0.3.0` on npm. The OWS member of
> Observer Protocol's three sibling enforcement engines, alongside
> [`wdk-op-policy`](https://github.com/observer-protocol/wdk-op-policy) (Tether WDK, PR #55)
> and [`mppx-op-account`](https://github.com/observer-protocol/mppx-op-account) (MPP/Tempo
> via mppx), all sharing a byte-identical verification core. *The binding layer is
> contested; the enforcement locus is not.*

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
`actionScope.geographic_restriction`) are surfaced in the decision log but never
ground a deny. A **binding constraint the verifier cannot establish from the
signing context is a deny** — wrongful acceptance is treated as categorically
worse than wrongful rejection.

`allowed_counterparty_types` is **not** advisory and this README previously said
it was. It has no enforcement path in any Observer Protocol engine, so a mandate
that sets it **denies**, tagged `[unenforceable]`. The property is accepted by
delegation schemas v2.1/v2.3/v2.4 and was recommended by AIP v0.8 §1.3; both the
recommendation and the property are withdrawn. A credential carrying it is
refused in full, not served with the field ignored.

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

The released OWS engine (v1.3.2) hands executables `transaction.raw_hex` only —
the full serialized transaction (the parsed `to`/`value`/`data` fields in
main-branch docs are newer than the latest release; discovered live-fire, not
from docs, for **both** EVM and Solana). This verifier decodes the payload
itself, zero runtime dependencies, and does not silently skip what it can't
read:

| Rail | Credential plane¹ | Native amount | Token amount (USDC/USDT) | Counterparty | Net effect |
|---|---|---|---|---|---|
| EVM (`eip155:*`) | ✅ | ✅ ETH/POL value | ✅ ERC-20 + EIP-3009 `transfer*` decoded at the token's own decimals | ✅ recipient (`to`, or the token-transfer `to`) | **Full enforcement** |
| Solana (`solana:*`) | ✅ | ✅ SOL (System transfer) | ✅ SPL **TransferChecked** (mint-identified, 6-dec) | ✅ wallet (SOL) / token account (SPL)³ | **Full enforcement** (legacy + v0), within the fail-closed boundaries below |
| Bitcoin, Tron, TON, Cosmos, Sui, XRPL, … | ✅ | ✗ payload unparsed | ✗ | ✗ | **Verified-identity only**: binding amount/counterparty mandates **deny**; identity/temporal/revocation-scoped mandates work |

¹ proof, issuer, schema, validity, revocation, time windows, rail allowlists — chain-independent.

**EVM payloads:** EIP-1559 / EIP-2930 / legacy RLP, with a `chainId`
cross-check against the signing context. Native value, plus ERC-20
`transfer`/`transferFrom` and EIP-3009 `transferWithAuthorization` /
`receiveWithAuthorization` (the x402 USDC path) decoded at the token's
registered decimals. Calldata to an **unknown** contract still denies under a
binding amount constraint unless `allowContractCalls: true` (native-value-only
measurement, said loudly).

**Solana payloads — what is enforced:** legacy and v0 (versioned) messages;
System-program SOL transfers; SPL Token **TransferChecked** for USDC/USDT
(mint identified from the instruction, amount at 6 decimals, on-chain decimals
cross-checked against the registry). Same-currency invariant (no FX), identical
to EVM.

**Solana payloads — fail-closed boundaries (deny any binding amount/counterparty
constraint; stated plainly, not stretched):**
- **Address Lookup Tables (v0 ALUT):** accounts loaded from on-chain tables are
  not in the static message. No on-chain reads in v1 → **deny** when a
  constraint would depend on an ALUT-loaded account.
- **Plain SPL `Transfer` (non-checked):** the mint is not in the instruction, so
  the asset cannot be proven offline → **deny** under a token ceiling. Use
  `TransferChecked` for enforceable token payments. (The asset is never
  guessed.)
- **Opaque / unhandled instructions** (unknown program, or unhandled
  System/Token instruction that could move value) alongside a transfer →
  **deny**: every instruction must satisfy the mandate. Benign `ComputeBudget`
  and `Memo` instructions do not defeat enforcement.
- **Multiple value transfers** in one transaction → **deny** (attribution
  unsupported in v1).
- **Network binding:** a Solana message carries a `recentBlockhash`, **not** the
  genesis hash, so mainnet-vs-devnet cannot be re-derived from the static
  payload (unlike EVM's embedded `chainId`). The cluster is taken from the
  PolicyContext `chain_id` via the rail map; this is trusted input, documented
  here rather than faked. *(Open question flagged for design review.)*

³ SPL transfers move between **token accounts**, not wallets. The verifier
matches the destination **token account** address against the mandate's
counterparty list; matching by wallet/DID requires that token account to be
listed (in the allowlist or `counterpartyAddressMap`). Deriving a token
account's owner offline (associated-token-account derivation) is a planned
extension; until then owner-based SPL counterparty matching fails closed.

**Contributing a rail:** implement payload parsing for the chain (amount +
recipient), add the CAIP-2 → rail mapping with its `family` to `DEFAULT_RAILS`,
and add pass/fail fixtures for every rule the parser enables. PRs are welcome —
the conformance runner (`test/run.mjs`) is the gate.

## Configuration

Everything arrives through the OWS policy file's `config` object (injected by
the engine as `policy_config`). No quiet defaults: the installer writes every
behavioral value out loud; the table is the contract.

| Key | Required | Meaning |
|---|---|---|
| `credentialPath` | ✅ | Delegation credential JSON. **Re-read on every call** — rotation/re-issue takes effect immediately |
| `issuerDid` | ✅ | Pinned trusted issuer. Credentials from any other issuer deny |
| `schemaAllowlist` | ✅ | Accepted `credentialSchema.id` URLs (frozen-URL schema policy; example accepts v2.1 + v2.4 — the current Sovereign-issued delegation schema) |
| `agentDid` | — | Pin `credentialSubject.id`; mismatch denies |
| `revocation.maxStalenessHours` | written explicitly (24) | Cache window for status lists when refresh fails. Older ⇒ deny |
| `revocation.onUnreachable` | written explicitly | `cache-then-deny` (the only implemented behavior, on purpose) |
| `revocation.fetchTimeoutMs` | written explicitly (1500) | Per-fetch budget inside OWS's hard 5s executable timeout |
| `didCache.maxStalenessHours` | written explicitly (24) | Same refresh-first policy for issuer DID documents |
| `rails` | defaults built in | CAIP-2 → `{rail, currency, decimals, family}` map; extend/override per deployment |
| `evmTokens` | defaults built in | lowercased ERC-20 contract → `{symbol, decimals}` (USDC/USDT preloaded); identifies token transfers |
| `solanaMints` | defaults built in | base58 SPL mint → `{symbol, decimals}` (USDC/USDT preloaded) |
| `allowContractCalls` | default `false` | Permit **unknown** EVM contract calldata under binding amount constraints, measured by native value only (read the footnote first) |
| `transactionCategory` | — | Category this key's transactions are declared as, matched against `allowed_transaction_categories` |
| `counterpartyAddressMap` | — | DID → addresses, for mandates that pin counterparties by DID (use token-account addresses for SPL) |
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
- **SPL counterparty matching is against the token account, not the wallet
  owner.** Offline associated-token-account derivation is a planned extension;
  until then, list token-account addresses in the allowlist or fail closed.
- **Solana v0 ALUT and plain SPL `Transfer` fail closed** under binding
  amount/counterparty constraints (no on-chain reads; mint not in a plain
  Transfer). See the support matrix for the full boundary list.
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
