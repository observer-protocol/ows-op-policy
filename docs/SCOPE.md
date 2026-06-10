# Capability scope — Observer Protocol × Open Wallet Standard integration

This document states what this project does and deliberately does not do in
its first release, and what is planned. It is the public scope statement for
the OP↔OWS integration.

## Why this integration

OWS gives agent wallets local-first key custody with a pre-signing policy
engine: policies attach to API keys, evaluate before the wallet secret's
decryption key is derived, and compose AND-wise. Its declarative rule set is
deliberately lean (chain allowlist, expiry, EIP-712 contract allowlist);
everything richer — spending limits, counterparty controls, time windows — is
routed to **custom executables**.

Observer Protocol issues signed, revocable, scope-limited delegation
credentials: a principal's cryptographic statement of what an agent may do.
This project is the bridge — an OWS custom executable that makes the OWS
policy gate consume an `ObserverDelegationCredential` as its authorization
provenance. The wallet then enforces not just *limits*, but *whose authority*
those limits flow from, with revocation and audit.

It is standalone by design: MIT, no private dependencies, no marketplace or
endorsement required. Any OWS user can install it; any verifier can audit the
decision trail.

## v1 scope (this release)

1. **Verifier executable** (`dist/ows-op-verify.cjs`, single file, Node ≥18,
   zero runtime dependencies) conforming to the OWS exec contract: stdin
   `PolicyContext` → stdout `{allow, reason}`, within the engine's 5-second
   budget, fail-closed on every error path.
2. **Credential verification:** `DataIntegrityProof`/`eddsa-jcs-2022` proof;
   pinned issuer with `did:web` resolution and a hard `assertionMethod`
   requirement; schema allowlist (frozen-URL policy, v2.1 by default);
   validity window; W3C Bitstring Status List revocation with an explicit,
   configured staleness policy (refresh-first; bounded cache fallback; deny
   beyond the window).
3. **Mandate enforcement** mapped to what a wallet signing request can
   actually establish: rails, same-currency amount ceilings (no FX),
   authorization levels (one-time / recurring / policy), counterparty
   allow/block lists, time-of-day windows, deny-side velocity caps. Binding
   constraints that cannot be established from the context **deny**; advisory
   fields are surfaced, never silently dropped, and never ground a deny.
4. **Multi-rail payload parsing, zero runtime dependencies:**
   - **EVM** — EIP-1559 / EIP-2930 / legacy RLP; native value plus ERC-20 and
     EIP-3009 (x402) token transfers decoded at the token's own decimals
     (USDC/USDT = 6); `chainId` cross-check.
   - **Solana** — hand-rolled parser for legacy and v0 (versioned) messages;
     System-program SOL transfers and SPL `TransferChecked` for USDC/USDT;
     per-instruction accounting (benign ComputeBudget/Memo vs opaque). Fail
     closed on v0 ALUT-loaded accounts, plain SPL `Transfer` (mint absent),
     opaque instructions, and multi-transfer attribution.
5. **Installer + policy template** that walk the same path a user walks by
   hand (executable install → policy file with fully-explicit config →
   self-test → `ows policy create` / `ows key create`), so a successful
   ceremony doubles as an integration test.
6. **Conformance suite**: every rule tested on both the pass and the fail
   side (66 checks, EVM + Solana), with all fixtures (keys included) generated
   fresh per run; plus live refresh-first/stale-cache revocation tests and a
   sandboxed live-fire harness that drives real `ows sign tx` calls on both an
   EVM and a Solana rail (deny + allow each).
7. **Unsigned append-only JSONL decision log.**

## Explicitly out of scope for v1

| Item | Status |
|---|---|
| Trust-score / reputation gating | Excluded — enforcement here is mandate-based, not score-based |
| Signed `PolicyEvaluationCredential` emission | Planned (v1.x): per-instance signing key with a published key-scoping document |
| World ID / personhood linkage (AIP v0.9) | Optional extension only; never a dependency of this integration |
| x402 payment attestation | Separate deliverable, not part of the policy gate |
| EVM + Solana payload parsing (native + USDC/USDT) | **Shipped** — see the README per-rail matrix |
| Bitcoin / Tron / TON / Cosmos / Sui / XRPL payload parsing | Contribution path documented in the README per-rail matrix |
| Solana v0 ALUT account resolution (on-chain table reads) | Out of v1 — fails closed; would require an RPC read in the signing path |
| Solana associated-token-account (owner) derivation | Planned — enables wallet/DID counterparty matching for SPL; until then matches token-account addresses |
| Plain SPL `Transfer` asset identification | Not possible offline (mint absent); use `TransferChecked` — fails closed under a token ceiling |
| Counterparty issuer-class attestation lookup | Planned alongside an attestation-context source; denies meanwhile |
| Order-plane constraints (venues, instruments, drawdown) | Belong to an order-aware evaluator, not the wallet signing gate |
| Stateful period/velocity accounting (allow-side) | Needs a stateful evaluator; deny-side enforcement ships in v1 |
| Upstream OWS PR (worked example in `open-wallet-standard/core`) | Nice-to-have distribution, not a dependency |

## Open items

- **Plain SPL `Transfer` handling — design call flagged for Boyd.** The task
  suggested "resolve via the mandate's declared unit — never guess." I chose
  **fail-closed** instead: a plain `Transfer` carries no mint, so the asset
  cannot be *identified* (only the amount and a destination token account are
  in the instruction). Interpreting the amount with the mandate's declared
  decimals would let an agent move an *unknown* token up to a USDC ceiling —
  exactly the wrongful-accept an identity gate must avoid. `TransferChecked`
  (mint-bearing) is the enforceable path and is fully supported. If you want
  the interpret-via-declared-unit behavior for plain `Transfer` despite the
  asset-identity gap, that's a one-line change in `resolve-transfer.ts` — say
  the word.
- **Solana network binding.** A Solana message carries a `recentBlockhash`,
  not the genesis hash, so mainnet-vs-devnet cannot be proven from the static
  payload (EVM embeds `chainId`; Solana does not). The cluster is trusted from
  the PolicyContext `chain_id` via the rail map. Options for a future version:
  accept this as the OWS-engine trust boundary, or require a signed
  attestation of the cluster. Flagged for Boyd's design review; not faked in v1.
- Alignment of the AIP draft texts' proof-suite language: the v0.6–v0.8
  drafts still cite `Ed25519Signature2026`, while this verifier implements
  the eddsa-jcs-2022 surface as deployed in production and rejects legacy
  suites. The draft-text alignment is a separate, already-tracked change in
  the AIP repository and is deliberately not bundled into this project.
- Final repository naming and publication.
- Signed-decision (PEC) emission model for third-party operators.
