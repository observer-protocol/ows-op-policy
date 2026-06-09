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
4. **Installer + policy template** that walk the same path a user walks by
   hand (executable install → policy file with fully-explicit config →
   self-test → `ows policy create` / `ows key create`), so a successful
   ceremony doubles as an integration test.
5. **Conformance suite**: every rule tested on both the pass and the fail
   side, with all fixtures (keys included) generated fresh per run; plus live
   refresh-first/stale-cache revocation behavior tests against a local server.
6. **Unsigned append-only JSONL decision log.**

## Explicitly out of scope for v1

| Item | Status |
|---|---|
| Trust-score / reputation gating | Excluded — enforcement here is mandate-based, not score-based |
| Signed `PolicyEvaluationCredential` emission | Planned (v1.x): per-instance signing key with a published key-scoping document |
| World ID / personhood linkage (AIP v0.9) | Optional extension only; never a dependency of this integration |
| x402 payment attestation | Separate deliverable, not part of the policy gate |
| Non-EVM payload parsing (amounts/recipients from `raw_hex`) | Contribution path documented in the README per-rail matrix |
| ERC-20 `transfer` calldata parsing | Planned; until then calldata under a binding ceiling denies unless explicitly allowed |
| Counterparty issuer-class attestation lookup | Planned alongside an attestation-context source; denies meanwhile |
| Order-plane constraints (venues, instruments, drawdown) | Belong to an order-aware evaluator, not the wallet signing gate |
| Stateful period/velocity accounting (allow-side) | Needs a stateful evaluator; deny-side enforcement ships in v1 |
| Upstream OWS PR (worked example in `open-wallet-standard/core`) | Nice-to-have distribution, not a dependency |

## Open items

- Alignment of the AIP draft texts' proof-suite language with the
  eddsa-jcs-2022 implementation surface (tracked in the AIP repository); this
  verifier implements the post-migration surface and rejects legacy suites.
- Final repository naming and publication.
- Signed-decision (PEC) emission model for third-party operators.
