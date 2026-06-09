# Launch checklist — ows-op-policy / @observer-protocol/ows-op-verify

Runs **after** the keystate ceremony smoke-test is green (gate items 1–3) and
the repo/package names are settled (gate item 4, done). Everything below is
mechanical; do it in order.

## Gate confirmation (all must be true before step 1)

- [ ] Keystate ceremony complete; **prod credentials verify clean through
      `ows-op-verify`** (ceremony runbook step 13, transcript committed).
- [ ] #key-1/#key-2 desync fixed; both offline re-signings done.
- [ ] P0 host forensics returned **Branch A** (Branch B blocks launch — a
      possibly-exposed host means the whole #key-5 provisioning re-plans).
- [ ] Names settled: repo `ows-op-policy`, package
      `@observer-protocol/ows-op-verify`. ✅

## 1. Push-time secrets scan (do not skip — standing policy)

```bash
cd ~/Desktop/OP_AT/ows-op-policy
git status --short                      # working tree clean / known files only
grep -rniE 'ows_key_[0-9a-f]|futurebit|media/nvme|PRIVATE KEY-----|OP_SIGNING_KEY|BEGIN OPENSSH|[0-9a-f]{64}' \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git --exclude-dir='.tmp' . \
  | grep -viE 'ows_key_\.\.\.|token to your agent'    # the doc placeholder is allowed
echo "exit $? — want 1 (no real matches)"
```

Clean = only the documented `ows_key_...` placeholder string in
`installer/install.mjs` and the prose. Fixtures generate keys at runtime and
are gitignored (`test/fixtures/out/`), as are `dist/` and `harness/.tmp/` —
confirm none are staged.

## 2. Create the public repo + first push

```bash
gh repo create observer-protocol/ows-op-policy --public \
  --description "Observer Protocol delegation verification for Open Wallet Standard wallets — pre-sign mandate enforcement as an OWS custom-executable policy." \
  --source . --remote origin --push
```

Post-push: confirm Actions/branch protections per org default; confirm the
three commits are present and the tree matches local (`git log --oneline`,
expect: initial / EVM raw_hex + live-fire / docs eddsa note).

## 3. npm publish

```bash
# remove the publish guard (it exists so an accidental `npm publish` can't fire pre-gate)
# edit package.json: delete the line  "private": true,
npm whoami                              # confirm logged in as the publishing account
npm run typecheck && npm test           # prepublishOnly runs these too; run them first to see output
npm publish --access public             # scoped package → public access explicit
# verify
npm view @observer-protocol/ows-op-verify version
npx @observer-protocol/ows-op-verify </dev/null   # should emit a deny JSON (no config), not crash
```

> The `prepublishOnly` hook runs `typecheck` + the full conformance suite; a
> red bar blocks publish automatically.

## 4. Post-publish smoke

- [ ] `npm view @observer-protocol/ows-op-verify` shows version 0.1.0, MIT,
      the README, 7 files.
- [ ] Fresh-machine install path works:
      `npx @observer-protocol/ows-op-verify` (no args) returns a well-formed
      `{"allow":false,...}` deny, proving the bin resolves.
- [ ] README renders on GitHub; the per-rail support matrix and the
      eddsa-jcs-2022 proof-suite note are intact.

---

## Loom recording — staged live-fire sequence (for Boyd)

The point of the recording: show a real OWS wallet **refusing to sign** an
out-of-scope transaction because an Observer Protocol mandate said no, then
**signing** an in-scope one — end to end, no hand-waving. Two ways to run it;
pick per how much you want on camera.

### Option A — the built-in harness (one command, fully sandboxed)

```bash
cd ~/Desktop/OP_AT/ows-op-policy
npm run livefire        # add -- --keep to leave the sandbox for inspection
```

It narrates each step: installs real OWS (v1.3.2), creates a wallet, registers
the OP policy, mints an agent key, then shows the deny (2 ETH over a 1 ETH
mandate ceiling → `policy denied: … [ceiling] …`), the allow (0.5 ETH →
signature bytes), the owner-tier bypass, and the JSONL decision log. ~90s of
output; clean for a screen capture.

### Option B — hand-run for narration (more screen time per beat)

Stage this in a scratch dir so your real `~/.ows` is untouched; paste-friendly,
no backtick traps:

```bash
mkdir -p /tmp/loom && cd /tmp/loom
npm init -y >/dev/null && npm install @open-wallet-standard/core >/dev/null 2>&1
export HOME=/tmp/loom/home && mkdir -p home

# 1. real OWS wallet
node_modules/.bin/ows wallet create --name agent-treasury

# 2. install the OP verifier + policy (uses the published package)
npx @observer-protocol/ows-op-verify --help 2>/dev/null || true
node ~/Desktop/OP_AT/ows-op-policy/installer/install.mjs --credential <your-delegation.json> --direct

# 3. bind it to an agent key
node_modules/.bin/ows policy create --file "$HOME/.ows/policies/op-delegation.json"
node_modules/.bin/ows key create --name demo-agent --wallet agent-treasury --policy op-delegation
#   copy the ows_key_... token into AGENT_TOKEN below

# 4. THE MONEY SHOT — agent tries an out-of-scope transaction, OWS refuses to sign
OWS_PASSPHRASE=$AGENT_TOKEN node_modules/.bin/ows sign tx --chain eip155:1 \
  --wallet agent-treasury --tx <over-ceiling-tx-hex>
#   → error: policy denied: op-verify: [ceiling] transaction value exceeds per_transaction_ceiling

# 5. in-scope transaction signs
OWS_PASSPHRASE=$AGENT_TOKEN node_modules/.bin/ows sign tx --chain eip155:1 \
  --wallet agent-treasury --tx <under-ceiling-tx-hex>
#   → <signature bytes>

# 6. the receipt — every decision logged
cat ~/.cache/ows-op-policy/decisions.jsonl | tail -2
```

Tx hexes for step 4/5: generate with
`node -e "import('/Users/agentic/Desktop/OP_AT/ows-op-policy/test/fixtures/lib.mjs').then(m=>console.log(m.buildEip1559Tx({to:'0xA11CE00000000000000000000000000000000001',valueWei:2000000000000000000n})))"`
(swap `valueWei` for the under-ceiling case).

> For the recording, use a **freshly re-issued #key-5 mandate** (post-ceremony)
> as `<your-delegation.json>` so the on-camera credential verifies clean — not
> a pre-ceremony #key-1 one, which would (correctly) deny on the proof check
> before the ceiling rule ever runs.

## Launch comment (Boyd writes; needs the #104 findings)

The OWS Issue #104 verification is done — see the findings reported in chat /
the `ows-integration-review` memory. Short version for the comment's framing:
#104 is a dormant solo-vendor (ThoughtProof) pitch for **LLM reasoning-quality
attestation**, which is orthogonal to **credential/delegation verification**;
the maintainer closed the vendor's example PR (#114) signalling third-party
policy executables live **outside** core; and **no OWS issue mentions verifiable
credentials at all** — the lane is open. Frame the launch as filling that gap,
not competing with #104.
