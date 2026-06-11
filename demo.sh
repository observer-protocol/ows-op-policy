#!/usr/bin/env bash
# demo.sh — single-window, self-narrating launch demo for the Loom.
# A screen recording of this script alone IS the video. Captions are full
# sentences: the story is understandable with the audio off.
#
#   cd ~/Desktop/OP_AT/ows-op-policy && ./demo.sh
#
# First run does a one-time sandbox setup (real OWS v1.3.2 install + wallet).
# Run it once to warm the sandbox, then record the second run. Set DEMO_PAUSE
# to change the beat pacing (default 2.5s).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX="$REPO/.demo-sandbox"
export HOME_REAL="$HOME"
PAUSE="${DEMO_PAUSE:-2.5}"
OWS="$SANDBOX/node_modules/.bin/ows"
SHOME="$SANDBOX/home"
PKG="@observer-protocol/ows-op-verify"
REPO_URL="github.com/observer-protocol/ows-op-policy"
FIX="$REPO/test/fixtures/out"

cyan=$'\033[1;36m'; green=$'\033[1;32m'; red=$'\033[1;31m'; dim=$'\033[2m'; bold=$'\033[1m'; rst=$'\033[0m'

banner() { # $1 = caption text (full sentences)
  printf '\n%s' "$cyan"
  printf '┌──────────────────────────────────────────────────────────────────────┐\n'
  printf '%s\n' "$1" | fold -s -w 70 | while IFS= read -r line || [ -n "$line" ]; do printf '│ %s%-70s%s │\n' "$bold" "$line" "$cyan"; done
  printf '└──────────────────────────────────────────────────────────────────────┘%s\n' "$rst"
  sleep "$PAUSE"
}
cmd() { printf '%s$ %s%s\n' "$dim" "$1" "$rst"; }
beat_pause() { sleep "$PAUSE"; }

# ── one-time setup (skipped once warm) ──────────────────────────────────────
setup() {
  printf '%sOne-time setup: installing a real Open Wallet Standard v1.3.2 sandbox…%s\n' "$dim" "$rst"
  rm -rf "$SANDBOX"; mkdir -p "$SHOME"
  ( cd "$REPO" && npm run build >/dev/null 2>&1 )
  node "$REPO/test/fixtures/gen.mjs" >/dev/null 2>&1
  printf '{"name":"demo-sandbox","private":true}' > "$SANDBOX/package.json"
  ( cd "$SANDBOX" && npm install @open-wallet-standard/core --no-fund --no-audit >/dev/null 2>&1 )
  HOME="$SHOME" "$OWS" wallet create --name agent-treasury >/dev/null 2>&1
  # OP policy bound to the conformance valid-policy credential (ceiling 1.0 ETH,
  # offline did.json + status list — verifies with no network in the hot path)
  FIX="$FIX" SHOME="$SHOME" SANDBOX="$SANDBOX" node -e '
    const fs=require("fs"),p=require("path");
    const cases=JSON.parse(fs.readFileSync(p.join(process.env.FIX,"cases.json"),"utf8")).cases;
    const cfg=cases.find(c=>c.ctx&&c.ctx.policy_config&&/valid-policy/.test(c.ctx.policy_config.credentialPath)).ctx.policy_config;
    const exe=p.join(process.env.SHOME,".ows","plugins","policies","ows-op-verify.cjs");
    const pol={id:"op-demo",name:"Observer Protocol delegation verification",version:1,created_at:"2026-06-11T00:00:00Z",rules:[],executable:exe,action:"deny",config:cfg};
    fs.writeFileSync(p.join(process.env.SANDBOX,"op-demo.json"),JSON.stringify(pol,null,2));
  '
  [ -s "$SANDBOX/op-demo.json" ] || { echo "setup FAILED: op-demo.json not written"; exit 1; }
  mkdir -p "$SHOME/.ows/plugins/policies"
  cp "$REPO/dist/ows-op-verify.cjs" "$SHOME/.ows/plugins/policies/ows-op-verify.cjs"
  HOME="$SHOME" "$OWS" policy create --file "$SANDBOX/op-demo.json" >/dev/null 2>&1
  HOME="$SHOME" "$OWS" key create --name demo-agent --wallet agent-treasury --policy op-demo 2>&1 \
    | grep -o 'ows_key_[a-f0-9]*' > "$SANDBOX/token"
  [ -s "$SANDBOX/token" ] || { echo "setup FAILED: no agent token (policy/key create)"; exit 1; }
  # pre-stage over/under EIP-1559 tx hexes (2 ETH vs 0.5 ETH to the merchant).
  # lib.mjs is an ES module — load via import(), not require().
  REPO="$REPO" node --input-type=module -e '
    const m = await import(process.env.REPO + "/test/fixtures/lib.mjs");
    const to = "0xA11CE00000000000000000000000000000000001";
    process.stdout.write(m.buildEip1559Tx({ to, valueWei: 2000000000000000000n }));
  ' > "$SANDBOX/over.tx"
  REPO="$REPO" node --input-type=module -e '
    const m = await import(process.env.REPO + "/test/fixtures/lib.mjs");
    const to = "0xA11CE00000000000000000000000000000000001";
    process.stdout.write(m.buildEip1559Tx({ to, valueWei: 500000000000000000n }));
  ' > "$SANDBOX/under.tx"
  # warm the npx cache so beat 2 is instant on the recorded run
  npx -y "$PKG" </dev/null >/dev/null 2>&1 || true
  touch "$SANDBOX/.ready"
  printf '%sSandbox ready.%s\n\n' "$dim" "$rst"
}

[ -f "$SANDBOX/.ready" ] || setup
TOKEN="$(cat "$SANDBOX/token")"
OVER="$(cat "$SANDBOX/over.tx")"; UNDER="$(cat "$SANDBOX/under.tx")"

clear 2>/dev/null || true

# ── Beat 1 ──────────────────────────────────────────────────────────────────
banner "Observer Protocol x Open Wallet Standard: a signed-mandate verifier for agent wallets. Published today on npm as $PKG. MIT licensed, zero runtime dependencies, one single-file policy executable."

# ── Beat 2 ──────────────────────────────────────────────────────────────────
banner "First, the default is safe. Run the verifier with no transaction context at all. With nothing to authorize, it denies. Fail-closed by design."
cmd "npx $PKG < /dev/null"
# Run from a neutral dir: inside the package's own repo, npx would resolve the
# unlinked local bin instead of the published one.
( cd "$SANDBOX" && npx -y "$PKG" </dev/null ) | python3 -m json.tool
beat_pause

# ── Beat 3 ──────────────────────────────────────────────────────────────────
banner "Now a REAL Open Wallet Standard v1.3.2 wallet. The agent's signed mandate allows up to 1 ETH. It attempts to send 2 ETH. OWS hands our policy the transaction, the policy denies it, and the wallet's signing key is never derived."
cmd "ows sign tx --chain eip155:1 --wallet agent-treasury --tx <2 ETH>"
HOME="$SHOME" OWS_PASSPHRASE="$TOKEN" "$OWS" sign tx --chain eip155:1 --wallet agent-treasury --tx "$OVER" 2>&1 | sed "s/.*/${red}&${rst}/" || true
beat_pause

# ── Beat 4 ──────────────────────────────────────────────────────────────────
banner "The same agent, within its mandate: 0.5 ETH. The policy verifies the credential and the amount, allows the action, and OWS returns real signature bytes."
cmd "ows sign tx --chain eip155:1 --wallet agent-treasury --tx <0.5 ETH>"
OUT="$(HOME="$SHOME" OWS_PASSPHRASE="$TOKEN" "$OWS" sign tx --chain eip155:1 --wallet agent-treasury --tx "$UNDER" 2>&1)"
printf '%ssignature: %s%s\n' "$green" "$OUT" "$rst"
beat_pause

# ── Beat 5 ──────────────────────────────────────────────────────────────────
banner "This is not a toy credential. Here is a real agent's live trading mandate, served from observerprotocol.org, signed with the W3C eddsa-jcs-2022 suite under key-5."
cmd "curl -s observerprotocol.org/credentials/maxi-0001-trading-mandate.json | proof"
MAND="$(curl -s --max-time 15 https://observerprotocol.org/credentials/maxi-0001-trading-mandate.json)"
printf '%s' "$MAND" | python3 -c 'import sys,json; p=json.load(sys.stdin)["proof"]; print(json.dumps({"type":p["type"],"cryptosuite":p["cryptosuite"],"verificationMethod":p["verificationMethod"]},indent=2))'
beat_pause
banner "And the production verification endpoint confirms it: signature valid, not expired, not revoked."
cmd "curl -s -X POST api.observerprotocol.org/api/v1/verify -d '{credential}'"
curl -s --max-time 15 -X POST https://api.observerprotocol.org/api/v1/verify -H 'content-type: application/json' -d "{\"credential\": $MAND}" | python3 -m json.tool
beat_pause

# ── Beat 6 ──────────────────────────────────────────────────────────────────
banner "Try it yourself in two minutes: npm run livefire. Repo: $REPO_URL. Package: $PKG. Discussion: open-wallet-standard/core issue #232."
