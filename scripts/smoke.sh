#!/usr/bin/env bash
# End-to-end check: issue a credential into the wallet, then present it to the verifier.
# Expects 'make up' and 'make testbed' to already be running.
set -euo pipefail

BASE=${BASE:-http://localhost:4000}

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1"; exit 1; }

say "Checking the testbed is up"
curl -fsS "$BASE/api/health" >/dev/null || fail "testbed is not answering on $BASE — run 'make testbed'"

say "Reading the issuer catalogue"
catalogue=$(curl -fsS "$BASE/api/catalogue")
echo "$catalogue" | head -c 400; echo
# Skip the *_deferred variants: they park on the deferred endpoint, which is not wired up.
configuration=$(echo "$catalogue" \
  | grep -oE '"[^"]*sd_jwt[^"]*"' | tr -d '"' | grep -v '_deferred$' | head -1 || true)
[ -n "$configuration" ] || fail "no SD-JWT VC configuration advertised; is the issuer up?"
echo "using: $configuration"

say "Issuing $configuration into the wallet"
issued=$(curl -fsS -X POST "$BASE/api/issue" \
  -H 'content-type: application/json' \
  -d "{\"credentialConfigurationId\":\"$configuration\",\"autoLogin\":true}")
echo "$issued" | head -c 600; echo
echo "$issued" | grep -q '"status":"issued"' || fail "issuance failed"

say "Presenting the credential to the verifier"
presented=$(curl -fsS -X POST "$BASE/api/present" \
  -H 'content-type: application/json' -d '{}')
echo "$presented" | head -c 800; echo
echo "$presented" | grep -q '"status":"presented"' || fail "presentation failed"

say "Smoke test passed"
