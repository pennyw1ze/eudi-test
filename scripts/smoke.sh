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
printf '%.400s\n' "$catalogue"
# Skip the *_deferred variants: they park on the deferred endpoint, which is not wired up.
configuration=$(echo "$catalogue" \
  | grep -oE '"[^"]*sd_jwt[^"]*"' | tr -d '"' | grep -v '_deferred$' | head -1 || true)
[ -n "$configuration" ] || fail "no SD-JWT VC configuration advertised; is the issuer up?"
echo "using: $configuration"

say "Issuing $configuration into the wallet"
issued=$(curl -fsS -X POST "$BASE/api/issue" \
  -H 'content-type: application/json' \
  -d "{\"credentialConfigurationId\":\"$configuration\",\"autoLogin\":true}")
printf '%.600s\n' "$issued"
echo "$issued" | grep -q '"status":"issued"' || fail "issuance failed"

# The reference issuer sets nbf to iat + 20s, so a credential presented immediately is
# correctly refused with "SD-JWT is not active yet". Retry until it becomes valid.
say "Presenting the credential to the verifier (waiting out the 20s validity window)"
for attempt in $(seq 1 15); do
  presented=$(curl -fsS -X POST "$BASE/api/present" \
    -H 'content-type: application/json' -d '{}')
  echo "$presented" | grep -q '"status":"presented"' && break
  echo "$presented" | grep -q 'not active yet' || break
  sleep 2
done
printf '%.800s\n' "$presented"
echo "$presented" | grep -q '"status":"presented"' || fail "presentation failed"

say "Smoke test passed"
