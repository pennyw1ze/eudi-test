#!/usr/bin/env bash
# Checks the host can actually run the testbed, and says what to do when it cannot.
set -uo pipefail

ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mfail\033[0m  %s\n' "$1"; FAILED=1; }

FAILED=0
echo "EUDI testbed · host check"

DOCKER=${DOCKER:-docker}

command -v ${DOCKER%% *} >/dev/null && ok "docker present" || bad "docker is not installed"

if $DOCKER info >/dev/null 2>&1; then
  ok "docker daemon reachable as '$DOCKER'"
elif sudo -n docker info >/dev/null 2>&1; then
  warn "docker needs root; run make with:  make up DOCKER=\"sudo docker\""
else
  bad "cannot talk to the docker daemon as '$DOCKER'"
  echo "        either:  make up DOCKER=\"sudo docker\"          (works immediately, asks for your password)"
  echo "        or:      sudo usermod -aG docker \$USER           (then log out and back in, no sudo afterwards)"
fi

if [ -x "$(command -v java)" ]; then
  version=$(java -version 2>&1 | head -1 | grep -oE '[0-9]+' | head -1)
  [ "${version:-0}" -ge 17 ] && ok "java $version" || bad "java 17+ required, found ${version:-none}"
else
  bad "java is not installed (17+ required)"
fi

[ -d vendor/eudi-srv-pid-issuer ] && ok "issuer sources vendored" \
  || warn "issuer not vendored yet — run 'make vendor'"
[ -d vendor/eudi-srv-web-verifier-endpoint-23220-4-kt ] && ok "verifier sources vendored" \
  || warn "verifier not vendored yet — run 'make vendor'"
[ -f gateway/certs/localhost.tls.pem ] && ok "gateway certificate present" \
  || warn "no gateway certificate — run 'make certs'"

# The whole stack is three JVMs plus Postgres; below ~3GB free it will thrash.
available=$(free -m 2>/dev/null | awk '/^Mem:/ {print $7}')
if [ -n "${available:-}" ]; then
  [ "$available" -ge 3000 ] && ok "${available}MB RAM available" \
    || warn "only ${available}MB RAM available; consider 'make up-issuer' and 'make up-verifier' separately"
fi

for port in 80 443 4000; do
  if command -v ss >/dev/null && ss -ltn "( sport = :$port )" 2>/dev/null | grep -q LISTEN; then
    warn "port $port is already in use"
  fi
done

echo
[ "$FAILED" = 0 ] && echo "Ready. Next: make setup && make up && make testbed" \
                  || echo "Fix the failures above, then re-run 'make doctor'."
exit $FAILED
