#!/usr/bin/env bash
# Can an attest key made now certify a key that already exists? Two stages on the connected
# device, some time apart, then the host check:
#   ./late.sh setup    install, then generate the "old" keys (platform attestation, no AK yet)
#   ./late.sh attest   later, in a new process: a fresh AK and every route to have it attest them
#   ./late.sh verify   check the newest setup and attest results on the host
# Run ./build.sh first. The attest stage runs under `am instrument --no-hidden-api-checks`, so
# the probe can also call keystore2's binder interface directly; that flag applies to this one
# process and changes nothing on the device.
set -euo pipefail
cd "$(dirname "$0")"

ADB="${ADB:-$HOME/Android/Sdk/platform-tools/adb}"
PKG=dev.eudi.akprobe
RUNNER="$PKG/dev.eudi.akprobe.ProbeInstrumentation"
mkdir -p results

# Runs probe mode $1 (extra am-instrument flags after it), prints its summary, pulls its result.
stage() {
    local out file
    out=$("$ADB" shell am instrument -w "${@:2}" -e mode "$1" "$RUNNER" | tr -d '\r')
    echo "$out"
    file=$(echo "$out" | sed -n 's/^wrote //p' | head -1)
    [ -n "$file" ] || { echo "the probe reported no result file" >&2; exit 1; }
    "$ADB" exec-out run-as "$PKG" cat "$file" > "results/$(basename "$file")"
    echo "pulled results/$(basename "$file")"
}

case "${1:-}" in
    setup)
        "$ADB" install -r "build/$PKG/akprobe.apk" >/dev/null
        stage late-setup ;;
    attest)
        stage late-attest --no-hidden-api-checks ;;
    verify)
        python3 -I verify_late.py "$(ls -t results/late-setup-*.json | head -1)" \
            "$(ls -t results/late-attest-*.json | head -1)" ;;
    *)
        sed -n '2,9p' "$0"
        exit 1 ;;
esac
