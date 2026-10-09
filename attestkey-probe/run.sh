#!/usr/bin/env bash
# Installs and runs the probe on the connected device, pulls the result JSON into results/
# and verifies it. Run ./build.sh first. Needs USB debugging and network on the phone
# (attestation certificates come from Google's remote key provisioning).
set -euo pipefail
cd "$(dirname "$0")"

ADB="${ADB:-$HOME/Android/Sdk/platform-tools/adb}"
PKG="${PKG:-dev.eudi.akprobe}"

"$ADB" install -r "build/$PKG/akprobe.apk"
"$ADB" logcat -c
"$ADB" shell am start -n "$PKG/dev.eudi.akprobe.MainActivity"

# Block until the probe logs the path of its result file (or give up after 10 minutes).
written=$(timeout 600 "$ADB" logcat -v raw -s AKPROBE:I -e '^wrote ' -m 1 | tr -d '\r' | grep '^wrote ' | head -1)
"$ADB" logcat -d -v raw -s AKPROBE:I AKPROBE:E | tr -d '\r'

file="${written#wrote }"
mkdir -p results
"$ADB" exec-out run-as "$PKG" cat "$file" > "results/$(basename "$file")"
echo "pulled results/$(basename "$file")"
python3 -I verify_attestkey.py "results/$(basename "$file")"
