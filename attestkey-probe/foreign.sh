#!/usr/bin/env bash
# Bob/Alice experiment: can Alice's attest key certify a key generated in Bob's keystore?
# Bob is the copy built with PACKAGE=dev.eudi.akprobe2, Alice is dev.eudi.akprobe: two apps,
# two keystore namespaces. Bob's public key and chain reach Alice through the host, as they
# would over a network. Build both copies first.
set -euo pipefail
cd "$(dirname "$0")"

ADB="${ADB:-$HOME/Android/Sdk/platform-tools/adb}"
ALICE=dev.eudi.akprobe
BOB=dev.eudi.akprobe2
mkdir -p results

# Starts app $1 in mode $2 and prints the on-device path of the result file it writes.
run_mode() {
    "$ADB" logcat -c
    "$ADB" shell am start -S -n "$1/dev.eudi.akprobe.MainActivity" --es mode "$2" >/dev/null
    timeout 300 "$ADB" logcat -v raw -s AKPROBE:I -e '^wrote ' -m 1 | tr -d '\r' \
        | grep '^wrote ' | head -1 | sed 's/^wrote //'
}

"$ADB" install -r "build/$BOB/akprobe.apk" >/dev/null
"$ADB" install -r "build/$ALICE/akprobe.apk" >/dev/null

bob_file=$(run_mode "$BOB" bob)
"$ADB" logcat -d -v raw -s AKPROBE:I | tr -d '\r'
"$ADB" exec-out run-as "$BOB" cat "$bob_file" > "results/$(basename "$bob_file")"
"$ADB" exec-in run-as "$ALICE" sh -c "cat > /data/user/0/$ALICE/files/bob.json" < "results/$(basename "$bob_file")"

alice_file=$(run_mode "$ALICE" alice)
"$ADB" logcat -d -v raw -s AKPROBE:I | tr -d '\r'
"$ADB" exec-out run-as "$ALICE" cat "$alice_file" > "results/$(basename "$alice_file")"

echo
python3 -I verify_foreign.py "results/$(basename "$bob_file")" "results/$(basename "$alice_file")"
