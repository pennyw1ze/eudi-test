#!/usr/bin/env bash
# Builds the attest-key probe APK without Gradle: aapt2 -> javac -> d8 -> zipalign -> apksigner.
# Output: build/<package>/akprobe.apk (signed with the local debug keystore). PACKAGE=...
# builds a copy under another package name, i.e. a different app to the device.
set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT="$SDK/build-tools/${BUILD_TOOLS:-36.0.0}"
JAR="$SDK/platforms/${PLATFORM:-android-36}/android.jar"
PACKAGE="${PACKAGE:-dev.eudi.akprobe}"
OUT="build/$PACKAGE"

rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex"

"$BT/aapt2" link -o "$OUT/unsigned.apk" --manifest AndroidManifest.xml -I "$JAR" \
    --rename-manifest-package "$PACKAGE"
javac -source 8 -target 8 -bootclasspath "$JAR" -Xlint:-options -d "$OUT/classes" $(find src -name '*.java')
"$BT/d8" --min-api 31 --lib "$JAR" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

python3 -I - "$OUT/unsigned.apk" "$OUT/dex/classes.dex" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "a") as apk:
    apk.write(sys.argv[2], "classes.dex")
EOF

"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
"$BT/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android \
    --key-pass pass:android --ks-key-alias androiddebugkey \
    --out "$OUT/akprobe.apk" "$OUT/aligned.apk"
echo "$OUT/akprobe.apk"
