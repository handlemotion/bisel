#!/bin/bash
# Release gate on a built app: fails if it carries get-task-allow, software keys, the fixture or debug hooks.
# usage: apple/Tools/check-release.sh path/to/Bisel.app
set -e
APP=${1:?usage: check-release.sh Bisel.app}
BIN="$APP/Contents/MacOS/Bisel"
if codesign -d --entitlements - "$APP" 2>&1 | grep -q get-task-allow; then echo "FAIL get-task-allow present"; exit 1; fi
for pat in SoftwareDeviceKeyStore software-keys.json BISEL_SOFTWARE_KEYS NOT-A-REAL-PASSWORD "DEV FIXTURE" BISEL_DEV_ BISEL_DATA_DIR; do
  if strings -a "$BIN" | grep -q -- "$pat"; then echo "FAIL binary contains $pat"; exit 1; fi
done
echo "OK: no get-task-allow, no software keys, no fixture/debug hooks in $APP"
