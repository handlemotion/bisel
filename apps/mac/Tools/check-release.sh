#!/bin/bash
# Release gate on a built app: fails if it carries get-task-allow, software keys, the fixture or debug hooks.
# usage: apps/mac/Tools/check-release.sh path/to/Bisel.app
set -e
APP=${1:?usage: check-release.sh Bisel.app}
BIN="$APP/Contents/MacOS/Bisel"
if codesign -d --entitlements - "$APP" 2>&1 | grep -q get-task-allow; then echo "FAIL get-task-allow present"; exit 1; fi
for pat in SoftwareDeviceKeyStore software-keys.json BISEL_SOFTWARE_KEYS NOT-A-REAL-PASSWORD "DEV FIXTURE" BISEL_DEV_ BISEL_DATA_DIR; do
  if strings -a "$BIN" | grep -q -- "$pat"; then echo "FAIL binary contains $pat"; exit 1; fi
done
# The agent CLI ships inside the app. It must carry no debug skip, and no keys or crypto: only BiselAgent (docs/AGENT-CLI.md).
TOOL="$APP/Contents/Helpers/bisel"
[ -x "$TOOL" ] || { echo "FAIL no agent tool at $TOOL"; exit 1; }
if codesign -d --entitlements - "$TOOL" 2>&1 | grep -q get-task-allow; then echo "FAIL get-task-allow on the agent tool"; exit 1; fi
for pat in BISEL_DEV_ BISEL_SOFTWARE_KEYS GRDB ItemSealer SecureEnclave VaultKeys; do
  if strings -a "$TOOL" | grep -q -- "$pat"; then echo "FAIL agent tool contains $pat"; exit 1; fi
done
echo "OK: no get-task-allow, no software keys, no fixture/debug hooks in $APP"
