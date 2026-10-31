#!/usr/bin/env bash
# The lane contract on real CloudKit (Development environment): opt-in, manual, never CI (docs/SYNC-LANES.md §10, L3).
# Builds the SIGNED Debug app from project.contract.yml into a scratch DerivedData path, runs its executable once with
# BISEL_DEV_LANE_CONTRACT=cloudkit and prints the log. It only ever touches throwaway stores in a temp dir and zones named
# bisel-l3-spike-*, which it deletes at the end. Never installs anything, never opens /Applications/Bisel.app or its data.
#
# Needs: Xcode signed in to team ZVGTVNUPVA, this Mac registered (docs/SYNC-LANES.md §3, entitlement spike), an iCloud
# account signed in on this Mac.
#
#   apps/mac/Tools/run-cloudkit-contract.sh [scratch dir]            all flows
#   BISEL_DEV_LANE_CONTRACT_ONLY="conflict" apps/mac/Tools/run-cloudkit-contract.sh   flows whose name contains that
set -euo pipefail

APPLE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${1:-${TMPDIR:-/tmp}/bisel-cloudkit-contract}"
mkdir -p "$SCRATCH/data"

cd "$APPLE"
xcodegen generate --spec project.contract.yml >/dev/null
xcodebuild -project BiselLaneContract.xcodeproj -scheme Bisel -configuration Debug -destination 'platform=macOS' \
  -derivedDataPath "$SCRATCH/dd" -allowProvisioningUpdates build >"$SCRATCH/build.log" 2>&1 \
  || { echo "build failed, see $SCRATCH/build.log" >&2; grep -E "error:" "$SCRATCH/build.log" | head -20 >&2; exit 2; }

APP="$SCRATCH/dd/Build/Products/Debug/Bisel.app"
codesign --display --entitlements - "$APP" 2>/dev/null | grep -q "iCloud.app.bisel" \
  || { echo "the built app does not carry the iCloud container entitlement" >&2; exit 2; }

# BISEL_DATA_DIR: belt and braces. The contract run never creates AppModel/VaultService, but if it ever did, the store
# would be a throwaway one, not the real box.
set +e
BISEL_DEV_LANE_CONTRACT=cloudkit BISEL_DEV_LANE_CONTRACT_LOG="$SCRATCH/contract.log" BISEL_DATA_DIR="$SCRATCH/data" \
  BISEL_DEV_LANE_CONTRACT_ONLY="${BISEL_DEV_LANE_CONTRACT_ONLY:-}" \
  "$APP/Contents/MacOS/Bisel" >"$SCRATCH/stdout.log" 2>"$SCRATCH/stderr.log"
status=$?
set -e
cat "$SCRATCH/contract.log" 2>/dev/null || cat "$SCRATCH/stdout.log"
echo "exit $status (logs in $SCRATCH)"
exit $status
