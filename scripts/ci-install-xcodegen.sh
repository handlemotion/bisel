#!/usr/bin/env bash
# CI only: installs a pinned XcodeGen release after checking its SHA-256 (the runner image does not ship XcodeGen).
#
#   scripts/ci-install-xcodegen.sh <version> <sha256 of xcodegen.zip>
set -euo pipefail

VERSION="$1" SHA256="$2"
DEST="${RUNNER_TEMP:-$(mktemp -d)}/xcodegen-$VERSION"
mkdir -p "$DEST"
curl -fsSL --retry 3 -o "$DEST/xcodegen.zip" "https://github.com/yonaskolb/XcodeGen/releases/download/$VERSION/xcodegen.zip"
echo "$SHA256  $DEST/xcodegen.zip" | shasum -a 256 -c -
unzip -q "$DEST/xcodegen.zip" -d "$DEST"
"$DEST/xcodegen/bin/xcodegen" --version
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$DEST/xcodegen/bin" >> "$GITHUB_PATH"; fi
