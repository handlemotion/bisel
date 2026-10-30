#!/usr/bin/env bash
# Builds the Mac app in Release (project.yml, no SoftwareKeys trait) and fails if any BISEL_DEV_ string is in the shipped bundle.
# Debug-only hooks (BISEL_DEV_FLOW, BISEL_DEV_FIXTURE, BISEL_DEV_STEP, ...) are read from the environment inside #if DEBUG /
# #if BISEL_DEV_FIXTURE; in Release they must be compiled out, or anyone who can set the app's environment could drive it.
#
#   scripts/check-release-hooks.sh              build Release, then check
#   scripts/check-release-hooks.sh --no-build   check the bundle from the last build
#   scripts/check-release-hooks.sh --control    also build Debug and require the strings THERE (proves the grep can see them)
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLE="$ROOT/apps/mac"
BUILD=1 CONTROL=0
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --control)  CONTROL=1 ;;
    -h|--help)  sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 64 ;;
  esac
done

# Matches in every Mach-O file of the bundle (main executable, frameworks, dylibs), printed one per line as file:string.
scan() {
  local app="$1" file names hits=0
  while IFS= read -r file; do
    names="$(strings -a "$file" 2>/dev/null | grep -o 'BISEL_DEV_[A-Z0-9_]*' | sort -u)"
    if [[ -n "$names" ]]; then echo "$names" | sed "s|^|${file#$app/}: |"; hits=1; fi
  done < <(find "$app" -type f \( -perm -u+x -o -name '*.dylib' \) -exec sh -c 'file -b "$1" | grep -q Mach-O && echo "$1"' _ {} \;)
  return $((hits == 0))   # 0 (success) when something was found
}

build() {  # build <spec> <project> <configuration> <derived data dir>
  ( cd "$APPLE" && xcodegen generate --spec "$1" >/dev/null && \
    xcodebuild -project "$2" -scheme Bisel -configuration "$3" -destination 'platform=macOS' -derivedDataPath "$4" \
      CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= build >"$4.log" 2>&1 ) \
    || { echo "FAIL: $3 build failed, see $4.log" >&2; tail -n 20 "$4.log" >&2; exit 2; }
}

REL_DD="$APPLE/build-release"
REL_APP="$REL_DD/Build/Products/Release/Bisel.app"
if (( BUILD )); then
  echo "building Release (project.yml)..."
  build project.yml Bisel.xcodeproj Release "$REL_DD"
fi
[[ -d "$REL_APP" ]] || { echo "FAIL: $REL_APP not found" >&2; exit 2; }

# A vacuous pass is the failure mode of a grep: make sure the scan sees strings in this binary at all.
EXE="$REL_APP/Contents/MacOS/Bisel"
if [[ "$(strings -a "$EXE" | grep -c 'box.bisel.app')" == 0 ]]; then
  echo "FAIL: control string box.bisel.app not found in $EXE; strings output is not usable" >&2; exit 2
fi

if (( CONTROL )); then
  echo "building Debug control (project.dev.yml)..."
  DBG_DD="$APPLE/build-release-control"
  build project.dev.yml BiselDev.xcodeproj Debug "$DBG_DD"
  if scan "$DBG_DD/Build/Products/Debug/Bisel.app" >/dev/null; then echo "control ok: Debug build contains BISEL_DEV_ strings"
  else echo "FAIL: control Debug build has no BISEL_DEV_ strings, so this check proves nothing" >&2; exit 2; fi
fi

if found="$(scan "$REL_APP")"; then
  echo "FAIL: BISEL_DEV_ strings in the Release build:" >&2
  echo "$found" | sed 's/^/  /' >&2
  exit 1
fi
echo "PASS: no BISEL_DEV_ strings in $REL_APP"
