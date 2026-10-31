#!/usr/bin/env bash
# One command to verify everything that can be verified without touching production.
# CI (.github/workflows/ci.yml) runs one mode per job; `pnpm ci:local` runs all of them, so a green local run is a green CI run.
#
#   scripts/check-all.sh                 server + core + app
#   scripts/check-all.sh --server        pnpm install, format + lint, typecheck, pnpm test, test:legacy
#   scripts/check-all.sh --core          BiselCore Swift flow suite (swift test --traits SoftwareKeys)
#   scripts/check-all.sh --app           xcodegen (project.dev.yml) + unsigned Debug build of the Mac app (software keys), + compile (never run) of the UI test sources
#   scripts/check-all.sh --release       Release build + BISEL_DEV_ strings check (scripts/check-release-hooks.sh), signing config lint; slow, opt-in
#   scripts/check-all.sh -v              stream every step's output instead of showing the tail of a failed one
#
# Flags combine (--server --core). Needs only tracked files: apps/server/.dev.vars is created from the example when missing.
# Local only: wrangler dev with a throwaway D1 on localhost; no Cloudflare login, no Doppler, no deploy command.
# Every step runs in its own process group, which is killed when the step ends and on Ctrl-C, so no dev server outlives the script.
# The server tests and the Swift flow tests each start their own wrangler dev on random free ports.
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGS="$(mktemp -d "${TMPDIR:-/tmp}/bisel-check.XXXXXX")"
RUN_SERVER=0 RUN_CORE=0 RUN_APP=0 RUN_RELEASE=0 VERBOSE=0

for arg in "$@"; do
  case "$arg" in
    --server)  RUN_SERVER=1 ;;
    --core)    RUN_CORE=1 ;;
    --app)     RUN_APP=1 ;;
    --release) RUN_RELEASE=1 ;;
    -v|--verbose) VERBOSE=1 ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)" >&2; exit 64 ;;
  esac
done
if (( RUN_SERVER + RUN_CORE + RUN_APP + RUN_RELEASE == 0 )); then RUN_SERVER=1 RUN_CORE=1 RUN_APP=1; fi

NAMES=() RESULTS=() TIMES=()
CHILD=0

kill_group() {
  (( CHILD > 0 )) || return 0
  kill -TERM -- "-$CHILD" 2>/dev/null
  sleep 0.3
  kill -KILL -- "-$CHILD" 2>/dev/null
  CHILD=0
}
cleanup() { kill_group; }
trap cleanup EXIT
trap 'echo; echo "interrupted"; exit 130' INT TERM

# step <name> <command...>: runs in a new session so the whole tree (pnpm, node, workerd, xcodebuild) can be taken down.
step() {
  local name="$1"; shift
  local log="$LOGS/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '-').log"
  local start=$SECONDS rc
  if [[ ${GITHUB_ACTIONS:-} == true ]]; then echo "::group::$name"; else printf '  %-44s' "$name"; fi
  [[ $VERBOSE == 1 && ${GITHUB_ACTIONS:-} != true ]] && echo
  if [[ $VERBOSE == 1 ]]; then
    perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' "$@" > >(tee "$log") 2>&1 &
  else
    perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' "$@" >"$log" 2>&1 &
  fi
  CHILD=$!
  wait "$CHILD"; rc=$?
  kill_group
  [[ ${GITHUB_ACTIONS:-} == true ]] && echo "::endgroup::"
  local took=$((SECONDS - start))
  NAMES+=("$name"); TIMES+=("$took")
  if (( rc == 0 )); then
    RESULTS+=("PASS"); [[ $VERBOSE == 1 ]] || echo "PASS  ${took}s"
  else
    RESULTS+=("FAIL"); [[ $VERBOSE == 1 ]] || echo "FAIL  ${took}s"
    [[ ${GITHUB_ACTIONS:-} == true ]] && echo "::error::$name failed after ${took}s"
    if [[ $VERBOSE != 1 ]]; then echo "    ---- last lines of $log"; tail -n 25 "$log" | sed 's/^/    | /'; fi
  fi
  return $rc
}

echo "bisel check-all  (logs: $LOGS)"
echo

SERVER_OK=1
if (( RUN_SERVER )); then
  echo "server"
  step "server: pnpm install --frozen-lockfile" bash -c "cd '$ROOT' && pnpm install --frozen-lockfile" || SERVER_OK=0
  if (( SERVER_OK )); then
    step "server: format + lint (pnpm check)" bash -c "cd '$ROOT' && pnpm check"
    step "server: typecheck (pnpm check-types)" bash -c "cd '$ROOT' && pnpm check-types"
    step "server: build + flow tests (pnpm test)" bash -c "cd '$ROOT' && pnpm test"
    step "server: migration test (test:legacy)" bash -c "cd '$ROOT/apps/server' && pnpm test:legacy"
  fi
  echo
fi

if (( RUN_CORE )); then
  echo "core"
  if [[ ! -d "$ROOT/node_modules" ]]; then
    # The Swift flow tests start `wrangler dev` from server/; they need the pinned wrangler.
    step "core: pnpm install --frozen-lockfile (server)" bash -c "cd '$ROOT' && pnpm install --frozen-lockfile" || true
  fi
  step "core: swift test --traits SoftwareKeys" bash -c "cd '$ROOT/apps/mac/Packages/BiselCore' && swift test --traits SoftwareKeys"
  echo
fi

APP_DD="$ROOT/apps/mac/build-check"
# Unsigned: this build only proves the app compiles; CI has no signing identity and needs none.
XCB_BASE="-project BiselDev.xcodeproj -scheme Bisel -destination 'platform=macOS' -derivedDataPath '$APP_DD'"
XCB_ARGS="$XCB_BASE CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO"

if (( RUN_APP )); then
  echo "app"
  step "app: xcodegen (project.dev.yml)" bash -c "cd '$ROOT/apps/mac' && xcodegen generate --spec project.dev.yml" \
    && step "app: build BiselDev (Debug)" bash -c "cd '$ROOT/apps/mac' && xcodebuild $XCB_ARGS -configuration Debug build" \
    && step "app: compile UI tests (not run)" bash -c "cd '$ROOT/apps/mac' && xcodebuild $XCB_ARGS -configuration Debug build-for-testing"
  echo
fi

if (( RUN_RELEASE )); then
  echo "release"
  step "release: no BISEL_DEV_ hooks in the binary" "$ROOT/scripts/check-release-hooks.sh"
  # Offline: the Developer ID plists parse, the release scripts parse, and the CloudKit schema (once exported) has R's fields and no index.
  step "release: signing config + CloudKit schema" bash -c "cd '$ROOT/apps/mac' && plutil -lint Tools/ExportOptions.plist Bisel/Bisel.entitlements \
    && bash -n Tools/release.sh && bash -n Tools/cloudkit-schema.sh \
    && if [[ -f CloudKit/schema.ckdb ]]; then Tools/cloudkit-schema.sh lint; else echo 'no CloudKit/schema.ckdb yet (RELEASE.md, step 5)'; fi"
  echo
fi

echo "summary"
FAILED=0
for i in "${!NAMES[@]}"; do
  printf '  %-4s %-48s %4ss\n' "${RESULTS[$i]}" "${NAMES[$i]}" "${TIMES[$i]}"
  [[ ${RESULTS[$i]} == FAIL ]] && FAILED=1
done
echo
if (( FAILED )); then echo "RESULT: FAIL  (logs: $LOGS)"; exit 1; fi
echo "RESULT: PASS"
rm -rf "$LOGS"
