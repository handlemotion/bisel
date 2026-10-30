#!/usr/bin/env bash
# One command to verify everything that can be verified without touching production.
#
#   scripts/check-all.sh                 server + core + app
#   scripts/check-all.sh --server        pnpm install, typecheck (server + dashboard), pnpm test, pnpm test:legacy
#   scripts/check-all.sh --core          BiselCore Swift flow suite (swift test --traits SoftwareKeys)
#   scripts/check-all.sh --app           xcodegen (project.dev.yml) + build of the Mac app, Debug, software keys, + compile (no run) of the UI tests
#   scripts/check-all.sh --ui            RUNS the XCUITest flow (launches the app and drives the screen): never in the default run, only when asked
#   scripts/check-all.sh --release       Release build + BISEL_DEV_ strings check (scripts/check-release-hooks.sh); slow, opt-in
#   scripts/check-all.sh -v              stream every step's output instead of showing the tail of a failed one
#
# Flags combine (--server --core). Needs only tracked files: server/.dev.vars is created from the example when missing.
# Local only: wrangler dev with a throwaway D1 on localhost; no Cloudflare login, no Doppler, no deploy command.
# Every step runs in its own process group, which is killed when the step ends and on Ctrl-C, so no dev server outlives the script.
# pnpm test needs :8788 free (the Swift flow tests pick random free ports).
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGS="$(mktemp -d "${TMPDIR:-/tmp}/bisel-check.XXXXXX")"
RUN_SERVER=0 RUN_CORE=0 RUN_APP=0 RUN_UI=0 RUN_RELEASE=0 VERBOSE=0

for arg in "$@"; do
  case "$arg" in
    --server)  RUN_SERVER=1 ;;
    --core)    RUN_CORE=1 ;;
    --app)     RUN_APP=1 ;;
    --ui)      RUN_UI=1 ;;
    --release) RUN_RELEASE=1 ;;
    -v|--verbose) VERBOSE=1 ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)" >&2; exit 64 ;;
  esac
done
if (( RUN_SERVER + RUN_CORE + RUN_APP + RUN_UI + RUN_RELEASE == 0 )); then RUN_SERVER=1 RUN_CORE=1 RUN_APP=1; fi

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
  printf '  %-44s' "$name"
  [[ $VERBOSE == 1 ]] && echo
  if [[ $VERBOSE == 1 ]]; then
    perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' "$@" > >(tee "$log") 2>&1 &
  else
    perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' "$@" >"$log" 2>&1 &
  fi
  CHILD=$!
  wait "$CHILD"; rc=$?
  kill_group
  local took=$((SECONDS - start))
  NAMES+=("$name"); TIMES+=("$took")
  if (( rc == 0 )); then
    RESULTS+=("PASS"); [[ $VERBOSE == 1 ]] || echo "PASS  ${took}s"
  else
    RESULTS+=("FAIL"); [[ $VERBOSE == 1 ]] || echo "FAIL  ${took}s"
    if [[ $VERBOSE != 1 ]]; then echo "    ---- last lines of $log"; tail -n 25 "$log" | sed 's/^/    | /'; fi
  fi
  return $rc
}

# Fails the step when something is already listening where a test server is about to start.
port_free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
leftovers() {
  if ! port_free 8788; then echo "a server is still listening on :8788 after the tests" >&2; return 1; fi
}

echo "bisel check-all  (logs: $LOGS)"
echo

SERVER_OK=1
if (( RUN_SERVER )); then
  echo "server"
  if ! port_free 8788; then
    echo "  :8788 is in use (a leftover wrangler dev?). Stop it and rerun." >&2
    NAMES+=("server: port 8788 free"); RESULTS+=("FAIL"); TIMES+=(0); SERVER_OK=0
  else
    step "server: pnpm install --frozen-lockfile" bash -c "cd '$ROOT/server' && pnpm install --frozen-lockfile" || SERVER_OK=0
    if (( SERVER_OK )); then
      step "server: typecheck (worker + dashboard)" bash -c "cd '$ROOT/server' && pnpm typecheck"
      step "server: pnpm test" bash -c "cd '$ROOT/server' && pnpm test"
      step "server: pnpm test:legacy" bash -c "cd '$ROOT/server' && pnpm test:legacy"
      step "server: no dev server left behind" bash -c "$(declare -f port_free leftovers); leftovers"
    fi
  fi
  echo
fi

if (( RUN_CORE )); then
  echo "core"
  if [[ ! -d "$ROOT/server/node_modules" ]]; then
    # The Swift flow tests start `wrangler dev` from server/; they need the pinned wrangler.
    step "core: pnpm install --frozen-lockfile (server)" bash -c "cd '$ROOT/server' && pnpm install --frozen-lockfile" || true
  fi
  step "core: swift test --traits SoftwareKeys" bash -c "cd '$ROOT/apple/Packages/BiselCore' && swift test --traits SoftwareKeys"
  echo
fi

APP_DD="$ROOT/apple/build-check"
XCB_ARGS="-project BiselDev.xcodeproj -scheme Bisel -destination 'platform=macOS' -derivedDataPath '$APP_DD' CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM="

if (( RUN_APP )); then
  echo "app"
  step "app: xcodegen (project.dev.yml)" bash -c "cd '$ROOT/apple' && xcodegen generate --spec project.dev.yml" \
    && step "app: build BiselDev (Debug)" bash -c "cd '$ROOT/apple' && xcodebuild $XCB_ARGS -configuration Debug build" \
    && step "app: compile UI tests (not run)" bash -c "cd '$ROOT/apple' && xcodebuild $XCB_ARGS -configuration Debug build-for-testing"
  echo
fi

if (( RUN_UI )); then
  echo "ui  (launches the app and drives the screen: leave the Mac alone until it ends)"
  step "ui: xcodegen (project.dev.yml)" bash -c "cd '$ROOT/apple' && xcodegen generate --spec project.dev.yml" \
    && step "ui: BiselFlowUITests" bash -c "cd '$ROOT/apple' && xcodebuild $XCB_ARGS -configuration Debug -only-testing:BiselUITests test"
  echo
fi

if (( RUN_RELEASE )); then
  echo "release"
  step "release: no BISEL_DEV_ hooks in the binary" "$ROOT/scripts/check-release-hooks.sh"
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
