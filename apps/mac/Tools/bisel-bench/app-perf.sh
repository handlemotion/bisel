#!/bin/zsh
# app-perf.sh <box-dir> <out.json> [build-dir]: ONE launch of an optimized Debug build (software keys) on a throwaway copy of a box
# seeded by bisel-bench. PanelBoxPerf measures launch, panel and settings inside that launch, writes the medians and quits.
# Never loop this: AGENTS.md forbids app launch loops. Build first with `app-perf.sh --build [build-dir]`.
set -eu
ROOT=${0:A:h:h:h}
if [[ ${1:-} == --build ]]; then
  BUILD=${2:?build dir}
  cd $ROOT
  xcodegen generate --spec project.dev.yml >/dev/null
  xcodebuild -project BiselDev.xcodeproj -scheme Bisel -configuration Debug -derivedDataPath $BUILD \
    CODE_SIGNING_ALLOWED=NO SWIFT_OPTIMIZATION_LEVEL=-O SWIFT_COMPILATION_MODE=wholemodule build 2>&1 | grep -E "error:|\*\* BUILD" | sort -u
  exit 0
fi
BOX=${1:?box dir}; OUT=${2:?out.json}; BUILD=${3:-$ROOT/build-perf}
RUN=$(mktemp -d "${TMPDIR:-/tmp}/bisel-perf.XXXXXX")
cp -R $BOX/ $RUN/box
trap 'rm -rf $RUN' EXIT
# BISEL_DEV_FLOW with no log only turns the global hotkey off, so this run and the installed app do not fight over it.
# Icons off: the fake sites of a seeded box must never reach the network.
env BISEL_DATA_DIR=$RUN/box BISEL_DEV_SKIP_BIOMETRIC=1 BISEL_DEV_AUTOUNLOCK=1 BISEL_DEV_FLOW=perf BISEL_DEV_NOHOVER=1 BISEL_DEV_STICKY=1 \
    BISEL_DEV_PANEL_PERF=box BISEL_DEV_PERF_OUT=$OUT \
    $BUILD/Build/Products/Debug/Bisel.app/Contents/MacOS/Bisel -icons.enabled NO 2>/dev/null &
PID=$!
for i in {1..600}; do kill -0 $PID 2>/dev/null || break; sleep 0.1; done
kill $PID 2>/dev/null || true
test -f $OUT && cat $OUT
