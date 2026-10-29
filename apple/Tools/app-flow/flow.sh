#!/bin/zsh
# Full headless flow against the real local server.
S=${BISEL_FLOW_DIR:-/tmp/bisel-flow}
pkill -f "$S/dd/Build/Products/Debug/Bisel.app"
$S/resetserver.sh
setopt nonomatch; rm -rf $S/dataA $S/dataB $S/dataC $S/dataD $S/dataE $S/phrase.txt $S/backup1.bisel-backup; rm -f $S/flow-*.log
n=0
run() { # phase dir [extra env]
  n=$((n+1)); local log=$S/flow-$n-$1.log; local phase=$1 dir=$2; shift 2
  $S/tools/launch.sh $dir BISEL_DEV_FLOW=$phase BISEL_DEV_FLOW_LOG=$log BISEL_DEV_PHRASE_FILE=$S/phrase.txt BISEL_DEV_1PUX=$S/fixtures/fake-export.1pux BISEL_DEV_CSV=$S/fixtures/fake-logins.csv BISEL_DEV_EXPORT_PATH=$S/backup1.bisel-backup BISEL_DEV_FIXTURES=$S/fixtures "$@" > /dev/null
  for i in {1..60}; do [ -s $log ] && break; sleep 1; done
  echo "== $phase ($(grep -c '^PASS' $log) pass, $(grep -c '^FAIL' $log) fail)"; grep '^FAIL' $log; sleep 2; pkill -f "$S/dd/Build/Products/Debug/Bisel.app"
}
run create $S/dataA
run recover $S/dataB BISEL_DEV_KEEP_A=1
run localedit $S/dataA
run remoteedit $S/dataB
run resolve $S/dataA
$S/stopserver.sh
run offline $S/dataB
$S/startserver.sh
run online $S/dataB
run revokeother $S/dataB
run revoked $S/dataA
$S/resetserver.sh > /dev/null
run restore $S/dataC
BISEL_ARGS='-security.requireTouchIDForSecrets YES' run strict $S/dataC
$S/resetserver.sh > /dev/null
run bootstraponly $S/dataD
run unconfirmed $S/dataD
run security $S/dataE
