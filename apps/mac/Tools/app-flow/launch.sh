#!/bin/zsh
# launch.sh <datadir> [extra env k=v ...] -> starts MY Debug build with a throwaway store; prints pid
S=${BISEL_FLOW_DIR:-/tmp/bisel-flow}
D=$1; shift
mkdir -p $D
env BISEL_DATA_DIR=$D BISEL_DEV_SKIP_BIOMETRIC=1 "$@" nohup $S/dd/Build/Products/Debug/Bisel.app/Contents/MacOS/Bisel ${=BISEL_ARGS} >> $S/app.log 2>&1 &
sleep 3
pgrep -f "$S/dd/Build/Products/Debug/Bisel.app/Contents/MacOS/Bisel"
