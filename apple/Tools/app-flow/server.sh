#!/bin/zsh
S=${BISEL_FLOW_DIR:-/tmp/bisel-flow}
ROOT=${BISEL_ROOT:-$HOME/Workspace/Product/bisel}
cd $ROOT/server
exec pnpm exec wrangler dev --port 8790 --persist-to $S/server-state
