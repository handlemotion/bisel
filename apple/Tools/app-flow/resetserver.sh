#!/bin/zsh
ROOT=${BISEL_ROOT:-$HOME/Workspace/Product/bisel}
# fresh, un-bootstrapped local server on :8790
S=${BISEL_FLOW_DIR:-/tmp/bisel-flow}
pkill -f "wrangler dev --port 8790" ; pkill -f "workerd.*8790"; sleep 2
rm -rf $S/server-state; mkdir -p $S/server-state
cd $ROOT/server && pnpm exec wrangler d1 migrations apply bisel --local --persist-to $S/server-state > /dev/null 2>&1
nohup $S/server.sh > $S/server.log 2>&1 &
for i in {1..30}; do curl -s -o /dev/null http://localhost:8790/x && break; sleep 1; done
echo "server reset"
