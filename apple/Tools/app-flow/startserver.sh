#!/bin/zsh
S=${BISEL_FLOW_DIR:-/tmp/bisel-flow}
nohup $S/server.sh > $S/server.log 2>&1 &
for i in {1..30}; do curl -s -o /dev/null http://localhost:8790/x && break; sleep 1; done; echo started
