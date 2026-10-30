#!/bin/zsh
# Prepares a flow directory: builds the helper tools, fixtures and the Debug app into $BISEL_FLOW_DIR (default /tmp/bisel-flow).
set -e
S=${BISEL_FLOW_DIR:-/tmp/bisel-flow}; H=$(cd "$(dirname "$0")" && pwd); APPLE=$(cd "$H/../.." && pwd)
mkdir -p $S/tools $S/fixtures
cp $H/*.sh $S/ ; cp $H/launch.sh $S/tools/ ; rm -f $S/setup.sh
swiftc -O $H/postnote.swift -o $S/tools/postnote
swiftc -O $H/axdrive.swift -o $S/tools/axdrive
python3 $H/make_fixtures.py $S/fixtures
(cd $APPLE && xcodegen generate --spec project.dev.yml >/dev/null && xcodebuild -project BiselDev.xcodeproj -scheme Bisel -configuration Debug -derivedDataPath $S/dd build | tail -1)
echo "ready: BISEL_FLOW_DIR=$S $S/flow.sh"
