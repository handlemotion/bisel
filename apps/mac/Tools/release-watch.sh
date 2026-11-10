#!/usr/bin/env bash
# Ships a release on its own once the release-please PR is merged. release-please leaves a draft GitHub release with no assets;
# this builds that tag with release.sh (signing, notarization and the Sparkle key stay in this Mac's keychain, never in CI) and
# publishes it with release.sh --publish. A launchd agent runs it every 10 minutes (and when the Mac wakes), so a merge made while
# the Mac was off or asleep ships as soon as it is back.
#
#   apps/mac/Tools/release-watch.sh --install     copy this script to ~/Library/Application Support/Bisel and load the launchd agent
#   apps/mac/Tools/release-watch.sh --uninstall   unload the agent and remove it
#   apps/mac/Tools/release-watch.sh --once        look once, ship the newest draft that has no assets (what the agent runs)
#
# A failed build is not retried for an hour; the log is ~/Library/Logs/Bisel/release-watch.log and a notification says which tag.
# To retry now: rm ~/Library/Caches/Bisel/release-watch/failed-<tag>.
set -euo pipefail

REPO=handlemotion/bisel
LABEL=app.bisel.release-watch
SUPPORT="$HOME/Library/Application Support/Bisel"
STATE="$HOME/Library/Caches/Bisel/release-watch"
LOGS="$HOME/Library/Logs/Bisel"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
RETRY_AFTER_MIN=60

case "${1:---once}" in
  --install)
    mkdir -p "$SUPPORT" "$LOGS" "$(dirname "$PLIST")"
    cp "${BASH_SOURCE[0]}" "$SUPPORT/release-watch.sh"; chmod +x "$SUPPORT/release-watch.sh"
    cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$SUPPORT/release-watch.sh</string><string>--once</string></array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StartInterval</key><integer>600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$LOGS/release-watch.log</string>
  <key>StandardErrorPath</key><string>$LOGS/release-watch.log</string>
</dict></plist>
EOF
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
    echo "installed: checks $REPO every 10 minutes. Log: $LOGS/release-watch.log"
    exit 0 ;;
  --uninstall)
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST" "$SUPPORT/release-watch.sh"
    echo "uninstalled"
    exit 0 ;;
  --once) ;;
  *) echo "usage: release-watch.sh --install | --uninstall | --once" >&2; exit 64 ;;
esac

mkdir -p "$STATE" "$LOGS"
log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
notify() { osascript -e "display notification \"$1\" with title \"Bisel release\"" >/dev/null 2>&1 || true; }

# One run at a time (a build takes many minutes and the agent fires every ten).
LOCK="$STATE/lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  if [[ -f "$LOCK/pid" ]] && kill -0 "$(cat "$LOCK/pid")" 2>/dev/null; then exit 0; fi
  rm -rf "$LOCK"; mkdir "$LOCK"
fi
echo $$ >"$LOCK/pid"
trap 'rm -rf "$LOCK"' EXIT

command -v gh >/dev/null || { log "gh not found"; exit 1; }
# Drafts with no assets, newest first. A draft that already has assets is a build someone is publishing by hand.
tag="$(gh release list -R "$REPO" --exclude-pre-releases --limit 10 --json tagName,isDraft \
  --jq '[.[] | select(.isDraft)] | .[].tagName' 2>/dev/null | while read -r t; do
    n="$(gh release view "$t" -R "$REPO" --json assets --jq '.assets | length' 2>/dev/null || echo 1)"
    [[ "$n" == 0 ]] && { echo "$t"; break; }
  done || true)"
[[ -n "$tag" ]] || exit 0

failed="$STATE/failed-$tag"
if [[ -f "$failed" && -z "$(find "$failed" -mmin +"$RETRY_AFTER_MIN" 2>/dev/null)" ]]; then exit 0; fi
rm -f "$failed"

log "shipping $tag"
CLONE="$STATE/repo"
# An && chain, not set -e: errexit is off inside an `if` condition.
if ! {
  { [[ -d "$CLONE/.git" ]] || gh repo clone "$REPO" "$CLONE" -- --quiet; } &&
  git -C "$CLONE" fetch --quiet --force --tags origin &&
  git -C "$CLONE" rev-parse --verify --quiet "$tag^{commit}" >/dev/null &&
  git -C "$CLONE" checkout --quiet --detach --force "$tag" &&
  git -C "$CLONE" clean -fdxq &&
  "$CLONE/apps/mac/Tools/release.sh" &&
  "$CLONE/apps/mac/Tools/release.sh" --publish "$tag"
}; then
  touch "$failed"
  log "FAILED $tag (no retry for ${RETRY_AFTER_MIN} min)"
  notify "$tag did not ship. See ~/Library/Logs/Bisel/release-watch.log"
  exit 1
fi
log "published $tag"
notify "$tag is published."
