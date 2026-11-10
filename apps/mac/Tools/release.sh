#!/usr/bin/env bash
# Builds the Developer ID release of Bisel: archive (project.yml, Release), export with Developer ID (Tools/ExportOptions.plist),
# notarize, staple, verify, package, then sign the package for Sparkle and write its appcast.xml. The one-time setup it needs
# (certificate, provisioning profile, notary credentials, Sparkle key) is in apps/mac/RELEASE.md; every check below fails with the
# step to take instead of a signing error halfway through.
#
#   apps/mac/Tools/release.sh                  DMG (signed, notarized, stapled) + appcast.xml in apps/mac/build-dist/
#   apps/mac/Tools/release.sh --zip            zip of the stapled app instead of a DMG
#   apps/mac/Tools/release.sh --preflight      only check the certificate, the profile, the notary profile and the Sparkle key
#   apps/mac/Tools/release.sh --allow-dirty    build from a working tree with uncommitted changes (never for a real release)
#   apps/mac/Tools/release.sh --publish vX.Y.Z attach the last build (package, SHA-256, appcast.xml) to that GitHub release, then publish it
#
# Environment: BISEL_NOTARY_PROFILE (default bisel-notary), the name given to `xcrun notarytool store-credentials`;
# BISEL_SPARKLE_ACCOUNT (default bisel), the keychain account `generate_keys --account` stored the update-signing key under.
# No password, key or token is read from the repo or the command line: notarytool and Sparkle take theirs from the keychain.
# Local only. CI builds Release unsigned (scripts/check-release-hooks.sh) and has no signing identity.
set -euo pipefail

TEAM=ZVGTVNUPVA
BUNDLE_ID=app.bisel.mac
CONTAINER=iCloud.app.bisel
PROFILE_NAME="Bisel Developer ID"   # PROVISIONING_PROFILE_SPECIFIER in project.yml and provisioningProfiles in ExportOptions.plist
AUTOFILL_ID=app.bisel.mac.autofill
AUTOFILL_PROFILE_NAME="Bisel AutoFill Developer ID"   # the same two places, for the extension
AUTOFILL_ENTITLEMENT=com.apple.developer.authentication-services.autofill-credential-provider
APP_GROUP="$TEAM.app.bisel"   # AutoFillSocket.appGroup
NOTARY_PROFILE="${BISEL_NOTARY_PROFILE:-bisel-notary}"
SPARKLE_ACCOUNT="${BISEL_SPARKLE_ACCOUNT:-bisel}"
REPO=handlemotion/bisel   # SUFeedURL in project.yml reads releases/latest/download/appcast.xml from it

APPLE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$APPLE/../.." && pwd)"
OUT="$APPLE/build-dist"
FORMAT=dmg PREFLIGHT=0 ALLOW_DIRTY=0 PUBLISH=""
while (( $# )); do
  case "$1" in
    --zip) FORMAT=zip ;;
    --dmg) FORMAT=dmg ;;
    --preflight) PREFLIGHT=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --publish) PUBLISH="${2:?--publish needs a tag, e.g. --publish v0.1.2}"; shift ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1 (try --help)" >&2; exit 64 ;;
  esac
  shift
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nrelease: %s\n' "$*" >&2; exit 1; }

# Sparkle's command-line tools ship in the package the archive resolved (project.yml pins the version).
SPARKLE_BIN="$OUT/dd/SourcePackages/artifacts/sparkle/Sparkle/bin"

# MARK: publish (the last build, no rebuild)

# Attaches what the last full run left in build-dist/ to the draft release that release-please made for <tag>, then publishes it.
# Refuses a build from another commit or version, an appcast whose signature does not verify, and a release that already has the assets.
if [[ -n "$PUBLISH" ]]; then
  say "publish $PUBLISH"
  command -v gh >/dev/null || die "gh not found."
  [[ -f "$OUT/appcast.xml" && -f "$OUT/build-info" ]] || die "no finished build in $OUT. Run apps/mac/Tools/release.sh first."
  # shellcheck source=/dev/null
  source "$OUT/build-info"   # VERSION, BUILD, COMMIT, ARTIFACT (written at the end of a full run)
  [[ "$PUBLISH" == "v$VERSION" ]] || die "the last build is Bisel $VERSION, not $PUBLISH."
  [[ -f "$ARTIFACT" && -f "$ARTIFACT.sha256" ]] || die "$ARTIFACT or its .sha256 is missing; rebuild."
  git -C "$ROOT" fetch --quiet origin "refs/tags/$PUBLISH:refs/tags/$PUBLISH" 2>/dev/null || true
  tagged="$(git -C "$ROOT" rev-parse --verify --quiet "$PUBLISH^{commit}")" || die "tag $PUBLISH not found (merge the release PR first)."
  [[ "$tagged" == "$COMMIT" ]] || die "the last build is from $COMMIT, but $PUBLISH is $tagged. Check out the tag and rebuild."
  grep -q "releases/download/$PUBLISH/$(basename "$ARTIFACT")" "$OUT/appcast.xml" || die "appcast.xml does not point at $PUBLISH."
  "$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$OUT/appcast.xml" >/dev/null || die "appcast.xml's signature does not verify."
  existing="$(gh release view "$PUBLISH" -R "$REPO" --json assets,isDraft,isPrerelease --jq '.assets[].name')" \
    || die "no GitHub release $PUBLISH in $REPO."
  for f in "$(basename "$ARTIFACT")" "$(basename "$ARTIFACT").sha256" appcast.xml; do
    grep -qx "$f" <<<"$existing" && die "release $PUBLISH already has $f. Delete that asset on GitHub first if it is really to be replaced."
  done
  gh release upload "$PUBLISH" -R "$REPO" "$ARTIFACT" "$ARTIFACT.sha256" "$OUT/appcast.xml"
  # Last, so releases/latest (the update feed) only moves once this release has its appcast.xml. Changes nothing on a published release.
  gh release edit "$PUBLISH" -R "$REPO" --draft=false >/dev/null
  [[ "$(gh api "repos/$REPO/releases/latest" --jq .tag_name)" == "$PUBLISH" ]] \
    || echo "warning: releases/latest (the update feed) does not point at $PUBLISH. Is it a pre-release, or is a newer release published?"
  echo "published: https://github.com/$REPO/releases/tag/$PUBLISH"
  exit 0
fi

# MARK: preflight

say "preflight"
for tool in xcodegen xcodebuild xcrun codesign spctl hdiutil ditto security; do
  command -v "$tool" >/dev/null || die "$tool not found."
done

IDENTITY="$(security find-identity -v -p codesigning | sed -nE "s/.*\"(Developer ID Application: .*\($TEAM\))\"$/\1/p" | head -n 1)"
[[ -n "$IDENTITY" ]] || die "no \"Developer ID Application\" certificate for team $TEAM in the keychain.
  Create it once: Xcode > Settings > Accounts > (team $TEAM) > Manage Certificates > + > Developer ID Application.
  See apps/mac/RELEASE.md, step 1."
echo "identity: $IDENTITY"

# The profile Xcode resolves by name. Read each installed profile's plist (security cms only decodes it, nothing is printed).
find_profile() {  # find_profile <name>: sets PROFILE and PROFILE_PLIST
  PROFILE="" PROFILE_PLIST=""
  local dir f plist name
  for dir in "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles" "$HOME/Library/MobileDevice/Provisioning Profiles"; do
    [[ -d "$dir" ]] || continue
    for f in "$dir"/*.provisionprofile; do
      [[ -f "$f" ]] || continue
      plist="$(security cms -D -i "$f" 2>/dev/null)" || continue
      name="$(/usr/libexec/PlistBuddy -c 'Print :Name' /dev/stdin <<<"$plist" 2>/dev/null || true)"
      [[ "$name" == "$1" ]] && { PROFILE="$f"; PROFILE_PLIST="$plist"; return 0; }
    done
  done
}
find_profile "$PROFILE_NAME"
[[ -n "$PROFILE" ]] || die "no provisioning profile named \"$PROFILE_NAME\" is installed.
  Create a Developer ID profile for $BUNDLE_ID with iCloud ($CONTAINER) in the developer portal, name it exactly
  \"$PROFILE_NAME\", then Xcode > Settings > Accounts > Download Manual Profiles. See apps/mac/RELEASE.md, step 2."
pp() { /usr/libexec/PlistBuddy -c "Print :$1" /dev/stdin <<<"$PROFILE_PLIST" 2>/dev/null || true; }
[[ "$(pp 'Entitlements:com.apple.application-identifier')" == "$TEAM.$BUNDLE_ID" ]] \
  || die "profile \"$PROFILE_NAME\" is not for $TEAM.$BUNDLE_ID (RELEASE.md, step 2)."
[[ "$(pp ProvisionsAllDevices)" == "true" ]] \
  || die "profile \"$PROFILE_NAME\" is not a Developer ID profile (it lists devices). Create it with type Developer ID (RELEASE.md, step 2)."
pp 'Entitlements:com.apple.developer.icloud-container-identifiers' | grep -qx "[[:space:]]*$CONTAINER" \
  || die "profile \"$PROFILE_NAME\" has no iCloud container $CONTAINER. Enable iCloud (CloudKit) with that container on the App ID and regenerate the profile (RELEASE.md, step 2)."
pp 'Entitlements:com.apple.developer.icloud-container-environment' | grep -q Production \
  || die "profile \"$PROFILE_NAME\" does not allow the Production CloudKit environment (RELEASE.md, step 2)."
expiry="$(pp ExpirationDate)"
expires_at="$(date -j -f '%a %b %d %T %Z %Y' "$expiry" +%s 2>/dev/null || true)"
if [[ -n "$expires_at" ]] && (( expires_at < $(date +%s) )); then
  die "profile \"$PROFILE_NAME\" expired on $expiry. Regenerate it (RELEASE.md, step 2)."
fi
# Both are checked here because a claim the profile does not authorise is worse than a failed build. The App Group is not restricted,
# so the app would still launch, but with its entitlements unvalidated, and the data protection keychain that holds the device keys
# can stop working. A Mac profile covers the group once App Groups is on the App ID: it lists <team>.*.
check_autofill_profile() {  # check_autofill_profile <profile name>
  [[ "$(pp "Entitlements:$AUTOFILL_ENTITLEMENT")" == "true" ]] \
    || die "profile \"$1\" does not grant AutoFill Credential Provider. Enable it on the App ID and regenerate the profile (RELEASE.md, step 2)."
  pp 'Entitlements:com.apple.security.application-groups' | grep -qE "^[[:space:]]*($TEAM\.\*|$APP_GROUP)$" \
    || die "profile \"$1\" does not authorise App Group $APP_GROUP. Enable App Groups on the App ID and regenerate the profile (RELEASE.md, step 2)."
}
check_autofill_profile "$PROFILE_NAME"
echo "profile:  $PROFILE_NAME (expires $expiry)"

find_profile "$AUTOFILL_PROFILE_NAME"
[[ -n "$PROFILE" ]] || die "no provisioning profile named \"$AUTOFILL_PROFILE_NAME\" is installed.
  Create a Developer ID profile for $AUTOFILL_ID, name it exactly that, then download it. See apps/mac/RELEASE.md, step 2."
[[ "$(pp 'Entitlements:com.apple.application-identifier')" == "$TEAM.$AUTOFILL_ID" ]] \
  || die "profile \"$AUTOFILL_PROFILE_NAME\" is not for $TEAM.$AUTOFILL_ID (RELEASE.md, step 2)."
[[ "$(pp ProvisionsAllDevices)" == "true" ]] \
  || die "profile \"$AUTOFILL_PROFILE_NAME\" is not a Developer ID profile (it lists devices). Create it with type Developer ID (RELEASE.md, step 2)."
check_autofill_profile "$AUTOFILL_PROFILE_NAME"
expiry="$(pp ExpirationDate)"
expires_at="$(date -j -f '%a %b %d %T %Z %Y' "$expiry" +%s 2>/dev/null || true)"
if [[ -n "$expires_at" ]] && (( expires_at < $(date +%s) )); then
  die "profile \"$AUTOFILL_PROFILE_NAME\" expired on $expiry. Regenerate it (RELEASE.md, step 2)."
fi
echo "profile:  $AUTOFILL_PROFILE_NAME (expires $expiry)"

# Validates the stored credentials against the notary service; prints nothing about them.
xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" --output-format json >/dev/null 2>&1 \
  || die "notary keychain profile \"$NOTARY_PROFILE\" is missing or its credentials are rejected.
  Store it once: xcrun notarytool store-credentials \"$NOTARY_PROFILE\" --apple-id <your Apple ID> --team-id $TEAM
  (it prompts for an app-specific password). See apps/mac/RELEASE.md, step 3."
echo "notary:   keychain profile \"$NOTARY_PROFILE\""

# Only looks the item up; -w (the secret) is never passed.
security find-generic-password -s "https://sparkle-project.org" -a "$SPARKLE_ACCOUNT" >/dev/null 2>&1 \
  || die "no Sparkle update-signing key for account \"$SPARKLE_ACCOUNT\" in the keychain.
  Without it no update can be signed. See apps/mac/RELEASE.md, step 6."
echo "sparkle:  keychain account \"$SPARKLE_ACCOUNT\""

if (( PREFLIGHT )); then echo; echo "preflight OK"; exit 0; fi

if (( ! ALLOW_DIRTY )) && [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
  die "the working tree has uncommitted changes. Release from a clean checkout of main (or pass --allow-dirty for a test run)."
fi

# MARK: archive and export

rm -rf "$OUT"; mkdir -p "$OUT"
ARCHIVE="$OUT/Bisel.xcarchive"
EXPORT="$OUT/export"
APP="$EXPORT/Bisel.app"

say "xcodegen (project.yml)"
(cd "$APPLE" && xcodegen generate --quiet)

say "archive (Release, Developer ID)"
# The build number only grows: the number of commits on this branch.
BUILD_NUMBER="$(git -C "$APPLE" rev-list --count HEAD)"
(cd "$APPLE" && xcodebuild -project Bisel.xcodeproj -scheme Bisel -configuration Release -destination 'generic/platform=macOS' \
  -derivedDataPath "$OUT/dd" -archivePath "$ARCHIVE" CURRENT_PROJECT_VERSION="$BUILD_NUMBER" archive >"$OUT/archive.log" 2>&1) \
  || { grep -E "error:" "$OUT/archive.log" | head -20 >&2; die "archive failed, see $OUT/archive.log"; }

say "export (developer-id)"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportOptionsPlist "$APPLE/Tools/ExportOptions.plist" -exportPath "$EXPORT" \
  >"$OUT/export.log" 2>&1 || { grep -E "error:" "$OUT/export.log" | head -20 >&2; die "export failed, see $OUT/export.log"; }
[[ -d "$APP" ]] || die "export produced no Bisel.app (see $OUT/export.log)"

# MARK: verify the signature before spending a notarization round trip

say "verify signature and entitlements"
codesign --verify --deep --strict --verbose=2 "$APP"
sig="$(codesign -dvv "$APP" 2>&1)"
grep -q "^Authority=Developer ID Application: .*($TEAM)$" <<<"$sig" || die "not signed with Developer ID ($TEAM)."
grep -qE '^CodeDirectory .*flags=0x[0-9a-f]*\(runtime\)' <<<"$sig" || die "hardened runtime is not on."
grep -q '^Timestamp=' <<<"$sig" || die "the signature has no secure timestamp."
ents="$(codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -convert xml1 -o - - 2>/dev/null)"
ent() { /usr/libexec/PlistBuddy -c "Print :$1" /dev/stdin <<<"$ents" 2>/dev/null || true; }
[[ "$(ent com.apple.developer.icloud-container-environment)" == "Production" ]] \
  || die "com.apple.developer.icloud-container-environment is not Production: the app would talk to the Development schema."
ent com.apple.developer.icloud-container-identifiers | grep -q "$CONTAINER" || die "the iCloud container entitlement is missing."
[[ "$(ent com.apple.developer.ubiquity-kvstore-identifier)" == "$TEAM.$BUNDLE_ID" ]] || die "the iCloud key-value storage entitlement is missing."
# They come from the profile (CODE_SIGN_INJECT_BASE_ENTITLEMENTS is NO in Release). Without them persistent Secure Enclave keys and
# the data-protection keychain fail with -34018, so the app could not create or open device keys.
[[ "$(ent com.apple.application-identifier)" == "$TEAM.$BUNDLE_ID" ]] || die "com.apple.application-identifier is not $TEAM.$BUNDLE_ID: the keychain would fail with -34018."
[[ "$(ent com.apple.developer.team-identifier)" == "$TEAM" ]] || die "com.apple.developer.team-identifier is not $TEAM: the keychain would fail with -34018."
ent keychain-access-groups | grep -q "$TEAM.app.bisel" || die "keychain-access-groups does not pin $TEAM.app.bisel: device keys would land in another group."
ent com.apple.security.get-task-allow | grep -q true && die "get-task-allow is in the signed entitlements."
[[ -f "$APP/Contents/embedded.provisionprofile" ]] || die "no embedded provisioning profile: macOS would kill the app at launch."
# The app trusts the agent tool by this signature (AgentPeer): a wrong identifier means every `bl` call is refused.
TOOL="$APP/Contents/Helpers/bisel"
[[ -x "$TOOL" ]] || die "no agent tool at $TOOL."
tool_sig="$(codesign -dvv "$TOOL" 2>&1)"
grep -q '^Identifier=app.bisel.cli$' <<<"$tool_sig" || die "the agent tool's identifier is not app.bisel.cli."
grep -q "^Authority=Developer ID Application: .*($TEAM)$" <<<"$tool_sig" || die "the agent tool is not signed with Developer ID ($TEAM)."
grep -qE '^CodeDirectory .*flags=0x[0-9a-f]*\(runtime\)' <<<"$tool_sig" || die "hardened runtime is not on for the agent tool."
grep -q '^Timestamp=' <<<"$tool_sig" || die "the agent tool's signature has no secure timestamp."
# The app trusts Chrome's native host by this signature too (AgentPeer.browserHostRequirement), and Chrome launches it by path.
BROWSER_HOST="$APP/Contents/Helpers/bisel-browser-host"
[[ -x "$BROWSER_HOST" ]] || die "no Chrome native host at $BROWSER_HOST."
host_sig="$(codesign -dvv "$BROWSER_HOST" 2>&1)"
grep -q '^Identifier=app.bisel.browser-host$' <<<"$host_sig" || die "the Chrome native host's identifier is not app.bisel.browser-host."
grep -q "^Authority=Developer ID Application: .*($TEAM)$" <<<"$host_sig" || die "the Chrome native host is not signed with Developer ID ($TEAM)."
grep -qE '^CodeDirectory .*flags=0x[0-9a-f]*\(runtime\)' <<<"$host_sig" || die "hardened runtime is not on for the Chrome native host."
grep -q '^Timestamp=' <<<"$host_sig" || die "the Chrome native host's signature has no secure timestamp."
[[ "$(ent "$AUTOFILL_ENTITLEMENT")" == "true" ]] || die "the app has no AutoFill entitlement: the identity store would refuse it."
ent com.apple.security.application-groups | grep -q "$APP_GROUP" || die "the app is not in App Group $APP_GROUP: the extension could not reach it."
# The app trusts the extension by this signature too (AgentPeer.autoFillRequirement), and macOS kills it without a sandbox or a profile.
APPEX="$APP/Contents/PlugIns/BiselAutoFill.appex"
[[ -d "$APPEX" ]] || die "no AutoFill extension at $APPEX."
appex_sig="$(codesign -dvv "$APPEX" 2>&1)"
grep -q "^Identifier=$AUTOFILL_ID$" <<<"$appex_sig" || die "the extension's identifier is not $AUTOFILL_ID."
grep -q "^Authority=Developer ID Application: .*($TEAM)$" <<<"$appex_sig" || die "the extension is not signed with Developer ID ($TEAM)."
grep -qE '^CodeDirectory .*flags=0x[0-9a-f]*\(runtime\)' <<<"$appex_sig" || die "hardened runtime is not on for the extension."
grep -q '^Timestamp=' <<<"$appex_sig" || die "the extension's signature has no secure timestamp."
[[ -f "$APPEX/Contents/embedded.provisionprofile" ]] || die "the extension has no embedded provisioning profile: macOS would kill it."
ents="$(codesign -d --entitlements - --xml "$APPEX" 2>/dev/null | plutil -convert xml1 -o - - 2>/dev/null)"
[[ "$(ent com.apple.security.app-sandbox)" == "true" ]] || die "the extension is not sandboxed."
[[ "$(ent "$AUTOFILL_ENTITLEMENT")" == "true" ]] || die "the extension has no AutoFill entitlement."
ent com.apple.security.application-groups | grep -q "$APP_GROUP" || die "the extension is not in App Group $APP_GROUP."
ent keychain-access-groups | grep -qx "[[:space:]]*$TEAM.app.bisel" && die "the extension is in the device keys' keychain group: it must hold no keys."
"$APPLE/Tools/check-release.sh" "$APP"   # get-task-allow, software keys, fixture and BISEL_DEV_ hooks
# An app whose SUPublicEDKey is not the keychain key's could never be updated again: Sparkle would reject every later update.
[[ -x "$SPARKLE_BIN/sign_update" ]] || die "Sparkle's tools are not in $SPARKLE_BIN (did the archive resolve the Sparkle package?)."
app_key="$(/usr/libexec/PlistBuddy -c 'Print :SUPublicEDKey' "$APP/Contents/Info.plist" 2>/dev/null || true)"
[[ -n "$app_key" && "$app_key" == "$("$SPARKLE_BIN/generate_keys" --account "$SPARKLE_ACCOUNT" -p)" ]] \
  || die "SUPublicEDKey in the app is not the public half of the keychain key \"$SPARKLE_ACCOUNT\" (project.yml, RELEASE.md step 6)."

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist")"

# MARK: notarize

# notarize <file>: submits, waits, and on anything but Accepted prints the service's log and stops.
notarize() {
  local file="$1" result id status
  # The exit code is not trusted either way: the JSON status decides.
  result="$(xcrun notarytool submit "$file" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 1h --output-format json)" || true
  id="$(plutil -extract id raw -o - - <<<"$result" 2>/dev/null || true)"
  status="$(plutil -extract status raw -o - - <<<"$result" 2>/dev/null || true)"
  echo "submission $id: $status"
  if [[ "$status" != "Accepted" ]]; then
    [[ -n "$id" ]] && xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" >&2 || true
    die "notarization of $(basename "$file") was $status."
  fi
}

say "notarize the app"
ditto -c -k --keepParent "$APP" "$OUT/Bisel-notarize.zip"
notarize "$OUT/Bisel-notarize.zip"
rm -f "$OUT/Bisel-notarize.zip"

say "staple and assess the app"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl -a -vv -t exec "$APP" >"$OUT/spctl-app.txt" 2>&1 || true
cat "$OUT/spctl-app.txt"
grep -q "source=Notarized Developer ID" "$OUT/spctl-app.txt" || die "Gatekeeper does not accept the app as notarized Developer ID."
codesign --verify --deep --strict --verbose=2 "$APP"

# MARK: package

say "package ($FORMAT)"
if [[ "$FORMAT" == zip ]]; then
  ARTIFACT="$OUT/Bisel-$VERSION.zip"
  # A zip cannot be stapled; the app inside it is.
  ditto -c -k --sequesterRsrc --keepParent "$APP" "$ARTIFACT"
else
  ARTIFACT="$OUT/Bisel-$VERSION.dmg"
  stage="$OUT/dmg"
  mkdir -p "$stage"
  ditto "$APP" "$stage/Bisel.app"
  ln -s /Applications "$stage/Applications"
  # hdiutil sometimes fails with "Resource busy" right after the copy (0.1.6 stopped here); the same call works seconds later.
  for attempt in 1 2 3 4 5; do
    hdiutil create -volname "Bisel $VERSION" -srcfolder "$stage" -fs APFS -format UDZO -ov "$ARTIFACT" >/dev/null && break
    (( attempt < 5 )) || die "hdiutil create failed five times."
    echo "hdiutil create failed (attempt $attempt), retrying in 10 s"; rm -f "$ARTIFACT"; sleep 10
  done
  rm -rf "$stage"
  codesign --sign "$IDENTITY" --timestamp "$ARTIFACT"
  notarize "$ARTIFACT"
  xcrun stapler staple "$ARTIFACT"
  xcrun stapler validate "$ARTIFACT"
  spctl -a -vv -t open --context context:primary-signature "$ARTIFACT" >"$OUT/spctl-dmg.txt" 2>&1 || true
  cat "$OUT/spctl-dmg.txt"
  grep -q "source=Notarized Developer ID" "$OUT/spctl-dmg.txt" || die "Gatekeeper does not accept the DMG as notarized Developer ID."
fi

# MARK: Sparkle appcast

# generate_appcast signs the package with the keychain key (EdDSA) and, because the app sets SURequireSignedFeed, the feed too.
# One item: the feed is the newest release's asset, and Sparkle only needs the newest version.
say "sign for Sparkle and write appcast.xml"
feed="$OUT/feed"
rm -rf "$feed"; mkdir -p "$feed"
cp "$ARTIFACT" "$feed/"
"$SPARKLE_BIN/generate_appcast" --account "$SPARKLE_ACCOUNT" \
  --download-url-prefix "https://github.com/$REPO/releases/download/v$VERSION/" \
  --full-release-notes-url "https://github.com/$REPO/releases/tag/v$VERSION" \
  --maximum-deltas 0 -o "$OUT/appcast.xml" "$feed" >"$OUT/appcast.log" 2>&1 \
  || { cat "$OUT/appcast.log" >&2; die "generate_appcast failed."; }
rm -rf "$feed"
# Check what the app will check: the feed's signature, and the enclosure's EdDSA signature over the exact bytes being shipped.
"$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$OUT/appcast.xml" >/dev/null || die "the appcast's signature does not verify."
ed_sig="$(sed -nE 's/.*sparkle:edSignature="([^"]+)".*/\1/p' "$OUT/appcast.xml" | head -n 1)"
[[ -n "$ed_sig" ]] || die "appcast.xml has no sparkle:edSignature."
"$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$ARTIFACT" "$ed_sig" >/dev/null || die "the package's EdDSA signature does not verify."
grep -q "<sparkle:version>$BUILD</sparkle:version>" "$OUT/appcast.xml" || die "appcast.xml does not carry build $BUILD."

(cd "$OUT" && shasum -a 256 "$(basename "$ARTIFACT")" >"$(basename "$ARTIFACT").sha256")
printf 'VERSION=%q\nBUILD=%q\nCOMMIT=%q\nARTIFACT=%q\n' "$VERSION" "$BUILD" "$(git -C "$ROOT" rev-parse HEAD)" "$ARTIFACT" >"$OUT/build-info"

say "done"
echo "Bisel $VERSION ($BUILD), commit $(git -C "$ROOT" rev-parse --short HEAD)"
echo "$ARTIFACT"
echo "$OUT/appcast.xml"
cat "$ARTIFACT.sha256"
echo
echo "Publish to the release-please release: apps/mac/Tools/release.sh --publish v$VERSION"
