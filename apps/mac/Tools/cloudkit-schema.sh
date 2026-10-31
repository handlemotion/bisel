#!/usr/bin/env bash
# The CloudKit schema of iCloud.app.bisel, kept in the repo (apps/mac/CloudKit/schema.ckdb) and checked against what
# CloudKitLane writes (docs/SYNC-LANES.md §3, §15): one record type R with k, rev, ep, w, sig, d and NO indexes, because the lane
# never queries (zone-change fetches and fetches by record ID only), so a QUERYABLE, SORTABLE or SEARCHABLE index would only
# have CloudKit index box metadata it never needs.
#
#   apps/mac/Tools/cloudkit-schema.sh lint                    check the repo file only (offline)
#   apps/mac/Tools/cloudkit-schema.sh export                  export Development into the repo file, then lint it
#   apps/mac/Tools/cloudkit-schema.sh validate                lint, then validate the repo file against Development and show drift
#   apps/mac/Tools/cloudkit-schema.sh import-development      lint, then import the repo file into Development (e.g. to drop indexes)
#   apps/mac/Tools/cloudkit-schema.sh validate --production   same as validate, against Production (read-only)
#   apps/mac/Tools/cloudkit-schema.sh deploy --production     lint, validate, show the diff, ask, then import into Production
#
# Needs a CloudKit management token saved once with `xcrun cktool save-token --type management` (RELEASE.md, step 4); cktool
# reads it from the keychain, this script never sees or passes it. Production is only ever touched by `deploy --production`,
# after a typed confirmation. Production schema changes are additive: record types and fields deployed there can never be removed.
set -euo pipefail

TEAM=ZVGTVNUPVA
CONTAINER=iCloud.app.bisel
APPLE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$APPLE/CloudKit/schema.ckdb"

CMD="${1:-}"; shift || true
ENVIRONMENT=development
for arg in "$@"; do
  case "$arg" in
    --production) ENVIRONMENT=production ;;
    *) echo "unknown flag: $arg (try --help)" >&2; exit 64 ;;
  esac
done
case "$CMD" in
  lint|export|validate|import-development|deploy) ;;
  -h|--help|"") sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown command: $CMD (try --help)" >&2; exit 64 ;;
esac
[[ "$CMD" == deploy && "$ENVIRONMENT" != production ]] && { echo "deploy only exists as: deploy --production" >&2; exit 64; }
[[ ( "$CMD" == export || "$CMD" == import-development ) && "$ENVIRONMENT" == production ]] && { echo "$CMD never targets Production" >&2; exit 64; }

die() { printf 'cloudkit-schema: %s\n' "$*" >&2; exit 1; }
ck() { xcrun cktool "$@" --team-id "$TEAM" --container-id "$CONTAINER"; }

need_token() {
  xcrun cktool get-teams >/dev/null 2>&1 || die "no CloudKit management token. Create one in CloudKit Console (Settings > Tokens),
  then: xcrun cktool save-token --type management   (it prompts; never pass the token as an argument). RELEASE.md, step 4."
}

# lint <file>: R has exactly the fields CloudKitLane.filled(_:with:) writes, with their types, and no index on any field.
lint() {
  local file="$1"
  [[ -f "$file" ]] || die "$file does not exist. Export it first: apps/mac/Tools/cloudkit-schema.sh export"
  awk '
    BEGIN { want["k"]="STRING"; want["rev"]="INT64"; want["ep"]="INT64"; want["w"]="STRING"; want["sig"]="BYTES"; want["d"]="BYTES"; bad=0 }
    /^[[:space:]]*RECORD[[:space:]]+TYPE[[:space:]]+/ {
      t=$3; gsub(/[("]/, "", t); type=t
      if (type != "R" && type != "Users") { print "unexpected record type " type " (CloudKitLane writes only R)"; bad=1 }
      next
    }
    type == "R" && /^[[:space:]]*\);/ { type=""; next }
    type == "R" && !/GRANT/ && NF >= 2 {
      f=$1; gsub(/"/, "", f); ty=$2; gsub(/,/, "", ty)
      if (f ~ /^___/) { if ($0 ~ /QUERYABLE|SORTABLE|SEARCHABLE/) { print "R." f ": index on a system field (the lane never queries)"; bad=1 }; next }
      if (!(f in want)) { print "R." f ": not a field CloudKitLane writes"; bad=1; next }
      if (ty != want[f]) { print "R." f ": " ty ", expected " want[f]; bad=1 }
      if ($0 ~ /QUERYABLE|SORTABLE|SEARCHABLE/) { print "R." f ": has an index (QUERYABLE/SORTABLE/SEARCHABLE); the lane never queries, remove it"; bad=1 }
      seen[f]=1
    }
    END {
      for (f in want) if (!(f in seen)) { print "R." f ": missing; a Production save with this field would fail"; bad=1 }
      exit bad
    }' "$file" || die "$file does not match what CloudKitLane writes (see above). Fix it in Development (CloudKit Console, or edit the
  file and run: cloudkit-schema.sh import-development), then export again."
  grep -qE '^[[:space:]]*RECORD[[:space:]]+TYPE[[:space:]]+"?R"?[[:space:]]*\(' "$file" || die "$file has no record type R."
  echo "lint OK: R(k STRING, rev INT64, ep INT64, w STRING, sig BYTES, d BYTES), no indexes"
}

# drift <environment>: the live schema next to the repo file.
drift() {
  local live
  live="$(mktemp "${TMPDIR:-/tmp}/bisel-ckschema.XXXXXX")"
  ck export-schema --environment "$1" --output-file "$live" >/dev/null
  if diff -u --label "$1 (live)" --label "repo" "$live" "$SCHEMA"; then echo "no drift: $1 matches the repo file"; fi
  rm -f "$live"
}

case "$CMD" in
  lint)
    lint "$SCHEMA" ;;

  export)
    need_token
    mkdir -p "$(dirname "$SCHEMA")"
    ck export-schema --environment development --output-file "$SCHEMA"
    echo "exported Development to ${SCHEMA#"$APPLE/"}"
    lint "$SCHEMA" ;;

  validate)
    lint "$SCHEMA"
    need_token
    ck validate-schema --environment "$ENVIRONMENT" --file "$SCHEMA"
    echo "validate-schema OK against $ENVIRONMENT"
    drift "$ENVIRONMENT" || true ;;

  import-development)
    lint "$SCHEMA"
    need_token
    ck import-schema --environment development --validate --file "$SCHEMA"
    echo "imported into Development" ;;

  deploy)
    lint "$SCHEMA"
    need_token
    [[ -t 0 ]] || die "deploy --production asks for a typed confirmation; run it from a terminal."
    ck validate-schema --environment production --file "$SCHEMA"
    echo "validate-schema OK against production"
    echo; echo "Production now vs the repo file (lines with + are what the deploy adds):"
    drift production || true
    echo
    echo "This changes the PRODUCTION schema of $CONTAINER. Record types and fields deployed there can never be removed."
    phrase="deploy $CONTAINER to production"
    read -r -p "Type \"$phrase\" to continue: " answer
    [[ "$answer" == "$phrase" ]] || die "not confirmed; nothing changed."
    if ! ck import-schema --environment production --validate --file "$SCHEMA"; then
      die "cktool did not import into Production. Apple documents the CloudKit Console as the way to promote a schema:
  https://icloud.developer.apple.com > CloudKit Database > $CONTAINER > Deploy Schema Changes (RELEASE.md, step 5)."
    fi
    echo "deployed to Production"
    drift production || true ;;
esac
