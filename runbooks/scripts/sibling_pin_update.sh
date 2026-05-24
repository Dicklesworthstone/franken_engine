#!/usr/bin/env bash
# sibling_pin_update.sh (bd-cixqu.13.4, M.4)
#
# Governed pin-advance for one sibling repository. The procedure enforces the
# M.4 safety property: a pin only advances when the integration smoke passes
# against the new SHA; otherwise the pin HOLDS at the last-passed SHA so a
# silent upstream regression cannot flow into our build.
#
# Steps (in order):
#   (a) record the PRIOR pin in the append-only audit ledger
#       (artifacts/sibling_repo_health/ledger.json) — ALWAYS,
#   (b) rerun the integration smoke against the new SHA,
#   (c) write the new SHA into docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md
#       ONLY if the smoke passed.
#
# Usage:
#   sibling_pin_update.sh <slug> <new_sha>
#   sibling_pin_update.sh selftest
#
# Environment:
#   SMOKE_CMD   integration smoke command (default: the standalone build gate).
#               Exit 0 = pass. Overridable for dry-runs / CI wiring.
#
# This script mirrors PinAuditLedger::apply_update in
# crates/franken-engine/src/sibling_repo_verification.rs (the source of truth).

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly DEFAULT_DOC="docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md"
readonly DEFAULT_LEDGER="artifacts/sibling_repo_health/ledger.json"
readonly DEFAULT_SMOKE="./scripts/test_standalone_build.sh ci"

is_valid_sha() { [[ "$1" =~ ^[a-f0-9]{7,40}$ ]]; }

prior_sha_from_doc() {
  local doc="$1" slug="$2"
  python3 - "$doc" "$slug" <<'PY'
import re, sys
from pathlib import Path
doc, slug = sys.argv[1], sys.argv[2]
pat = re.compile(r"^\|\s*`" + re.escape(slug) + r"`\s*\|\s*`([0-9a-f]{7,40})`")
for line in Path(doc).read_text().splitlines():
    m = pat.match(line.strip())
    if m:
        print(m.group(1)); break
PY
}

# Append a PinAuditEntry to the ledger. Args: ledger slug prior new passed committed note
record_ledger() {
  local ledger="$1" slug="$2" prior="$3" new="$4" passed="$5" committed="$6" note="$7"
  mkdir -p "$(dirname "${ledger}")"
  python3 - "$ledger" "$slug" "$prior" "$new" "$passed" "$committed" "$note" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
ledger, slug, prior, new, passed, committed, note = sys.argv[1:8]
p = Path(ledger)
data = json.loads(p.read_text()) if p.exists() else {"entries": []}
data["entries"].append({
    "repo": slug,
    "prior_sha": prior,
    "new_sha": new,
    "smoke_passed": passed == "true",
    "committed": committed == "true",
    "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "note": note,
})
p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
print(f"ledger entry #{len(data['entries'])} recorded for {slug}")
PY
}

# Surgically rewrite the one table row for <slug> to <new_sha> + today's date.
commit_pin_to_doc() {
  local doc="$1" slug="$2" new="$3"
  python3 - "$doc" "$slug" "$new" <<'PY'
import re, sys
from datetime import datetime, timezone
from pathlib import Path
doc, slug, new = sys.argv[1], sys.argv[2], sys.argv[3]
today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
pat = re.compile(r"^(\|\s*`" + re.escape(slug) + r"`\s*\|\s*`)[0-9a-f]{7,40}(`\s*\|\s*)[0-9-]+(\s*\|.*)$")
lines = Path(doc).read_text().splitlines(keepends=True)
hits = 0
for i, line in enumerate(lines):
    m = pat.match(line.rstrip("\n"))
    if m:
        lines[i] = f"{m.group(1)}{new}{m.group(2)}{today}{m.group(3)}\n"
        hits += 1
if hits != 1:
    sys.exit(f"expected exactly one row for {slug}, found {hits}")
Path(doc).write_text("".join(lines))
print(f"pin row for {slug} advanced to {new[:7]} ({today})")
PY
}

# Core pin-update flow. Args: doc ledger slug new_sha smoke_cmd
do_update() {
  local doc="$1" ledger="$2" slug="$3" new="$4" smoke="$5"
  if ! is_valid_sha "${new}"; then
    echo "ERROR: invalid new SHA '${new}' (expected 7-40 lowercase hex)" >&2
    return 2
  fi
  local prior; prior="$(prior_sha_from_doc "${doc}" "${slug}")"
  if [[ -z "${prior}" ]]; then
    echo "ERROR: no existing pin for '${slug}' in ${doc}" >&2
    return 2
  fi
  echo "[pin-update] ${slug}: ${prior:0:7} -> ${new:0:7}"

  # (b) rerun integration smoke against the new pin.
  echo "[pin-update] running smoke: ${smoke}"
  local passed="false"
  if eval "${smoke}"; then passed="true"; fi

  if [[ "${passed}" == "true" ]]; then
    # (a)+(c): record prior pin, then commit the advance.
    record_ledger "${ledger}" "${slug}" "${prior}" "${new}" "true" "true" \
      "smoke passed; pin advanced ${prior:0:7} -> ${new:0:7}"
    commit_pin_to_doc "${doc}" "${slug}" "${new}"
    echo "[pin-update] COMMITTED: ${slug} now pinned at ${new:0:7}"
    return 0
  else
    # (a) only: record the held pin; doc is left untouched (safety property).
    record_ledger "${ledger}" "${slug}" "${prior}" "${new}" "false" "false" \
      "smoke FAILED; pin held at ${prior:0:7} (safety property)"
    echo "[pin-update] HELD: smoke failed; ${slug} stays pinned at ${prior:0:7}" >&2
    return 1
  fi
}

run_selftest() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  local doc="${tmp}/iso.md" ledger="${tmp}/ledger.json"
  cat > "${doc}" <<'EOF'
| Repository | Commit SHA | Updated |
|------------|------------|---------|
| `frankentui` | `33ad1c57d545292242e41a477c8278c70ed7e0d6` | 2026-05-21 |
EOF
  local newsha="c0c8f32892a71f432a3ead0e5a04a9352549ccd4"

  echo "--- selftest case 1: smoke FAILS -> pin must hold ---"
  set +e
  do_update "${doc}" "${ledger}" "frankentui" "${newsha}" "false"
  local rc=$?
  set -e
  [[ ${rc} -eq 1 ]] || { echo "FAIL: expected hold rc=1, got ${rc}"; return 1; }
  grep -q "33ad1c5" "${doc}" || { echo "FAIL: doc changed on smoke fail"; return 1; }
  python3 -c "import json;e=json.load(open('${ledger}'))['entries'];assert len(e)==1 and e[0]['committed'] is False, e"

  echo "--- selftest case 2: smoke PASSES -> pin advances ---"
  do_update "${doc}" "${ledger}" "frankentui" "${newsha}" "true"
  grep -q "c0c8f32" "${doc}" || { echo "FAIL: doc not advanced on smoke pass"; return 1; }
  python3 -c "import json;e=json.load(open('${ledger}'))['entries'];assert len(e)==2 and e[1]['committed'] is True, e"
  echo "SELFTEST OK: hold-on-fail preserves pin; pass advances pin + records both attempts"
}

MODE="${1:-}"
case "${MODE}" in
  selftest)
    run_selftest
    ;;
  "" | -h | --help)
    echo "Usage: $0 <slug> <new_sha>   |   $0 selftest" >&2
    exit 2
    ;;
  *)
    SLUG="$1"
    NEW_SHA="${2:?need <new_sha>}"
    do_update "${DEFAULT_DOC}" "${DEFAULT_LEDGER}" "${SLUG}" "${NEW_SHA}" "${SMOKE_CMD:-${DEFAULT_SMOKE}}"
    ;;
esac
