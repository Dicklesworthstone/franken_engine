#!/usr/bin/env bash
# sibling_status.sh (bd-cixqu.13.4, M.4)
#
# Operator query script for the sibling-repo integration-verification surface.
# Lists every sibling repository pinned in
# docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md together with:
#   - its current pinned SHA + the date the pin was last updated,
#   - the local /dp/<slug> HEAD and whether it matches the pin (drift),
#   - its last-passed timestamp and last-failed reason, read from the pin
#     audit ledger (artifacts/sibling_repo_health/ledger.json) when present.
#
# Modes:
#   status     (default) plain-English summary on stdout + JSON report under
#              artifacts/sibling_repo_health/<ts>/.
#   json       emit ONLY the JSON report on stdout (pipe-friendly, no artifacts).
#   selftest   run against an in-tree fixture table and assert the parse +
#              verdict outcomes. No /dp access, fully deterministic.
#
# JSON shape: franken-engine.sibling-repo-health.v1 — the same schema the
# sibling_repo_verification.rs core emits, so script output and Rust output
# diff cleanly.
#
# This script mirrors crates/franken-engine/src/sibling_repo_verification.rs;
# the Rust module is the source of truth for validation and the JSON shape.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly ISOLATION_DOC="docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md"
readonly LEDGER="artifacts/sibling_repo_health/ledger.json"
readonly SCHEMA_VERSION="franken-engine.sibling-repo-health.v1"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly GENERATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SIBLINGS_ROOT="${SIBLINGS_ROOT:-/dp}"

MODE="${1:-status}"

# Core: emit the JSON health report. Args: <isolation_doc> <ledger_or_-> <root>
emit_report() {
  local doc="$1" ledger="$2" root="$3"
  python3 - "$doc" "$ledger" "$root" "$SCHEMA_VERSION" "$GENERATED_UTC" <<'PY'
import json, re, subprocess, sys
from pathlib import Path

doc, ledger_path, root, schema_version, generated_utc = sys.argv[1:6]

# Parse the SHA-pin markdown table: | `repo` | `sha` | date |
pins = {}
row = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{7,40})`\s*\|\s*([0-9-]+)\s*\|")
for line in Path(doc).read_text().splitlines():
    m = row.match(line.strip())
    if m:
        pins[m.group(1)] = {"sha": m.group(2), "updated": m.group(3)}

ledger = {}
if ledger_path != "-" and Path(ledger_path).exists():
    data = json.loads(Path(ledger_path).read_text())
    for e in data.get("entries", []):
        repo = e.get("repo")
        if e.get("smoke_passed"):
            ledger.setdefault(repo, {})["last_passed_utc"] = e.get("timestamp_utc")
        else:
            ledger.setdefault(repo, {})["last_failed_reason"] = e.get("note")

def head(slug):
    p = Path(root) / slug
    if not p.is_dir():
        return None
    try:
        return subprocess.check_output(
            ["git", "-C", str(p), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return None

out_pins, passed, skipped, failed = [], 0, 0, 0
for slug in sorted(pins):
    info = pins[slug]
    led = ledger.get(slug, {})
    local = head(slug)
    if local is None:
        verdict = "skip"; skipped += 1
    elif local.startswith(info["sha"]) or info["sha"].startswith(local[:len(info["sha"])]):
        verdict = "pass"; passed += 1
    else:
        verdict = "fail"; failed += 1
        led.setdefault("last_failed_reason",
                       f"local HEAD {local[:12]} != pinned {info['sha'][:12]}")
    out_pins.append({
        "repo": slug,
        "pinned_sha": info["sha"],
        "updated_utc": info["updated"],
        "local_head": local,
        "verdict": verdict,
        "last_passed_utc": led.get("last_passed_utc"),
        "last_failed_reason": led.get("last_failed_reason"),
    })

report = {
    "schema_version": schema_version,
    "generated_utc": generated_utc,
    "total": len(out_pins),
    "passed": passed, "skipped": skipped, "failed": failed,
    "pins": out_pins,
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

render_summary() {
  python3 - <<'PY'
import json, sys
r = json.load(sys.stdin)
print(f"Sibling-repo health ({r['generated_utc']}) — "
      f"{'HEALTHY' if r['failed'] == 0 else 'DEGRADED'}")
print(f"  total={r['total']} pass={r['passed']} skip={r['skipped']} fail={r['failed']}")
for p in r["pins"]:
    lf = p["last_failed_reason"] or "-"
    print(f"  - {p['repo']:<14} {p['pinned_sha'][:7]}  {p['verdict']:<4}  "
          f"last_passed={p['last_passed_utc'] or '-'}  fail={lf}")
PY
}

run_selftest() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  cat > "${tmp}/iso.md" <<'EOF'
| Repository | Commit SHA | Updated |
|------------|------------|---------|
| `asupersync` | `094b59c859611f7f804fac79d185538d6e7aa171` | 2026-05-21 |
| `frankentui` | `33ad1c57d545292242e41a477c8278c70ed7e0d6` | 2026-05-21 |
EOF
  # No fixture repos under the empty root -> both must be "skip".
  local report; report="$(emit_report "${tmp}/iso.md" "-" "${tmp}/noroot")"
  echo "${report}"
  python3 - <<PY
import json
r = json.loads('''${report}''')
assert r["total"] == 2, r["total"]
assert r["skipped"] == 2, r["skipped"]
assert {p["repo"] for p in r["pins"]} == {"asupersync", "frankentui"}, r
assert r["pins"][0]["repo"] == "asupersync", "pins must be sorted"
print("SELFTEST OK: parsed 2 pins, both skip (no local repos), sorted")
PY
}

case "${MODE}" in
  json)
    emit_report "${ISOLATION_DOC}" "${LEDGER}" "${SIBLINGS_ROOT}"
    ;;
  selftest)
    run_selftest
    ;;
  status)
    readonly OUT_DIR="artifacts/sibling_repo_health/${TIMESTAMP}"
    mkdir -p "${OUT_DIR}/step_logs"
    {
      echo "command: $0 ${MODE}"
      echo "generated_utc: ${GENERATED_UTC}"
      echo "rustflags: ${RUSTFLAGS:-<unset>}"
      echo "cargo_incremental: ${CARGO_INCREMENTAL:-<unset>}"
      echo "siblings_root: ${SIBLINGS_ROOT}"
    } > "${OUT_DIR}/commands.txt"
    report="$(emit_report "${ISOLATION_DOC}" "${LEDGER}" "${SIBLINGS_ROOT}")"
    echo "${report}" > "${OUT_DIR}/report.json"
    echo "${report}" | render_summary | tee "${OUT_DIR}/summary.txt"
    echo "[sibling_status] report written to ${OUT_DIR}/report.json" >&2
    ;;
  *)
    echo "Usage: $0 [status|json|selftest]" >&2
    exit 2
    ;;
esac
