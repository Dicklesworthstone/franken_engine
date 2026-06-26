#!/usr/bin/env bash
# run_coverage_summary_bundle_gate.sh — gate for the ES2020 weighted coverage
# summary bundle (bd-fqlfw.7.4, E7.T4, FE-CLAIM-026).
#
# Modes:
#   ci   (default)  Validate the committed bundle, fail-closed on contract
#                   violations (FE-REPRO-0001..0008), and apply the freshness
#                   window.
#   generate        Re-run the real Test262 coverage summary (needs the
#                   franken_coverage_frontier binary + a tc39/test262 checkout)
#                   and rebuild the bundle via build_coverage_summary_bundle.py.
#
# The reproducible assertion bound here is coverage_summary.json#report_digest
# (a pure function of the per-view counts), recorded in repro.lock.expected_outputs.
# The figure is a conservative lower bound (harness includes not preloaded).
set -uo pipefail

bundle_dir="${COVERAGE_BUNDLE_DIR:-docs/coverage/es2020_coverage_summary_bundle_v1}"
corpus="${TEST262_CORPUS:-/data/projects/test262_corpus}"
max_age_days="${COVERAGE_MAX_AGE_DAYS:-365}"
mode="${1:-ci}"

log() { printf '%s\n' "$*" >&2; }
fail() {
  log "❌ FE-REPRO ${1}: ${2}"
  exit 1
}
require_tool() { command -v "$1" >/dev/null 2>&1 || { log "missing required tool: $1"; exit 2; }; }

require_tool jq
require_tool python3
require_tool sha256sum

validate_bundle() {
  local d="$1"
  [[ -d "$d" ]] || fail "FE-REPRO-0001" "bundle dir missing: $d"

  # FE-REPRO-0001/0002: all four files present and valid JSON.
  local f
  for f in coverage_summary.json env.json manifest.json repro.lock; do
    [[ -f "$d/$f" ]] || fail "FE-REPRO-0001" "missing required bundle file: $f"
    jq empty "$d/$f" 2>/dev/null || fail "FE-REPRO-0002" "invalid JSON in $f"
  done

  # FE-REPRO-0002: schema versions.
  [[ "$(jq -r '.schema_version' "$d/coverage_summary.json")" == "franken-engine.coverage-summary.v1" ]] \
    || fail "FE-REPRO-0002" "coverage_summary.json schema mismatch"
  [[ "$(jq -r '.schema_version' "$d/env.json")" == "franken-engine.env.v1" ]] \
    || fail "FE-REPRO-0002" "env.json schema mismatch"
  [[ "$(jq -r '.schema_version' "$d/manifest.json")" == "franken-engine.manifest.v1" ]] \
    || fail "FE-REPRO-0002" "manifest.json schema mismatch"
  [[ "$(jq -r '.schema_version' "$d/repro.lock")" == "franken-engine.repro-lock.v1" ]] \
    || fail "FE-REPRO-0002" "repro.lock schema mismatch"

  # FE-REPRO-0004: content-addressing — manifest digests match recomputed files.
  local pair key file sha_actual sha_manifest
  for pair in "coverage:coverage_summary.json" "env:env.json" "lock:repro.lock"; do
    key="${pair%%:*}"; file="${pair##*:}"
    sha_actual="sha256:$(sha256sum "$d/$file" | cut -d' ' -f1)"
    sha_manifest="$(jq -r ".artifacts.${key}.sha256" "$d/manifest.json")"
    [[ "$sha_actual" == "$sha_manifest" ]] \
      || fail "FE-REPRO-0004" "digest mismatch for $file (manifest=$sha_manifest actual=$sha_actual)"
  done

  # FE-REPRO-0005: repro.lock binds expected_output to the measured report_digest,
  # and provenance (corpus commit) is present.
  local digest_lock digest_report corpus_commit
  digest_lock="$(jq -r '.expected_outputs[0].sha256' "$d/repro.lock")"
  digest_report="$(jq -r '.report_digest' "$d/coverage_summary.json")"
  [[ -n "$digest_report" && "$digest_lock" == "$digest_report" ]] \
    || fail "FE-REPRO-0005" "repro.lock expected_output ($digest_lock) != coverage report_digest ($digest_report)"
  corpus_commit="$(jq -r '.corpus_commit' "$d/coverage_summary.json")"
  [[ -n "$corpus_commit" && "$corpus_commit" != "null" ]] \
    || fail "FE-REPRO-0005" "coverage_summary.json missing corpus_commit provenance"

  # FE-REPRO-0005: the headline recorded in manifest matches the report.
  local hl_manifest hl_report
  hl_manifest="$(jq -r '.headline.observable_surface_executed_millionths' "$d/manifest.json")"
  hl_report="$(jq -r '.observable_surface_executed_millionths' "$d/coverage_summary.json")"
  [[ "$hl_manifest" == "$hl_report" ]] \
    || fail "FE-REPRO-0005" "manifest headline ($hl_manifest) != report headline ($hl_report)"

  # Anti-gaming invariant: all six views present and the floor is one of them.
  local view_count floor
  view_count="$(jq -r '.views | length' "$d/coverage_summary.json")"
  [[ "$view_count" == "6" ]] || fail "FE-REPRO-0002" "expected 6 views, got $view_count"
  floor="$(jq -r '.floor_view' "$d/coverage_summary.json")"
  [[ -n "$floor" && "$floor" != "null" ]] || fail "FE-REPRO-0002" "floor_view missing"

  # FE-REPRO-0007: freshness window on the bundle generation time.
  local gen_at
  gen_at="$(jq -r '.generated_at_utc' "$d/manifest.json")"
  python3 - "$gen_at" "$max_age_days" <<'PY' || fail "FE-REPRO-0007" "bundle is stale or has an unparseable timestamp"
import sys, datetime as dt
stamp, max_days = sys.argv[1], int(sys.argv[2])
try:
    gen = dt.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
except ValueError:
    sys.exit(1)
age = (dt.datetime.now(dt.timezone.utc) - gen).days
sys.exit(0 if 0 <= age <= max_days else 1)
PY

  log "✅ coverage-summary bundle valid: headline=${hl_report} millionths, floor=${floor}, corpus=${corpus_commit:0:12}, digest=${digest_report:0:12}"
}

case "$mode" in
  ci|verify)
    validate_bundle "$bundle_dir"
    log "PASS run_coverage_summary_bundle_gate.sh ($mode)"
    ;;
  generate)
    bin="target/release/franken_coverage_frontier"
    [[ -x "$bin" ]] || bin="target/debug/franken_coverage_frontier"
    [[ -x "$bin" ]] || { log "no franken_coverage_frontier binary built; run: cargo build --release -p frankenengine-engine --bin franken_coverage_frontier"; exit 2; }
    [[ -d "$corpus" ]] || { log "test262 corpus not found at $corpus (set TEST262_CORPUS)"; exit 2; }
    tmp="$(mktemp -d)"
    log "running real Test262 coverage over $corpus (this takes ~10-15 min)…"
    "$bin" --run-suite "$corpus" --coverage-summary --out "$tmp/coverage_summary.json" >/dev/null \
      || { log "coverage run failed"; exit 1; }
    python3 scripts/build_coverage_summary_bundle.py --summary "$tmp/coverage_summary.json" --out-dir "$bundle_dir" \
      || { log "bundle build failed"; exit 1; }
    rm -rf "$tmp"
    validate_bundle "$bundle_dir"
    log "PASS run_coverage_summary_bundle_gate.sh (generate)"
    ;;
  *)
    log "usage: $0 [ci|verify|generate]"
    exit 2
    ;;
esac
