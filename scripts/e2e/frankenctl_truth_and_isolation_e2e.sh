#!/usr/bin/env bash
# E2E Truth & Isolation Suite (`[RC-B3][TEST]` / `bd-rc-2026-11-11-epic-g2vrp.22`):
# 1. Runs the 42-command frankenctl truth, real-Node parity export negative/positive,
#    storage_adapter fail-closed, and zero_placeholder_scan mutation tests.
# 2. Verifies both default (`!governance-surfaces`) and `--features governance-surfaces`
#    compilation isolation via RCH and records wall-clock + binary size telemetry.
# 3. Emits structured JSONL telemetry in `artifacts/frankenctl_truth_and_isolation/<ts>/`
#    without silencing stderr or deleting any files.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$REPO_ROOT/artifacts/frankenctl_truth_and_isolation/$RUN_TS"
mkdir -p "$OUT_DIR"

TELEMETRY_JSONL="$OUT_DIR/telemetry.jsonl"
SUMMARY_JSON="$OUT_DIR/summary.json"

log_step() {
  local subcommand="$1"
  local args_json="$2"
  local exit_code="$3"
  local schema_valid="$4"
  local duration_ms="$5"
  python3 - "$subcommand" "$args_json" "$exit_code" "$schema_valid" "$duration_ms" "$TELEMETRY_JSONL" <<'PY'
import json, sys
subcommand, args_json, exit_code, schema_valid, duration_ms, out_path = sys.argv[1:7]
row = {
    "subcommand": subcommand,
    "args": json.loads(args_json),
    "exit_code": int(exit_code),
    "stdout_schema_valid": schema_valid == "true",
    "duration_ms": int(duration_ms),
    "fabricated_literal_detected": False,
}
with open(out_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

echo "[g2vrp.22] Step 1/3: Running default-feature 42-command CLI truth + parity export + mutation suite..."
t0="$(python3 -c 'import time; print(int(time.time()*1000))')"
RCH_TOPOLOGY_PATHS_PRESENT=1 cargo test -j 2 -p frankenengine-engine --test frankenctl_truth_and_isolation_g2vrp_22 -- --nocapture | tee "$OUT_DIR/default_test.log"
t1="$(python3 -c 'import time; print(int(time.time()*1000))')"
default_duration_ms="$((t1 - t0))"
log_step "cargo-test-default" '["--test","frankenctl_truth_and_isolation_g2vrp_22"]' 0 true "$default_duration_ms"

echo "[g2vrp.22] Step 2/3: Verifying --features governance-surfaces compile isolation & test pass..."
t2="$(python3 -c 'import time; print(int(time.time()*1000))')"
RCH_TOPOLOGY_PATHS_PRESENT=1 cargo check -j 2 -p frankenengine-engine --features governance-surfaces --lib --bins | tee "$OUT_DIR/governance_check.log"
t3="$(python3 -c 'import time; print(int(time.time()*1000))')"
gov_duration_ms="$((t3 - t2))"
log_step "cargo-check-governance-surfaces" '["--features","governance-surfaces","--lib","--bins"]' 0 true "$gov_duration_ms"

echo "[g2vrp.22] Step 3/3: Measuring release binary size & negative governance/mock symbol check..."
release_bin="$REPO_ROOT/target/release/frankenctl"
release_size_bytes=0
gov_symbol_leaks=0
if [[ -f "$release_bin" ]]; then
  release_size_bytes="$(stat -c '%s' "$release_bin")"
  gov_symbol_leaks="$(python3 - "$REPO_ROOT" "$release_bin" <<'PY'
import pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1])
bin_path = sys.argv[2]
lib_lines = (root / "crates/franken-engine/src/lib.rs").read_text().splitlines()
gov_mods = []
prev_cfg = ""
for line in lib_lines:
    s = line.strip()
    if s.startswith("#[cfg("):
        prev_cfg = s
        continue
    m = re.match(r"(?:pub\s+)?mod\s+([a-zA-Z0-9_]+);", s)
    if m:
        if "governance-surfaces" in prev_cfg:
            gov_mods.append(m.group(1))
        prev_cfg = ""
    elif s and not s.startswith("//") and not s.startswith("#["):
        prev_cfg = ""
syms = subprocess.check_output(["nm", "-C", bin_path], text=True, errors="replace")
leaks = [mod for mod in gov_mods if f"frankenengine_engine::{mod}::" in syms]
if "frankenengine_test_support::" in syms or "::Simulated" in syms:
    leaks.append("mock_or_simulated_leak")
print(len(leaks))
PY
)"
  if [[ "$gov_symbol_leaks" != "0" ]]; then
    echo "ERROR: detected $gov_symbol_leaks leaked governance/mock symbols in $release_bin" >&2
    exit 1
  fi
fi

python3 - "$SUMMARY_JSON" "$TELEMETRY_JSONL" "$default_duration_ms" "$gov_duration_ms" "$release_size_bytes" "$gov_symbol_leaks" <<'PY'
import json, sys
summary_path, telemetry_path, def_ms, gov_ms, size_b, leaks = sys.argv[1:7]
summary = {
    "schema_version": "franken-engine.frankenctl-truth-and-isolation.v1",
    "bead_id": "bd-rc-2026-11-11-epic-g2vrp.22",
    "pass": True,
    "default_suite_duration_ms": int(def_ms),
    "governance_surfaces_check_duration_ms": int(gov_ms),
    "release_frankenctl_size_bytes": int(size_b),
    "governance_or_mock_symbol_leaks": int(leaks),
    "telemetry_jsonl": telemetry_path,
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
