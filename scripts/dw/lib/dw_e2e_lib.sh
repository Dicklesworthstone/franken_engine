#!/usr/bin/env bash
# dw_e2e_lib.sh — shared end-to-end harness for Dueling-Wizards (bd-fqlfw) capabilities.
#
# Implements the DW.STD (bd-fqlfw.11) Testing & Verification Standard's e2e contract
# so every `scripts/run_dw_<cap>.sh ci` gate emits an identical, audit-grade bundle:
#   artifacts/<cap>/<timestamp>/
#     ├── run_manifest.json   signed-able manifest: schema id, source revision, host facts,
#     │                       content hashes, commands, outcome, degraded receipts
#     ├── events.jsonl        the DETAILED LOG — one structured line per step
#     ├── commands.txt        human transcript of every command run
#     ├── steps/<n>_<slug>.log per-step stdout+stderr
#     └── degraded_receipt.json (only if a real dependency was unavailable)
#
# Contract (DW.STD): exit 0 = pass; non-zero = fail-closed; a degraded receipt is emitted
# (never a silent pass) when a real dependency is absent. Logging is self-diagnosing:
# every step records inputs (with hashes), the decision + why, outputs (with hashes), timing.
#
# Determinism discipline: LC_ALL=C sorting, sha256 content hashes, no wall-clock in hashed
# positions (timestamps are recorded as metadata, never mixed into a content hash).
#
# Usage (see scripts/dw/templates/run_dw_capability.sh.template):
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/dw_e2e_lib.sh"
#   dw_begin "<capability-slug>" "<mode>"
#   dw_run_step "cargo test -p frankenengine-engine --test foo" cargo test ...
#   dw_run_step "cargo test -p frankenengine-engine --test foo" dw_cargo_results cargo test ...
#   dw_require_dep node "node --version"   # emits degraded receipt + fails closed if absent
#   dw_finish

set -euo pipefail

# ---- internal state ---------------------------------------------------------
DW_CAP=""
DW_MODE=""
DW_RUN_DIR=""
DW_EVENTS=""
DW_COMMANDS=""
DW_STEPS_DIR=""
DW_STEP_N=0
DW_FAILED_STEP=""
DW_DEGRADED=0
DW_SCHEMA="franken-engine.dw-e2e-bundle.v1"
DW_START_NS=0

# ---- helpers ----------------------------------------------------------------
dw__now_ns()  { date -u +%s%N; }
dw__now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# sha256 of a file (empty string yields the well-known empty-input digest)
dw_sha256() {
  if [[ -f "$1" ]]; then sha256sum "$1" | awk '{print $1}'; else printf '%s' "" | sha256sum | awk '{print $1}'; fi
}

# JSON-escape a string (handles backslash, quote, newline, tab, CR)
dw__json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

# Append one structured event to events.jsonl.
# args: step_name status detail_json_object
dw_log_event() {
  local name="$1" status="$2" detail="${3:-{\}}"
  local line
  line=$(printf '{"ts":"%s","cap":"%s","step":"%s","status":"%s","detail":%s}' \
    "$(dw__now_iso)" "$DW_CAP" "$(dw__json_escape "$name")" "$status" "$detail")
  printf '%s\n' "$line" >> "$DW_EVENTS"
  # human breadcrumb on stderr so an operator watching the run sees progress
  printf '  [dw:%s] %-7s %s\n' "$DW_CAP" "$status" "$name" >&2
}

# Begin a bundle. args: capability-slug mode
dw_begin() {
  DW_CAP="$1"; DW_MODE="${2:-ci}"
  local root_dir artifact_root timestamp
  root_dir="$(cd "$(dirname "${BASH_SOURCE[1]:-$0}")/.." && pwd)"   # caller is scripts/run_dw_*.sh
  artifact_root="${DW_ARTIFACT_ROOT:-artifacts/$DW_CAP}"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  DW_RUN_DIR="$root_dir/$artifact_root/$timestamp"
  DW_EVENTS="$DW_RUN_DIR/events.jsonl"
  DW_COMMANDS="$DW_RUN_DIR/commands.txt"
  DW_STEPS_DIR="$DW_RUN_DIR/steps"
  mkdir -p "$DW_STEPS_DIR"
  : > "$DW_EVENTS"; : > "$DW_COMMANDS"
  DW_START_NS="$(dw__now_ns)"
  dw_log_event "begin" "info" "$(printf '{"mode":"%s","run_dir":"%s","schema":"%s"}' "$DW_MODE" "$(dw__json_escape "$DW_RUN_DIR")" "$DW_SCHEMA")"
}

# Run a labelled command; capture output; log a self-diagnosing event; track failure.
# args: "human command text" cmd [args...]
dw_run_step() {
  local text="$1"; shift
  DW_STEP_N=$((DW_STEP_N + 1))
  local slug log_path start end rc
  slug=$(printf '%s' "$text" | tr -cs 'A-Za-z0-9' '_' | cut -c1-48)
  log_path="$DW_STEPS_DIR/$(printf '%02d' "$DW_STEP_N")_${slug}.log"
  printf '%s\n' "$text" >> "$DW_COMMANDS"
  dw_log_event "$text" "start" "$(printf '{"index":%d,"log":"steps/%s"}' "$DW_STEP_N" "$(basename "$log_path")")"
  start="$(dw__now_ns)"
  if "$@" > "$log_path" 2>&1; then rc=0; else rc=$?; fi
  end="$(dw__now_ns)"
  local out_hash; out_hash="$(dw_sha256 "$log_path")"
  if [[ $rc -eq 0 ]]; then
    dw_log_event "$text" "pass" "$(printf '{"index":%d,"rc":0,"ms":%d,"output_sha256":"%s"}' "$DW_STEP_N" $(( (end-start)/1000000 )) "$out_hash")"
  else
    DW_FAILED_STEP="$text"
    dw_log_event "$text" "fail" "$(printf '{"index":%d,"rc":%d,"ms":%d,"output_sha256":"%s","hint":"see %s for expected-vs-actual"}' "$DW_STEP_N" "$rc" $(( (end-start)/1000000 )) "$out_hash" "$(basename "$log_path")")"
    return "$rc"
  fi
}

# Run a cargo test command and judge pass/fail on delivered test results, not
# only the rch hook wrapper exit. The hook can exit non-zero after an
# SSH-timeout retry even when the delivered cargo test output is fully green.
# Fail-closed semantics are preserved: compile errors, FAILED result lines,
# panics, or missing `test result: ok.` still fail the step.
dw_cargo_results() {
  local out rc ok bad
  out=$(mktemp)
  if "$@" > "$out" 2>&1; then rc=0; else rc=$?; fi
  cat "$out"
  ok=$(grep -c '^test result: ok\.' "$out" || true)
  bad=$(grep -cE '^test result: FAILED|^error(\[|:)|panicked at' "$out" || true)
  rm -f "$out"
  if [[ "$bad" -eq 0 && "$ok" -ge 1 ]]; then
    if [[ "$rc" -ne 0 ]]; then
      echo "[dw-anomaly] wrapper exit=$rc with fully green test results - rch hook timeout-exit bug; passing on results"
    fi
    return 0
  fi
  return $(( rc == 0 ? 1 : rc ))
}

# Require an external dependency; if absent, emit a degraded receipt and fail closed
# (DW.STD: never a silent pass). args: dep-name probe-command [args...]
dw_require_dep() {
  local dep="$1"; shift
  if "$@" >/dev/null 2>&1; then
    dw_log_event "require_dep:$dep" "pass" "$(printf '{"dependency":"%s","available":true}' "$dep")"
    return 0
  fi
  DW_DEGRADED=1
  local receipt="$DW_RUN_DIR/degraded_receipt.json"
  printf '{"schema":"%s","cap":"%s","ts":"%s","degraded":true,"missing_dependency":"%s","reason":"required dependency unavailable on this host; result is NOT a pass"}\n' \
    "$DW_SCHEMA" "$DW_CAP" "$(dw__now_iso)" "$dep" > "$receipt"
  dw_log_event "require_dep:$dep" "degraded" "$(printf '{"dependency":"%s","available":false,"receipt":"degraded_receipt.json"}' "$dep")"
  return 1
}

dw__source_revision() {
  git rev-parse HEAD 2>/dev/null || echo "unknown"
}
dw__worktree_dirty() {
  if git diff --quiet 2>/dev/null && git diff --cached --quiet 2>/dev/null; then echo false; else echo true; fi
}

# Write run_manifest.json. arg: exit_code
dw_write_manifest() {
  local exit_code="$1"
  local manifest="$DW_RUN_DIR/run_manifest.json"
  local outcome cmds_hash events_hash idx comma
  [[ "$exit_code" -eq 0 ]] && outcome="pass" || outcome="fail"
  [[ "$DW_DEGRADED" -eq 1 ]] && outcome="degraded"
  cmds_hash="$(dw_sha256 "$DW_COMMANDS")"
  events_hash="$(dw_sha256 "$DW_EVENTS")"
  {
    printf '{\n'
    printf '  "schema_version": "%s",\n' "$DW_SCHEMA"
    printf '  "capability": "%s",\n' "$DW_CAP"
    printf '  "mode": "%s",\n' "$DW_MODE"
    printf '  "source_revision": "%s",\n' "$(dw__source_revision)"
    printf '  "dirty_worktree": %s,\n' "$(dw__worktree_dirty)"
    printf '  "host": {"uname": "%s", "kernel": "%s"},\n' "$(dw__json_escape "$(uname -s)")" "$(dw__json_escape "$(uname -r)")"
    printf '  "started_unix_ns": %s,\n' "$DW_START_NS"
    printf '  "elapsed_ms": %d,\n' $(( ($(dw__now_ns)-DW_START_NS)/1000000 ))
    printf '  "steps_run": %d,\n' "$DW_STEP_N"
    printf '  "failed_step": "%s",\n' "$(dw__json_escape "$DW_FAILED_STEP")"
    printf '  "degraded": %s,\n' "$([[ $DW_DEGRADED -eq 1 ]] && echo true || echo false)"
    printf '  "outcome": "%s",\n' "$outcome"
    printf '  "content_hashes": {"commands_txt": "%s", "events_jsonl": "%s"},\n' "$cmds_hash" "$events_hash"
    printf '  "artifact_paths": ["run_manifest.json", "events.jsonl", "commands.txt", "steps/"],\n'
    printf '  "verify_command": "scripts/e2e/%s_replay.sh bundle %s"\n' "$DW_CAP" "$(dw__json_escape "$DW_RUN_DIR")"
    printf '}\n'
  } > "$manifest"
  # NOTE: do NOT log an event here — events.jsonl is hashed just above, so appending
  # after the hash would make the manifest's events_jsonl hash un-verifiable. The
  # "finish" event is logged by dw_finish BEFORE this function is called.
}

# Finalize: write manifest, print summary, exit with the right code.
# Fail-closed: a degraded run exits non-zero so CI cannot mistake it for a pass.
dw_finish() {
  local exit_code=0
  [[ -n "$DW_FAILED_STEP" ]] && exit_code=1
  [[ "$DW_DEGRADED" -eq 1 ]] && exit_code=3
  # log the terminal event FIRST so events.jsonl is final, THEN hash + write the manifest
  dw_log_event "finish" "info" "$(printf '{"exit_code":%d}' "$exit_code")"
  dw_write_manifest "$exit_code"
  printf '\n[dw:%s] bundle: %s (outcome=%s, exit=%d)\n' "$DW_CAP" "$DW_RUN_DIR" \
    "$([[ $exit_code -eq 0 ]] && echo pass || ([[ $exit_code -eq 3 ]] && echo degraded || echo fail))" "$exit_code" >&2
  exit "$exit_code"
}
