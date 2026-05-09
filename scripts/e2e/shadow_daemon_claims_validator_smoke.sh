#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VALIDATOR="$PROJECT_ROOT/scripts/validate_shadow_daemon_claims.sh"
BASE_PROOF_DOC="$PROJECT_ROOT/docs/SHADOW_DAEMON_PROOF_STATE.md"
BASE_DRILL="$PROJECT_ROOT/scripts/e2e/shadow_daemon_lifecycle_drill.sh"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
ARTIFACT_DIR="${SHADOW_CLAIMS_VALIDATOR_SMOKE_DIR:-$PROJECT_ROOT/tmp/shadow_daemon_claims_validator_smoke_$RUN_ID}"
CASES_DIR="$ARTIFACT_DIR/cases"
COMMANDS_FILE="$ARTIFACT_DIR/commands.txt"
RESULTS_JSONL="$ARTIFACT_DIR/case_results.jsonl"
COVERAGE_MD="$ARTIFACT_DIR/coverage_matrix.md"

mkdir -p "$CASES_DIR"
: > "$COMMANDS_FILE"
: > "$RESULTS_JSONL"

record_result() {
    local case_name="$1"
    local expected="$2"
    local status="$3"
    local outcome="$4"
    local expected_diagnostic="$5"
    local diagnostic_matched="$6"
    local stdout_path="$7"
    local stderr_path="$8"

    python3 - "$RESULTS_JSONL" "$case_name" "$expected" "$status" "$outcome" "$expected_diagnostic" "$diagnostic_matched" "$stdout_path" "$stderr_path" <<'PY'
import json
import sys

path, case_name, expected, status, outcome, expected_diagnostic, diagnostic_matched, stdout_path, stderr_path = sys.argv[1:]
row = {
    "case": case_name,
    "expected": expected,
    "expected_diagnostic": expected_diagnostic,
    "diagnostic_matched": diagnostic_matched == "true",
    "status": int(status),
    "outcome": outcome,
    "stdout": stdout_path,
    "stderr": stderr_path,
}
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

copy_fixture_inputs() {
    local case_dir="$1"
    local proof_doc="$case_dir/SHADOW_DAEMON_PROOF_STATE.md"
    local drill="$case_dir/shadow_daemon_lifecycle_drill.sh"

    cp "$BASE_PROOF_DOC" "$proof_doc"
    cp "$BASE_DRILL" "$drill"

    printf '%s\n' "$proof_doc" "$drill"
}

mark_no_mock_gate_green() {
    local proof_doc="$1"

    python3 - "$proof_doc" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
for index, line in enumerate(lines):
    if "- **Status**:" in line and "BLOCKED" in line:
        lines[index] = "- **Status**: GREEN"
        break
else:
    raise SystemExit("could not find blocked no_mock_drill status")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

remove_synthetic_exit_guard() {
    local drill="$1"

    python3 - "$drill" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if "EXIT_SYNTHETIC_EVIDENCE" not in text:
    raise SystemExit("could not find synthetic exit guard")
path.write_text(text.replace("EXIT_SYNTHETIC_EVIDENCE", "EXIT_REMOVED_SYNTHETIC_GUARD"), encoding="utf-8")
PY
}

append_bare_shadow_cargo_invocation() {
    local drill="$1"

    {
        printf '\n'
        printf '# regression fixture: cargo run --bin shadow_replay_verify\n'
    } >> "$drill"
}

run_validator_case() {
    local case_name="$1"
    local expected="$2"
    local expected_diagnostic="$3"
    local proof_doc="$4"
    local drill="$5"
    local case_dir="$CASES_DIR/$case_name"
    local stdout_path="$case_dir/stdout.txt"
    local stderr_path="$case_dir/stderr.txt"
    local status=0
    local outcome="pass"
    local diagnostic_matched="false"

    mkdir -p "$case_dir"

    printf 'case=%s expected=%s diagnostic=%q SHADOW_PROOF_DOC=%q SHADOW_LIFECYCLE_DRILL=%q bash %q validate\n' \
        "$case_name" "$expected" "$expected_diagnostic" "$proof_doc" "$drill" "$VALIDATOR" >> "$COMMANDS_FILE"

    set +e
    SHADOW_PROOF_DOC="$proof_doc" SHADOW_LIFECYCLE_DRILL="$drill" bash "$VALIDATOR" validate > "$stdout_path" 2> "$stderr_path"
    status=$?
    set -e

    if [[ "$expected" == "success" && "$status" -ne 0 ]]; then
        outcome="fail"
    elif [[ "$expected" == "failure" && "$status" -eq 0 ]]; then
        outcome="fail"
    fi

    if grep -Fq -- "$expected_diagnostic" "$stdout_path" || grep -Fq -- "$expected_diagnostic" "$stderr_path"; then
        diagnostic_matched="true"
    else
        outcome="fail"
    fi

    record_result "$case_name" "$expected" "$status" "$outcome" "$expected_diagnostic" "$diagnostic_matched" "$stdout_path" "$stderr_path"

    if [[ "$outcome" == "fail" ]]; then
        return 1
    fi

    return 0
}

write_coverage_matrix() {
    cat > "$COVERAGE_MD" <<EOF
# Shadow Claim Validator Smoke Coverage

| Requirement | Positive case | Negative case | Expected diagnostic |
| --- | --- | --- | --- |
| Repository proof-state doc and lifecycle drill remain truthful | real_repository_inputs | n/a | VALIDATION PASSED |
| no_mock_drill must not be documented green | real_repository_inputs | green_no_mock_gate | no_mock_drill is still documented as green |
| no_mock_drill must remain documented blocked | real_repository_inputs | green_no_mock_gate | no_mock_drill is still documented as green |
| Lifecycle drill must keep a synthetic-evidence exit guard | real_repository_inputs | missing_synthetic_exit_guard | Lifecycle drill no longer has a synthetic-evidence exit guard |
| Synthetic lifecycle drill must not invoke bare shadow helper Cargo commands | real_repository_inputs | bare_shadow_helper_cargo | Synthetic lifecycle drill still invokes shadow helper binaries via bare cargo |

Artifacts:
- Commands: $COMMANDS_FILE
- Case verdicts: $RESULTS_JSONL
EOF
}

main() {
    local failures=0
    local case_dir
    local proof_doc
    local drill

    echo "Writing shadow claim validator smoke artifacts to $ARTIFACT_DIR"

    if ! run_validator_case "real_repository_inputs" "success" "VALIDATION PASSED" "$BASE_PROOF_DOC" "$BASE_DRILL"; then
        failures=$((failures + 1))
    fi

    case_dir="$CASES_DIR/green_no_mock_gate"
    mkdir -p "$case_dir"
    mapfile -t green_inputs < <(copy_fixture_inputs "$case_dir")
    proof_doc="${green_inputs[0]}"
    drill="${green_inputs[1]}"
    mark_no_mock_gate_green "$proof_doc"
    if ! run_validator_case "green_no_mock_gate" "failure" "no_mock_drill is still documented as green" "$proof_doc" "$drill"; then
        failures=$((failures + 1))
    fi

    case_dir="$CASES_DIR/missing_synthetic_exit_guard"
    mkdir -p "$case_dir"
    mapfile -t missing_guard_inputs < <(copy_fixture_inputs "$case_dir")
    proof_doc="${missing_guard_inputs[0]}"
    drill="${missing_guard_inputs[1]}"
    remove_synthetic_exit_guard "$drill"
    if ! run_validator_case "missing_synthetic_exit_guard" "failure" "Lifecycle drill no longer has a synthetic-evidence exit guard" "$proof_doc" "$drill"; then
        failures=$((failures + 1))
    fi

    case_dir="$CASES_DIR/bare_shadow_helper_cargo"
    mkdir -p "$case_dir"
    mapfile -t bare_cargo_inputs < <(copy_fixture_inputs "$case_dir")
    proof_doc="${bare_cargo_inputs[0]}"
    drill="${bare_cargo_inputs[1]}"
    append_bare_shadow_cargo_invocation "$drill"
    if ! run_validator_case "bare_shadow_helper_cargo" "failure" "Synthetic lifecycle drill still invokes shadow helper binaries via bare cargo" "$proof_doc" "$drill"; then
        failures=$((failures + 1))
    fi

    write_coverage_matrix

    if [[ "$failures" -gt 0 ]]; then
        echo "Shadow claim validator smoke failed: $failures case(s) missed expectation"
        echo "Artifacts: $ARTIFACT_DIR"
        exit 1
    fi

    echo "Shadow claim validator smoke passed"
    echo "Artifacts: $ARTIFACT_DIR"
}

main "$@"
