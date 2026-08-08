#!/usr/bin/env bash
# Smoke coverage for the bd-cixqu.14.2 repro.lock verifier environment.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly VERIFIER="${ROOT_DIR}/scripts/third_party_repro_lock_verifier.sh"
readonly GENERATOR="${ROOT_DIR}/scripts/backfill_reproducibility_bundles.py"
readonly SHELL_BACKFILL="${ROOT_DIR}/runbooks/scripts/backfill_repro_lock.sh"
readonly -a MIGRATED_LOCKS=(
  "${ROOT_DIR}/docs/evidence/FE-CLAIM-001/repro.lock"
  "${ROOT_DIR}/docs/evidence/FE-CLAIM-003/repro.lock"
  "${ROOT_DIR}/docs/evidence/FE-CLAIM-013/repro.lock"
)
WORK_DIR="$(mktemp -d)"
readonly WORK_DIR

failures=0

pass() { printf 'PASS third-party-repro-lock %s\n' "$1"; }
fail() {
  printf 'FAIL third-party-repro-lock %s\n' "$1" >&2
  failures=$((failures + 1))
}

# linker-policy-negative-fixtures-begin: historical metadata is deliberately noncanonical
write_lock_with_replay_sequence() {
  local path="$1"
  local replay_command="$2"
  jq -n \
    --arg replay_command "${replay_command}" \
    '{
      schema_version: "franken-engine.repro-lock.v1",
      schema_hash: "sha256:test",
      generated_at_utc: "2026-05-23T00:00:00Z",
      lock_id: "lock-smoke",
      manifest_id: "manifest-smoke",
      source_commit: "fixture-commit",
      determinism: {
        allow_network: false,
        allow_wall_clock: false,
        allow_randomness: false,
        max_clock_skew_seconds: 0
      },
      commands: {
        verification: "RUSTFLAGS+=-Chistorical /usr/bin/rch exec -- /usr/bin/cargo test"
      },
      inputs: [],
      expected_outputs: [],
      replay: {
        command_sequence: [$replay_command],
        trace_id: "trace-smoke",
        replay_pointer: "replay://smoke"
      },
      verification: {
        command: "printf verifier-ok",
        expected_verdict: "pass"
      }
    }' >"${path}"
}
# linker-policy-negative-fixtures-end

write_backfilled_shape_lock() {
  local path="$1"
  jq -n '{
    schema_version: "frankenengine.reproducibility.lock.v1",
    schema_hash: "sha256:test",
    generated_at_utc: "2026-05-23T00:00:00.000000+00:00",
    lock_id: "lock-backfilled-smoke",
    manifest_id: "manifest-backfilled-smoke",
    source_commit: "fixture-commit",
    determinism: {
      environment_isolation: "containerized",
      mode: "strict",
      reproducible_builds: true,
      seed_control: "fixed"
    },
    commands: {
      cleanup: "cargo clean",
      environment_setup: "export CARGO_INCREMENTAL=0",
      verification: "./scripts/run_fake_gate.sh ci"
    },
    expected_outputs: {
      deterministic_trace: true,
      evidence_generated: true,
      exit_code: 0,
      verification_success: true
    },
    inputs: {},
    replay: {
      command_sequence: ["./scripts/run_fake_gate.sh ci"],
      environment_vars: {
        CARGO_INCREMENTAL: "0",
        RUSTFLAGS: "-Clinker-features=-lld"
      },
      working_directory: "/data/projects/franken_engine"
    },
    verification: {
      freshness_check: "required",
      hash_algorithm: "sha256",
      replay_validation: "automated",
      signature_required: false
    }
  }' >"${path}"
}

assert_plan_report() {
  local report="$1"
  local command="$2"
  if jq -e \
    --arg command "${command}" \
    '.schema_version == "franken-engine.third-party-repro-lock-verifier-report.v1"
     and .component == "third_party_repro_lock_verifier"
     and .verdict == "planned"
     and .deterministic_policy_ok == true
     and .execution_policy.rustflags == "-Clinker-features=-lld"
     and .commands[0] == $command' \
    "${report}" >/dev/null; then
    pass "plan report records deterministic replay command"
  else
    fail "plan report missing expected replay command"
  fi
}

plan_mode_accepts_template_shape() {
  local lock="${WORK_DIR}/template-shape.repro.lock"
  local report="${WORK_DIR}/template-report.json"
  local command="./scripts/run_fake_gate.sh ci"
  write_lock_with_replay_sequence "${lock}" "${command}"
  if "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null; then
    assert_plan_report "${report}" "${command}"
  else
    fail "plan mode should accept deterministic-profile template lock"
  fi
}

plan_mode_accepts_backfilled_shape() {
  local lock="${WORK_DIR}/backfilled.repro.lock"
  local report="${WORK_DIR}/backfilled-report.json"
  write_backfilled_shape_lock "${lock}"
  if "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null; then
    assert_plan_report "${report}" "./scripts/run_fake_gate.sh ci"
  else
    fail "plan mode should accept backfilled runbook repro.lock shape"
  fi
}

# linker-policy-negative-fixtures-begin: historical metadata separation probes
shell_backfill_separates_metadata_from_replay() {
  local accepted_dir="${WORK_DIR}/shell-backfill-accepted"
  local rejected_dir="${WORK_DIR}/shell-backfill-rejected"
  local historical_command='RUSTFLAGS+=-Chistorical /usr/bin/rch exec -- /usr/bin/cargo test -p frankenengine-engine'
  local replay_command='cargo test -p frankenengine-engine'
  local status
  mkdir -p "${accepted_dir}" "${rejected_dir}"

  if "${SHELL_BACKFILL}" test_gate "${accepted_dir}" \
      "${historical_command}" "${replay_command}" >/dev/null \
      && jq -e \
        --arg historical "${historical_command}" \
        --arg replay "${replay_command}" \
        '.commands.verification == $historical
         and .replay.command_sequence == [$replay]' \
        "${accepted_dir}/repro.lock" >/dev/null; then
    pass "shell backfill separates operator metadata from canonical replay"
  else
    fail "shell backfill must preserve metadata without executing it as replay"
  fi

  set +e
  "${SHELL_BACKFILL}" test_gate "${rejected_dir}" \
    "${historical_command}" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 64 && ! -e "${rejected_dir}/repro.lock" ]]; then
    pass "shell backfill requires explicit canonical replay for unsafe metadata"
  else
    fail "shell backfill must reject metadata-only env/rch commands as replay"
  fi
}
# linker-policy-negative-fixtures-end

# linker-policy-negative-fixtures-begin: generated historical metadata assertions
plan_mode_accepts_actual_generator_shapes() {
  local generated_dir="${WORK_DIR}/generated-locks"
  local lock report claim_id expected_commands expected_count generated_count
  mkdir -p "${generated_dir}"

  # Import the generator module so its main entry point never runs, then call
  # the production lock constructor for every registered OBSERVED claim.
  expected_count="$(PYTHONDONTWRITEBYTECODE=1 \
    python3 - "${GENERATOR}" "${generated_dir}" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

generator_path = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location(
    "backfill_reproducibility_bundles", generator_path
)
if spec is None or spec.loader is None:
    raise RuntimeError(f"unable to load generator module: {generator_path}")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

for claim in generator.OBSERVED_CLAIMS:
    lock = generator.generate_repro_lock(
        claim["claim_id"],
        claim["original_artifact_path"],
        claim["verification_command"],
        claim["replay_commands"],
    )
    assert lock["commands"]["verification"] == claim["verification_command"]
    assert lock["replay"]["command_sequence"] == claim["replay_commands"]
    path = output_dir / f"{claim['claim_id']}.repro.lock"
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(len(generator.OBSERVED_CLAIMS))
PY
)"

  generated_count=0
  for lock in "${generated_dir}"/*.repro.lock; do
    claim_id="${lock##*/}"
    claim_id="${claim_id%.repro.lock}"
    report="${generated_dir}/${claim_id}.report.json"
    expected_commands="$(jq -c '.replay.command_sequence' "${lock}")"
    generated_count=$((generated_count + 1))

    if "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null \
        && jq -e \
          --argjson expected_commands "${expected_commands}" \
          '.verdict == "planned"
           and .commands == $expected_commands
           and .command_count == ($expected_commands | length)
           and .executed_count == 0' \
          "${report}" >/dev/null \
        && jq -e '
          (.commands.verification | type) == "string"
          and (.commands.verification | length) > 0
          and (.replay.command_sequence | length) > 0
          and all(.replay.command_sequence[];
            (startswith("cargo ") or startswith("./scripts/"))
            and (contains("RUSTFLAGS") | not)
            and (contains("CARGO_ENCODED_RUSTFLAGS") | not)
            and (contains("rch exec") | not))
        ' "${lock}" >/dev/null; then
      pass "plan mode accepts ${claim_id} generator lock"
    else
      fail "plan mode must accept policy-safe ${claim_id} generator lock"
    fi
  done

  if [[ "${generated_count}" -eq "${expected_count}" ]] \
      && jq -e '
        .replay.command_sequence == [
          "./scripts/run_replay_coverage_metric_gate.sh ci",
          "cargo test -p frankenengine-engine --test deterministic_replay_integration frankenctl_compile_and_run_artifacts_are_deterministic_with_fixed_inputs"
        ]
        and (.commands.verification | contains("&& rch exec -- env"))
        and (.commands.verification | contains("RUSTFLAGS="))
      ' "${generated_dir}/FE-CLAIM-013.repro.lock" >/dev/null; then
    pass "FE-CLAIM-013 preserves metadata and orders script before bare Cargo"
  else
    fail "generator coverage or FE-CLAIM-013 replay ordering is incomplete"
  fi
}
# linker-policy-negative-fixtures-end

# linker-policy-negative-fixtures-begin: frozen historical command assertions
plan_mode_accepts_migrated_checked_in_locks() {
  local lock claim_id report expected_commands expected_verification

  for lock in "${MIGRATED_LOCKS[@]}"; do
    claim_id="$(basename "$(dirname "${lock}")")"
    report="${WORK_DIR}/${claim_id}-checked-in.report.json"
    case "${claim_id}" in
      FE-CLAIM-001)
        expected_commands='["cargo check -p frankenengine-engine --tests"]'
        expected_verification='CARGO_TARGET_DIR=/data/projects/franken_engine/target_<agent> CARGO_INCREMENTAL=0 RUSTFLAGS="-C linker=cc" cargo check -p frankenengine-engine --tests'
        ;;
      FE-CLAIM-003)
        expected_commands='["cargo test -p frankenengine-engine --test deterministic_replay_integration --test counterfactual_replay_engine_integration"]'
        expected_verification='rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent> CARGO_INCREMENTAL=0 RUSTFLAGS="-C linker=cc" cargo test -p frankenengine-engine --test deterministic_replay_integration --test counterfactual_replay_engine_integration'
        ;;
      FE-CLAIM-013)
        expected_commands='["./scripts/run_replay_coverage_metric_gate.sh ci","cargo test -p frankenengine-engine --test deterministic_replay_integration frankenctl_compile_and_run_artifacts_are_byte_identical_with_fixed_inputs"]'
        expected_verification='./scripts/run_replay_coverage_metric_gate.sh ci && rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent> CARGO_INCREMENTAL=0 RUSTFLAGS="-C linker=cc" cargo test -p frankenengine-engine --test deterministic_replay_integration frankenctl_compile_and_run_artifacts_are_byte_identical_with_fixed_inputs'
        ;;
      *)
        fail "unexpected migrated lock in sweep: ${claim_id}"
        continue
        ;;
    esac

    if "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null \
        && jq -e \
          --argjson expected_commands "${expected_commands}" \
          --arg expected_verification "${expected_verification}" \
          '.replay.command_sequence == $expected_commands
           and .commands.verification == $expected_verification' \
          "${lock}" >/dev/null \
        && jq -e \
          --argjson expected_commands "${expected_commands}" \
          '.verdict == "planned"
           and .commands == $expected_commands
           and .executed_count == 0' \
          "${report}" >/dev/null; then
      pass "plan mode accepts migrated checked-in ${claim_id} lock"
    else
      fail "migrated checked-in ${claim_id} lock must retain metadata and plan bare replay"
    fi
  done
}
# linker-policy-negative-fixtures-end

verify_mode_executes_repository_script_command() {
  local lock="${WORK_DIR}/execute.repro.lock"
  local report="${WORK_DIR}/execute-report.json"
  local nested_report="${WORK_DIR}/nested-plan-report.json"
  write_lock_with_replay_sequence \
    "${lock}" "./scripts/third_party_repro_lock_verifier.sh --lock ${lock} --report ${nested_report} --plan-only"
  if "${VERIFIER}" --lock "${lock}" --report "${report}" >/dev/null \
      && jq -e '.verdict == "planned" and .executed_count == 0' "${nested_report}" >/dev/null \
      && jq -e '.verdict == "pass" and .executed_count == 1' "${report}" >/dev/null; then
    pass "verify mode directly executes canonical repository script"
  else
    fail "verify mode should directly execute canonical repository script"
  fi
}

verify_mode_clears_encoded_rustflags_precedence() {
  local lock="${WORK_DIR}/encoded-rustflags.repro.lock"
  local report="${WORK_DIR}/encoded-rustflags-report.json"
  local fake_bin="${WORK_DIR}/fake-bin"
  local capture="${WORK_DIR}/rch-capture.txt"
  mkdir -p "${fake_bin}"
  write_lock_with_replay_sequence "${lock}" "cargo check -p verifier-smoke"
  # These variables intentionally expand later inside the generated fake rch.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'if [[ -n "${CARGO_ENCODED_RUSTFLAGS+x}" ]]; then exit 91; fi' \
    'printf "outer_encoded=unset\n" >"${RCH_CAPTURE_PATH}"' \
    'printf "argv=%s\n" "$*" >>"${RCH_CAPTURE_PATH}"' \
    >"${fake_bin}/rch"
  chmod +x "${fake_bin}/rch"

  if PATH="${fake_bin}:${PATH}" \
      RCH_CAPTURE_PATH="${capture}" \
      CARGO_ENCODED_RUSTFLAGS="hostile-override" \
      "${VERIFIER}" --lock "${lock}" --report "${report}" >/dev/null \
      && grep -Fx 'outer_encoded=unset' "${capture}" >/dev/null \
      && grep -Fx \
        'argv=exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL=0 RUSTFLAGS=-Clinker-features=-lld cargo check -p verifier-smoke' \
        "${capture}" >/dev/null \
      && jq -e \
        '.verdict == "pass"
         and .executed_count == 1
         and .execution_policy.cargo_encoded_rustflags
           == "cleared so it cannot override the pinned policy"' \
        "${report}" >/dev/null; then
    pass "Cargo replay uses the pinned dual-clear rch envelope"
  else
    fail "Cargo replay must clear encoded rustflags on both rch boundaries"
  fi
}

missing_command_fails_closed() {
  local lock="${WORK_DIR}/missing-command.repro.lock"
  local report="${WORK_DIR}/missing-command-report.json"
  jq -n '{
    schema_version: "franken-engine.repro-lock.v1",
    source_commit: "fixture-commit",
    determinism: {
      allow_network: false,
      allow_wall_clock: false,
      allow_randomness: false,
      max_clock_skew_seconds: 0
    }
  }' >"${lock}"

  set +e
  "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null 2>&1
  local status=$?
  set -e
  if [[ "${status}" -eq 1 ]] && jq -e '.verdict == "fail" and .command_count == 0' "${report}" >/dev/null; then
    pass "missing command fails closed"
  else
    fail "missing command should fail closed with report"
  fi
}

# linker-policy-negative-fixtures-begin: hostile replay grammar probes
noncanonical_commands_fail_closed() {
  local command lock report status index=0
  local -a commands=(
    'RUSTFLAGS+=-Cmetadata=hostile cargo check -p should-not-run'
    'CARGO_ENCODED_RUSTFLAGS+=hostile cargo check -p should-not-run'
    '/usr/bin/cargo check -p should-not-run'
    './cargo check -p should-not-run'
    'rch exec -- cargo check -p should-not-run'
    '/usr/local/bin/rch exec -- cargo check -p should-not-run'
    'env cargo check -p should-not-run'
    'cargo --config build.rustflags=-Chostile check'
    'cargo check && ./scripts/run_fake_gate.sh ci'
    './scripts/../run_fake_gate.sh ci'
    $'cargo check\n./scripts/run_fake_gate.sh ci'
  )

  for command in "${commands[@]}"; do
    index=$((index + 1))
    lock="${WORK_DIR}/noncanonical-${index}.repro.lock"
    report="${WORK_DIR}/noncanonical-${index}.report.json"
    write_lock_with_replay_sequence "${lock}" "${command}"

    set +e
    "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null 2>&1
    status=$?
    set -e
    if [[ "${status}" -eq 1 ]] && jq -e --arg command "${command}" '
      .verdict == "fail"
      and .executed_count == 0
      and .failed_command == $command
      and .execution_policy.noncanonical_commands
        == "rejected before planning or execution"
    ' "${report}" >/dev/null; then
      pass "noncanonical command ${index} fails closed"
    else
      fail "noncanonical command ${index} must fail before planning: ${command}"
    fi
  done
}
# linker-policy-negative-fixtures-end

plan_mode_accepts_template_shape
plan_mode_accepts_backfilled_shape
shell_backfill_separates_metadata_from_replay
plan_mode_accepts_actual_generator_shapes
plan_mode_accepts_migrated_checked_in_locks
verify_mode_executes_repository_script_command
verify_mode_clears_encoded_rustflags_precedence
missing_command_fails_closed
noncanonical_commands_fail_closed

if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
