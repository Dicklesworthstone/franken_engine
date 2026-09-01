#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/franken-red-team-repeated.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

python3 - "$root_dir" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
import red_team_compromise_rate_corpus as corpus
import red_team_compromise_rate_metric as comparator

corpus.install_corpus()
assert comparator.SCENARIOS == corpus.SCENARIOS
assert len(corpus.SCENARIOS) == 10
assert len({scenario.scenario_id for scenario in corpus.SCENARIOS}) == 10
assert {scenario.attack_class for scenario in corpus.SCENARIOS} == {
    "ambient_authority_escape",
    "prototype_pollution",
    "supply_chain_execution",
}
scenario_dir = root / "crates/franken-engine/tests/red_team_scenarios"
for scenario in corpus.SCENARIOS:
    script = scenario_dir / f"{scenario.scenario_id}.js"
    manifest_path = scenario_dir / f"{scenario.scenario_id}.manifest.json"
    assert script.is_file(), script
    assert manifest_path.is_file(), manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["name"] == scenario.scenario_id
    assert manifest["payload"]["program"] == script.name
PY

python3 - "$work_dir" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
scenarios = (
    ("environment_variable_exfiltration", "ambient_authority_escape"),
    ("process_privilege_surface_probe", "ambient_authority_escape"),
    ("prototype_pollution_capability_escape", "prototype_pollution"),
    ("shell_command_injection_package_script", "ambient_authority_escape"),
    ("supply_chain_backdoor_execution", "supply_chain_execution"),
    ("ambient_authority_via_globalthis", "ambient_authority_escape"),
    ("capability_shadowed_import", "ambient_authority_escape"),
    ("reflect_apply_authority_smuggling", "ambient_authority_escape"),
    ("typed_effect_laundering_downcast", "ambient_authority_escape"),
    ("smuggle_flow_via_unanalyzed_construct", "ambient_authority_escape"),
)
runtimes = ("node", "bun", "frankenengine")


def dump(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path: pathlib.Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


(root / "bin").mkdir(parents=True)
identities = {}
for runtime in runtimes:
    executable = root / "bin" / runtime
    executable.write_text(f"#!/bin/sh\nprintf '%s\\n' {runtime}-fixture-v1\n", encoding="utf-8")
    executable.chmod(0o755)
    identities[runtime] = {
        "runtime": runtime,
        "executable_path": executable.relative_to(root).as_posix(),
        "executable_sha256": sha(executable),
        "version_command": [str(executable), "--version"],
        "version_exit_code": 0,
        "version_stdout": f"{runtime}-fixture-v1",
        "version_stderr": "",
    }

scenario_bindings = {}
for scenario_id, _ in scenarios:
    script = root / "scenarios" / f"{scenario_id}.js"
    manifest = root / "scenarios" / f"{scenario_id}.manifest.json"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(f"// {scenario_id} synthetic smoke payload\n", encoding="utf-8")
    dump(manifest, {"name": scenario_id, "payload": {"program": script.name}})
    scenario_bindings[scenario_id] = (script, manifest, sha(script), sha(manifest))

for trial_index in range(1, 101):
    trial_id = f"trial-{trial_index:04d}"
    trial = root / "trials" / trial_id
    dump(trial / "bundle_status.json", {
        "status": "pass",
        "reason": "synthetic_receipt_fixture",
        "failure_count": 0,
        "exit_code": 0,
        "verdict_scope": "single_repetition_receipt_only_not_claim_verdict",
    })
    dump(trial / "runtime_inventory.json", {
        "schema_version": "franken-engine.red-team-compromise-rate-runtime-inventory.v1",
        "code_revision": "rev-smoke",
        "runtimes": [identities[runtime] for runtime in runtimes],
    })
    rows = []
    for scenario_id, attack_class in scenarios:
        script, manifest, script_hash, manifest_hash = scenario_bindings[scenario_id]
        runtime_receipts = {}
        dispositions = {}
        for runtime in runtimes:
            attack_succeeded = runtime != "frankenengine"
            dispositions[runtime] = attack_succeeded
            transcript_path = trial / "transcripts" / f"{scenario_id}.{runtime}.json"
            dump(transcript_path, {
                "schema_version": "franken-engine.red-team-compromise-rate-runtime-transcript.v2",
                "scenario_id": scenario_id,
                "attack_class": attack_class,
                "runtime": runtime,
                "code_revision": "rev-smoke",
                "script_path": script.relative_to(root).as_posix(),
                "script_sha256": script_hash,
                "manifest_path": manifest.relative_to(root).as_posix(),
                "manifest_sha256": manifest_hash,
                "runtime_identity": identities[runtime],
                "command": [runtime, scenario_id],
                "exit_code": 0 if attack_succeeded else 1,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "duration_ms": trial_index,
                "attack_succeeded": attack_succeeded,
                "disposition_source": "synthetic.explicit",
                "measurement_status": "observed",
                "is_placeholder_data": False,
                "frankenengine_report": None,
            })
            runtime_receipts[runtime] = {
                "transcript_path": transcript_path.relative_to(root).as_posix(),
                "transcript_hash": sha(transcript_path),
                "disposition_source": "synthetic.explicit",
            }
        witness_path = trial / "witnesses" / f"{scenario_id}.json"
        dump(witness_path, {
            "schema_version": "franken-engine.red-team-compromise-rate-witness.v2",
            "scenario_id": scenario_id,
            "attack_class": attack_class,
            "security_critical": True,
            "measurement_status": "observed",
            "is_placeholder_data": False,
            "code_revision": "rev-smoke",
            "script_path": script.relative_to(root).as_posix(),
            "script_sha256": script_hash,
            "manifest_path": manifest.relative_to(root).as_posix(),
            "manifest_sha256": manifest_hash,
            "runtime_receipts": {
                runtime: {
                    "path": runtime_receipts[runtime]["transcript_path"],
                    "sha256": runtime_receipts[runtime]["transcript_hash"],
                    "attack_succeeded": dispositions[runtime],
                    "disposition_source": "synthetic.explicit",
                }
                for runtime in runtimes
            },
        })
        rows.append({
            "schema_version": "franken-engine.red-team-compromise-rate-scenario-row.v2",
            "scenario_id": scenario_id,
            "attack_class": attack_class,
            "security_critical": True,
            "measurement_status": "observed",
            "is_placeholder_data": False,
            "frankenengine_attacker_succeeded": False,
            "frankenengine_measured_attacker_succeeded": False,
            "node_attacker_succeeded": True,
            "bun_attacker_succeeded": True,
            "runtime_receipts": runtime_receipts,
            "witness_path": witness_path.relative_to(root).as_posix(),
            "witness_hash": sha(witness_path),
            "replay_command": "synthetic-smoke-replay",
            "replay_exit_code": 0,
            "duration_ms": trial_index * 3,
            "negative_fixture": None,
        })
    (trial / "scenarios.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
PY

python3 "$root_dir/scripts/aggregate_red_team_trials.py" aggregate \
  --root "$work_dir" \
  --trial-root "$work_dir/trials" \
  --output-dir "$work_dir/aggregate" \
  --code-revision rev-smoke \
  --verification-command './scripts/run_bd_28otw_attacker_harness.sh --replay --harness-output aggregate/harness_output.json'

python3 "$root_dir/scripts/annotate_red_team_harness_semantics.py" \
  "$work_dir/aggregate/harness_output.json"
python3 "$root_dir/scripts/annotate_red_team_harness_semantics.py" \
  "$work_dir/aggregate/harness_output.json" --check

python3 "$root_dir/scripts/aggregate_red_team_trials.py" verify \
  --root "$work_dir" \
  --harness-output "$work_dir/aggregate/harness_output.json"

python3 "$root_dir/scripts/aggregate_red_team_trials.py" verify \
  --root "$work_dir" \
  --harness-output "$work_dir/aggregate/harness_output.json" \
  --scenario environment_variable_exfiltration \
  --runtime franken_engine

python3 - "$work_dir/aggregate/harness_output.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert value["schema_version"] == "franken-engine.red-team-harness-output.v1"
assert value["min_trials_per_runtime"] == 100
assert value["corpus_id"] == "red_team_security_critical_compromise_v2"
assert value["denominator_semantics"] == "distinct_security_critical_scenarios"
assert value["repetition_role"] == "stability_and_replay_not_independent_sampling"
assert value["confidence_interpretation"] == "receipt_completeness_and_stability_not_population_confidence"
assert value["zero_cell_guard"] == "one_hypothetical_frankenengine_compromise"
assert value["distinct_scenario_count"] == 10
assert value["attack_class_count"] == 3
assert value["runtime_scenario_pair_count"] == 30
assert len(value["results"]) == 30
for row in value["results"]:
    assert row["attempts_total"] == 100
    expected = 0 if row["runtime"] == "franken_engine" else 100
    assert row["attempts_successful"] == expected
PY

cp -a "$work_dir/aggregate" "$work_dir/aggregate-pristine"
python3 - "$work_dir/aggregate/harness_output.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["distinct_scenario_count"] = 11
path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "$root_dir/scripts/annotate_red_team_harness_semantics.py" \
  "$work_dir/aggregate/harness_output.json" --check >/dev/null 2>&1; then
  echo 'semantic annotation tamper unexpectedly passed validation' >&2
  exit 1
fi
rm -rf "$work_dir/aggregate"
cp -a "$work_dir/aggregate-pristine" "$work_dir/aggregate"

python3 - "$work_dir/aggregate/transcripts/environment_variable_exfiltration.node.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["attempts_total"] = 99
path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "$root_dir/scripts/aggregate_red_team_trials.py" verify \
  --root "$work_dir" \
  --harness-output "$work_dir/aggregate/harness_output.json" >/dev/null 2>&1; then
  echo 'aggregate transcript tamper unexpectedly passed replay' >&2
  exit 1
fi
rm -rf "$work_dir/aggregate"
mv "$work_dir/aggregate-pristine" "$work_dir/aggregate"

python3 - "$work_dir/trials/trial-0001/transcripts/environment_variable_exfiltration.node.json" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(path.read_bytes() + b"\n")
PY
if python3 "$root_dir/scripts/aggregate_red_team_trials.py" verify \
  --root "$work_dir" \
  --harness-output "$work_dir/aggregate/harness_output.json" >/dev/null 2>&1; then
  echo 'source receipt tamper unexpectedly passed replay' >&2
  exit 1
fi

rm -rf "$work_dir/aggregate-too-small"
if python3 "$root_dir/scripts/aggregate_red_team_trials.py" aggregate \
  --root "$work_dir" \
  --trial-root "$work_dir/trials" \
  --output-dir "$work_dir/aggregate-too-small" \
  --code-revision rev-smoke \
  --verification-command synthetic \
  --minimum-trials 101 >/dev/null 2>&1; then
  echo 'insufficient-repetition campaign unexpectedly aggregated' >&2
  exit 1
fi
python3 - "$work_dir/aggregate-too-small/aggregation_blocker.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert value["status"] == "fail_closed"
assert value["reason"] == "insufficient_trials"
assert value["placeholder_results_emitted"] is False
PY

printf '%s\n' 'red-team scenario-corpus stability harness smoke: PASS'
