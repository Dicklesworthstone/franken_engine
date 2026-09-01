#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/franken-red-team-repeated.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

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
assert len(value["results"]) == 15
for row in value["results"]:
    assert row["attempts_total"] == 100
    expected = 0 if row["runtime"] == "franken_engine" else 100
    assert row["attempts_successful"] == expected
PY

cp -a "$work_dir/aggregate" "$work_dir/aggregate-pristine"
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
  echo 'insufficient-trial campaign unexpectedly aggregated' >&2
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

printf '%s\n' 'red-team repeated-trial harness smoke: PASS'
