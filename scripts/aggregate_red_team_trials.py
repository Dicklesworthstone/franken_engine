#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from red_team_trial_common import (
    BLOCKER_SCHEMA,
    DETAILS_SCHEMA,
    HARNESS_SCHEMA,
    RUNTIME_ORDER,
    RUST_RUNTIME_NAMES,
    SCENARIO_SET,
    TRANSCRIPT_SCHEMA,
    WITNESS_SCHEMA,
    AggregationBlocked,
    TrialReceipt,
    load_json,
    require_object,
    resolve_artifact,
    root_relative,
    runtime_inventory_key,
    sha256_ref,
    verify_hash,
    write_json,
    write_jsonl,
)
from red_team_trial_reader import verify_trial, verify_trial_set


def aggregate(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    trial_root = args.trial_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        if args.minimum_trials < 100 and os.environ.get("RED_TEAM_HARNESS_ALLOW_TEST_MINIMUM") != "true":
            raise AggregationBlocked(
                "unsafe_trial_minimum",
                "Use the production minimum of 100 trials; only hermetic smoke fixtures may lower it",
                f"requested minimum_trials={args.minimum_trials}",
            )
        try:
            trial_dirs = sorted(
                path for path in trial_root.iterdir() if path.is_dir() and path.name.startswith("trial-")
            )
        except FileNotFoundError as exc:
            raise AggregationBlocked(
                "missing_trial_root",
                "Run the receipt-bound comparator campaign before aggregation",
                f"trial root does not exist: {trial_root}",
            ) from exc
        if len(trial_dirs) < args.minimum_trials:
            raise AggregationBlocked(
                "insufficient_trials",
                "Run at least 100 complete receipt-bound trials before aggregation",
                f"found {len(trial_dirs)} trial directories, below required {args.minimum_trials}",
            )
        receipts: list[TrialReceipt] = []
        inventory_key: str | None = None
        inventory_value: dict[str, Any] | None = None
        trial_index: list[dict[str, Any]] = []
        for trial_dir in trial_dirs:
            trial_receipts, inventory, status = verify_trial(root, trial_dir, args.code_revision)
            key = runtime_inventory_key(inventory)
            if inventory_key is None:
                inventory_key = key
                inventory_value = inventory
            elif key != inventory_key:
                raise AggregationBlocked(
                    "runtime_inventory_drift",
                    "Rerun the campaign after pinning one exact Node, Bun, and FrankenEngine executable set",
                    f"runtime inventory changed at {trial_dir.name}",
                )
            receipts.extend(trial_receipts)
            trial_index.append(
                {
                    "trial_id": trial_dir.name,
                    "bundle_path": root_relative(trial_dir, root),
                    "bundle_status": status.get("status"),
                    "runtime_inventory_path": root_relative(trial_dir / "runtime_inventory.json", root),
                    "runtime_inventory_hash": sha256_ref(trial_dir / "runtime_inventory.json"),
                    "scenarios_path": root_relative(trial_dir / "scenarios.jsonl", root),
                    "scenarios_hash": sha256_ref(trial_dir / "scenarios.jsonl"),
                }
            )
        scenario_ids, metadata = verify_trial_set(receipts, args.minimum_trials)
        trial_index_path = output_dir / "trial_index.jsonl"
        write_jsonl(trial_index_path, trial_index)
        runtime_inventory_path = output_dir / "runtime_inventory.json"
        write_json(runtime_inventory_path, inventory_value)

        per_key: dict[tuple[str, str], list[TrialReceipt]] = defaultdict(list)
        for receipt in receipts:
            per_key[(receipt.scenario_id, receipt.runtime)].append(receipt)
        results: list[dict[str, Any]] = []
        harness_output_path = output_dir / "harness_output.json"
        for scenario_id in scenario_ids:
            attack_class = metadata[scenario_id]["attack_class"]
            script_path, script_hash, manifest_path, manifest_hash = metadata[scenario_id]["script_binding"]
            for runtime in RUNTIME_ORDER:
                entries = sorted(per_key[(scenario_id, runtime)], key=lambda entry: entry.trial_id)
                attempts_successful = sum(entry.attack_succeeded for entry in entries)
                duration_ms = sum(entry.duration_ms for entry in entries)
                aggregate_transcript_path = output_dir / "transcripts" / f"{scenario_id}.{runtime}.json"
                aggregate_transcript = {
                    "schema_version": TRANSCRIPT_SCHEMA,
                    "code_revision": args.code_revision,
                    "scenario_id": scenario_id,
                    "attack_class": attack_class,
                    "security_critical": True,
                    "runtime": RUST_RUNTIME_NAMES[runtime],
                    "attempts_total": len(entries),
                    "attempts_successful": attempts_successful,
                    "duration_ms": duration_ms,
                    "runtime_identity": entries[0].runtime_identity,
                    "script_path": script_path,
                    "script_hash": script_hash,
                    "manifest_path": manifest_path,
                    "manifest_hash": manifest_hash,
                    "trials": [
                        {
                            "trial_id": entry.trial_id,
                            "attack_succeeded": entry.attack_succeeded,
                            "duration_ms": entry.duration_ms,
                            "transcript_path": entry.transcript_path,
                            "transcript_hash": entry.transcript_hash,
                            "witness_path": entry.witness_path,
                            "witness_hash": entry.witness_hash,
                        }
                        for entry in entries
                    ],
                }
                write_json(aggregate_transcript_path, aggregate_transcript)
                aggregate_transcript_hash = sha256_ref(aggregate_transcript_path)
                aggregate_witness_path = output_dir / "witnesses" / f"{scenario_id}.{runtime}.json"
                write_json(
                    aggregate_witness_path,
                    {
                        "schema_version": WITNESS_SCHEMA,
                        "code_revision": args.code_revision,
                        "scenario_id": scenario_id,
                        "attack_class": attack_class,
                        "security_critical": True,
                        "runtime": RUST_RUNTIME_NAMES[runtime],
                        "attempts_total": len(entries),
                        "attempts_successful": attempts_successful,
                        "aggregate_transcript_path": root_relative(aggregate_transcript_path, root),
                        "aggregate_transcript_hash": aggregate_transcript_hash,
                        "runtime_executable_sha256": entries[0].runtime_identity["executable_sha256"],
                        "trial_index_path": root_relative(trial_index_path, root),
                        "trial_index_hash": sha256_ref(trial_index_path),
                    },
                )
                replay_command = (
                    "python3 scripts/aggregate_red_team_trials.py verify "
                    f"--root . --harness-output {root_relative(harness_output_path, root)} "
                    f"--scenario {scenario_id} --runtime {RUST_RUNTIME_NAMES[runtime]} "
                    f"--minimum-trials {args.minimum_trials}"
                )
                results.append(
                    {
                        "scenario_id": scenario_id,
                        "attack_class": attack_class,
                        "security_critical": True,
                        "runtime": RUST_RUNTIME_NAMES[runtime],
                        "attempts_total": len(entries),
                        "attempts_successful": attempts_successful,
                        "witness_path": root_relative(aggregate_witness_path, root),
                        "witness_hash": sha256_ref(aggregate_witness_path),
                        "transcript_path": root_relative(aggregate_transcript_path, root),
                        "transcript_hash": aggregate_transcript_hash,
                        "replay_command": replay_command,
                        "replay_exit_code": 0,
                        "duration_ms": duration_ms,
                    }
                )
        details_path = output_dir / "measurement_details.json"
        write_json(
            details_path,
            {
                "schema_version": DETAILS_SCHEMA,
                "code_revision": args.code_revision,
                "scenario_set": SCENARIO_SET,
                "minimum_trials_per_runtime": args.minimum_trials,
                "trials_total": len(trial_dirs),
                "trial_index_path": root_relative(trial_index_path, root),
                "trial_index_hash": sha256_ref(trial_index_path),
                "runtime_inventory_path": root_relative(runtime_inventory_path, root),
                "runtime_inventory_hash": sha256_ref(runtime_inventory_path),
                "results": results,
            },
        )
        write_json(
            harness_output_path,
            {
                "schema_version": HARNESS_SCHEMA,
                "code_revision": args.code_revision,
                "freshness_days": 0,
                "scenario_set": SCENARIO_SET,
                "artifact_path": root_relative(details_path, root),
                "artifact_hash": sha256_ref(details_path),
                "verification_command": args.verification_command,
                "redaction_status": "redacted",
                "confidence_millionths": 1_000_000,
                "min_trials_per_runtime": args.minimum_trials,
                "results": results,
            },
        )
        verify_harness(root, harness_output_path, None, None, args.minimum_trials)
        write_json(
            output_dir / "bundle_status.json",
            {
                "schema_version": "franken-engine.red-team-repeated-trial-status.v1",
                "status": "pass",
                "reason": "receipt_bound_repeated_trial_harness_verified",
                "harness_output_path": root_relative(harness_output_path, root),
                "harness_output_hash": sha256_ref(harness_output_path),
            },
        )
        print(f"red_team_harness_output={harness_output_path}")
        return 0
    except AggregationBlocked as blocked:
        _write_blocker(output_dir, blocked.reason, blocked.detail, blocked.remediation)
        print(f"repeated-trial aggregation blocked: {blocked.reason}: {blocked.detail}", file=sys.stderr)
        return 1
    except Exception as error:
        _write_blocker(
            output_dir,
            "aggregation_internal_error",
            f"{type(error).__name__}: {error}",
            "Inspect and repair the aggregator; do not convert an internal failure into measurement evidence",
        )
        print(f"repeated-trial aggregation failed closed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


def _write_blocker(output_dir: Path, reason: str, detail: str, remediation: str) -> None:
    write_json(
        output_dir / "aggregation_blocker.json",
        {
            "schema_version": BLOCKER_SCHEMA,
            "status": "fail_closed",
            "reason": reason,
            "detail": detail,
            "remediation": remediation,
            "placeholder_results_emitted": False,
        },
    )


def verify_harness(
    root: Path,
    harness_output_path: Path,
    scenario_filter: str | None,
    runtime_filter: str | None,
    minimum_trials: int,
) -> None:
    output = require_object(load_json(harness_output_path, "harness output"), "harness output")
    if output.get("schema_version") != HARNESS_SCHEMA:
        raise AggregationBlocked(
            "unsupported_harness_schema",
            "Regenerate the bundle with the current repeated-trial producer",
            f"unsupported schema_version {output.get('schema_version')!r}",
        )
    declared_minimum = output.get("min_trials_per_runtime")
    if not isinstance(declared_minimum, int) or declared_minimum < minimum_trials:
        raise AggregationBlocked(
            "insufficient_trials",
            "Replay an output produced with at least the requested number of trials",
            f"declared minimum {declared_minimum!r} is below required {minimum_trials}",
        )
    artifact_path = resolve_artifact(output.get("artifact_path"), root, "artifact_path")
    verify_hash(artifact_path, output.get("artifact_hash"), "artifact_hash")
    details = require_object(load_json(artifact_path, "measurement details"), "measurement details")
    if details.get("schema_version") != DETAILS_SCHEMA:
        raise AggregationBlocked(
            "unsupported_measurement_details_schema",
            "Regenerate the bundle with the current repeated-trial producer",
            f"unsupported details schema {details.get('schema_version')!r}",
        )
    results = output.get("results")
    if details.get("results") != results:
        raise AggregationBlocked(
            "measurement_details_mismatch",
            "Discard the modified bundle and regenerate it from immutable trial receipts",
            "harness_output results do not match the hash-bound measurement details",
        )
    if not isinstance(results, list) or not results:
        raise AggregationBlocked(
            "missing_harness_results",
            "Regenerate the repeated-trial bundle",
            "harness output contains no results",
        )
    seen: set[tuple[str, str]] = set()
    selected = 0
    valid_runtimes = set(RUST_RUNTIME_NAMES.values())
    for raw in results:
        result = require_object(raw, "harness result")
        scenario_id = result.get("scenario_id")
        runtime = result.get("runtime")
        if not isinstance(scenario_id, str) or runtime not in valid_runtimes:
            raise AggregationBlocked(
                "invalid_harness_result",
                "Regenerate the repeated-trial bundle with valid scenario and runtime identifiers",
                f"invalid result identity: {scenario_id!r}/{runtime!r}",
            )
        key = (scenario_id, runtime)
        if result.get("security_critical") is not True:
            raise AggregationBlocked(
                "noncritical_harness_result",
                "Regenerate the FE-CLAIM-011 bundle with security-critical rows only",
                f"{scenario_id}/{runtime} is not security_critical",
            )
        replay_command = result.get("replay_command")
        if result.get("replay_exit_code") != 0 or not isinstance(replay_command, str) or not replay_command.strip():
            raise AggregationBlocked(
                "unreplayable_harness_result",
                "Regenerate the bundle with a successful, explicit replay command for every result",
                f"{scenario_id}/{runtime} has incomplete replay metadata",
            )
        if key in seen:
            raise AggregationBlocked(
                "duplicate_harness_result",
                "Regenerate the bundle with one aggregate row per scenario/runtime pair",
                f"duplicate result {scenario_id}/{runtime}",
            )
        seen.add(key)
        if scenario_filter not in {None, "all", scenario_id} or runtime_filter not in {None, "all", runtime}:
            continue
        selected += 1
        _verify_result(root, result, minimum_trials)
    scenario_ids = {scenario_id for scenario_id, _ in seen}
    expected = {(scenario_id, runtime) for scenario_id in scenario_ids for runtime in valid_runtimes}
    if seen != expected:
        raise AggregationBlocked(
            "incomplete_harness_matrix",
            "Regenerate the bundle with exactly one Node, Bun, and FrankenEngine result per scenario",
            f"missing={sorted(expected - seen)} extra={sorted(seen - expected)}",
        )
    if selected == 0:
        raise AggregationBlocked(
            "replay_filter_not_found",
            "Use a scenario/runtime pair present in the harness output",
            f"no result matched scenario={scenario_filter!r} runtime={runtime_filter!r}",
        )


def _verify_result(root: Path, result: dict[str, Any], minimum_trials: int) -> None:
    scenario_id = result["scenario_id"]
    runtime = result["runtime"]
    attempts_total = result.get("attempts_total")
    attempts_successful = result.get("attempts_successful")
    if not isinstance(attempts_total, int) or attempts_total < minimum_trials:
        raise AggregationBlocked(
            "insufficient_trials",
            "Rerun the full repeated-trial campaign",
            f"{scenario_id}/{runtime} has {attempts_total!r} attempts",
        )
    if not isinstance(attempts_successful, int) or not 0 <= attempts_successful <= attempts_total:
        raise AggregationBlocked(
            "invalid_attempt_counts",
            "Regenerate the aggregate from immutable trial receipts",
            f"{scenario_id}/{runtime} has invalid success count {attempts_successful!r}",
        )
    transcript_path = resolve_artifact(result.get("transcript_path"), root, "transcript_path")
    witness_path = resolve_artifact(result.get("witness_path"), root, "witness_path")
    verify_hash(transcript_path, result.get("transcript_hash"), f"{scenario_id}/{runtime} transcript_hash")
    verify_hash(witness_path, result.get("witness_hash"), f"{scenario_id}/{runtime} witness_hash")
    transcript = require_object(load_json(transcript_path, "aggregate transcript"), "aggregate transcript")
    witness = require_object(load_json(witness_path, "aggregate witness"), "aggregate witness")
    if transcript.get("schema_version") != TRANSCRIPT_SCHEMA or witness.get("schema_version") != WITNESS_SCHEMA:
        raise AggregationBlocked(
            "unsupported_aggregate_receipt_schema",
            "Regenerate the aggregate receipts with the current producer",
            f"{scenario_id}/{runtime} aggregate receipt schema mismatch",
        )
    if transcript.get("scenario_id") != scenario_id or transcript.get("runtime") != runtime:
        raise AggregationBlocked(
            "aggregate_receipt_binding_mismatch",
            "Discard the modified aggregate and replay from clean trial receipts",
            f"{scenario_id}/{runtime} transcript binding mismatch",
        )
    if transcript.get("attempts_total") != attempts_total or transcript.get("attempts_successful") != attempts_successful:
        raise AggregationBlocked(
            "aggregate_attempt_mismatch",
            "Discard the modified aggregate and replay from clean trial receipts",
            f"{scenario_id}/{runtime} transcript counts disagree with harness output",
        )
    trials = transcript.get("trials")
    if not isinstance(trials, list) or len(trials) != attempts_total:
        raise AggregationBlocked(
            "aggregate_trial_index_mismatch",
            "Regenerate the aggregate transcript from the full trial index",
            f"{scenario_id}/{runtime} trial list length mismatch",
        )
    recomputed_successes = 0
    for trial in trials:
        entry = require_object(trial, "aggregate trial receipt")
        if not isinstance(entry.get("attack_succeeded"), bool):
            raise AggregationBlocked(
                "ambiguous_runtime_disposition",
                "Regenerate the aggregate from explicit boolean runtime dispositions",
                f"{scenario_id}/{runtime} trial has no boolean disposition",
            )
        recomputed_successes += bool(entry["attack_succeeded"])
        source_transcript = resolve_artifact(entry.get("transcript_path"), root, "source transcript_path")
        source_witness = resolve_artifact(entry.get("witness_path"), root, "source witness_path")
        verify_hash(source_transcript, entry.get("transcript_hash"), "source transcript_hash")
        verify_hash(source_witness, entry.get("witness_hash"), "source witness_hash")
    if recomputed_successes != attempts_successful:
        raise AggregationBlocked(
            "aggregate_attempt_mismatch",
            "Discard the modified aggregate and replay from clean trial receipts",
            f"{scenario_id}/{runtime} recomputed successes {recomputed_successes} != {attempts_successful}",
        )
    if witness.get("aggregate_transcript_hash") != result.get("transcript_hash"):
        raise AggregationBlocked(
            "aggregate_witness_mismatch",
            "Regenerate the aggregate witness from the verified transcript",
            f"{scenario_id}/{runtime} witness does not bind the aggregate transcript",
        )


def verify(args: argparse.Namespace) -> int:
    try:
        verify_harness(
            args.root.resolve(),
            args.harness_output.resolve(),
            args.scenario,
            args.runtime,
            args.minimum_trials,
        )
        print("red_team_harness_replay=pass")
        return 0
    except AggregationBlocked as blocked:
        print(f"red-team harness replay blocked: {blocked.reason}: {blocked.detail}", file=sys.stderr)
        return 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aggregate and replay receipt-bound red-team runtime trials")
    subparsers = parser.add_subparsers(dest="command", required=True)
    aggregate_parser = subparsers.add_parser("aggregate")
    aggregate_parser.add_argument("--root", type=Path, required=True)
    aggregate_parser.add_argument("--trial-root", type=Path, required=True)
    aggregate_parser.add_argument("--output-dir", type=Path, required=True)
    aggregate_parser.add_argument("--code-revision", required=True)
    aggregate_parser.add_argument("--verification-command", required=True)
    aggregate_parser.add_argument("--minimum-trials", type=int, default=100)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--harness-output", type=Path, required=True)
    verify_parser.add_argument("--scenario", default="all")
    verify_parser.add_argument(
        "--runtime", choices=("all", "node", "bun", "franken_engine"), default="all"
    )
    verify_parser.add_argument("--minimum-trials", type=int, default=100)
    args = parser.parse_args(argv)
    if getattr(args, "minimum_trials", 1) <= 0:
        parser.error("--minimum-trials must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return aggregate(args) if args.command == "aggregate" else verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
