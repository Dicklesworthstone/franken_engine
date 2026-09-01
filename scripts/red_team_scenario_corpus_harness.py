#!/usr/bin/env python3
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import aggregate_red_team_trials as generic
from annotate_red_team_harness_semantics import SemanticError, annotate, load, verify_annotations
from red_team_scenario_corpus_contract import CONTRACT
from red_team_trial_common import (
    AggregationBlocked,
    load_json,
    require_object,
    resolve_artifact,
    root_relative,
    sha256_ref,
    write_json,
)

REPETITION_VERDICT_SCOPE = CONTRACT.repetition_verdict_scope
AGGREGATE_VERDICT_SCOPE = CONTRACT.aggregate_verdict_scope
CLAIM_VERDICT_PRODUCER = CONTRACT.claim_verdict_producer
EXPECTED_SCENARIOS = len(CONTRACT.scenarios)
EXPECTED_ATTACK_CLASSES = len(CONTRACT.attack_classes)
EXPECTED_RUNTIME_PAIRS = CONTRACT.runtime_scenario_pair_count


class CorpusHarnessError(ValueError):
    pass


def _validate_string_fields(value: dict[str, Any], label: str, expected: dict[str, str]) -> None:
    mismatches = [
        f"{field}={value.get(field)!r}"
        for field, expected_value in expected.items()
        if value.get(field) != expected_value
    ]
    if mismatches:
        raise CorpusHarnessError(f"{label} semantic mismatch: {', '.join(mismatches)}")


def _semantic_fields(verdict_scope: str) -> dict[str, Any]:
    return {
        "corpus_id": CONTRACT.corpus_id,
        "scenario_set": CONTRACT.corpus_id,
        "denominator_semantics": CONTRACT.denominator_semantics,
        "repetition_role": CONTRACT.repetition_role,
        "confidence_interpretation": CONTRACT.confidence_interpretation,
        "zero_cell_guard": CONTRACT.zero_cell_guard,
        "zero_cell_guard_count": CONTRACT.zero_cell_guard_count,
        "corpus_contract_path": "docs/red_team_scenario_corpus_v2.json",
        "corpus_contract_sha256": CONTRACT.source_sha256,
        "verdict_scope": verdict_scope,
        "claim_verdict_eligible": False,
        "claim_verdict_producer": CONTRACT.claim_verdict_producer,
    }


def validate_repetition_bundle(trial_dir: Path) -> None:
    trial_id = trial_dir.name
    status = require_object(
        load_json(trial_dir / "bundle_status.json", f"{trial_id} bundle status"),
        "bundle status",
    )
    scope = require_object(
        load_json(trial_dir / "repetition_scope.json", f"{trial_id} repetition scope"),
        "repetition scope",
    )
    expected = {
        field: value
        for field, value in _semantic_fields(CONTRACT.repetition_verdict_scope).items()
        if isinstance(value, str)
    }
    _validate_string_fields(status, f"{trial_id} bundle_status", expected)
    _validate_string_fields(scope, f"{trial_id} repetition_scope", expected)
    if status.get("claim_verdict_eligible") is not False:
        raise CorpusHarnessError(f"{trial_id} bundle_status must set claim_verdict_eligible=false")
    if scope.get("claim_verdict_eligible") is not False:
        raise CorpusHarnessError(f"{trial_id} repetition_scope must set claim_verdict_eligible=false")
    expected_numbers = {
        "zero_cell_guard_count": CONTRACT.zero_cell_guard_count,
        "distinct_scenario_count": EXPECTED_SCENARIOS,
        "attack_class_count": EXPECTED_ATTACK_CLASSES,
        "runtime_scenario_pair_count": EXPECTED_RUNTIME_PAIRS,
        "required_stability_repetitions_per_runtime_scenario": (
            CONTRACT.required_stability_repetitions_per_runtime_scenario
        ),
    }
    mismatches = {
        field: {"expected": expected, "actual": scope.get(field)}
        for field, expected in expected_numbers.items()
        if scope.get(field) != expected
    }
    if mismatches:
        raise CorpusHarnessError(f"{trial_id} repetition scope count mismatch: {mismatches}")


def validate_repetition_set(trial_root: Path) -> None:
    try:
        trial_dirs = sorted(
            path for path in trial_root.iterdir() if path.is_dir() and path.name.startswith("trial-")
        )
    except FileNotFoundError as error:
        raise CorpusHarnessError(f"trial root does not exist: {trial_root}") from error
    if not trial_dirs:
        raise CorpusHarnessError(f"trial root contains no repetition bundles: {trial_root}")
    for trial_dir in trial_dirs:
        validate_repetition_bundle(trial_dir)


def validate_result_matrix(results: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        raise CorpusHarnessError(f"{label} results must be an array")
    observed_scenarios: dict[str, str] = {}
    runtime_matrix: dict[str, set[str]] = defaultdict(set)
    normalized: list[dict[str, Any]] = []
    for index, raw_result in enumerate(results):
        result = require_object(raw_result, f"{label} result[{index}]")
        scenario_id = result.get("scenario_id")
        attack_class = result.get("attack_class")
        runtime = result.get("runtime")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise CorpusHarnessError(f"{label} result[{index}] has no scenario_id")
        if not isinstance(attack_class, str) or not attack_class:
            raise CorpusHarnessError(f"{label} result[{index}] has no attack_class")
        if runtime not in CONTRACT.runtimes:
            raise CorpusHarnessError(f"{label} result[{index}] has invalid runtime {runtime!r}")
        previous_class = observed_scenarios.setdefault(scenario_id, attack_class)
        if previous_class != attack_class:
            raise CorpusHarnessError(
                f"{label} scenario {scenario_id} has inconsistent attack classes"
            )
        if runtime in runtime_matrix[scenario_id]:
            raise CorpusHarnessError(f"{label} has duplicate pair {scenario_id}/{runtime}")
        runtime_matrix[scenario_id].add(runtime)
        normalized.append(result)

    if observed_scenarios != CONTRACT.scenario_map:
        missing = sorted(set(CONTRACT.scenario_map) - set(observed_scenarios))
        extra = sorted(set(observed_scenarios) - set(CONTRACT.scenario_map))
        wrong_class = {
            scenario_id: {
                "expected": CONTRACT.scenario_map[scenario_id],
                "actual": observed_scenarios[scenario_id],
            }
            for scenario_id in sorted(set(observed_scenarios) & set(CONTRACT.scenario_map))
            if observed_scenarios[scenario_id] != CONTRACT.scenario_map[scenario_id]
        }
        raise CorpusHarnessError(
            f"{label} corpus identity mismatch: missing={missing}, extra={extra}, wrong_class={wrong_class}"
        )
    expected_runtimes = set(CONTRACT.runtimes)
    incomplete = {
        scenario_id: sorted(expected_runtimes - runtimes)
        for scenario_id, runtimes in runtime_matrix.items()
        if runtimes != expected_runtimes
    }
    if incomplete or len(normalized) != EXPECTED_RUNTIME_PAIRS:
        raise CorpusHarnessError(
            f"{label} runtime matrix mismatch: rows={len(normalized)}, incomplete={incomplete}"
        )
    return normalized


def finalize_aggregate(root: Path, output_dir: Path, minimum_trials: int) -> None:
    if minimum_trials < CONTRACT.required_stability_repetitions_per_runtime_scenario:
        raise CorpusHarnessError(
            f"minimum_trials={minimum_trials} is below contract floor "
            f"{CONTRACT.required_stability_repetitions_per_runtime_scenario}"
        )
    harness_path = output_dir / "harness_output.json"
    harness = require_object(load_json(harness_path, "harness output"), "harness output")
    details_path = resolve_artifact(harness.get("artifact_path"), root, "artifact_path")
    details = require_object(load_json(details_path, "measurement details"), "measurement details")
    results = validate_result_matrix(details.get("results"), "measurement details")

    harness_rel = root_relative(harness_path, root)
    rewritten_results: list[dict[str, Any]] = []
    for result in results:
        scenario_id = result["scenario_id"]
        runtime = result["runtime"]
        rewritten = dict(result)
        rewritten["replay_command"] = (
            "python3 scripts/red_team_scenario_corpus_harness.py verify "
            f"--root . --harness-output {harness_rel} "
            f"--scenario {scenario_id} --runtime {runtime} "
            f"--minimum-trials {minimum_trials}"
        )
        rewritten_results.append(rewritten)

    details.update(_semantic_fields(CONTRACT.aggregate_verdict_scope))
    details["required_stability_repetitions_per_runtime_scenario"] = (
        CONTRACT.required_stability_repetitions_per_runtime_scenario
    )
    details["minimum_stability_repetitions_per_runtime"] = minimum_trials
    details["distinct_scenario_count"] = EXPECTED_SCENARIOS
    details["attack_class_count"] = EXPECTED_ATTACK_CLASSES
    details["runtime_scenario_pair_count"] = EXPECTED_RUNTIME_PAIRS
    details["results"] = rewritten_results
    write_json(details_path, details)

    harness["scenario_set"] = CONTRACT.corpus_id
    harness["artifact_hash"] = sha256_ref(details_path)
    harness["results"] = rewritten_results
    harness.update(_semantic_fields(CONTRACT.aggregate_verdict_scope))
    harness = annotate(harness)
    write_json(harness_path, harness)
    verify_annotations(load(harness_path))
    generic.verify_harness(root, harness_path, None, None, minimum_trials)

    status_path = output_dir / "bundle_status.json"
    status = require_object(load_json(status_path, "aggregate bundle status"), "bundle status")
    status.update(_semantic_fields(CONTRACT.aggregate_verdict_scope))
    status["status"] = "pass"
    status["reason"] = "receipt_bound_scenario_corpus_stability_input_verified"
    status["harness_output_hash"] = sha256_ref(harness_path)
    write_json(status_path, status)


def validate_aggregate_semantics(root: Path, harness_path: Path) -> None:
    harness = load(harness_path)
    verify_annotations(harness)
    expected = {
        field: value
        for field, value in _semantic_fields(CONTRACT.aggregate_verdict_scope).items()
        if isinstance(value, str)
    }
    _validate_string_fields(harness, "harness output", expected)
    if harness.get("claim_verdict_eligible") is not False:
        raise CorpusHarnessError("harness output must set claim_verdict_eligible=false")
    validate_result_matrix(harness.get("results"), "harness output")
    details_path = resolve_artifact(harness.get("artifact_path"), root, "artifact_path")
    details = require_object(load_json(details_path, "measurement details"), "measurement details")
    _validate_string_fields(details, "measurement details", expected)
    if details.get("claim_verdict_eligible") is not False:
        raise CorpusHarnessError("measurement details must set claim_verdict_eligible=false")
    validate_result_matrix(details.get("results"), "measurement details")
    if details.get("results") != harness.get("results"):
        raise CorpusHarnessError("measurement details and harness results diverge")


def write_fail_status(output_dir: Path, reason: str, detail: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        output_dir / "bundle_status.json",
        {
            "schema_version": "franken-engine.red-team-scenario-corpus-status.v1",
            "status": "fail_closed",
            "reason": reason,
            "detail": detail,
            **_semantic_fields(CONTRACT.aggregate_verdict_scope),
            "placeholder_results_emitted": False,
        },
    )


def write_contract_blocker(output_dir: Path, reason: str, error: Exception) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    detail = f"{type(error).__name__}: {error}"
    write_json(
        output_dir / "aggregation_blocker.json",
        {
            "schema_version": "franken-engine.red-team-scenario-corpus-blocker.v1",
            "status": "fail_closed",
            "reason": reason,
            "detail": detail,
            "remediation": (
                "Regenerate all repetitions through red_team_compromise_rate_corpus.py and "
                "aggregate them through red_team_scenario_corpus_harness.py"
            ),
            "placeholder_results_emitted": False,
        },
    )
    write_fail_status(output_dir, reason, detail)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = generic.parse_args(arguments)
    try:
        if args.command == "aggregate":
            validate_repetition_set(args.trial_root.resolve())
            exit_code = generic.aggregate(args)
            if exit_code != 0:
                write_fail_status(
                    args.output_dir.resolve(),
                    "underlying_receipt_aggregation_failed",
                    "generic receipt aggregation returned a non-zero status",
                )
                return exit_code
            finalize_aggregate(args.root.resolve(), args.output_dir.resolve(), args.minimum_trials)
            print(f"red_team_scenario_corpus_harness={args.output_dir.resolve() / 'harness_output.json'}")
            return 0
        validate_aggregate_semantics(args.root.resolve(), args.harness_output.resolve())
        return generic.verify(args)
    except (CorpusHarnessError, SemanticError, AggregationBlocked) as error:
        if args.command == "aggregate":
            write_contract_blocker(
                args.output_dir.resolve(), "scenario_corpus_contract_violation", error
            )
        print(f"red-team scenario-corpus contract blocked: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        if args.command == "aggregate":
            write_contract_blocker(
                args.output_dir.resolve(), "scenario_corpus_internal_error", error
            )
        print(
            f"red-team scenario-corpus contract failed closed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
