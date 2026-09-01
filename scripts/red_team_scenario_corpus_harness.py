#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import aggregate_red_team_trials as generic
from annotate_red_team_harness_semantics import (
    CONFIDENCE_INTERPRETATION,
    CORPUS_ID,
    DENOMINATOR_SEMANTICS,
    REPETITION_ROLE,
    ZERO_CELL_GUARD,
    annotate,
    load,
    verify_annotations,
)
from red_team_trial_common import (
    load_json,
    require_object,
    resolve_artifact,
    root_relative,
    sha256_ref,
    write_json,
)

REPETITION_VERDICT_SCOPE = "single_repetition_receipt_only_not_claim_verdict"
AGGREGATE_VERDICT_SCOPE = "aggregate_stability_input_only_not_claim_verdict"
CLAIM_VERDICT_PRODUCER = "franken_red_team_harness_gate"
EXPECTED_SCENARIOS = 10
EXPECTED_ATTACK_CLASSES = 3
EXPECTED_RUNTIME_PAIRS = 30


class CorpusContractError(ValueError):
    pass


def _validate_string_fields(value: dict[str, Any], label: str, expected: dict[str, str]) -> None:
    mismatches = [
        f"{field}={value.get(field)!r}"
        for field, expected_value in expected.items()
        if value.get(field) != expected_value
    ]
    if mismatches:
        raise CorpusContractError(f"{label} semantic mismatch: {', '.join(mismatches)}")


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
        "corpus_id": CORPUS_ID,
        "denominator_semantics": DENOMINATOR_SEMANTICS,
        "repetition_role": REPETITION_ROLE,
        "confidence_interpretation": CONFIDENCE_INTERPRETATION,
        "verdict_scope": REPETITION_VERDICT_SCOPE,
    }
    _validate_string_fields(status, f"{trial_id} bundle_status", expected)
    _validate_string_fields(scope, f"{trial_id} repetition_scope", expected)
    if status.get("claim_verdict_eligible") is not False:
        raise CorpusContractError(f"{trial_id} bundle_status must set claim_verdict_eligible=false")
    if scope.get("claim_verdict_eligible") is not False:
        raise CorpusContractError(f"{trial_id} repetition_scope must set claim_verdict_eligible=false")
    if scope.get("distinct_scenario_count") != EXPECTED_SCENARIOS:
        raise CorpusContractError(
            f"{trial_id} declares {scope.get('distinct_scenario_count')!r} distinct scenarios"
        )
    if scope.get("attack_class_count") != EXPECTED_ATTACK_CLASSES:
        raise CorpusContractError(
            f"{trial_id} declares {scope.get('attack_class_count')!r} attack classes"
        )
    if scope.get("claim_verdict_producer") != CLAIM_VERDICT_PRODUCER:
        raise CorpusContractError(
            f"{trial_id} claim_verdict_producer={scope.get('claim_verdict_producer')!r}"
        )


def validate_repetition_set(trial_root: Path) -> None:
    try:
        trial_dirs = sorted(
            path for path in trial_root.iterdir() if path.is_dir() and path.name.startswith("trial-")
        )
    except FileNotFoundError as error:
        raise CorpusContractError(f"trial root does not exist: {trial_root}") from error
    if not trial_dirs:
        raise CorpusContractError(f"trial root contains no repetition bundles: {trial_root}")
    for trial_dir in trial_dirs:
        validate_repetition_bundle(trial_dir)


def _semantic_fields(verdict_scope: str) -> dict[str, Any]:
    return {
        "corpus_id": CORPUS_ID,
        "scenario_set": CORPUS_ID,
        "denominator_semantics": DENOMINATOR_SEMANTICS,
        "repetition_role": REPETITION_ROLE,
        "confidence_interpretation": CONFIDENCE_INTERPRETATION,
        "zero_cell_guard": ZERO_CELL_GUARD,
        "verdict_scope": verdict_scope,
        "claim_verdict_eligible": False,
        "claim_verdict_producer": CLAIM_VERDICT_PRODUCER,
    }


def finalize_aggregate(root: Path, output_dir: Path, minimum_trials: int) -> None:
    harness_path = output_dir / "harness_output.json"
    harness = require_object(load_json(harness_path, "harness output"), "harness output")
    details_path = resolve_artifact(harness.get("artifact_path"), root, "artifact_path")
    details = require_object(load_json(details_path, "measurement details"), "measurement details")
    results = details.get("results")
    if not isinstance(results, list) or len(results) != EXPECTED_RUNTIME_PAIRS:
        raise CorpusContractError(
            f"aggregate must contain {EXPECTED_RUNTIME_PAIRS} runtime/scenario pairs; found "
            f"{len(results) if isinstance(results, list) else 'non-list'}"
        )
    scenarios = {result.get("scenario_id") for result in results if isinstance(result, dict)}
    attack_classes = {result.get("attack_class") for result in results if isinstance(result, dict)}
    if len(scenarios) != EXPECTED_SCENARIOS or len(attack_classes) != EXPECTED_ATTACK_CLASSES:
        raise CorpusContractError(
            f"aggregate corpus shape mismatch: scenarios={len(scenarios)}, "
            f"attack_classes={len(attack_classes)}"
        )

    harness_rel = root_relative(harness_path, root)
    rewritten_results: list[dict[str, Any]] = []
    for raw_result in results:
        result = require_object(raw_result, "aggregate result")
        scenario_id = result.get("scenario_id")
        runtime = result.get("runtime")
        result["replay_command"] = (
            "python3 scripts/red_team_scenario_corpus_harness.py verify "
            f"--root . --harness-output {harness_rel} "
            f"--scenario {scenario_id} --runtime {runtime} "
            f"--minimum-trials {minimum_trials}"
        )
        rewritten_results.append(result)

    details.update(_semantic_fields(AGGREGATE_VERDICT_SCOPE))
    details["minimum_stability_repetitions_per_runtime"] = minimum_trials
    details["distinct_scenario_count"] = EXPECTED_SCENARIOS
    details["attack_class_count"] = EXPECTED_ATTACK_CLASSES
    details["runtime_scenario_pair_count"] = EXPECTED_RUNTIME_PAIRS
    details["results"] = rewritten_results
    write_json(details_path, details)

    harness["scenario_set"] = CORPUS_ID
    harness["artifact_hash"] = sha256_ref(details_path)
    harness["results"] = rewritten_results
    harness.update(_semantic_fields(AGGREGATE_VERDICT_SCOPE))
    harness = annotate(harness)
    write_json(harness_path, harness)
    verify_annotations(load(harness_path))
    generic.verify_harness(root, harness_path, None, None, minimum_trials)

    status_path = output_dir / "bundle_status.json"
    status = require_object(load_json(status_path, "aggregate bundle status"), "bundle status")
    status.update(_semantic_fields(AGGREGATE_VERDICT_SCOPE))
    status["reason"] = "receipt_bound_scenario_corpus_stability_input_verified"
    status["harness_output_hash"] = sha256_ref(harness_path)
    write_json(status_path, status)


def validate_aggregate_semantics(root: Path, harness_path: Path) -> None:
    harness = load(harness_path)
    verify_annotations(harness)
    expected = _semantic_fields(AGGREGATE_VERDICT_SCOPE)
    _validate_string_fields(
        harness,
        "harness output",
        {field: value for field, value in expected.items() if isinstance(value, str)},
    )
    if harness.get("claim_verdict_eligible") is not False:
        raise CorpusContractError("harness output must set claim_verdict_eligible=false")
    details_path = resolve_artifact(harness.get("artifact_path"), root, "artifact_path")
    details = require_object(load_json(details_path, "measurement details"), "measurement details")
    _validate_string_fields(
        details,
        "measurement details",
        {field: value for field, value in expected.items() if isinstance(value, str)},
    )
    if details.get("claim_verdict_eligible") is not False:
        raise CorpusContractError("measurement details must set claim_verdict_eligible=false")
    if details.get("results") != harness.get("results"):
        raise CorpusContractError("measurement details and harness results diverge")


def write_contract_blocker(output_dir: Path, error: CorpusContractError) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        output_dir / "aggregation_blocker.json",
        {
            "schema_version": "franken-engine.red-team-scenario-corpus-blocker.v1",
            "status": "fail_closed",
            "reason": "scenario_corpus_contract_violation",
            "detail": str(error),
            "remediation": (
                "Regenerate all repetitions through red_team_compromise_rate_corpus.py and "
                "aggregate them through red_team_scenario_corpus_harness.py"
            ),
            "placeholder_results_emitted": False,
        },
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = generic.parse_args(arguments)
    try:
        if args.command == "aggregate":
            validate_repetition_set(args.trial_root.resolve())
            exit_code = generic.aggregate(args)
            if exit_code != 0:
                return exit_code
            finalize_aggregate(args.root.resolve(), args.output_dir.resolve(), args.minimum_trials)
            print(f"red_team_scenario_corpus_harness={args.output_dir.resolve() / 'harness_output.json'}")
            return 0
        validate_aggregate_semantics(args.root.resolve(), args.harness_output.resolve())
        return generic.verify(args)
    except CorpusContractError as error:
        if args.command == "aggregate":
            write_contract_blocker(args.output_dir.resolve(), error)
        print(f"red-team scenario-corpus contract blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
