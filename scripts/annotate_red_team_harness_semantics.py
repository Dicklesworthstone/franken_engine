#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from red_team_scenario_corpus_contract import CONTRACT

CORPUS_ID = CONTRACT.corpus_id
DENOMINATOR_SEMANTICS = CONTRACT.denominator_semantics
REPETITION_ROLE = CONTRACT.repetition_role
CONFIDENCE_INTERPRETATION = CONTRACT.confidence_interpretation
ZERO_CELL_GUARD = CONTRACT.zero_cell_guard
EXPECTED_RUNTIMES = set(CONTRACT.runtimes)
EXPECTED_SCENARIOS = len(CONTRACT.scenarios)
EXPECTED_ATTACK_CLASSES = len(CONTRACT.attack_classes)
EXPECTED_SCENARIO_MAP = CONTRACT.scenario_map


class SemanticError(ValueError):
    pass


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticError(f"{label} must be a JSON object")
    return value


def load(path: Path) -> dict[str, Any]:
    try:
        return require_object(json.loads(path.read_text(encoding="utf-8")), "harness output")
    except OSError as error:
        raise SemanticError(f"failed to read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise SemanticError(f"invalid JSON in {path}: {error}") from error


def analyze(value: dict[str, Any]) -> tuple[dict[str, str], dict[str, set[str]]]:
    results = value.get("results")
    if not isinstance(results, list) or not results:
        raise SemanticError("harness output must contain a non-empty results array")
    observed_scenarios: dict[str, str] = {}
    runtime_matrix: dict[str, set[str]] = defaultdict(set)
    for index, raw in enumerate(results):
        row = require_object(raw, f"results[{index}]")
        scenario_id = row.get("scenario_id")
        attack_class = row.get("attack_class")
        runtime = row.get("runtime")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise SemanticError(f"results[{index}].scenario_id must be non-empty")
        if not isinstance(attack_class, str) or not attack_class.strip():
            raise SemanticError(f"results[{index}].attack_class must be non-empty")
        if runtime not in EXPECTED_RUNTIMES:
            raise SemanticError(f"results[{index}].runtime is invalid: {runtime!r}")
        previous_class = observed_scenarios.setdefault(scenario_id, attack_class)
        if previous_class != attack_class:
            raise SemanticError(
                f"scenario {scenario_id} has inconsistent attack classes: {previous_class!r} and {attack_class!r}"
            )
        if runtime in runtime_matrix[scenario_id]:
            raise SemanticError(f"duplicate runtime row for {scenario_id}/{runtime}")
        runtime_matrix[scenario_id].add(runtime)
    incomplete = {
        scenario_id: sorted(EXPECTED_RUNTIMES - runtimes)
        for scenario_id, runtimes in runtime_matrix.items()
        if runtimes != EXPECTED_RUNTIMES
    }
    if incomplete:
        raise SemanticError(f"incomplete runtime matrix: {incomplete}")
    return observed_scenarios, runtime_matrix


def validate_shape(
    observed_scenarios: dict[str, str], runtime_matrix: dict[str, set[str]]
) -> None:
    if observed_scenarios != EXPECTED_SCENARIO_MAP:
        missing = sorted(set(EXPECTED_SCENARIO_MAP) - set(observed_scenarios))
        extra = sorted(set(observed_scenarios) - set(EXPECTED_SCENARIO_MAP))
        wrong_class = {
            scenario_id: {
                "expected": EXPECTED_SCENARIO_MAP[scenario_id],
                "actual": observed_scenarios[scenario_id],
            }
            for scenario_id in sorted(set(observed_scenarios) & set(EXPECTED_SCENARIO_MAP))
            if observed_scenarios[scenario_id] != EXPECTED_SCENARIO_MAP[scenario_id]
        }
        raise SemanticError(
            f"corpus identity mismatch: missing={missing}, extra={extra}, wrong_class={wrong_class}"
        )
    if len(runtime_matrix) != EXPECTED_SCENARIOS:
        raise SemanticError(
            f"corpus requires {EXPECTED_SCENARIOS} distinct scenarios; found {len(runtime_matrix)}"
        )


def annotate(value: dict[str, Any]) -> dict[str, Any]:
    observed_scenarios, runtime_matrix = analyze(value)
    validate_shape(observed_scenarios, runtime_matrix)
    value["corpus_id"] = CONTRACT.corpus_id
    value["scenario_set"] = CONTRACT.corpus_id
    value["denominator_semantics"] = CONTRACT.denominator_semantics
    value["repetition_role"] = CONTRACT.repetition_role
    value["confidence_interpretation"] = CONTRACT.confidence_interpretation
    value["zero_cell_guard"] = CONTRACT.zero_cell_guard
    value["zero_cell_guard_count"] = CONTRACT.zero_cell_guard_count
    value["required_stability_repetitions_per_runtime_scenario"] = (
        CONTRACT.required_stability_repetitions_per_runtime_scenario
    )
    value["corpus_contract_path"] = "docs/red_team_scenario_corpus_v2.json"
    value["corpus_contract_sha256"] = CONTRACT.source_sha256
    value["distinct_scenario_count"] = len(observed_scenarios)
    value["attack_class_count"] = len(set(observed_scenarios.values()))
    value["runtime_scenario_pair_count"] = sum(len(runtimes) for runtimes in runtime_matrix.values())
    return value


def verify_annotations(value: dict[str, Any]) -> None:
    observed_scenarios, runtime_matrix = analyze(value)
    expected = {
        "corpus_id": CONTRACT.corpus_id,
        "scenario_set": CONTRACT.corpus_id,
        "denominator_semantics": CONTRACT.denominator_semantics,
        "repetition_role": CONTRACT.repetition_role,
        "confidence_interpretation": CONTRACT.confidence_interpretation,
        "zero_cell_guard": CONTRACT.zero_cell_guard,
        "zero_cell_guard_count": CONTRACT.zero_cell_guard_count,
        "required_stability_repetitions_per_runtime_scenario": (
            CONTRACT.required_stability_repetitions_per_runtime_scenario
        ),
        "corpus_contract_path": "docs/red_team_scenario_corpus_v2.json",
        "corpus_contract_sha256": CONTRACT.source_sha256,
        "distinct_scenario_count": len(observed_scenarios),
        "attack_class_count": len(set(observed_scenarios.values())),
        "runtime_scenario_pair_count": sum(len(runtimes) for runtimes in runtime_matrix.values()),
    }
    mismatches = {
        field: {"expected": expected_value, "actual": value.get(field)}
        for field, expected_value in expected.items()
        if value.get(field) != expected_value
    }
    if mismatches:
        raise SemanticError(f"harness semantic annotations are missing or inconsistent: {mismatches}")
    validate_shape(observed_scenarios, runtime_matrix)


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bind and validate exact FE-CLAIM-011 scenario-corpus semantics"
    )
    parser.add_argument("harness_output", type=Path)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        value = load(args.harness_output)
        if args.check:
            verify_annotations(value)
        else:
            write_atomic(args.harness_output, annotate(value))
            verify_annotations(load(args.harness_output))
        print("red_team_harness_semantics=pass")
        return 0
    except SemanticError as error:
        print(f"red-team harness semantics blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
