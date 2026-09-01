#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

CORPUS_ID = "red_team_security_critical_compromise_v2"
DENOMINATOR_SEMANTICS = "distinct_security_critical_scenarios"
REPETITION_ROLE = "stability_and_replay_not_independent_sampling"
CONFIDENCE_INTERPRETATION = "receipt_completeness_and_stability_not_population_confidence"
ZERO_CELL_GUARD = "one_hypothetical_frankenengine_compromise"
EXPECTED_RUNTIMES = {"node", "bun", "franken_engine"}
EXPECTED_SCENARIOS = 10
MIN_ATTACK_CLASSES = 3


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


def analyze(value: dict[str, Any]) -> tuple[set[str], set[str], dict[str, set[str]]]:
    results = value.get("results")
    if not isinstance(results, list) or not results:
        raise SemanticError("harness output must contain a non-empty results array")
    scenarios: set[str] = set()
    attack_classes: set[str] = set()
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
        if runtime in runtime_matrix[scenario_id]:
            raise SemanticError(f"duplicate runtime row for {scenario_id}/{runtime}")
        scenarios.add(scenario_id)
        attack_classes.add(attack_class)
        runtime_matrix[scenario_id].add(runtime)
    incomplete = {
        scenario_id: sorted(EXPECTED_RUNTIMES - runtimes)
        for scenario_id, runtimes in runtime_matrix.items()
        if runtimes != EXPECTED_RUNTIMES
    }
    if incomplete:
        raise SemanticError(f"incomplete runtime matrix: {incomplete}")
    return scenarios, attack_classes, runtime_matrix


def annotate(value: dict[str, Any]) -> dict[str, Any]:
    scenarios, attack_classes, runtime_matrix = analyze(value)
    if len(scenarios) != EXPECTED_SCENARIOS:
        raise SemanticError(
            f"corpus requires {EXPECTED_SCENARIOS} distinct scenarios; found {len(scenarios)}"
        )
    if len(attack_classes) < MIN_ATTACK_CLASSES:
        raise SemanticError(
            f"corpus requires at least {MIN_ATTACK_CLASSES} attack classes; found {len(attack_classes)}"
        )
    value["corpus_id"] = CORPUS_ID
    value["denominator_semantics"] = DENOMINATOR_SEMANTICS
    value["repetition_role"] = REPETITION_ROLE
    value["confidence_interpretation"] = CONFIDENCE_INTERPRETATION
    value["zero_cell_guard"] = ZERO_CELL_GUARD
    value["distinct_scenario_count"] = len(scenarios)
    value["attack_class_count"] = len(attack_classes)
    value["runtime_scenario_pair_count"] = sum(len(runtimes) for runtimes in runtime_matrix.values())
    return value


def verify_annotations(value: dict[str, Any]) -> None:
    scenarios, attack_classes, runtime_matrix = analyze(value)
    expected = {
        "corpus_id": CORPUS_ID,
        "denominator_semantics": DENOMINATOR_SEMANTICS,
        "repetition_role": REPETITION_ROLE,
        "confidence_interpretation": CONFIDENCE_INTERPRETATION,
        "zero_cell_guard": ZERO_CELL_GUARD,
        "distinct_scenario_count": len(scenarios),
        "attack_class_count": len(attack_classes),
        "runtime_scenario_pair_count": sum(len(runtimes) for runtimes in runtime_matrix.values()),
    }
    mismatches = {
        field: {"expected": expected_value, "actual": value.get(field)}
        for field, expected_value in expected.items()
        if value.get(field) != expected_value
    }
    if mismatches:
        raise SemanticError(f"harness semantic annotations are missing or inconsistent: {mismatches}")
    if len(scenarios) != EXPECTED_SCENARIOS:
        raise SemanticError(
            f"corpus requires {EXPECTED_SCENARIOS} distinct scenarios; found {len(scenarios)}"
        )
    if len(attack_classes) < MIN_ATTACK_CLASSES:
        raise SemanticError(
            f"corpus requires at least {MIN_ATTACK_CLASSES} attack classes; found {len(attack_classes)}"
        )


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bind and validate scenario-denominator semantics on FE-CLAIM-011 harness output"
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
