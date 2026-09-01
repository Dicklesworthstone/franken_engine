#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import red_team_compromise_rate_metric as comparator
from red_team_scenario_corpus_contract import CONTRACT

CORPUS_ID = CONTRACT.corpus_id
CORPUS_SEMANTICS = CONTRACT.denominator_semantics
VERDICT_SCOPE = CONTRACT.repetition_verdict_scope
SCENARIOS = tuple(
    comparator.ScenarioSpec(scenario.scenario_id, scenario.attack_class)
    for scenario in CONTRACT.scenarios
)


def install_corpus() -> None:
    expected = tuple(
        (scenario.scenario_id, scenario.attack_class) for scenario in CONTRACT.scenarios
    )
    actual = tuple((scenario.scenario_id, scenario.attack_class) for scenario in SCENARIOS)
    if actual != expected:
        raise RuntimeError(f"FE-CLAIM-011 comparator corpus drift: {actual!r} != {expected!r}")
    comparator.SCENARIOS = SCENARIOS


def bundle_dir_from_args(arguments: list[str]) -> Path:
    for index, argument in enumerate(arguments):
        if argument == "--bundle-dir":
            if index + 1 >= len(arguments):
                raise RuntimeError("--bundle-dir requires a value")
            return Path(arguments[index + 1])
        if argument.startswith("--bundle-dir="):
            return Path(argument.split("=", 1)[1])
    raise RuntimeError("the corpus adapter requires --bundle-dir")


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def scope_fields() -> dict[str, Any]:
    return {
        "corpus_id": CONTRACT.corpus_id,
        "scenario_set": CONTRACT.corpus_id,
        "denominator_semantics": CONTRACT.denominator_semantics,
        "repetition_role": CONTRACT.repetition_role,
        "confidence_interpretation": CONTRACT.confidence_interpretation,
        "zero_cell_guard": CONTRACT.zero_cell_guard,
        "zero_cell_guard_count": CONTRACT.zero_cell_guard_count,
        "corpus_contract_path": "docs/red_team_scenario_corpus_v2.json",
        "verdict_scope": CONTRACT.repetition_verdict_scope,
        "claim_verdict_eligible": False,
        "claim_verdict_producer": CONTRACT.claim_verdict_producer,
    }


def scope_repetition_bundle(bundle_dir: Path) -> None:
    fields = scope_fields()
    for file_name in (
        "bundle_status.json",
        "metric_artifact.json",
        "metric_report.json",
        "compromise_details.json",
    ):
        path = bundle_dir / file_name
        if not path.is_file():
            continue
        value = load_object(path)
        value.update(fields)
        if file_name == "metric_artifact.json":
            value["observed_value_scope"] = "single_repetition_raw_ratio_not_claim_metric"
        comparator.write_json(path, value)

    comparator.write_json(
        bundle_dir / "repetition_scope.json",
        {
            "schema_version": "franken-engine.red-team-repetition-scope.v1",
            **fields,
            "distinct_scenario_count": len(CONTRACT.scenarios),
            "attack_class_count": len(CONTRACT.attack_classes),
            "runtime_scenario_pair_count": CONTRACT.runtime_scenario_pair_count,
            "required_stability_repetitions_per_runtime_scenario": (
                CONTRACT.required_stability_repetitions_per_runtime_scenario
            ),
        },
    )

    summary_path = bundle_dir / "summary.md"
    if summary_path.is_file():
        original = summary_path.read_text(encoding="utf-8")
        warning = (
            "# Single-Repetition Receipt Bundle\n\n"
            "This bundle records one complete comparator repetition. Its local status is an "
            "execution disposition only, not the FE-CLAIM-011 verdict. The claim decision is "
            "made only after the complete stability campaign is aggregated and evaluated by "
            "`franken_red_team_harness_gate`. Repetitions are not independent population samples.\n\n"
        )
        summary_path.write_text(warning + original, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    install_corpus()
    bundle_dir = bundle_dir_from_args(arguments)
    exit_code = comparator.main(arguments)
    scope_repetition_bundle(bundle_dir)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
