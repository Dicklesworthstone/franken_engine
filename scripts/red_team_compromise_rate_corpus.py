#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import red_team_compromise_rate_metric as comparator
from annotate_red_team_harness_semantics import (
    CONFIDENCE_INTERPRETATION,
    CORPUS_ID,
    DENOMINATOR_SEMANTICS,
    REPETITION_ROLE,
)

CORPUS_SEMANTICS = DENOMINATOR_SEMANTICS
VERDICT_SCOPE = "single_repetition_receipt_only_not_claim_verdict"
SCENARIOS = (
    comparator.ScenarioSpec("environment_variable_exfiltration", "ambient_authority_escape"),
    comparator.ScenarioSpec("process_privilege_surface_probe", "ambient_authority_escape"),
    comparator.ScenarioSpec("prototype_pollution_capability_escape", "prototype_pollution"),
    comparator.ScenarioSpec("shell_command_injection_package_script", "ambient_authority_escape"),
    comparator.ScenarioSpec("supply_chain_backdoor_execution", "supply_chain_execution"),
    comparator.ScenarioSpec("ambient_authority_via_globalthis", "ambient_authority_escape"),
    comparator.ScenarioSpec("capability_shadowed_import", "ambient_authority_escape"),
    comparator.ScenarioSpec("reflect_apply_authority_smuggling", "ambient_authority_escape"),
    comparator.ScenarioSpec("typed_effect_laundering_downcast", "ambient_authority_escape"),
    comparator.ScenarioSpec("smuggle_flow_via_unanalyzed_construct", "ambient_authority_escape"),
)


def install_corpus() -> None:
    scenario_ids = [scenario.scenario_id for scenario in SCENARIOS]
    if len(scenario_ids) != 10 or len(set(scenario_ids)) != len(scenario_ids):
        raise RuntimeError("the FE-CLAIM-011 comparator corpus must contain ten distinct scenarios")
    attack_classes = {scenario.attack_class for scenario in SCENARIOS}
    if attack_classes != {
        "ambient_authority_escape",
        "prototype_pollution",
        "supply_chain_execution",
    }:
        raise RuntimeError(f"unexpected FE-CLAIM-011 attack-class inventory: {sorted(attack_classes)}")
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
        "corpus_id": CORPUS_ID,
        "denominator_semantics": DENOMINATOR_SEMANTICS,
        "repetition_role": REPETITION_ROLE,
        "confidence_interpretation": CONFIDENCE_INTERPRETATION,
        "verdict_scope": VERDICT_SCOPE,
        "claim_verdict_eligible": False,
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
            "distinct_scenario_count": len(SCENARIOS),
            "attack_class_count": len({scenario.attack_class for scenario in SCENARIOS}),
            "claim_verdict_producer": "franken_red_team_harness_gate",
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
