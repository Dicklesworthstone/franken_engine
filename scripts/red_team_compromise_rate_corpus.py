#!/usr/bin/env python3
from __future__ import annotations

import sys

import red_team_compromise_rate_metric as comparator

CORPUS_ID = "red_team_security_critical_compromise_v2"
CORPUS_SEMANTICS = "distinct_security_critical_scenarios"
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


def main(argv: list[str] | None = None) -> int:
    install_corpus()
    return comparator.main(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
