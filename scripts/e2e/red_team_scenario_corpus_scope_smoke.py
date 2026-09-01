#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import red_team_compromise_rate_corpus as corpus
import red_team_scenario_corpus_harness as scoped
from annotate_red_team_harness_semantics import SemanticError, annotate, verify_annotations
from red_team_scenario_corpus_contract import CONTRACT


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def expect_contract_error(action) -> None:
    try:
        action()
    except scoped.CorpusHarnessError:
        return
    raise AssertionError("expected CorpusHarnessError")


def expect_semantic_error(action) -> None:
    try:
        action()
    except SemanticError:
        return
    raise AssertionError("expected SemanticError")


def repetition_scope_smoke(root: Path) -> None:
    trial = root / "trials" / "trial-0001"
    write_json(
        trial / "bundle_status.json",
        {"schema_version": "fixture.v1", "status": "pass", "reason": "fixture"},
    )
    for name in ("metric_artifact.json", "metric_report.json", "compromise_details.json"):
        write_json(trial / name, {"schema_version": "fixture.v1"})
    (trial / "summary.md").write_text("# Legacy Local Status\n", encoding="utf-8")

    corpus.scope_repetition_bundle(trial)
    status = load_json(trial / "bundle_status.json")
    scope = load_json(trial / "repetition_scope.json")
    assert status["corpus_id"] == CONTRACT.corpus_id
    assert status["verdict_scope"] == CONTRACT.repetition_verdict_scope
    assert status["claim_verdict_eligible"] is False
    assert scope["distinct_scenario_count"] == len(CONTRACT.scenarios)
    assert scope["attack_class_count"] == len(CONTRACT.attack_classes)
    assert scope["runtime_scenario_pair_count"] == CONTRACT.runtime_scenario_pair_count
    assert scope["claim_verdict_producer"] == CONTRACT.claim_verdict_producer
    assert scope["corpus_contract_path"] == "docs/red_team_scenario_corpus_v2.json"
    assert "not the FE-CLAIM-011 verdict" in (trial / "summary.md").read_text(encoding="utf-8")
    scoped.validate_repetition_bundle(trial)

    status["claim_verdict_eligible"] = True
    write_json(trial / "bundle_status.json", status)
    expect_contract_error(lambda: scoped.validate_repetition_bundle(trial))
    status["claim_verdict_eligible"] = False
    write_json(trial / "bundle_status.json", status)

    scope["distinct_scenario_count"] = 9
    write_json(trial / "repetition_scope.json", scope)
    expect_contract_error(lambda: scoped.validate_repetition_bundle(trial))


def aggregate_scope_smoke(root: Path) -> None:
    results = [
        {
            "scenario_id": scenario.scenario_id,
            "attack_class": scenario.attack_class,
            "security_critical": True,
            "runtime": runtime,
        }
        for scenario in CONTRACT.scenarios
        for runtime in CONTRACT.runtimes
    ]
    details_path = root / "aggregate" / "measurement_details.json"
    harness_path = root / "aggregate" / "harness_output.json"
    semantic_fields = {
        "corpus_id": CONTRACT.corpus_id,
        "scenario_set": CONTRACT.corpus_id,
        "denominator_semantics": CONTRACT.denominator_semantics,
        "repetition_role": CONTRACT.repetition_role,
        "confidence_interpretation": CONTRACT.confidence_interpretation,
        "zero_cell_guard": CONTRACT.zero_cell_guard,
        "zero_cell_guard_count": CONTRACT.zero_cell_guard_count,
        "corpus_contract_path": "docs/red_team_scenario_corpus_v2.json",
        "verdict_scope": CONTRACT.aggregate_verdict_scope,
        "claim_verdict_eligible": False,
        "claim_verdict_producer": CONTRACT.claim_verdict_producer,
    }
    details = {"schema_version": "fixture.details.v1", "results": results, **semantic_fields}
    write_json(details_path, details)
    harness = annotate(
        {
            "schema_version": "franken-engine.red-team-harness-output.v1",
            "scenario_set": CONTRACT.corpus_id,
            "artifact_path": "aggregate/measurement_details.json",
            "artifact_hash": "sha256:" + "0" * 64,
            "results": results,
            **semantic_fields,
        }
    )
    write_json(harness_path, harness)
    verify_annotations(harness)
    scoped.validate_aggregate_semantics(root, harness_path)

    details["results"] = details["results"][:-1]
    write_json(details_path, details)
    expect_contract_error(lambda: scoped.validate_aggregate_semantics(root, harness_path))
    write_json(details_path, {"schema_version": "fixture.details.v1", "results": results, **semantic_fields})

    tampered = json.loads(json.dumps(harness))
    tampered["results"][0]["scenario_id"] = "count_preserving_lookalike"
    expect_semantic_error(lambda: verify_annotations(tampered))

    tampered = json.loads(json.dumps(harness))
    target = next(
        row
        for row in tampered["results"]
        if row["scenario_id"] == "reflect_apply_authority_smuggling"
    )
    target["attack_class"] = "prototype_pollution"
    expect_semantic_error(lambda: verify_annotations(tampered))

    harness["scenario_set"] = "legacy-five-scenario-set"
    write_json(harness_path, harness)
    expect_semantic_error(lambda: verify_annotations(harness))


def blocker_smoke(root: Path) -> None:
    output_dir = root / "blocked"
    write_json(
        output_dir / "bundle_status.json",
        {"schema_version": "legacy.pass.v1", "status": "pass", "reason": "stale"},
    )
    error = scoped.CorpusHarnessError("scope mismatch fixture")
    scoped.write_contract_blocker(output_dir, "scenario_corpus_contract_violation", error)
    blocker = load_json(output_dir / "aggregation_blocker.json")
    status = load_json(output_dir / "bundle_status.json")
    assert blocker["status"] == "fail_closed"
    assert blocker["reason"] == "scenario_corpus_contract_violation"
    assert blocker["placeholder_results_emitted"] is False
    assert status["status"] == "fail_closed"
    assert status["claim_verdict_eligible"] is False
    assert status["verdict_scope"] == CONTRACT.aggregate_verdict_scope
    assert status["reason"] == "scenario_corpus_contract_violation"


def main() -> int:
    corpus.install_corpus()
    assert tuple(
        (scenario.scenario_id, scenario.attack_class) for scenario in corpus.SCENARIOS
    ) == tuple(
        (scenario.scenario_id, scenario.attack_class) for scenario in CONTRACT.scenarios
    )
    with tempfile.TemporaryDirectory(prefix="franken-red-team-corpus-scope-") as temporary:
        root = Path(temporary)
        repetition_scope_smoke(root)
        aggregate_scope_smoke(root)
        blocker_smoke(root)
    print("red-team scenario-corpus scope smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
