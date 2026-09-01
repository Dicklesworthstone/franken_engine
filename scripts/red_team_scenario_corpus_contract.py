#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = REPO_ROOT / "docs/red_team_scenario_corpus_v2.json"
SCENARIO_ROOT = REPO_ROOT / "crates/franken-engine/tests/red_team_scenarios"
EXPECTED_SCHEMA = "franken-engine.red-team-scenario-corpus.v2"


class CorpusContractError(ValueError):
    pass


@dataclass(frozen=True)
class CorpusScenario:
    scenario_id: str
    attack_class: str

    @property
    def script_path(self) -> Path:
        return SCENARIO_ROOT / f"{self.scenario_id}.js"

    @property
    def manifest_path(self) -> Path:
        return SCENARIO_ROOT / f"{self.scenario_id}.manifest.json"


@dataclass(frozen=True)
class CorpusContract:
    schema_version: str
    corpus_id: str
    denominator_semantics: str
    repetition_role: str
    confidence_interpretation: str
    zero_cell_guard: str
    zero_cell_guard_count: int
    required_stability_repetitions_per_runtime_scenario: int
    repetition_verdict_scope: str
    aggregate_verdict_scope: str
    claim_verdict_producer: str
    claim_id: str
    owning_bead: str
    runtimes: tuple[str, ...]
    scenarios: tuple[CorpusScenario, ...]
    source_sha256: str

    @property
    def scenario_map(self) -> dict[str, str]:
        return {scenario.scenario_id: scenario.attack_class for scenario in self.scenarios}

    @property
    def attack_classes(self) -> frozenset[str]:
        return frozenset(scenario.attack_class for scenario in self.scenarios)

    @property
    def runtime_scenario_pair_count(self) -> int:
        return len(self.runtimes) * len(self.scenarios)


def sha256_ref_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CorpusContractError(f"{label} must be a JSON object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CorpusContractError(f"{label} must be a non-empty string")
    return value


def _require_positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise CorpusContractError(f"{label} must be a positive integer")
    return value


def load_contract(path: Path = CONTRACT_PATH) -> CorpusContract:
    try:
        raw_bytes = path.read_bytes()
        raw = _require_object(json.loads(raw_bytes), "corpus contract")
    except OSError as error:
        raise CorpusContractError(f"failed to read corpus contract {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise CorpusContractError(f"invalid corpus contract JSON in {path}: {error}") from error

    schema_version = _require_string(raw.get("schema_version"), "schema_version")
    if schema_version != EXPECTED_SCHEMA:
        raise CorpusContractError(
            f"unsupported corpus schema {schema_version!r}; expected {EXPECTED_SCHEMA!r}"
        )

    raw_runtimes = raw.get("runtimes")
    if not isinstance(raw_runtimes, list) or not raw_runtimes:
        raise CorpusContractError("runtimes must be a non-empty array")
    runtimes = tuple(
        _require_string(runtime, f"runtimes[{index}]")
        for index, runtime in enumerate(raw_runtimes)
    )
    if len(runtimes) != len(set(runtimes)):
        raise CorpusContractError("runtimes must be unique")
    if runtimes != ("node", "bun", "franken_engine"):
        raise CorpusContractError(f"unexpected runtime order or inventory: {runtimes!r}")

    raw_scenarios = raw.get("scenarios")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise CorpusContractError("scenarios must be a non-empty array")
    scenarios = tuple(
        CorpusScenario(
            scenario_id=_require_string(
                _require_object(item, f"scenarios[{index}]").get("scenario_id"),
                f"scenarios[{index}].scenario_id",
            ),
            attack_class=_require_string(
                _require_object(item, f"scenarios[{index}]").get("attack_class"),
                f"scenarios[{index}].attack_class",
            ),
        )
        for index, item in enumerate(raw_scenarios)
    )
    scenario_ids = [scenario.scenario_id for scenario in scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise CorpusContractError("scenario IDs must be unique")
    if len(scenarios) != 10:
        raise CorpusContractError(
            f"FE-CLAIM-011 corpus must contain exactly 10 scenarios; found {len(scenarios)}"
        )
    attack_classes = {scenario.attack_class for scenario in scenarios}
    if attack_classes != {
        "ambient_authority_escape",
        "prototype_pollution",
        "supply_chain_execution",
    }:
        raise CorpusContractError(f"unexpected attack-class inventory: {sorted(attack_classes)}")

    contract = CorpusContract(
        schema_version=schema_version,
        corpus_id=_require_string(raw.get("corpus_id"), "corpus_id"),
        denominator_semantics=_require_string(
            raw.get("denominator_semantics"), "denominator_semantics"
        ),
        repetition_role=_require_string(raw.get("repetition_role"), "repetition_role"),
        confidence_interpretation=_require_string(
            raw.get("confidence_interpretation"), "confidence_interpretation"
        ),
        zero_cell_guard=_require_string(raw.get("zero_cell_guard"), "zero_cell_guard"),
        zero_cell_guard_count=_require_positive_int(
            raw.get("zero_cell_guard_count"), "zero_cell_guard_count"
        ),
        required_stability_repetitions_per_runtime_scenario=_require_positive_int(
            raw.get("required_stability_repetitions_per_runtime_scenario"),
            "required_stability_repetitions_per_runtime_scenario",
        ),
        repetition_verdict_scope=_require_string(
            raw.get("repetition_verdict_scope"), "repetition_verdict_scope"
        ),
        aggregate_verdict_scope=_require_string(
            raw.get("aggregate_verdict_scope"), "aggregate_verdict_scope"
        ),
        claim_verdict_producer=_require_string(
            raw.get("claim_verdict_producer"), "claim_verdict_producer"
        ),
        claim_id=_require_string(raw.get("claim_id"), "claim_id"),
        owning_bead=_require_string(raw.get("owning_bead"), "owning_bead"),
        runtimes=runtimes,
        scenarios=scenarios,
        source_sha256=sha256_ref_bytes(raw_bytes),
    )
    if contract.zero_cell_guard_count != 1:
        raise CorpusContractError("FE-CLAIM-011 zero-cell guard count must remain exactly 1")
    if contract.required_stability_repetitions_per_runtime_scenario != 100:
        raise CorpusContractError("FE-CLAIM-011 stability repetition floor must remain exactly 100")
    if contract.claim_id != "FE-CLAIM-011" or contract.owning_bead != "bd-1vwza":
        raise CorpusContractError(
            f"claim ownership mismatch: {contract.claim_id}/{contract.owning_bead}"
        )
    return contract


def validate_repository_bindings(contract: CorpusContract) -> None:
    for scenario in contract.scenarios:
        if not scenario.script_path.is_file():
            raise CorpusContractError(
                f"missing scenario script: {scenario.script_path.relative_to(REPO_ROOT)}"
            )
        if not scenario.manifest_path.is_file():
            raise CorpusContractError(
                f"missing scenario manifest: {scenario.manifest_path.relative_to(REPO_ROOT)}"
            )
        try:
            manifest = _require_object(
                json.loads(scenario.manifest_path.read_text(encoding="utf-8")),
                f"manifest {scenario.scenario_id}",
            )
        except json.JSONDecodeError as error:
            raise CorpusContractError(
                f"invalid scenario manifest {scenario.manifest_path.relative_to(REPO_ROOT)}: {error}"
            ) from error
        if manifest.get("name") != scenario.scenario_id:
            raise CorpusContractError(
                f"manifest name mismatch for {scenario.scenario_id}: {manifest.get('name')!r}"
            )
        payload = _require_object(manifest.get("payload"), f"{scenario.scenario_id}.payload")
        if payload.get("program") != scenario.script_path.name:
            raise CorpusContractError(
                f"manifest program mismatch for {scenario.scenario_id}: {payload.get('program')!r}"
            )
        expected_outcome = _require_object(
            manifest.get("expected_outcome"), f"{scenario.scenario_id}.expected_outcome"
        )
        for runtime, expected in (
            ("node", "succeeds"),
            ("bun", "succeeds"),
            ("frankenengine", "fail_closed"),
        ):
            runtime_outcome = _require_object(
                expected_outcome.get(runtime),
                f"{scenario.scenario_id}.expected_outcome.{runtime}",
            )
            if runtime_outcome.get("outcome") != expected:
                raise CorpusContractError(
                    f"manifest outcome mismatch for {scenario.scenario_id}/{runtime}: "
                    f"expected {expected!r}, got {runtime_outcome.get('outcome')!r}"
                )
        measurement = _require_object(
            manifest.get("measurement"), f"{scenario.scenario_id}.measurement"
        )
        if measurement.get("success_signal") != "attack_succeeded == true":
            raise CorpusContractError(
                f"manifest success signal mismatch for {scenario.scenario_id}: "
                f"{measurement.get('success_signal')!r}"
            )


CONTRACT = load_contract()
CONTRACT_SHA256 = CONTRACT.source_sha256
validate_repository_bindings(CONTRACT)
