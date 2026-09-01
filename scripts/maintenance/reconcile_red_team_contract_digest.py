#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUST_GATE = ROOT / "crates/franken-engine/src/bin/franken_red_team_harness_gate.rs"
RUST_TEST = ROOT / "crates/franken-engine/tests/red_team_harness_gate_cli.rs"
PYTHON_SMOKE = ROOT / "scripts/e2e/red_team_scenario_corpus_scope_smoke.py"


class ReconcileError(RuntimeError):
    pass


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise ReconcileError(f"{label}: expected one old fragment, found {count}")
    return text.replace(old, new, 1)


def reconcile_rust_gate(text: str) -> str:
    text = replace_once(
        text,
        "use frankenengine_engine::disruptive_floor_metric_gate::{\n"
        "    DEFAULT_MAX_FRESHNESS_DAYS, DEFAULT_MIN_CONFIDENCE_MILLIONTHS,\n"
        "    DisruptiveMetricId, MetricArtifact,\n"
        "};\n"
        "use frankenengine_engine::red_team_compromise_rate_metric_gate::{",
        "use frankenengine_engine::disruptive_floor_metric_gate::{\n"
        "    DEFAULT_MAX_FRESHNESS_DAYS, DEFAULT_MIN_CONFIDENCE_MILLIONTHS,\n"
        "    DisruptiveMetricId, MetricArtifact,\n"
        "};\n"
        "use frankenengine_engine::hash_tiers::ContentHash;\n"
        "use frankenengine_engine::red_team_compromise_rate_metric_gate::{",
        "Rust gate ContentHash import",
    )
    text = replace_once(
        text,
        "    fn validate(&self) -> Result<(), String> {",
        "    fn source_sha256() -> String {\n"
        "        format!(\n"
        "            \"sha256:{}\",\n"
        "            ContentHash::compute(include_bytes!(\n"
        "                \"../../../../docs/red_team_scenario_corpus_v2.json\"\n"
        "            ))\n"
        "            .to_hex()\n"
        "        )\n"
        "    }\n\n"
        "    fn validate(&self) -> Result<(), String> {",
        "Rust gate contract digest method",
    )
    text = replace_once(
        text,
        "    corpus_contract_path: &'static str,\n"
        "    claim_scope: &'static str,",
        "    corpus_contract_path: &'static str,\n"
        "    corpus_contract_sha256: String,\n"
        "    claim_scope: &'static str,",
        "Rust report digest field",
    )
    text = replace_once(
        text,
        "    let object = value\n"
        "        .as_object()\n"
        "        .ok_or_else(|| \"harness output must be a JSON object\".to_string())?;\n"
        "    for (field, expected) in [",
        "    let object = value\n"
        "        .as_object()\n"
        "        .ok_or_else(|| \"harness output must be a JSON object\".to_string())?;\n"
        "    let contract_sha256 = CorpusContract::source_sha256();\n"
        "    for (field, expected) in [",
        "Rust semantic digest local",
    )
    text = replace_once(
        text,
        "        (\"corpus_contract_path\", CONTRACT_PATH),\n"
        "    ] {",
        "        (\"corpus_contract_path\", CONTRACT_PATH),\n"
        "        (\"corpus_contract_sha256\", contract_sha256.as_str()),\n"
        "    ] {",
        "Rust semantic digest assertion",
    )
    text = replace_once(
        text,
        "        corpus_contract_path: CONTRACT_PATH,\n"
        "        claim_scope:",
        "        corpus_contract_path: CONTRACT_PATH,\n"
        "        corpus_contract_sha256: CorpusContract::source_sha256(),\n"
        "        claim_scope:",
        "Rust report digest value",
    )
    return text


def reconcile_rust_test(text: str) -> str:
    text = replace_once(
        text,
        "use serde_json::Value;",
        "use frankenengine_engine::hash_tiers::ContentHash;\nuse serde_json::Value;",
        "Rust test ContentHash import",
    )
    text = replace_once(
        text,
        "fn fixture() -> Value {\n"
        "    serde_json::from_str(include_str!(\"fixtures/red_team_harness_output_v1.json\"))\n"
        "        .expect(\"valid harness fixture\")\n"
        "}\n",
        "fn fixture() -> Value {\n"
        "    serde_json::from_str(include_str!(\"fixtures/red_team_harness_output_v1.json\"))\n"
        "        .expect(\"valid harness fixture\")\n"
        "}\n\n"
        "fn contract_sha256() -> String {\n"
        "    format!(\n"
        "        \"sha256:{}\",\n"
        "        ContentHash::compute(include_bytes!(\n"
        "            \"../../../docs/red_team_scenario_corpus_v2.json\"\n"
        "        ))\n"
        "        .to_hex()\n"
        "    )\n"
        "}\n",
        "Rust test contract digest helper",
    )
    text = replace_once(
        text,
        "    value[\"corpus_contract_path\"] = Value::from(\"docs/red_team_scenario_corpus_v2.json\");\n"
        "    value[\"distinct_scenario_count\"] = Value::from(10);",
        "    value[\"corpus_contract_path\"] = Value::from(\"docs/red_team_scenario_corpus_v2.json\");\n"
        "    value[\"corpus_contract_sha256\"] = Value::from(contract_sha256());\n"
        "    value[\"distinct_scenario_count\"] = Value::from(10);",
        "Rust fixture digest annotation",
    )
    text = replace_once(
        text,
        "#[test]\n"
        "fn below_contract_stability_floor_is_invalid_input() {",
        "#[test]\n"
        "fn aggregate_input_must_match_embedded_contract_digest() {\n"
        "    let mut value = ten_scenario_fixture();\n"
        "    value[\"corpus_contract_sha256\"] = Value::from(format!(\"sha256:{}\", \"0\".repeat(64)));\n"
        "    assert_invalid(\n"
        "        &value,\n"
        "        \"wrong-contract-digest\",\n"
        "        \"corpus_contract_sha256 mismatch\",\n"
        "    );\n"
        "}\n\n"
        "#[test]\n"
        "fn below_contract_stability_floor_is_invalid_input() {",
        "Rust digest negative test",
    )
    return text


def reconcile_python_smoke(text: str) -> str:
    text = replace_once(
        text,
        "        \"corpus_contract_path\": \"docs/red_team_scenario_corpus_v2.json\",\n"
        "        \"verdict_scope\": CONTRACT.aggregate_verdict_scope,",
        "        \"corpus_contract_path\": \"docs/red_team_scenario_corpus_v2.json\",\n"
        "        \"corpus_contract_sha256\": CONTRACT.source_sha256,\n"
        "        \"verdict_scope\": CONTRACT.aggregate_verdict_scope,",
        "Python smoke aggregate digest annotation",
    )
    text = replace_once(
        text,
        "    assert scope[\"corpus_contract_path\"] == \"docs/red_team_scenario_corpus_v2.json\"\n"
        "    assert \"not the FE-CLAIM-011 verdict\"",
        "    assert scope[\"corpus_contract_path\"] == \"docs/red_team_scenario_corpus_v2.json\"\n"
        "    assert scope[\"corpus_contract_sha256\"] == CONTRACT.source_sha256\n"
        "    assert \"not the FE-CLAIM-011 verdict\"",
        "Python smoke repetition digest assertion",
    )
    text = replace_once(
        text,
        "    harness[\"scenario_set\"] = \"legacy-five-scenario-set\"\n"
        "    write_json(harness_path, harness)\n"
        "    expect_semantic_error(lambda: verify_annotations(harness))",
        "    tampered = json.loads(json.dumps(harness))\n"
        "    tampered[\"corpus_contract_sha256\"] = \"sha256:\" + \"0\" * 64\n"
        "    expect_semantic_error(lambda: verify_annotations(tampered))\n\n"
        "    harness[\"scenario_set\"] = \"legacy-five-scenario-set\"\n"
        "    write_json(harness_path, harness)\n"
        "    expect_semantic_error(lambda: verify_annotations(harness))",
        "Python digest tamper drill",
    )
    return text


def reconcile(path: Path, transform) -> None:
    original = path.read_text(encoding="utf-8")
    updated = transform(original)
    if updated != original:
        path.write_text(updated, encoding="utf-8")


def verify() -> None:
    rust_gate = RUST_GATE.read_text(encoding="utf-8")
    rust_test = RUST_TEST.read_text(encoding="utf-8")
    python_smoke = PYTHON_SMOKE.read_text(encoding="utf-8")
    required = {
        "Rust gate": [
            "use frankenengine_engine::hash_tiers::ContentHash;",
            "fn source_sha256() -> String",
            "corpus_contract_sha256: String",
            '("corpus_contract_sha256", contract_sha256.as_str())',
            "corpus_contract_sha256: CorpusContract::source_sha256()",
        ],
        "Rust test": [
            "fn contract_sha256() -> String",
            'value["corpus_contract_sha256"] = Value::from(contract_sha256());',
            "fn aggregate_input_must_match_embedded_contract_digest()",
        ],
        "Python smoke": [
            '"corpus_contract_sha256": CONTRACT.source_sha256',
            'scope["corpus_contract_sha256"] == CONTRACT.source_sha256',
            'tampered["corpus_contract_sha256"] = "sha256:" + "0" * 64',
        ],
    }
    for label, needles in required.items():
        text = {"Rust gate": rust_gate, "Rust test": rust_test, "Python smoke": python_smoke}[label]
        for needle in needles:
            if needle not in text:
                raise ReconcileError(f"{label} missing digest binding: {needle}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bind the FE-CLAIM-011 corpus contract digest through Rust and negative tests")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.write:
            reconcile(RUST_GATE, reconcile_rust_gate)
            reconcile(RUST_TEST, reconcile_rust_test)
            reconcile(PYTHON_SMOKE, reconcile_python_smoke)
        verify()
        print("red_team_contract_digest_reconciliation=pass")
        return 0
    except (OSError, ReconcileError) as error:
        print(f"red-team contract digest reconciliation blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
