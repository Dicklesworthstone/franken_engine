#!/usr/bin/env python3
"""Manifest-driven semantic-fidelity vector runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SUITE_SCHEMA_VERSION = "franken-engine.semantic-fidelity-vectors.v1"
RUN_SCHEMA_VERSION = "franken-engine.semantic-fidelity-workbench-run.v1"
EVENT_SCHEMA_VERSION = "franken-engine.semantic-fidelity-event.v1"
RESULT_SCHEMA_VERSION = "franken-engine.semantic-fidelity-vector-result.v1"
PATH_PARITY_SCHEMA_VERSION = "franken-engine.semantic-fidelity-path-parity-report.v1"
AUTO_TRIAGE_SCHEMA_VERSION = "franken-engine.semantic-fidelity-auto-triage-report.v1"

SHA_PREFIX = "sha256:"
HASH_DOMAIN = "franken-engine.semantic-fidelity.hash.v1"

EXPECTED_TOP_FIELDS = {
    "schema_version",
    "suite_id",
    "owning_bead",
    "description",
    "determinism_policy",
    "vectors",
}
EXPECTED_VECTOR_FIELDS = {
    "vector_id",
    "semantic_family",
    "description",
    "source",
    "route_under_test",
    "oracle_routes",
    "expectation",
    "analyzed_scope",
    "hashes",
    "provenance",
    "remediation",
}
VALID_EXPECTATION_KINDS = {
    "normal",
    "js_error",
    "unsupported",
    "degraded",
    "expected_unknown",
}
EXTERNAL_ROUTE_KINDS = {
    "node_oracle": "node",
    "bun_oracle": "bun",
}
BUILTIN_FAMILY_HINTS = (
    ("array_length", "Array.length"),
    ("number_digits", "Number.prototype.toExponential/toPrecision"),
    ("string_at", "String.prototype.at"),
    ("string_from_char_code", "String.fromCharCode"),
    ("string_from_code_point", "String.fromCodePoint"),
    ("string_index", "String.prototype.at"),
    ("string_repeat", "String.prototype.repeat"),
    ("runner_classification", "runner_classification"),
    ("self_test", "self_test"),
)


class VectorError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def utc_now() -> str:
    override = os.environ.get("SEMANTIC_FIDELITY_NOW_UTC")
    if override:
        return normalize_utc(override)
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_utc(value: str) -> str:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def clone_json(value: Any) -> Any:
    return json.loads(canonical_json(value))


def sha256_text(value: str) -> str:
    return SHA_PREFIX + hashlib.sha256(value.encode("utf-8")).hexdigest()


def length_prefixed_hash(fields: dict[str, str]) -> str:
    hasher = hashlib.sha256()
    ordered = sorted(fields.items())
    hasher.update(HASH_DOMAIN.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(len(ordered).to_bytes(4, "big"))
    for name, value in ordered:
        name_bytes = name.encode("utf-8")
        value_bytes = value.encode("utf-8")
        hasher.update(len(name_bytes).to_bytes(4, "big"))
        hasher.update(name_bytes)
        hasher.update(len(value_bytes).to_bytes(8, "big"))
        hasher.update(value_bytes)
    return SHA_PREFIX + hasher.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise VectorError("malformed_vector", f"{path} must contain a JSON object")
    return loaded


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical_json(row))
            handle.write("\n")


def display_path(path: Path) -> str:
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def suite_hash(suite: dict[str, Any]) -> str:
    return sha256_text(canonical_json(suite))


def source_hash_payload(source: dict[str, Any], suite_dir: Path) -> dict[str, str]:
    kind = source.get("kind")
    fields = {
        "kind": str(kind),
        "parse_goal": str(source.get("parse_goal", "")),
        "source_label": str(source.get("source_label", "")),
    }
    if kind == "inline_source":
        fields["inline_source"] = str(source.get("inline_source", ""))
    elif kind == "fixture_path":
        raw_path = str(source.get("fixture_path", ""))
        fixture_path = (suite_dir / raw_path).resolve(strict=False)
        fields["fixture_path"] = raw_path
        if fixture_path.is_file():
            fields["fixture_content_sha256"] = SHA_PREFIX + hashlib.sha256(
                fixture_path.read_bytes()
            ).hexdigest()
        else:
            fields["fixture_content_sha256"] = "missing"
    else:
        fields["unknown_source_kind"] = str(kind)
    return fields


def computed_hashes(vector: dict[str, Any], suite_dir: Path) -> dict[str, str]:
    route_metadata = {
        "route_under_test": vector.get("route_under_test"),
        "oracle_routes": vector.get("oracle_routes", []),
    }
    return {
        "source_sha256": length_prefixed_hash(source_hash_payload(vector["source"], suite_dir)),
        "route_metadata_sha256": length_prefixed_hash(
            {"route_metadata": canonical_json(route_metadata)}
        ),
        "expectation_sha256": length_prefixed_hash(
            {"expectation": canonical_json(vector["expectation"])}
        ),
    }


def validate_sha(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.startswith(SHA_PREFIX):
        raise VectorError("source_hash_mismatch", f"{field} must start with {SHA_PREFIX}")
    tail = value[len(SHA_PREFIX) :]
    if len(tail) != 64 or any(ch not in "0123456789abcdef" for ch in tail):
        raise VectorError("source_hash_mismatch", f"{field} must be lowercase sha256 hex")


def reject_unknown_keys(obj: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise VectorError("malformed_vector", f"{context} has unknown keys: {', '.join(unknown)}")


def validate_suite_shape(suite: dict[str, Any]) -> None:
    reject_unknown_keys(suite, EXPECTED_TOP_FIELDS, "suite")
    if suite.get("schema_version") != SUITE_SCHEMA_VERSION:
        raise VectorError("malformed_vector", f"schema_version must be {SUITE_SCHEMA_VERSION}")
    vectors = suite.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise VectorError("malformed_vector", "vectors must be a non-empty array")


def validate_vector(vector: dict[str, Any], suite_dir: Path) -> list[str]:
    reject_unknown_keys(vector, EXPECTED_VECTOR_FIELDS, str(vector.get("vector_id", "<unknown>")))
    for field in (
        "vector_id",
        "semantic_family",
        "description",
        "source",
        "route_under_test",
        "expectation",
        "analyzed_scope",
        "hashes",
        "provenance",
        "remediation",
    ):
        if field not in vector:
            raise VectorError("malformed_vector", f"{vector.get('vector_id')} missing {field}")
    if not isinstance(vector.get("source"), dict):
        raise VectorError("malformed_vector", f"{vector.get('vector_id')} source must be object")
    if not isinstance(vector.get("route_under_test"), dict):
        raise VectorError(
            "malformed_vector", f"{vector.get('vector_id')} route_under_test must be object"
        )
    if not isinstance(vector.get("expectation"), dict):
        raise VectorError(
            "ambiguous_expectation", f"{vector.get('vector_id')} expectation must be object"
        )
    kind = vector["expectation"].get("kind")
    if kind not in VALID_EXPECTATION_KINDS:
        raise VectorError(
            "ambiguous_expectation",
            f"{vector.get('vector_id')} expectation.kind is invalid: {kind}",
        )
    route_ids = [vector["route_under_test"].get("route_id")]
    for route in vector.get("oracle_routes", []) or []:
        if not isinstance(route, dict):
            raise VectorError("malformed_vector", f"{vector.get('vector_id')} oracle route invalid")
        route_ids.append(route.get("route_id"))
    if len(route_ids) != len(set(route_ids)):
        raise VectorError("malformed_vector", f"{vector.get('vector_id')} has duplicate route_id")

    hashes = vector.get("hashes")
    if not isinstance(hashes, dict):
        raise VectorError("source_hash_mismatch", f"{vector.get('vector_id')} hashes must be object")
    for field in ("source_sha256", "route_metadata_sha256", "expectation_sha256"):
        validate_sha(hashes.get(field), field)
    expected_hashes = computed_hashes(vector, suite_dir)
    mismatches = [
        field for field, expected in expected_hashes.items() if hashes.get(field) != expected
    ]
    if mismatches:
        raise VectorError(
            "source_hash_mismatch",
            f"{vector.get('vector_id')} hash mismatch: {', '.join(mismatches)}",
        )
    return []


def validate_vectors(suite: dict[str, Any], suite_dir: Path) -> list[dict[str, Any]]:
    validate_suite_shape(suite)
    seen: set[str] = set()
    errors: list[dict[str, Any]] = []
    for vector in suite["vectors"]:
        if not isinstance(vector, dict):
            errors.append({"vector_id": "<non-object>", "code": "malformed_vector", "message": "vector must be object"})
            continue
        vector_id = str(vector.get("vector_id", "<missing>"))
        if vector_id in seen:
            errors.append(
                {
                    "vector_id": vector_id,
                    "code": "duplicate_vector_id",
                    "message": f"duplicate vector_id: {vector_id}",
                }
            )
            continue
        seen.add(vector_id)
        try:
            validate_vector(vector, suite_dir)
        except VectorError as err:
            errors.append({"vector_id": vector_id, "code": err.code, "message": str(err)})
    return errors


def source_text(vector: dict[str, Any], suite_dir: Path) -> str:
    source = vector["source"]
    if source["kind"] == "inline_source":
        return str(source["inline_source"])
    path = (suite_dir / str(source["fixture_path"])).resolve(strict=False)
    return path.read_text(encoding="utf-8")


def run_external_js(runtime: str, source: str, timeout_seconds: int) -> dict[str, Any]:
    exe = shutil.which(runtime)
    if exe is None:
        return {
            "available": False,
            "ok": False,
            "reason_code": "external_oracle_unavailable",
            "stdout": "",
            "stderr": f"{runtime} not found on PATH",
            "exit_code": None,
        }
    wrapper = (
        f"const source = {json.dumps(source)};\n"
        "try {\n"
        "  const value = (0, eval)(source);\n"
        "  const valueKind = value === null ? 'null' : typeof value;\n"
        "  console.log(JSON.stringify({ok:true,value_kind:valueKind,value:String(value)}));\n"
        "} catch (err) {\n"
        "  console.log(JSON.stringify({ok:false,error_class:err && err.name ? err.name : 'Error',message:String(err && err.message ? err.message : err)}));\n"
        "}\n"
    )
    try:
        completed = subprocess.run(
            [exe, "-e", wrapper],
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as err:
        return {
            "available": True,
            "ok": False,
            "reason_code": "nondeterministic_output",
            "stdout": err.stdout or "",
            "stderr": err.stderr or "runtime timed out",
            "exit_code": None,
        }
    parsed: dict[str, Any] | None = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            parsed = None
    return {
        "available": True,
        "ok": completed.returncode == 0 and parsed is not None,
        "parsed": parsed,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "exit_code": completed.returncode,
    }


def evaluate_expectation(
    vector: dict[str, Any],
    suite_dir: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    expectation = vector["expectation"]
    route = vector["route_under_test"]
    route_kind = route.get("route_kind")
    if expectation["kind"] in {"unsupported", "degraded", "expected_unknown"}:
        return {
            "outcome": expectation["kind"],
            "passed": True,
            "reason_codes": [expectation.get("reason_code", expectation["kind"])],
            "actual": None,
            "route_status": "declared",
        }
    if route_kind not in EXTERNAL_ROUTE_KINDS:
        return {
            "outcome": "degraded",
            "passed": True,
            "reason_codes": ["unsupported_route"],
            "actual": None,
            "route_status": "not_executed",
        }
    runtime = route.get("external_runtime") or EXTERNAL_ROUTE_KINDS[route_kind]
    actual = run_external_js(str(runtime), source_text(vector, suite_dir), timeout_seconds)
    if not actual.get("available"):
        return {
            "outcome": "degraded",
            "passed": True,
            "reason_codes": ["external_oracle_unavailable"],
            "actual": actual,
            "route_status": "degraded",
        }
    parsed = actual.get("parsed")
    if not actual.get("ok") or not isinstance(parsed, dict):
        return {
            "outcome": "fail_closed",
            "passed": False,
            "reason_codes": ["nondeterministic_output"],
            "actual": actual,
            "route_status": "failed",
        }
    if expectation["kind"] == "js_error":
        if parsed.get("ok") is not False:
            return {
                "outcome": "fail_closed",
                "passed": False,
                "reason_codes": ["expected_error_class_mismatch"],
                "actual": actual,
                "route_status": "executed",
            }
        expected_class = expectation["error_class"]
        if parsed.get("error_class") != expected_class:
            return {
                "outcome": "fail_closed",
                "passed": False,
                "reason_codes": ["expected_error_class_mismatch"],
                "actual": actual,
                "route_status": "executed",
            }
        for needle in expectation.get("message_contains", []) or []:
            if needle not in str(parsed.get("message", "")):
                return {
                    "outcome": "fail_closed",
                    "passed": False,
                    "reason_codes": ["expected_error_class_mismatch"],
                    "actual": actual,
                    "route_status": "executed",
                }
        return {
            "outcome": "passed",
            "passed": True,
            "reason_codes": [],
            "actual": actual,
            "route_status": "executed",
        }
    expected_value = expectation.get("value")
    if parsed.get("ok") is not True or str(parsed.get("value")) != str(expected_value):
        return {
            "outcome": "fail_closed",
            "passed": False,
            "reason_codes": ["expected_value_mismatch"],
            "actual": actual,
            "route_status": "executed",
        }
    return {
        "outcome": "passed",
        "passed": True,
        "reason_codes": [],
        "actual": actual,
        "route_status": "executed",
    }


def expected_observation(expectation: dict[str, Any]) -> dict[str, Any]:
    kind = expectation["kind"]
    if kind == "js_error":
        return {
            "kind": kind,
            "error_class": expectation.get("error_class"),
            "message_contains": expectation.get("message_contains", []),
            "catchable": expectation.get("catchable"),
        }
    if kind == "normal":
        return {
            "kind": kind,
            "value": str(expectation.get("value")),
        }
    return {
        "kind": kind,
        "reason_code": expectation.get("reason_code", kind),
        "consumer_action": expectation.get("consumer_action"),
    }


def actual_observation(evaluation: dict[str, Any]) -> dict[str, Any]:
    actual = evaluation.get("actual")
    if not isinstance(actual, dict):
        return {
            "kind": evaluation["outcome"],
            "route_status": evaluation["route_status"],
            "reason_codes": evaluation["reason_codes"],
        }
    parsed = actual.get("parsed")
    if isinstance(parsed, dict):
        if parsed.get("ok") is False:
            return {
                "kind": "js_error",
                "error_class": parsed.get("error_class"),
                "message": parsed.get("message"),
                "route_status": evaluation["route_status"],
                "exit_code": actual.get("exit_code"),
            }
        if parsed.get("ok") is True:
            return {
                "kind": "normal",
                "value": str(parsed.get("value")),
                "value_kind": parsed.get("value_kind"),
                "route_status": evaluation["route_status"],
                "exit_code": actual.get("exit_code"),
            }
    return {
        "kind": "runtime_output",
        "available": actual.get("available"),
        "ok": actual.get("ok"),
        "route_status": evaluation["route_status"],
        "reason_code": actual.get("reason_code"),
        "exit_code": actual.get("exit_code"),
        "stderr": actual.get("stderr", ""),
    }


def first_divergence(vector: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any] | None:
    if evaluation["passed"]:
        return None
    reason = evaluation["reason_codes"][0] if evaluation["reason_codes"] else "unknown"
    return {
        "reason_code": reason,
        "expected": expected_observation(vector["expectation"]),
        "actual": actual_observation(evaluation),
    }


def evidence_classification(vector: dict[str, Any], evaluation: dict[str, Any]) -> str:
    outcome = evaluation["outcome"]
    route_kind = vector["route_under_test"].get("route_kind")
    if outcome == "passed" and route_kind in EXTERNAL_ROUTE_KINDS:
        return "accepted_external_oracle"
    if outcome in {"unsupported", "expected_unknown"}:
        return "declared_non_execution"
    if outcome == "degraded":
        if route_kind in EXTERNAL_ROUTE_KINDS:
            return "degraded_external_oracle"
        return "degraded_non_executed_route"
    if outcome == "fail_closed":
        return "fail_closed"
    return "unclassified"


def builtin_from_family(semantic_family: str) -> str:
    for prefix, builtin in BUILTIN_FAMILY_HINTS:
        if semantic_family.startswith(prefix):
            return builtin
    parts = [part for part in semantic_family.split("_") if part]
    if not parts:
        return "unknown"
    return ".".join(parts[:2]) if len(parts) > 1 else parts[0]


def expected_signature(row: dict[str, Any]) -> str:
    return canonical_json(row["expected_outcome"])


def actual_signature(row: dict[str, Any]) -> str:
    return canonical_json(row["actual_outcome"])


def group_status(route_disagreement: bool, rows: list[dict[str, Any]]) -> str:
    if any(not row["passed"] for row in rows):
        return "has_failures"
    if route_disagreement:
        return "route_disagreement"
    if any(row["evidence_classification"] != "accepted_external_oracle" for row in rows):
        return "degraded_or_declared"
    return "route_agrees"


def build_path_parity_report(
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    validation_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in results:
        builtin = builtin_from_family(row["semantic_family"])
        grouped.setdefault((builtin, row["semantic_family"]), []).append(row)

    groups: list[dict[str, Any]] = []
    failure_groups: list[dict[str, Any]] = []
    for (builtin, semantic_family), rows in sorted(grouped.items()):
        ordered_rows = sorted(rows, key=lambda row: (row["route_id"], row["vector_id"]))
        actual_signatures = sorted({actual_signature(row) for row in ordered_rows})
        route_rows = [
            {
                "vector_id": row["vector_id"],
                "source_sha256": row["source_sha256"],
                "dispatch_route": row["dispatch_route"],
                "route_id": row["route_id"],
                "route_kind": row["route_kind"],
                "outcome": row["outcome"],
                "passed": row["passed"],
                "route_status": row["route_status"],
                "evidence_classification": row["evidence_classification"],
                "expected_signature": expected_signature(row),
                "actual_signature": actual_signature(row),
                "reason_codes": row["reason_codes"],
                "first_divergence": row["first_divergence"],
            }
            for row in ordered_rows
        ]
        source_groups: dict[str, list[dict[str, Any]]] = {}
        for row in ordered_rows:
            source_groups.setdefault(row["source_sha256"], []).append(row)
        source_route_disagreements = []
        for source_sha256, source_rows in sorted(source_groups.items()):
            source_actual_signatures = sorted({actual_signature(row) for row in source_rows})
            if len(source_rows) > 1 and len(source_actual_signatures) > 1:
                source_route_disagreements.append(
                    {
                        "source_sha256": source_sha256,
                        "route_count": len(source_rows),
                        "actual_signatures": source_actual_signatures,
                        "routes": [
                            {
                                "vector_id": row["vector_id"],
                                "dispatch_route": row["dispatch_route"],
                                "outcome": row["outcome"],
                                "evidence_classification": row["evidence_classification"],
                                "actual_signature": actual_signature(row),
                            }
                            for row in sorted(
                                source_rows, key=lambda row: (row["route_id"], row["vector_id"])
                            )
                        ],
                    }
                )
        route_disagreement = bool(source_route_disagreements)
        groups.append(
            {
                "builtin": builtin,
                "semantic_family": semantic_family,
                "group_status": group_status(route_disagreement, ordered_rows),
                "route_disagreement": route_disagreement,
                "route_count": len(route_rows),
                "failure_count": sum(1 for row in ordered_rows if not row["passed"]),
                "non_executed_count": sum(
                    1
                    for row in ordered_rows
                    if row["evidence_classification"]
                    in {"declared_non_execution", "degraded_non_executed_route"}
                ),
                "degraded_count": sum(
                    1
                    for row in ordered_rows
                    if row["evidence_classification"].startswith("degraded_")
                ),
                "actual_signatures": actual_signatures,
                "source_route_disagreements": source_route_disagreements,
                "routes": route_rows,
            }
        )
        for row in ordered_rows:
            if not row["passed"]:
                failure_groups.append(
                    {
                        "builtin": builtin,
                        "semantic_family": semantic_family,
                        "dispatch_route": row["dispatch_route"],
                        "vector_id": row["vector_id"],
                        "outcome": row["outcome"],
                        "reason_codes": row["reason_codes"],
                        "first_divergence": row["first_divergence"],
                    }
                )

    return {
        "schema_version": PATH_PARITY_SCHEMA_VERSION,
        "generated_at_utc": manifest["generated_at_utc"],
        "suite_id": manifest["suite_id"],
        "suite_sha256": manifest["suite_sha256"],
        "decision": manifest["decision"],
        "validation_errors": validation_errors,
        "summary": {
            "vector_count": len(results),
            "builtin_group_count": len(groups),
            "route_disagreement_group_count": sum(
                1 for group in groups if group["route_disagreement"]
            ),
            "failure_group_count": len(failure_groups),
            "degraded_or_declared_group_count": sum(
                1
                for group in groups
                if group["group_status"] in {"degraded_or_declared", "route_disagreement"}
            ),
        },
        "groups": groups,
        "failure_groups": failure_groups,
    }


def suggested_bead_title(row: dict[str, Any]) -> str:
    builtin = builtin_from_family(row["semantic_family"])
    return (
        f"[semantic-fidelity] {builtin} drift via {row['route_id']} "
        f"({row['vector_id']})"
    )


def suggested_bead_description(row: dict[str, Any]) -> str:
    rerun = row["command_replay_hints"].get("runner_command", "<missing runner command>")
    replay = row["command_replay_hints"].get(
        "preserved_bundle_replay", "<missing preserved replay command>"
    )
    return "\n".join(
        [
            "## Background",
            "Semantic-fidelity workbench found an unlinked confirmed drift.",
            "",
            "## Route",
            f"- vector_id: `{row['vector_id']}`",
            f"- semantic_family: `{row['semantic_family']}`",
            f"- route_id: `{row['route_id']}`",
            f"- route_kind: `{row['route_kind']}`",
            "",
            "## Expected",
            f"```json\n{json.dumps(row['expected_outcome'], indent=2, sort_keys=True)}\n```",
            "",
            "## Actual",
            f"```json\n{json.dumps(row['actual_outcome'], indent=2, sort_keys=True)}\n```",
            "",
            "## First Divergence",
            f"```json\n{json.dumps(row['first_divergence'], indent=2, sort_keys=True)}\n```",
            "",
            "## Validation",
            f"- Run: `{rerun}`",
            f"- Replay preserved bundle: `{replay}`",
        ]
    )


def triage_classification(row: dict[str, Any]) -> str:
    if not row["passed"]:
        return "confirmed_failure"
    if row["evidence_classification"] == "declared_non_execution":
        return "unsupported_or_expected_unknown"
    if row["evidence_classification"].startswith("degraded_"):
        return "degraded_surface"
    return "accepted_oracle"


def triage_action(row: dict[str, Any], existing_bead_refs: list[str]) -> str:
    classification = triage_classification(row)
    if classification == "confirmed_failure" and existing_bead_refs:
        return "link_existing_bead"
    if classification == "confirmed_failure":
        return "suggest_new_bead"
    if classification == "unsupported_or_expected_unknown":
        return "classify_unsupported_surface"
    if classification == "degraded_surface":
        return "record_degraded_oracle"
    return "no_action"


def build_auto_triage_report(
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    validation_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    entries = []
    for row in sorted(results, key=lambda result: result["vector_id"]):
        existing_bead_refs = [
            str(bead)
            for bead in row.get("remediation", {}).get("existing_bead_refs", []) or []
        ]
        existing_beads = [
            {
                "bead_id": bead_id,
                "match_basis": [
                    "fixture.remediation.existing_bead_refs",
                    f"semantic_family:{row['semantic_family']}",
                ],
            }
            for bead_id in existing_bead_refs
        ]
        action = triage_action(row, existing_bead_refs)
        suggestion = None
        if action == "suggest_new_bead":
            suggestion = {
                "idempotency_key": sha256_text(
                    "|".join(
                        [
                            row["vector_id"],
                            row["source_sha256"],
                            row["route_id"],
                            canonical_json(row["first_divergence"]),
                        ]
                    )
                ),
                "title": suggested_bead_title(row),
                "description": suggested_bead_description(row),
            }
        entries.append(
            {
                "vector_id": row["vector_id"],
                "semantic_family": row["semantic_family"],
                "builtin": builtin_from_family(row["semantic_family"]),
                "dispatch_route": row["dispatch_route"],
                "outcome": row["outcome"],
                "passed": row["passed"],
                "evidence_classification": row["evidence_classification"],
                "triage_classification": triage_classification(row),
                "triage_action": action,
                "reason_codes": row["reason_codes"],
                "first_divergence": row["first_divergence"],
                "existing_beads": existing_beads,
                "suggested_bead": suggestion,
                "unsupported_surface": action == "classify_unsupported_surface",
                "degraded_surface": action == "record_degraded_oracle",
                "validation_commands": row["command_replay_hints"],
            }
        )

    return {
        "schema_version": AUTO_TRIAGE_SCHEMA_VERSION,
        "generated_at_utc": manifest["generated_at_utc"],
        "suite_id": manifest["suite_id"],
        "suite_sha256": manifest["suite_sha256"],
        "decision": manifest["decision"],
        "validation_errors": validation_errors,
        "summary": {
            "entry_count": len(entries),
            "confirmed_failure_count": sum(
                1 for entry in entries if entry["triage_classification"] == "confirmed_failure"
            ),
            "existing_bead_link_count": sum(
                len(entry["existing_beads"])
                for entry in entries
                if entry["triage_action"] == "link_existing_bead"
            ),
            "suggested_bead_count": sum(
                1 for entry in entries if entry["suggested_bead"] is not None
            ),
            "unsupported_surface_count": sum(
                1 for entry in entries if entry["unsupported_surface"]
            ),
            "degraded_surface_count": sum(1 for entry in entries if entry["degraded_surface"]),
        },
        "entries": entries,
    }


def replay_hints(
    vector_id: str,
    suite_path: Path | None,
    run_dir: Path | None,
    timeout_seconds: int,
) -> dict[str, str]:
    hints = {"vector_id": vector_id}
    if suite_path is not None:
        suite_display = display_path(suite_path)
        hints["runner_command"] = (
            "python3 scripts/semantic_fidelity_workbench.py "
            f"--suite {shlex_quote(suite_display)} "
            f"--timeout-seconds {timeout_seconds} --pretty"
        )
    if run_dir is not None:
        run_display = display_path(run_dir)
        hints["preserved_bundle_replay"] = (
            "scripts/e2e/semantic_fidelity_workbench_replay.sh "
            f"{shlex_quote(run_display)}"
        )
    return hints


def build_result(
    vector: dict[str, Any],
    suite_dir: Path,
    generated_at: str,
    timeout_seconds: int,
    suite_path: Path | None = None,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    evaluation = evaluate_expectation(vector, suite_dir, timeout_seconds)
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "vector_id": vector["vector_id"],
        "semantic_family": vector["semantic_family"],
        "source_sha256": vector["hashes"]["source_sha256"],
        "route_id": vector["route_under_test"]["route_id"],
        "route_kind": vector["route_under_test"]["route_kind"],
        "dispatch_route": vector["route_under_test"],
        "oracle_routes": vector.get("oracle_routes", []),
        "expectation_kind": vector["expectation"]["kind"],
        "expected_outcome": expected_observation(vector["expectation"]),
        "actual_outcome": actual_observation(evaluation),
        "outcome": evaluation["outcome"],
        "passed": evaluation["passed"],
        "reason_codes": evaluation["reason_codes"],
        "route_status": evaluation["route_status"],
        "hashes": vector["hashes"],
        "actual": evaluation["actual"],
        "first_divergence": first_divergence(vector, evaluation),
        "evidence_classification": evidence_classification(vector, evaluation),
        "command_replay_hints": replay_hints(
            vector["vector_id"], suite_path, run_dir, timeout_seconds
        ),
        "remediation": vector["remediation"],
    }


def summary_decision(results: list[dict[str, Any]], validation_errors: list[dict[str, Any]]) -> str:
    if validation_errors or any(not row["passed"] for row in results):
        return "fail_closed"
    if any(row["outcome"] == "degraded" for row in results):
        return "degraded"
    if any(row["outcome"] in {"unsupported", "expected_unknown"} for row in results):
        return "supported_with_non_passing_vectors"
    return "supported"


def write_summary(
    path: Path,
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    path_parity_report: dict[str, Any],
    auto_triage_report: dict[str, Any],
) -> None:
    lines = [
        "# Semantic Fidelity Workbench Summary",
        "",
        f"Decision: `{manifest['decision']}`",
        f"Suite: `{manifest['suite_id']}`",
        f"Generated: `{manifest['generated_at_utc']}`",
        f"Path parity groups: `{path_parity_report['summary']['builtin_group_count']}`",
        f"Route-disagreement groups: `{path_parity_report['summary']['route_disagreement_group_count']}`",
        f"Auto-triage suggestions: `{auto_triage_report['summary']['suggested_bead_count']}`",
        "",
        "| Vector | Route | Outcome | Reasons |",
        "| --- | --- | --- | --- |",
    ]
    for row in results:
        reasons = ", ".join(row["reason_codes"]) if row["reason_codes"] else "-"
        lines.append(
            f"| `{row['vector_id']}` | `{row['route_id']}` | `{row['outcome']}` | {reasons} |"
        )
    lines.extend(
        [
            "",
            "## Path Parity",
            "",
            "| Builtin | Semantic Family | Status | Route Count | Failures |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for group in path_parity_report["groups"]:
        lines.append(
            f"| `{group['builtin']}` | `{group['semantic_family']}` | "
            f"`{group['group_status']}` | {group['route_count']} | {group['failure_count']} |"
        )
    lines.extend(
        [
            "",
            "## Auto Triage",
            "",
            "| Vector | Classification | Action | Existing Beads |",
            "| --- | --- | --- | --- |",
        ]
    )
    for entry in auto_triage_report["entries"]:
        beads = ", ".join(bead["bead_id"] for bead in entry["existing_beads"]) or "-"
        lines.append(
            f"| `{entry['vector_id']}` | `{entry['triage_classification']}` | "
            f"`{entry['triage_action']}` | {beads} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test_vector(vector_id: str, marker: str, expectation: dict[str, Any]) -> dict[str, Any]:
    return {
        "vector_id": vector_id,
        "semantic_family": "self_test",
        "description": f"Self-test vector for {vector_id}",
        "source": {
            "kind": "inline_source",
            "parse_goal": "script",
            "inline_source": marker,
        },
        "route_under_test": {
            "route_id": f"self-test.{vector_id}",
            "route_kind": "node_oracle",
            "external_runtime": "node",
        },
        "oracle_routes": [],
        "expectation": expectation,
        "analyzed_scope": {
            "scope_status": "analyzed",
            "claim_policy": "runner_self_test",
        },
        "hashes": {
            "source_sha256": SHA_PREFIX + ("0" * 64),
            "route_metadata_sha256": SHA_PREFIX + ("0" * 64),
            "expectation_sha256": SHA_PREFIX + ("0" * 64),
        },
        "provenance": {"bead_refs": ["bd-mihky.3"]},
        "remediation": {"failure_reason_codes": [], "suggested_next_action": "none"},
    }


def self_test_suite(vectors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SUITE_SCHEMA_VERSION,
        "suite_id": "semfid-self-test-suite",
        "owning_bead": "bd-mihky.7",
        "description": "Build-free semantic-fidelity runner self-test suite",
        "determinism_policy": {"clock": "fixed", "external_routes": "stubbed"},
        "vectors": vectors,
    }


def with_computed_hashes(vector: dict[str, Any], suite_dir: Path) -> dict[str, Any]:
    cloned = clone_json(vector)
    cloned["hashes"] = computed_hashes(cloned, suite_dir)
    return cloned


def run_self_test() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    original_runner = globals()["run_external_js"]

    def fake_runner(runtime: str, source: str, timeout_seconds: int) -> dict[str, Any]:
        del runtime, timeout_seconds
        if source == "semfid-selftest-pass":
            return {
                "available": True,
                "ok": True,
                "parsed": {
                    "ok": False,
                    "error_class": "RangeError",
                    "message": "Invalid count",
                },
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
            }
        if source == "semfid-selftest-fail":
            return {
                "available": True,
                "ok": True,
                "parsed": {"ok": True, "value_kind": "string", "value": "actual"},
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
            }
        return {
            "available": False,
            "ok": False,
            "reason_code": "external_oracle_unavailable",
            "stdout": "",
            "stderr": "semantic self-test runtime missing",
            "exit_code": None,
        }

    globals()["run_external_js"] = fake_runner
    try:
        pass_row = build_result(
            self_test_vector(
                "pass",
                "semfid-selftest-pass",
                {"kind": "js_error", "error_class": "RangeError"},
            ),
            Path.cwd(),
            "2030-01-01T00:00:00Z",
            1,
        )
        fail_row = build_result(
            self_test_vector(
                "fail",
                "semfid-selftest-fail",
                {"kind": "normal", "value": "expected"},
            ),
            Path.cwd(),
            "2030-01-01T00:00:00Z",
            1,
        )
        degraded_row = build_result(
            self_test_vector(
                "degraded",
                "semfid-selftest-degraded",
                {"kind": "js_error", "error_class": "RangeError"},
            ),
            Path.cwd(),
            "2030-01-01T00:00:00Z",
            1,
        )
    finally:
        globals()["run_external_js"] = original_runner

    check("pass row classification", pass_row["outcome"] == "passed" and pass_row["passed"])
    check(
        "fail row classification",
        fail_row["outcome"] == "fail_closed"
        and not fail_row["passed"]
        and fail_row["reason_codes"] == ["expected_value_mismatch"],
    )
    check(
        "degraded row classification",
        degraded_row["outcome"] == "degraded"
        and degraded_row["passed"]
        and degraded_row["reason_codes"] == ["external_oracle_unavailable"],
    )
    check("supported decision", summary_decision([pass_row], []) == "supported")
    check("degraded decision", summary_decision([pass_row, degraded_row], []) == "degraded")
    check("fail-closed decision", summary_decision([pass_row, fail_row, degraded_row], []) == "fail_closed")
    check(
        "validation-error decision",
        summary_decision([], [{"vector_id": "bad", "code": "source_hash_mismatch"}]) == "fail_closed",
    )
    valid_vector = with_computed_hashes(
        self_test_vector(
            "schema-valid",
            "semfid-selftest-pass",
            {"kind": "js_error", "error_class": "RangeError"},
        ),
        Path.cwd(),
    )
    check("schema-valid vector", validate_vectors(self_test_suite([valid_vector]), Path.cwd()) == [])

    unknown_key_vector = clone_json(valid_vector)
    unknown_key_vector["unexpected"] = True
    check(
        "schema unknown-key rejection",
        validate_vectors(self_test_suite([unknown_key_vector]), Path.cwd())[0]["code"]
        == "malformed_vector",
    )

    invalid_expectation_vector = clone_json(valid_vector)
    invalid_expectation_vector["expectation"]["kind"] = "maybe"
    invalid_expectation_vector["hashes"] = computed_hashes(invalid_expectation_vector, Path.cwd())
    check(
        "schema expectation-kind rejection",
        validate_vectors(self_test_suite([invalid_expectation_vector]), Path.cwd())[0]["code"]
        == "ambiguous_expectation",
    )

    duplicate_route_vector = clone_json(valid_vector)
    duplicate_route_vector["oracle_routes"] = [clone_json(duplicate_route_vector["route_under_test"])]
    duplicate_route_vector["hashes"] = computed_hashes(duplicate_route_vector, Path.cwd())
    check(
        "schema duplicate-route rejection",
        validate_vectors(self_test_suite([duplicate_route_vector]), Path.cwd())[0]["code"]
        == "malformed_vector",
    )

    duplicate_id = clone_json(valid_vector)
    check(
        "schema duplicate vector-id rejection",
        validate_vectors(self_test_suite([valid_vector, duplicate_id]), Path.cwd())[0]["code"]
        == "duplicate_vector_id",
    )

    bad_hash_vector = clone_json(valid_vector)
    bad_hash_vector["hashes"]["source_sha256"] = SHA_PREFIX + ("1" * 64)
    check(
        "schema source-hash mismatch rejection",
        validate_vectors(self_test_suite([bad_hash_vector]), Path.cwd())[0]["code"]
        == "source_hash_mismatch",
    )
    check("result expected outcome logged", pass_row["expected_outcome"]["error_class"] == "RangeError")
    check("result actual outcome logged", pass_row["actual_outcome"]["error_class"] == "RangeError")
    check("result no first divergence on pass", pass_row["first_divergence"] is None)
    check("result first divergence on fail", fail_row["first_divergence"]["reason_code"] == "expected_value_mismatch")
    check("result evidence classification", pass_row["evidence_classification"] == "accepted_external_oracle")
    self_manifest = {
        "generated_at_utc": "2030-01-01T00:00:00Z",
        "suite_id": "semfid-self-test-suite",
        "suite_sha256": SHA_PREFIX + ("2" * 64),
        "decision": "fail_closed",
    }
    parity = build_path_parity_report(self_manifest, [pass_row, fail_row, degraded_row], [])
    check("path parity schema", parity["schema_version"] == PATH_PARITY_SCHEMA_VERSION)
    check("path parity deterministic group count", parity["summary"]["builtin_group_count"] == 1)
    check(
        "path parity disagreement detected",
        parity["groups"][0]["route_disagreement"] is True
        and parity["groups"][0]["group_status"] == "has_failures",
    )
    check("path parity failure grouped", parity["failure_groups"][0]["vector_id"] == "fail")
    linked_failure = clone_json(fail_row)
    linked_failure["remediation"]["existing_bead_refs"] = ["bd-mihky.3"]
    unknown_row = build_result(
        self_test_vector(
            "unknown",
            "semfid-selftest-pass",
            {
                "kind": "expected_unknown",
                "reason_code": "engine_route_not_executed_by_runner",
                "consumer_action": "record_and_continue",
            },
        ),
        Path.cwd(),
        "2030-01-01T00:00:00Z",
        1,
    )
    triage = build_auto_triage_report(
        self_manifest,
        [pass_row, fail_row, linked_failure, degraded_row, unknown_row],
        [],
    )
    check("auto triage schema", triage["schema_version"] == AUTO_TRIAGE_SCHEMA_VERSION)
    check("auto triage existing link", triage["summary"]["existing_bead_link_count"] == 1)
    check("auto triage suggestion", triage["summary"]["suggested_bead_count"] == 1)
    check("auto triage unsupported", triage["summary"]["unsupported_surface_count"] == 1)
    check("auto triage degraded", triage["summary"]["degraded_surface_count"] == 1)

    if failures:
        print("semantic fidelity workbench self-test FAIL", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("semantic fidelity workbench self-test PASS")
    return 0


def command_line() -> str:
    return " ".join(shlex_quote(arg) for arg in sys.argv)


def shlex_quote(value: str) -> str:
    if not value:
        return "''"
    safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
    if all(ch in safe for ch in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run(args: argparse.Namespace) -> int:
    suite_path = args.suite.resolve(strict=True)
    suite_dir = suite_path.parent
    suite = read_json(suite_path)
    generated_at = utc_now()
    run_dir = args.out_dir
    if run_dir is None:
        stamp = generated_at.replace("-", "").replace(":", "").replace("Z", "Z")
        run_dir = Path("artifacts/semantic_fidelity_workbench") / stamp
    run_dir.mkdir(parents=True, exist_ok=True)

    validation_errors = validate_vectors(suite, suite_dir)
    results: list[dict[str, Any]] = []
    if not validation_errors:
        vectors = sorted(suite["vectors"], key=lambda row: row["vector_id"])
        for vector in vectors:
            results.append(
                build_result(
                    vector,
                    suite_dir,
                    generated_at,
                    args.timeout_seconds,
                    suite_path,
                    run_dir,
                )
            )

    decision = summary_decision(results, validation_errors)
    artifacts = {
        "run_manifest": "run_manifest.json",
        "events": "events.jsonl",
        "commands": "commands.txt",
        "vector_results": "vector_results.jsonl",
        "summary": "summary.md",
    }
    manifest = {
        "schema_version": RUN_SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "suite_id": suite.get("suite_id"),
        "suite_path": display_path(suite_path),
        "suite_sha256": suite_hash(suite),
        "decision": decision,
        "validation_errors": validation_errors,
        "artifact_paths": artifacts,
        "command": command_line(),
    }
    artifacts["path_parity_report"] = "path_parity_report.json"
    artifacts["auto_triage_report"] = "auto_triage_report.json"
    events: list[dict[str, Any]] = [
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event": "run_started",
            "generated_at_utc": generated_at,
            "suite_id": suite.get("suite_id"),
            "decision_id": suite.get("suite_id"),
            "outcome": "ok",
            "error_code": None,
        }
    ]
    for error in validation_errors:
        events.append(
            {
                "schema_version": EVENT_SCHEMA_VERSION,
                "event": "validation_error",
                "generated_at_utc": generated_at,
                "vector_id": error.get("vector_id"),
                "outcome": "fail_closed",
                "error_code": error.get("code"),
                "message": error.get("message"),
            }
        )
    for result in results:
        events.append(
            {
                "schema_version": EVENT_SCHEMA_VERSION,
                "event": "vector_evaluated",
                "generated_at_utc": generated_at,
                "vector_id": result["vector_id"],
                "route_id": result["route_id"],
                "source_sha256": result["source_sha256"],
                "dispatch_route": result["dispatch_route"],
                "expected_outcome": result["expected_outcome"],
                "actual_outcome": result["actual_outcome"],
                "outcome": result["outcome"],
                "error_code": result["reason_codes"][0] if result["reason_codes"] else None,
                "first_divergence": result["first_divergence"],
                "command_replay_hints": result["command_replay_hints"],
            }
        )
    events.append(
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event": "run_finished",
            "generated_at_utc": generated_at,
            "suite_id": suite.get("suite_id"),
            "outcome": decision,
            "error_code": validation_errors[0]["code"] if validation_errors else None,
        }
    )

    write_json(run_dir / artifacts["run_manifest"], manifest)
    path_parity_report = build_path_parity_report(manifest, results, validation_errors)
    auto_triage_report = build_auto_triage_report(manifest, results, validation_errors)
    append_jsonl(run_dir / artifacts["events"], events)
    append_jsonl(run_dir / artifacts["vector_results"], results)
    write_json(run_dir / artifacts["path_parity_report"], path_parity_report)
    write_json(run_dir / artifacts["auto_triage_report"], auto_triage_report)
    (run_dir / artifacts["commands"]).write_text(command_line() + "\n", encoding="utf-8")
    write_summary(
        run_dir / artifacts["summary"],
        manifest,
        results,
        path_parity_report,
        auto_triage_report,
    )

    if args.pretty:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(canonical_json(manifest))
    return 1 if decision == "fail_closed" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, help="Semantic fidelity suite JSON")
    parser.add_argument("--out-dir", type=Path, help="Artifact output directory")
    parser.add_argument("--self-test", action="store_true", help="Run build-free classifier self-test")
    parser.add_argument("--timeout-seconds", type=int, default=10, help="Per-runtime timeout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print run manifest")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    if args.suite is None:
        parser.error("--suite is required unless --self-test is used")
    try:
        return run(args)
    except (OSError, json.JSONDecodeError, VectorError, subprocess.SubprocessError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
