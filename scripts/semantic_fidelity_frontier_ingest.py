#!/usr/bin/env python3
"""Convert semantic-fidelity workbench bundles into scoped E7 frontier rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "franken-engine.semantic-fidelity-frontier-ingest.v1"
ERROR_SCHEMA_VERSION = "franken-engine.semantic-fidelity-frontier-ingest-error.v1"
WORKBENCH_VECTOR_SCHEMA_VERSION = "franken-engine.semantic-fidelity-vectors.v1"
WORKBENCH_RUN_SCHEMA_VERSION = "franken-engine.semantic-fidelity-workbench-run.v1"
WORKBENCH_RESULT_SCHEMA_VERSION = "franken-engine.semantic-fidelity-vector-result.v1"
SCOPE = "semantic_fidelity_subset"
CLAIM_POLICY = "no_claim_promotion"
SHA_PREFIX = "sha256:"
HASH_DOMAIN = "franken-engine.semantic-fidelity-frontier-ingest.cluster.v1"

REQUIRED_ARTIFACTS = {
    "run_manifest": "run_manifest.json",
    "vector_results": "vector_results.jsonl",
    "summary": "summary.md",
}
OPTIONAL_ARTIFACTS = {
    "path_parity_report": "path_parity_report.json",
    "auto_triage_report": "auto_triage_report.json",
}
ROUTE_FIELDS = {"route_id", "route_kind", "engine_lane", "external_runtime"}
BEAD_ID_RE = re.compile(r"^bd-[a-z0-9]+(\.[0-9]+)*$")


class IngestError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def read_json(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestError("missing_source_artifact", f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError("malformed_source_artifact", f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise IngestError("malformed_source_artifact", f"{path} must contain a JSON object")
    return loaded


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise IngestError(
                        "malformed_source_artifact",
                        f"{path}:{line_number} is not valid JSON: {exc}",
                    ) from exc
                if not isinstance(parsed, dict):
                    raise IngestError(
                        "malformed_source_artifact",
                        f"{path}:{line_number} must contain a JSON object",
                    )
                rows.append(parsed)
    except OSError as exc:
        raise IngestError("missing_source_artifact", f"cannot read {path}: {exc}") from exc
    if not rows:
        raise IngestError("malformed_source_artifact", f"{path} has no rows")
    return rows


def sha256_file(path: Path) -> str:
    try:
        return SHA_PREFIX + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise IngestError("missing_source_artifact", f"cannot hash {path}: {exc}") from exc


def display_path(path: Path) -> str:
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


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


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "row"


def normalize_outcome(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {"kind": "malformed", "reason_code": "missing_outcome"}
    kind = str(value.get("kind", "malformed"))
    normalized: dict[str, str] = {"kind": kind}
    if "value_kind" in value:
        normalized["value_kind"] = str(value["value_kind"])
    if "value" in value:
        normalized["normalized_value"] = str(value["value"])
    if "normalized_value" in value:
        normalized["normalized_value"] = str(value["normalized_value"])
    if "error_class" in value:
        normalized["error_class"] = str(value["error_class"])
    if "message" in value:
        normalized["message_fragment"] = str(value["message"])
    contains = value.get("message_contains")
    if isinstance(contains, list) and contains and "message_fragment" not in normalized:
        normalized["message_fragment"] = str(contains[0])
    if "reason_code" in value:
        normalized["reason_code"] = str(value["reason_code"])
    reason_codes = value.get("reason_codes")
    if isinstance(reason_codes, list) and reason_codes and "reason_code" not in normalized:
        normalized["reason_code"] = str(reason_codes[0])
    return normalized


def route_for(result: dict[str, Any]) -> dict[str, str]:
    raw = result.get("dispatch_route")
    if not isinstance(raw, dict):
        raw = {
            "route_id": result.get("route_id"),
            "route_kind": result.get("route_kind"),
        }
    route: dict[str, str] = {}
    for field in ROUTE_FIELDS:
        if field in raw and raw[field] is not None:
            route[field] = str(raw[field])
    if "route_id" not in route or "route_kind" not in route:
        raise IngestError("malformed_source_artifact", "vector result missing route identity")
    return route


def oracle_mode(route: dict[str, str], result: dict[str, Any]) -> str:
    route_kind = route.get("route_kind")
    classification = str(result.get("evidence_classification", ""))
    if route_kind in {"node_oracle", "bun_oracle"}:
        return "external_oracle"
    if route_kind == "source_eval" and classification == "declared_non_execution":
        return "source_eval_declared"
    if route_kind == "test262_context":
        return "no_oracle"
    if route_kind in {
        "source_eval",
        "builtin_function_kind",
        "hostcall_builtin",
        "string_intrinsic_table",
        "stdlib_reference",
    }:
        return "internal_route"
    return "mixed"


def scope_state_for(result: dict[str, Any], observed: dict[str, str]) -> str:
    classification = str(result.get("evidence_classification", ""))
    if classification == "accepted_external_oracle":
        return "accepted_external_oracle"
    if classification == "declared_non_execution":
        return "declared_non_execution"
    if classification == "unsupported":
        return "unsupported"
    if classification == "degraded":
        return "degraded"
    if result.get("passed") is False or result.get("outcome") == "failed":
        return "mismatch"
    kind = observed.get("kind")
    if kind == "expected_unknown":
        return "expected_unknown"
    if kind == "unsupported":
        return "unsupported"
    if kind == "degraded":
        return "degraded"
    if kind == "malformed":
        return "malformed"
    return "malformed"


def coverage_counting(scope_state: str) -> str:
    if scope_state == "accepted_external_oracle":
        return "eligible_subset_row"
    if scope_state in {"mismatch", "malformed"}:
        return "fail_closed"
    return "non_passing_scoped_evidence"


def unsupported_reason_for(
    result: dict[str, Any],
    observed: dict[str, str],
    expected: dict[str, str],
    scope_state: str,
) -> str | None:
    if scope_state == "accepted_external_oracle":
        return None
    reason_codes = result.get("reason_codes")
    if isinstance(reason_codes, list) and reason_codes:
        return str(reason_codes[0])
    for candidate in (
        observed.get("reason_code"),
        expected.get("reason_code"),
        str(result.get("first_divergence") or ""),
    ):
        if candidate:
            return candidate
    return scope_state


def related_beads(result: dict[str, Any], source_bead_ids: list[str]) -> list[str]:
    refs = list(source_bead_ids)
    remediation = result.get("remediation")
    if isinstance(remediation, dict):
        extra = remediation.get("existing_bead_refs")
        if isinstance(extra, list):
            refs.extend(str(value) for value in extra)
    unique = sorted({ref for ref in refs if BEAD_ID_RE.match(ref)})
    if not unique:
        raise IngestError("malformed_source_artifact", "frontier row has no valid related bead ids")
    return unique


def evidence_paths(bundle: Path, manifest: dict[str, Any]) -> dict[str, str]:
    paths = {
        "source_bundle_path": display_path(bundle),
        "run_manifest_path": display_path(bundle / REQUIRED_ARTIFACTS["run_manifest"]),
        "vector_results_path": display_path(bundle / REQUIRED_ARTIFACTS["vector_results"]),
        "summary_path": display_path(bundle / REQUIRED_ARTIFACTS["summary"]),
    }
    for name, file_name in OPTIONAL_ARTIFACTS.items():
        path = bundle / file_name
        if path.is_file():
            paths[f"{name}_path"] = display_path(path)
    suite_path = manifest.get("suite_path")
    if isinstance(suite_path, str) and suite_path:
        paths["source_fixture_path"] = suite_path
    return paths


def cluster_id_for(row: dict[str, Any]) -> str:
    digest = length_prefixed_hash(cluster_signature(row))
    return "semfid-cluster-" + digest.removeprefix(SHA_PREFIX)[:16]


def cluster_signature(row: dict[str, Any]) -> dict[str, str]:
    expected = row["expected_outcome"]
    observed = row["observed_outcome"]
    route = row["route"]
    return {
        "expected_outcome.error_class": expected.get("error_class", ""),
        "expected_outcome.kind": expected.get("kind", ""),
        "observed_outcome.error_class": observed.get("error_class", ""),
        "observed_outcome.kind": observed.get("kind", ""),
        "oracle_mode": row["oracle_mode"],
        "route.route_kind": route.get("route_kind", ""),
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "scope_state": row["scope_state"],
        "semantic_family": row["semantic_family"],
    }


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != WORKBENCH_RUN_SCHEMA_VERSION:
        raise IngestError("schema_version_mismatch", "run_manifest has unexpected schema_version")
    artifact_paths = manifest.get("artifact_paths")
    if not isinstance(artifact_paths, dict):
        raise IngestError("malformed_source_artifact", "run_manifest missing artifact_paths")
    for key, file_name in REQUIRED_ARTIFACTS.items():
        if artifact_paths.get(key) != file_name:
            raise IngestError(
                "malformed_source_artifact",
                f"run_manifest artifact_paths.{key} must be {file_name}",
            )


def source_suite_schema(manifest: dict[str, Any]) -> str:
    suite_path = manifest.get("suite_path")
    if not isinstance(suite_path, str) or not suite_path:
        return WORKBENCH_VECTOR_SCHEMA_VERSION
    path = Path(suite_path)
    if not path.is_file():
        return WORKBENCH_VECTOR_SCHEMA_VERSION
    suite = read_json(path)
    return str(suite.get("schema_version", WORKBENCH_VECTOR_SCHEMA_VERSION))


def build_row(
    result: dict[str, Any],
    bundle: Path,
    manifest: dict[str, Any],
    source_bead_ids: list[str],
) -> dict[str, Any]:
    if result.get("schema_version") != WORKBENCH_RESULT_SCHEMA_VERSION:
        raise IngestError("schema_version_mismatch", "vector result has unexpected schema_version")
    route = route_for(result)
    observed = normalize_outcome(result.get("actual_outcome"))
    expected = normalize_outcome(result.get("expected_outcome"))
    scope_state = scope_state_for(result, observed)
    source_hash = result.get("source_sha256")
    hashes = result.get("hashes")
    if not source_hash and isinstance(hashes, dict):
        source_hash = hashes.get("source_sha256")
    row = {
        "row_id": "semfid-frontier-row-"
        + slugify(f"{result.get('vector_id', 'unknown')}-{route['route_id']}"),
        "cluster_id": "semfid-cluster-0000000000000000",
        "vector_id": str(result.get("vector_id", "")),
        "semantic_family": str(result.get("semantic_family", "")),
        "source_hash": str(source_hash or ""),
        "route": route,
        "oracle_mode": oracle_mode(route, result),
        "observed_outcome": observed,
        "expected_outcome": expected,
        "scope_state": scope_state,
        "unsupported_reason": unsupported_reason_for(result, observed, expected, scope_state),
        "coverage_counting": coverage_counting(scope_state),
        "related_bead_ids": related_beads(result, source_bead_ids),
        "evidence_paths": evidence_paths(bundle, manifest),
    }
    if not row["vector_id"]:
        raise IngestError("malformed_source_artifact", "vector result missing vector_id")
    if not row["source_hash"].startswith(SHA_PREFIX):
        raise IngestError("artifact_hash_mismatch", f"{row['vector_id']} missing source hash")
    row["cluster_id"] = cluster_id_for(row)
    return row


def check_duplicate_rows(rows: list[dict[str, Any]]) -> None:
    row_ids: set[str] = set()
    triples: set[tuple[str, str, str]] = set()
    clusters: dict[str, str] = {}
    for row in rows:
        row_id = row["row_id"]
        if row_id in row_ids:
            raise IngestError("duplicate_row_id", f"duplicate row_id {row_id}")
        row_ids.add(row_id)
        triple = (row["cluster_id"], row["vector_id"], row["route"]["route_id"])
        if triple in triples:
            raise IngestError("duplicate_frontier_row", f"duplicate frontier row {triple}")
        triples.add(triple)
        cluster_key = canonical_json(cluster_signature(row))
        existing = clusters.setdefault(row["cluster_id"], cluster_key)
        if existing != cluster_key:
            raise IngestError("cluster_id_collision", f"cluster collision {row['cluster_id']}")


def build_bundle(bundle: Path, source_bead_ids: list[str]) -> dict[str, Any]:
    bundle = bundle.resolve()
    if not bundle.is_dir():
        raise IngestError("missing_source_artifact", f"bundle directory not found: {bundle}")
    for file_name in REQUIRED_ARTIFACTS.values():
        if not (bundle / file_name).is_file():
            raise IngestError("missing_source_artifact", f"missing required artifact {file_name}")
    manifest = read_json(bundle / REQUIRED_ARTIFACTS["run_manifest"])
    validate_manifest(manifest)
    results = read_jsonl(bundle / REQUIRED_ARTIFACTS["vector_results"])
    rows = [build_row(result, bundle, manifest, source_bead_ids) for result in results]
    rows.sort(key=lambda row: (row["cluster_id"], row["vector_id"], row["route"]["route_id"]))
    check_duplicate_rows(rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "claim_policy": CLAIM_POLICY,
        "generated_from": {
            "workbench_schema_version": source_suite_schema(manifest),
            "source_bundle_path": display_path(bundle),
            "source_suite_id": str(manifest.get("suite_id", "")),
            "source_suite_sha256": str(manifest.get("suite_sha256", "")),
            "run_manifest_sha256": sha256_file(bundle / REQUIRED_ARTIFACTS["run_manifest"]),
            "vector_results_sha256": sha256_file(bundle / REQUIRED_ARTIFACTS["vector_results"]),
            "summary_sha256": sha256_file(bundle / REQUIRED_ARTIFACTS["summary"]),
            "source_bead_ids": source_bead_ids,
        },
        "determinism_policy": {
            "row_ordering": "lexicographic_by_cluster_vector_route",
            "hash_preimage": "length_prefixed_utf8_fields_v1",
            "duplicate_row_policy": "fail_closed",
        },
        "rows": rows,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path, help="Semantic-fidelity workbench bundle")
    parser.add_argument("--out", type=Path, help="Write ingest bundle JSON to this path")
    parser.add_argument(
        "--source-bead",
        action="append",
        default=[],
        help="Source or related bead id to attach to every row; may be repeated",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    source_bead_ids = args.source_bead or ["bd-mihky", "bd-mihky.10", "bd-fqlfw.7"]
    invalid = [bead_id for bead_id in source_bead_ids if not BEAD_ID_RE.match(bead_id)]
    if invalid:
        raise IngestError("malformed_source_artifact", f"invalid bead id(s): {', '.join(invalid)}")
    payload = build_bundle(args.bundle, sorted(set(source_bead_ids)))
    rendered = (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if args.pretty
        else canonical_json(payload) + "\n"
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except IngestError as exc:
        error = {
            "schema_version": ERROR_SCHEMA_VERSION,
            "ok": False,
            "reason_code": exc.reason_code,
            "message": str(exc),
        }
        sys.stderr.write(json.dumps(error, sort_keys=True) + "\n")
        raise SystemExit(2)
