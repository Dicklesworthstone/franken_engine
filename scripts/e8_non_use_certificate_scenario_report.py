#!/usr/bin/env python3
"""Offline E8 non-use/non-exfiltration certificate scenario report for security reviewers.

Implements bd-grwh9.4 under docs/EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md.
Advisory proof-reader only: consumes E8 data contracts, certificate bundles,
optional refusal ledgers, claim-to-proof matrix rows, and read-only Beads
snapshots without mutating any repository, tracker, or runtime state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "franken-engine.external-trust-artifact-explanation.v1"
DATA_CONTRACT_SCHEMA = "franken-engine.data-contract.v1"
SUPPORTED_NON_USE_CERT_SCHEMAS = {
    "franken-engine.non-use-certificate.v1",
    "franken-engine.non-use-certificate.v2",
}
SUPPORTED_USE_CERT_SCHEMAS = {
    "franken-engine.use-certificate.v1",
    "franken-engine.use-certificate.v2",
}
SUPPORTED_REPRO_LOCK_SCHEMAS = {
    "franken-engine.repro-lock.v1",
    "franken-engine.repro-lock.v2",
}
SUPPORTED_BUNDLE_SCHEMAS = {
    "franken-engine.e8-certificate-bundle.v1",
    "franken-engine.e8-certificate-bundle.v2",
}
E8_REFUSAL_LEDGER_SCHEMA = "franken-engine.e8-refusal-ledger.v1"

REQUIRED_CAPSTONE_BUNDLE_FILES = (
    "non_use_certificate.json",
    "use_certificate.json",
    "repro.lock",
    "declassification_receipts.jsonl",
    "capability_trace.jsonl",
    "audit.md",
)

CAPABILITY_DECLARATION_ORDER = (
    "VmDispatch",
    "GcInvoke",
    "IrLowering",
    "PolicyRead",
    "PolicyWrite",
    "EvidenceEmit",
    "DecisionInvoke",
    "NetworkEgress",
    "LeaseManagement",
    "IdempotencyDerive",
    "ExtensionLifecycle",
    "HeapAllocate",
    "EnvRead",
    "ProcessSpawn",
    "FsRead",
    "FsWrite",
    "Console",
    "Timer",
    "ModuleLoad",
    "Builtin",
)
LABEL_ORDER = ("Public", "Internal", "Confidential", "Secret", "TopSecret")
CAP_RANK = {name: idx for idx, name in enumerate(CAPABILITY_DECLARATION_ORDER)}
LABEL_RANK = {name: idx for idx, name in enumerate(LABEL_ORDER)}

MOCK_MARKERS = (
    "MockCertificate",
    "mock_certificate",
    "hot_paths_simulation",
    "node_simulation",
    "bun_simulation",
    "franken_simulation",
    "placeholder evidence",
    "fixture-only evidence",
)
LOCAL_FALLBACK_MARKERS = (
    "Remote toolchain failure, falling back to local",
    "falling back to local",
    "fallback to local",
    "RCH local fallback",
    "ran locally instead of rch",
    "running locally",
    "[RCH] local (",
    "local fallback was used",
    "local_fallback_observed\": true",
    "local_fallback_contaminated",
)
REFUSED_FALLBACK_PHRASES = (
    "refusing local fallback",
    "refused local fallback",
    "local fallback refused",
)

E8_RESULT_CLASSES = {
    "certifiable_subset",
    "uncertified",
    "degraded",
    "fail_closed",
    "out_of_scope",
}
E8_NON_CERTIFIABLE_CLASSES = {
    "uncertified",
    "degraded",
    "fail_closed",
    "out_of_scope",
}
E8_REFUSAL_CODE_CLASSES = {
    "missing_data_contract_binding": "missing_evidence",
    "missing_run_input_hash": "missing_evidence",
    "run_input_hash_mismatch": "fail_closed",
    "unsupported_syntax_surface": "uncertified",
    "unproven_ifc_propagation": "uncertified",
    "missing_flow_proof_obligation": "missing_evidence",
    "fallback_flow_envelope": "degraded",
    "missing_declassification_receipt": "fail_closed",
    "missing_source_span": "degraded",
    "missing_explain_or_replay_bundle": "missing_evidence",
    "out_of_scope_covert_channel": "out_of_scope",
    "out_of_scope_timing_channel": "out_of_scope",
}

FAIL_CLOSED_CODES = {
    "absent_artifact",
    "malformed_manifest",
    "unsupported_schema",
    "unavailable_e8_certifier",
    "incomplete_artifact_bundle",
    "missing_reproducibility_bundle",
    "duplicate_e8_identifier",
    "unknown_e8_claim_reference",
    "missing_required_field",
    "hash_mismatch",
    "stale_artifact",
    "stale_or_unfresh",
    "mock_contaminated",
    "local_fallback_contaminated",
    "malformed_e8_refusal_ledger",
    "missing_replay_command",
    "invalid_replay_command",
    "invalid_matrix_schema",
    "unreadable_matrix",
    "contradictory_bead_status",
}
NOT_PROMOTABLE_CODES = {
    "explicit_e8_uncertified_refusal",
    "claim_not_observed",
}
DEGRADED_CODES = {
    "stale_tracker_state",
    "source_span_unavailable",
}

THREAT_MODEL_HOLES = [
    "Explicit-flow IFC only (explicit_flow_ifc_v1): covert channels and microarchitectural/timing side channels are out of scope.",
    "Control-flow implicit channels outside tracked PC-label/analyzed-subset obligations are out of scope; unanalyzed constructs refuse certification.",
    "Embedded signature_envelope.verification_key is self-carried metadata, not an external trust anchor; reviewers MUST verify against an independently pinned runtime VerificationKey via frankenctl verify non-use-certificate.",
    "Use-certificate output dependency posture is a conservative over-approximation unless an explicit OutputIndependentOf claim holds within analyzed scope.",
]


def utc_now() -> str:
    for env_key in ("E8_EXPLAINER_NOW_UTC", "BUNDLE_DOCTOR_NOW_UTC"):
        override = os.environ.get(env_key)
        if override:
            return normalize_utc(override)
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_utc(value: str) -> str:
    return parse_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def is_sha256_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def display_path(path: Path) -> str:
    cwd = Path.cwd().resolve()
    try:
        resolved = path.resolve()
        return str(resolved.relative_to(cwd))
    except ValueError:
        return str(path)


def load_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists() or not path.is_file():
        return None, "missing"
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, f"json_error: {exc}"
    if not isinstance(loaded, dict):
        return None, "not_object"
    return loaded, None


def canonical_data_contract_hash(contract: dict[str, Any]) -> str | None:
    try:
        bindings = []
        for item in contract.get("input_bindings", []):
            entry: dict[str, Any] = {
                "binding_id": item["binding_id"],
                "object_ref": item["object_ref"],
            }
            if item.get("path") is not None:
                entry["path"] = item["path"]
            entry["label"] = item["label"]
            entry["owner"] = item["owner"]
            entry["role"] = item["role"]
            entry["allowed_purposes"] = sorted(set(item.get("allowed_purposes", [])))
            if item.get("content_hash_hex") is not None:
                entry["content_hash_hex"] = item["content_hash_hex"]
            bindings.append(entry)

        sinks = []
        for sink in contract.get("allowed_sinks", []):
            sinks.append(
                {
                    "sink_id": sink["sink_id"],
                    "clearance": sink["clearance"],
                    "location": sink["location"],
                    "allowed_labels": sorted(
                        set(sink.get("allowed_labels", [])),
                        key=lambda lbl: (LABEL_RANK.get(lbl, 999), str(lbl)),
                    ),
                }
            )

        routes = []
        for req in contract.get("required_declassification_routes", []):
            route = req["route"]
            routes.append(
                {
                    "route": {
                        "route_id": route["route_id"],
                        "source_label": route["source_label"],
                        "target_clearance": route["target_clearance"],
                        "conditions": list(route.get("conditions", [])),
                    },
                    "required_for_claims": sorted(set(req.get("required_for_claims", []))),
                }
            )

        claims = []
        for claim in contract.get("requested_output_claims", []):
            ctype = claim.get("claim_type")
            if ctype == "no_flow":
                claims.append(
                    {
                        "claim_type": "no_flow",
                        "claim_id": claim["claim_id"],
                        "source_label": claim["source_label"],
                        "sink_clearance": claim["sink_clearance"],
                    }
                )
            elif ctype == "output_independent_of":
                claims.append(
                    {
                        "claim_type": "output_independent_of",
                        "claim_id": claim["claim_id"],
                        "binding_id": claim["binding_id"],
                    }
                )
            elif ctype == "capability_not_used":
                claims.append(
                    {
                        "claim_type": "capability_not_used",
                        "claim_id": claim["claim_id"],
                        "capability": claim["capability"],
                    }
                )
            else:
                claims.append(claim)

        normalized: dict[str, Any] = {
            "schema_version": contract["schema_version"],
            "contract_id": contract["contract_id"],
            "extension_id": contract["extension_id"],
            "input_bindings": bindings,
            "allowed_purposes": sorted(set(contract.get("allowed_purposes", []))),
            "allowed_capabilities": sorted(
                set(contract.get("allowed_capabilities", [])),
                key=lambda cap: (CAP_RANK.get(cap, 999), str(cap)),
            ),
            "allowed_sinks": sinks,
            "required_declassification_routes": routes,
            "requested_output_claims": claims,
        }
        metadata = contract.get("metadata")
        if isinstance(metadata, dict) and metadata:
            normalized["metadata"] = dict(sorted(metadata.items()))
        encoded = json.dumps(normalized, separators=(",", ":")).encode("utf-8")
        return sha256_bytes(encoded)
    except Exception:  # noqa: BLE001
        return None


def scan_text_markers(paths: list[Path]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    mock_hits: list[dict[str, str]] = []
    fallback_hits: list[dict[str, str]] = []
    for path in sorted(set(paths), key=display_path):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            lowered = line.lower()
            for marker in MOCK_MARKERS:
                if marker.lower() in lowered:
                    mock_hits.append({"path": display_path(path), "marker": marker})
            if any(refused in lowered for refused in REFUSED_FALLBACK_PHRASES):
                continue
            for marker in LOCAL_FALLBACK_MARKERS:
                if marker.lower() in lowered:
                    fallback_hits.append({"path": display_path(path), "marker": marker})
    return mock_hits, fallback_hits


def check_duplicate_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    dups: list[str] = []
    for raw in values:
        if isinstance(raw, str):
            if raw in seen and raw not in dups:
                dups.append(raw)
            seen.add(raw)
    return dups


def validate_refusal_ledger(ledger: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    malformed = False
    if ledger.get("schema_version") != E8_REFUSAL_LEDGER_SCHEMA:
        malformed = True
    ledger_id = ledger.get("ledger_id")
    if not non_empty_str(ledger_id):
        malformed = True
    result_class = ledger.get("result_class")
    if result_class not in E8_RESULT_CLASSES:
        malformed = True
    if ledger.get("positive_non_use_claim_allowed") is not False:
        malformed = True
    source_refs = ledger.get("source_refs")
    source_ids: set[str] = set()
    if not isinstance(source_refs, list) or not source_refs:
        malformed = True
    else:
        for ref in source_refs:
            if not isinstance(ref, dict) or not non_empty_str(ref.get("id")) or not non_empty_str(ref.get("path")):
                malformed = True
            else:
                if ref["id"] in source_ids:
                    malformed = True
                source_ids.add(ref["id"])
    refusal_codes = ledger.get("refusal_codes")
    normalized_codes: list[dict[str, Any]] = []
    if not isinstance(refusal_codes, list):
        malformed = True
    else:
        for entry in refusal_codes:
            if not isinstance(entry, dict):
                malformed = True
                continue
            code = entry.get("code")
            cls = entry.get("class")
            src = entry.get("source_ref_id")
            rem = entry.get("remediation")
            if (
                code not in E8_REFUSAL_CODE_CLASSES
                or E8_REFUSAL_CODE_CLASSES.get(code) != cls
                or src not in source_ids
                or not non_empty_str(rem)
            ):
                malformed = True
            normalized_codes.append(
                {
                    "code": code,
                    "class": cls,
                    "source_ref_id": src,
                    "remediation": rem,
                }
            )
        if result_class == "certifiable_subset" and normalized_codes:
            malformed = True
        if result_class in E8_NON_CERTIFIABLE_CLASSES and not normalized_codes:
            malformed = True
    return (
        {
            "ledger_id": ledger_id,
            "result_class": result_class,
            "refusal_codes": normalized_codes,
        },
        malformed,
    )


def choose_decision(reason_codes: list[str]) -> str:
    code_set = set(reason_codes)
    if code_set & FAIL_CLOSED_CODES:
        return "fail_closed"
    if "unsupported_input_kind" in code_set:
        return "unsupported"
    if code_set & NOT_PROMOTABLE_CODES:
        return "not_promotable"
    if code_set & DEGRADED_CODES:
        return "degraded"
    return "supported"


def is_zero_exit(decision: str) -> bool:
    return decision in {"supported", "degraded"}


def read_bead_refs(beads_jsonl: Path | None) -> tuple[list[dict[str, Any]], list[str]]:
    target_ids = ("bd-fqlfw.8", "bd-fqlfw.8.7")
    if beads_jsonl is None:
        default_path = Path(".beads/issues.jsonl")
        if not default_path.is_file():
            return [], []
        beads_jsonl = default_path
    if not beads_jsonl.is_file():
        return (
            [
                {
                    "bead_id": bid,
                    "status": "unknown",
                    "assignee": None,
                    "blockers": [],
                    "tracker_source": display_path(beads_jsonl),
                    "freshness_status": "missing",
                }
                for bid in target_ids
            ],
            ["stale_tracker_state"],
        )
    by_id: dict[str, dict[str, Any]] = {}
    try:
        for line in beads_jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if isinstance(obj, dict) and isinstance(obj.get("id"), str):
                by_id[obj["id"]] = obj
    except Exception:  # noqa: BLE001
        return [], ["stale_tracker_state"]

    refs: list[dict[str, Any]] = []
    extra_reasons: list[str] = []
    for bid in target_ids:
        item = by_id.get(bid)
        if item is None:
            refs.append(
                {
                    "bead_id": bid,
                    "status": "missing",
                    "assignee": None,
                    "blockers": [],
                    "tracker_source": display_path(beads_jsonl),
                    "freshness_status": "missing_bead",
                }
            )
            extra_reasons.append("stale_tracker_state")
        else:
            blockers = [
                dep.get("depends_on_id")
                for dep in item.get("dependencies", [])
                if isinstance(dep, dict)
                and dep.get("type") == "blocks"
                and by_id.get(str(dep.get("depends_on_id")), {}).get("status") != "closed"
            ]
            refs.append(
                {
                    "bead_id": bid,
                    "status": item.get("status", "unknown"),
                    "assignee": item.get("assignee"),
                    "blockers": sorted(str(b) for b in blockers if b),
                    "tracker_source": display_path(beads_jsonl),
                    "freshness_status": "fresh",
                }
            )
    return refs, extra_reasons


def build_report(
    contract_path: Path,
    bundle_arg: Path,
    now_utc: str,
    refusal_ledger_path: Path | None = None,
    claim_matrix_path: Path | None = None,
    beads_jsonl_path: Path | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    remediation: list[str] = []
    source_inputs: list[dict[str, Any]] = []
    artifact_refs: list[dict[str, Any]] = []
    claim_refs: list[dict[str, Any]] = []
    replay_commands: list[str] = []
    scanned_paths: list[Path] = []
    warnings: list[str] = []

    def add_reason(code: str, action: str, warning: str | None = None) -> None:
        if code not in reason_codes:
            reason_codes.append(code)
        if action and action not in remediation:
            remediation.append(action)
        if warning and warning not in warnings:
            warnings.append(warning)

    # 1. Load & validate DataContract
    contract, contract_err = load_json_object(contract_path)
    if contract_path.is_file():
        scanned_paths.append(contract_path)
    contract_file_sha = file_hash(contract_path) if contract_path.is_file() else None
    source_inputs.append(
        {
            "input_kind": "e8_certificate_bundle",
            "source_path": display_path(contract_path),
            "schema_version": contract.get("schema_version") if contract else None,
            "content_hash": contract_file_sha,
            "freshness": "present" if contract else "unavailable",
            "availability": "present" if contract else (contract_err or "missing"),
        }
    )
    artifact_refs.append(
        {
            "artifact_id": "e8-data-contract",
            "path": display_path(contract_path),
            "content_hash": contract_file_sha,
            "required": True,
            "present": contract is not None,
            "schema_version": contract.get("schema_version") if contract else None,
            "replay_command": None,
        }
    )

    contract_claim_ids: set[str] = set()
    contract_binding_ids: set[str] = set()
    computed_contract_hash: str | None = None

    if contract_err == "missing":
        add_reason(
            "absent_artifact",
            "Provide a readable E8 data contract JSON file via --contract.",
            f"Data contract missing at {display_path(contract_path)}.",
        )
    elif contract_err is not None or contract is None:
        add_reason(
            "malformed_manifest",
            "Fix the E8 data contract so it parses as a valid JSON object.",
            f"Data contract could not be parsed ({contract_err}).",
        )
    else:
        c_schema = contract.get("schema_version")
        if c_schema != DATA_CONTRACT_SCHEMA:
            add_reason(
                "unsupported_schema",
                f"Use supported data-contract schema `{DATA_CONTRACT_SCHEMA}`.",
                f"Unsupported data contract schema `{c_schema}`.",
            )
        for req_field in (
            "contract_id",
            "extension_id",
            "input_bindings",
            "allowed_purposes",
            "allowed_capabilities",
            "allowed_sinks",
            "requested_output_claims",
        ):
            val = contract.get(req_field)
            if val is None or (isinstance(val, (str, list, dict)) and len(val) == 0):
                add_reason(
                    "missing_required_field",
                    f"Populate required non-empty data contract field `{req_field}`.",
                    f"Data contract field `{req_field}` is missing or empty.",
                )

        purposes = contract.get("allowed_purposes", [])
        if isinstance(purposes, list) and check_duplicate_strings(purposes):
            add_reason(
                "duplicate_e8_identifier",
                "Deduplicate `allowed_purposes` in the E8 data contract.",
                "Duplicate purpose identifier in `allowed_purposes`.",
            )

        bindings = contract.get("input_bindings", [])
        if isinstance(bindings, list):
            b_ids = [b.get("binding_id") for b in bindings if isinstance(b, dict)]
            if check_duplicate_strings(b_ids):
                add_reason(
                    "duplicate_e8_identifier",
                    "Deduplicate `input_bindings[].binding_id` in the data contract.",
                    "Duplicate `binding_id` in data contract `input_bindings`.",
                )
            for b in bindings:
                if isinstance(b, dict) and non_empty_str(b.get("binding_id")):
                    contract_binding_ids.add(b["binding_id"])
                    if b.get("content_hash_hex") is not None and not is_sha256_hex(
                        b.get("content_hash_hex")
                    ):
                        add_reason(
                            "invalid_expected_hash",
                            "Use 64-character lowercase SHA-256 hex for `input_bindings[].content_hash_hex`.",
                            f"Invalid SHA-256 hex on input binding `{b['binding_id']}`.",
                        )

        sinks = contract.get("allowed_sinks", [])
        if isinstance(sinks, list):
            s_ids = [s.get("sink_id") for s in sinks if isinstance(s, dict)]
            if check_duplicate_strings(s_ids):
                add_reason(
                    "duplicate_e8_identifier",
                    "Deduplicate `allowed_sinks[].sink_id` in the data contract.",
                    "Duplicate `sink_id` in data contract `allowed_sinks`.",
                )

        req_claims = contract.get("requested_output_claims", [])
        if isinstance(req_claims, list):
            c_ids = [c.get("claim_id") for c in req_claims if isinstance(c, dict)]
            if check_duplicate_strings(c_ids):
                add_reason(
                    "duplicate_e8_identifier",
                    "Deduplicate `requested_output_claims[].claim_id` in the data contract.",
                    "Duplicate `claim_id` in data contract `requested_output_claims`.",
                )
            for c in req_claims:
                if not isinstance(c, dict):
                    continue
                cid = c.get("claim_id")
                if non_empty_str(cid):
                    contract_claim_ids.add(cid)
                if c.get("claim_type") == "output_independent_of":
                    ref_bid = c.get("binding_id")
                    if not non_empty_str(ref_bid) or ref_bid not in contract_binding_ids:
                        add_reason(
                            "unknown_e8_claim_reference",
                            "Ensure `output_independent_of.binding_id` references a declared `input_bindings[].binding_id`.",
                            f"Claim `{cid}` references unknown input binding `{ref_bid}`.",
                        )

        routes = contract.get("required_declassification_routes", [])
        if isinstance(routes, list):
            r_ids = [
                r.get("route", {}).get("route_id")
                for r in routes
                if isinstance(r, dict) and isinstance(r.get("route"), dict)
            ]
            if check_duplicate_strings(r_ids):
                add_reason(
                    "duplicate_e8_identifier",
                    "Deduplicate `required_declassification_routes[].route.route_id`.",
                    "Duplicate declassification `route_id` in data contract.",
                )
            for r in routes:
                if not isinstance(r, dict):
                    continue
                route_obj = r.get("route", {})
                rid = route_obj.get("route_id") if isinstance(route_obj, dict) else None
                req_for = r.get("required_for_claims", [])
                if not isinstance(req_for, list) or not req_for:
                    add_reason(
                        "missing_required_field",
                        "Populate non-empty `required_for_claims` on every declassification route.",
                        f"Route `{rid}` has empty `required_for_claims`.",
                    )
                else:
                    for cid in req_for:
                        if cid not in contract_claim_ids:
                            add_reason(
                                "unknown_e8_claim_reference",
                                "Ensure every `required_for_claims` entry references a declared `requested_output_claims[].claim_id`.",
                                f"Declassification route `{rid}` references undeclared claim `{cid}`.",
                            )

        computed_contract_hash = canonical_data_contract_hash(contract)

    # Optional claim-to-proof matrix check when matrix claim refs are supplied
    matrix_claim_ids: set[str] | None = None
    metadata_matrix_refs: list[str] = []
    if contract and isinstance(contract.get("metadata"), dict):
        raw_refs = contract["metadata"].get("matrix_claim_refs", "")
        if isinstance(raw_refs, str) and raw_refs.strip():
            metadata_matrix_refs = [part.strip() for part in raw_refs.split(",") if part.strip()]
    if claim_matrix_path is not None or metadata_matrix_refs:
        effective_matrix_path = claim_matrix_path or Path("docs/claim_to_proof_matrix_v1.json")
        matrix_obj, matrix_err = load_json_object(effective_matrix_path)
        if matrix_err is not None or matrix_obj is None:
            add_reason(
                "unreadable_matrix",
                "Provide a valid `claim_to_proof_matrix_v1.json` before linking E8 matrix claims.",
                f"Claim matrix unreadable at {display_path(effective_matrix_path)}.",
            )
        else:
            claims_list = matrix_obj.get("claims")
            if not isinstance(claims_list, list):
                add_reason(
                    "invalid_matrix_schema",
                    "Fix `claim_to_proof_matrix_v1.json` `claims` array.",
                    "Claim matrix missing `claims` array.",
                )
            else:
                matrix_claim_ids = {
                    row.get("claim_id")
                    for row in claims_list
                    if isinstance(row, dict) and non_empty_str(row.get("claim_id"))
                }
                for m_cid in metadata_matrix_refs:
                    if m_cid not in matrix_claim_ids:
                        add_reason(
                            "unknown_e8_claim_reference",
                            f"Add `{m_cid}` to `docs/claim_to_proof_matrix_v1.json` or remove the invalid matrix reference.",
                            f"Data contract references unknown matrix claim `{m_cid}`.",
                        )

    # 2. Resolve & validate E8 certificate bundle
    bundle_dir = bundle_arg if bundle_arg.is_dir() else bundle_arg.parent
    non_use_path = (
        bundle_arg
        if bundle_arg.is_file() and bundle_arg.name.endswith(".json")
        else bundle_dir / "non_use_certificate.json"
    )
    use_path = bundle_dir / "use_certificate.json"
    repro_path = bundle_dir / "repro.lock"
    declass_path = bundle_dir / "declassification_receipts.jsonl"
    cap_trace_path = bundle_dir / "capability_trace.jsonl"
    audit_md_path = bundle_dir / "audit.md"

    non_use_cert: dict[str, Any] | None = None
    use_cert: dict[str, Any] | None = None
    repro_lock: dict[str, Any] | None = None

    if not bundle_arg.exists():
        add_reason(
            "unavailable_e8_certifier",
            "Run `frankenctl run --data-contract <contract.json> --certificate-out <bundle-dir>` to emit E8 capstone evidence.",
            f"Certificate bundle absent at {display_path(bundle_arg)}.",
        )
        source_inputs.append(
            {
                "input_kind": "e8_certificate_bundle",
                "source_path": display_path(bundle_arg),
                "schema_version": None,
                "content_hash": None,
                "freshness": "unavailable",
                "availability": "missing",
            }
        )
    else:
        for member_name in REQUIRED_CAPSTONE_BUNDLE_FILES:
            mpath = bundle_dir / member_name
            present = mpath.is_file()
            if present:
                scanned_paths.append(mpath)
            else:
                add_reason(
                    "unavailable_e8_certifier",
                    f"Emit complete E8 certificate capstone bundle (missing `{member_name}`).",
                    f"Certificate bundle lacks required E8 capstone member `{member_name}`.",
                )
                add_reason(
                    "incomplete_artifact_bundle",
                    f"Re-emit the E8 certificate bundle so `{member_name}` is present.",
                )
                if member_name == "repro.lock":
                    add_reason(
                        "missing_reproducibility_bundle",
                        "Include `repro.lock` in the E8 certificate bundle.",
                    )
            artifact_refs.append(
                {
                    "artifact_id": f"e8-bundle:{member_name}",
                    "path": display_path(mpath),
                    "content_hash": file_hash(mpath) if present else None,
                    "required": True,
                    "present": present,
                    "schema_version": None,
                    "replay_command": None,
                }
            )

        if non_use_path.is_file():
            non_use_cert, nu_err = load_json_object(non_use_path)
            if nu_err is not None or non_use_cert is None:
                add_reason(
                    "malformed_manifest",
                    "Regenerate `non_use_certificate.json` as valid JSON.",
                    f"Malformed `non_use_certificate.json` ({nu_err}).",
                )
            else:
                source_inputs.append(
                    {
                        "input_kind": "e8_certificate_bundle",
                        "source_path": display_path(non_use_path),
                        "schema_version": non_use_cert.get("schema_version"),
                        "content_hash": file_hash(non_use_path),
                        "freshness": "present",
                        "availability": "present",
                    }
                )
                if non_use_cert.get("schema_version") not in SUPPORTED_NON_USE_CERT_SCHEMAS:
                    add_reason(
                        "unsupported_schema",
                        "Use a supported E8 non-use certificate schema (`franken-engine.non-use-certificate.v2`).",
                        f"Unsupported non-use certificate schema `{non_use_cert.get('schema_version')}`.",
                    )

        if use_path.is_file():
            use_cert, u_err = load_json_object(use_path)
            if u_err is not None or use_cert is None:
                add_reason(
                    "malformed_manifest",
                    "Regenerate `use_certificate.json` as valid JSON.",
                    f"Malformed `use_certificate.json` ({u_err}).",
                )
            elif use_cert.get("schema_version") not in SUPPORTED_USE_CERT_SCHEMAS:
                add_reason(
                    "unsupported_schema",
                    "Use a supported E8 use certificate schema (`franken-engine.use-certificate.v2`).",
                    f"Unsupported use certificate schema `{use_cert.get('schema_version')}`.",
                )

        if repro_path.is_file():
            repro_lock, rl_err = load_json_object(repro_path)
            if rl_err is not None or repro_lock is None:
                add_reason(
                    "malformed_manifest",
                    "Regenerate `repro.lock` as valid JSON.",
                    f"Malformed `repro.lock` ({rl_err}).",
                )
            else:
                if (
                    repro_lock.get("schema_version") not in SUPPORTED_REPRO_LOCK_SCHEMAS
                    or repro_lock.get("bundle_schema_version") not in SUPPORTED_BUNDLE_SCHEMAS
                ):
                    add_reason(
                        "unsupported_schema",
                        "Use supported E8 repro.lock and bundle schema versions.",
                        f"Unsupported repro.lock schema `{repro_lock.get('schema_version')}` / `{repro_lock.get('bundle_schema_version')}`.",
                    )
                files_list = repro_lock.get("files")
                if not isinstance(files_list, list) or not files_list:
                    add_reason(
                        "invalid_required_member",
                        "Populate `repro.lock` `files` digests.",
                        "`repro.lock` is missing `files` entries.",
                    )
                else:
                    for entry in files_list:
                        if not isinstance(entry, dict) or not non_empty_str(entry.get("name")):
                            add_reason(
                                "invalid_required_member",
                                "Fix malformed entry in `repro.lock` `files`.",
                            )
                            continue
                        member_file = bundle_dir / str(entry["name"])
                        declared_sha = entry.get("sha256_hex")
                        if not is_sha256_hex(declared_sha):
                            add_reason(
                                "invalid_required_member",
                                f"Fix invalid SHA-256 digest for `{entry['name']}` in `repro.lock`.",
                            )
                        elif member_file.is_file() and file_hash(member_file).lower() != str(declared_sha).lower():
                            add_reason(
                                "hash_mismatch",
                                f"Regenerate E8 bundle; `{entry['name']}` bytes diverge from `repro.lock`.",
                                f"Bundle file `{entry['name']}` SHA-256 does not match `repro.lock`.",
                            )

                cmds = repro_lock.get("commands")
                if cmds is None or (isinstance(cmds, list) and len(cmds) == 0):
                    add_reason(
                        "missing_replay_command",
                        "Include exact replay and emission commands in `repro.lock`.",
                        "`repro.lock` declares no replay commands.",
                    )
                elif not isinstance(cmds, list) or any(not non_empty_str(c) for c in cmds):
                    add_reason(
                        "invalid_replay_command",
                        "Ensure every entry in `repro.lock.commands` is a non-empty string.",
                        "`repro.lock` contains invalid replay command entry.",
                    )
                else:
                    replay_commands.extend(str(c).strip() for c in cmds)

    # 3. Cross-validate DataContract <-> NonUseCertificate <-> UseCertificate
    if non_use_cert is not None:
        scope = non_use_cert.get("scope")
        if not isinstance(scope, dict):
            add_reason(
                "missing_required_field",
                "Populate `scope` object in `non_use_certificate.json`.",
                "`non_use_certificate.json` lacks `scope`.",
            )
            scope = {}
        run_input_hash = scope.get("run_input_content_hash_hex")
        if not is_sha256_hex(run_input_hash):
            add_reason(
                "missing_required_field",
                "Bind a valid 64-hex SHA-256 `scope.run_input_content_hash_hex` when emitting the E8 certificate.",
                "Certificate is missing valid `scope.run_input_content_hash_hex`.",
            )
        replay_hash = scope.get("replay_trace_content_hash_hex")
        if not is_sha256_hex(replay_hash):
            add_reason(
                "missing_required_field",
                "Bind a valid 64-hex SHA-256 `scope.replay_trace_content_hash_hex`.",
                "Certificate is missing valid `scope.replay_trace_content_hash_hex`.",
            )
        cert_contract_hash = scope.get("contract_hash_hex")
        if not is_sha256_hex(cert_contract_hash):
            add_reason(
                "missing_required_field",
                "Bind a valid 64-hex SHA-256 `scope.contract_hash_hex`.",
                "Certificate is missing valid `scope.contract_hash_hex`.",
            )
        elif contract is not None:
            if scope.get("contract_id") != contract.get("contract_id") or (
                computed_contract_hash is not None
                and str(cert_contract_hash).lower() != computed_contract_hash.lower()
            ):
                add_reason(
                    "hash_mismatch",
                    "Re-emit the E8 certificate against the current DataContract (`contract_hash_hex` mismatch).",
                    f"Stale data contract: certificate bound `{cert_contract_hash}`, current contract hashes to `{computed_contract_hash}`.",
                )
                add_reason(
                    "stale_artifact",
                    "Refresh the E8 certificate bundle so it matches the supplied DataContract.",
                )
            purpose = scope.get("purpose")
            allowed_purposes = contract.get("allowed_purposes", [])
            if isinstance(allowed_purposes, list) and purpose not in allowed_purposes:
                add_reason(
                    "stale_artifact",
                    f"Authorize purpose `{purpose}` in the data contract or re-run with an allowed purpose.",
                    f"Certificate purpose `{purpose}` is not authorized by data contract.",
                )

        if use_cert is not None and isinstance(use_cert.get("scope"), dict):
            if use_cert["scope"] != scope:
                add_reason(
                    "hash_mismatch",
                    "Re-emit bundle; `use_certificate.json` scope diverges from `non_use_certificate.json`.",
                    "`use_certificate.json` and `non_use_certificate.json` scopes do not match.",
                )

        cert_claims = non_use_cert.get("claims")
        if not isinstance(cert_claims, list) or not cert_claims:
            add_reason(
                "missing_required_field",
                "Populate `claims` verdicts in `non_use_certificate.json`.",
                "`non_use_certificate.json` has no `claims` entries.",
            )
        else:
            cert_cids = [c.get("claim_id") for c in cert_claims if isinstance(c, dict)]
            if check_duplicate_strings(cert_cids):
                add_reason(
                    "duplicate_e8_identifier",
                    "Deduplicate `claims[].claim_id` in `non_use_certificate.json`.",
                    "Duplicate `claim_id` in `non_use_certificate.json`.",
                )
            for item in cert_claims:
                if not isinstance(item, dict):
                    continue
                cid = str(item.get("claim_id", ""))
                evaluation = str(item.get("evaluation", ""))
                if contract is not None and cid not in contract_claim_ids:
                    add_reason(
                        "unknown_e8_claim_reference",
                        f"Align certificate claim `{cid}` with `data_contract.requested_output_claims`.",
                        f"Certificate contains claim `{cid}` absent from DataContract.",
                    )
                if matrix_claim_ids is not None and cid.startswith("FE-CLAIM-") and cid not in matrix_claim_ids:
                    add_reason(
                        "unknown_e8_claim_reference",
                        f"Add `{cid}` to `docs/claim_to_proof_matrix_v1.json`.",
                        f"Certificate references unknown claim-matrix ID `{cid}`.",
                    )
                holds = evaluation == "holds_within_analyzed_scope"
                claim_refs.append(
                    {
                        "claim_id": cid,
                        "allowed_state": "observed" if holds else "hypothesis",
                        "actual_wording_state": "observed" if holds else "hypothesis",
                        "source_path": display_path(non_use_path),
                        "source_span": None,
                        "owning_bead": "bd-fqlfw.8",
                        "downgrade_text": item.get("detail") if not holds else None,
                    }
                )
                if evaluation == "contradicted":
                    add_reason(
                        "explicit_e8_uncertified_refusal",
                        f"Claim `{cid}` was contradicted ({item.get('detail')}); do not trust run as non-exfiltrating.",
                        f"Claim `{cid}` CONTRADICTED: {item.get('detail')}",
                    )
                elif not holds:
                    add_reason(
                        "explicit_e8_uncertified_refusal",
                        f"Claim `{cid}` evaluated to `{evaluation}`; keep non-use claim uncertified.",
                        f"Claim `{cid}` not proven ({evaluation}).",
                    )

            if contract is not None:
                missing_from_cert = sorted(contract_claim_ids - set(str(x) for x in cert_cids if x))
                if missing_from_cert:
                    add_reason(
                        "unknown_e8_claim_reference",
                        f"Re-emit certificate covering all contract claims (missing: {', '.join(missing_from_cert)}).",
                        f"Certificate omits requested contract claims: {', '.join(missing_from_cert)}.",
                    )

        cert_status = non_use_cert.get("certificate_status")
        ledger_class = non_use_cert.get("refusal_ledger_result_class")
        if cert_status != "certified_within_analyzed_scope" or ledger_class in E8_NON_CERTIFIABLE_CLASSES:
            add_reason(
                "explicit_e8_uncertified_refusal",
                f"Preserve refusal ledger `{non_use_cert.get('refusal_ledger_id')}` (`{ledger_class}`) and block positive non-use trust.",
                f"Certificate status is `{cert_status}` (refusal ledger class `{ledger_class}`).",
            )

    # 4. Optional standalone E8 refusal ledger
    explicit_refusal_summary: dict[str, Any] | None = None
    if refusal_ledger_path is not None:
        if refusal_ledger_path.is_file():
            scanned_paths.append(refusal_ledger_path)
        rl_obj, rl_err = load_json_object(refusal_ledger_path)
        source_inputs.append(
            {
                "input_kind": "e8_refusal_ledger",
                "source_path": display_path(refusal_ledger_path),
                "schema_version": rl_obj.get("schema_version") if rl_obj else None,
                "content_hash": file_hash(refusal_ledger_path) if refusal_ledger_path.is_file() else None,
                "freshness": "present" if rl_obj else "unavailable",
                "availability": "present" if rl_obj else (rl_err or "missing"),
            }
        )
        if rl_err is not None or rl_obj is None:
            add_reason(
                "malformed_e8_refusal_ledger",
                "Provide a valid E8 refusal ledger JSON file.",
                f"Refusal ledger unreadable ({rl_err}).",
            )
        else:
            explicit_refusal_summary, malformed_rl = validate_refusal_ledger(rl_obj)
            if malformed_rl:
                add_reason(
                    "malformed_e8_refusal_ledger",
                    "Rerun the E8 preflight producer to fix the malformed refusal ledger.",
                    "Malformed E8 refusal ledger failed schema/invariant validation.",
                )
            elif explicit_refusal_summary["result_class"] in E8_NON_CERTIFIABLE_CLASSES:
                add_reason(
                    "explicit_e8_uncertified_refusal",
                    f"Preserve refusal ledger `{explicit_refusal_summary['ledger_id']}` and block positive non-use wording.",
                    f"Explicit E8 refusal ledger `{explicit_refusal_summary['ledger_id']}` has class `{explicit_refusal_summary['result_class']}`.",
                )

    # 5. Mock & local-fallback scan
    mock_hits, fallback_hits = scan_text_markers(scanned_paths)
    if mock_hits:
        add_reason(
            "mock_contaminated",
            "Replace mock, simulated, or placeholder certificate fixtures with live runtime-certified E8 artifacts.",
            f"Mock contamination detected ({mock_hits[0]['marker']} in {mock_hits[0]['path']}).",
        )
    if fallback_hits:
        add_reason(
            "local_fallback_contaminated",
            "Re-run heavy proof generation through remote `rch` workers.",
            f"Local-fallback contamination detected ({fallback_hits[0]['marker']} in {fallback_hits[0]['path']}).",
        )

    # 6. Read-only Beads context
    bead_refs, bead_reasons = read_bead_refs(beads_jsonl_path)
    for br_code in bead_reasons:
        add_reason(
            br_code,
            "Sync `.beads/issues.jsonl` so E8 owning bead status can be verified.",
        )

    # Verification command synthesis (read-only guidance, never executed here)
    verify_command = (
        f"frankenctl verify non-use-certificate --bundle {display_path(bundle_dir)} "
        f"--data-contract {display_path(contract_path)} --key-file <trusted-runtime-verification-key.json>"
    )
    if verify_command not in replay_commands:
        verification_commands = [verify_command, *replay_commands]
    else:
        verification_commands = list(replay_commands)

    # Build structured security-reviewer scenario view
    scope_obj = (non_use_cert or {}).get("scope") if isinstance((non_use_cert or {}).get("scope"), dict) else {}
    use_obj = use_cert or {}
    sig_env = (non_use_cert or {}).get("signature_envelope") if isinstance((non_use_cert or {}).get("signature_envelope"), dict) else {}
    key_prov = sig_env.get("key_provenance") if isinstance(sig_env.get("key_provenance"), dict) else {}

    scenario_view = {
        "extension_id": scope_obj.get("extension_id") or (contract or {}).get("extension_id"),
        "contract_id": scope_obj.get("contract_id") or (contract or {}).get("contract_id"),
        "contract_hash_hex": scope_obj.get("contract_hash_hex") or computed_contract_hash,
        "computed_contract_hash_hex": computed_contract_hash,
        "authorized_purpose": scope_obj.get("purpose"),
        "contract_allowed_purposes": sorted(set((contract or {}).get("allowed_purposes", [])))
        if isinstance((contract or {}).get("allowed_purposes"), list)
        else [],
        "run_input_content_hash_hex": scope_obj.get("run_input_content_hash_hex"),
        "replay_trace_content_hash_hex": scope_obj.get("replay_trace_content_hash_hex"),
        "certificate_status": (non_use_cert or {}).get("certificate_status"),
        "refusal_ledger_id": (explicit_refusal_summary or {}).get("ledger_id")
        or (non_use_cert or {}).get("refusal_ledger_id"),
        "refusal_ledger_result_class": (explicit_refusal_summary or {}).get("result_class")
        or (non_use_cert or {}).get("refusal_ledger_result_class"),
        "signer": {
            "producer_id": sig_env.get("producer_id"),
            "authority_class": key_prov.get("authority_class"),
            "key_id": key_prov.get("key_id"),
            "signed_epoch": sig_env.get("signed_epoch"),
        },
        "data_ingress": [
            {
                "binding_id": b.get("binding_id"),
                "role": b.get("role"),
                "label": b.get("label"),
                "owner": b.get("owner"),
                "object_ref": b.get("object_ref"),
                "allowed_purposes": b.get("allowed_purposes"),
                "ingressed": any(
                    isinstance(ib, dict)
                    and ib.get("binding_id") == b.get("binding_id")
                    and ib.get("ingressed") is True
                    for ib in use_obj.get("inputs_bound", [])
                )
                if use_cert
                else None,
            }
            for b in ((contract or {}).get("input_bindings") or [])
            if isinstance(b, dict)
        ],
        "capabilities": {
            "contract_allowed": list(scope_obj.get("contract_capabilities") or (contract or {}).get("allowed_capabilities") or []),
            "runtime_granted": list(scope_obj.get("runtime_granted_capabilities") or []),
            "granted_beyond_contract": list(use_obj.get("capabilities_granted_beyond_contract") or []),
            "recorded_use": list(use_obj.get("capability_use_evidence") or []),
        },
        "sinks": [
            {
                "sink_id": s.get("sink_id"),
                "clearance": s.get("clearance"),
                "location": s.get("location"),
                "allowed_labels": s.get("allowed_labels"),
                "potentially_reached": s.get("sink_id") in (use_obj.get("sinks_potentially_reached") or [])
                if use_cert
                else None,
            }
            for s in ((contract or {}).get("allowed_sinks") or [])
            if isinstance(s, dict)
        ],
        "declassification_routes": [
            {
                "route_id": r.get("route", {}).get("route_id"),
                "source_label": r.get("route", {}).get("source_label"),
                "target_clearance": r.get("route", {}).get("target_clearance"),
                "conditions": r.get("route", {}).get("conditions", []),
                "required_for_claims": r.get("required_for_claims", []),
                "exercised": r.get("route", {}).get("route_id")
                in (use_obj.get("declassification_route_ids_exercised") or [])
                if use_cert
                else None,
            }
            for r in ((contract or {}).get("required_declassification_routes") or [])
            if isinstance(r, dict) and isinstance(r.get("route"), dict)
        ],
        "declassification_receipt_count": (non_use_cert or {}).get("declassification_receipt_count"),
        "certified_claims": [
            {
                "claim_id": c.get("claim_id"),
                "claim_type": (c.get("claim") or {}).get("claim_type") if isinstance(c.get("claim"), dict) else None,
                "evaluation": c.get("evaluation"),
                "evidence_refs": c.get("evidence_refs", []),
                "detail": c.get("detail"),
            }
            for c in ((non_use_cert or {}).get("claims") or [])
            if isinstance(c, dict)
        ],
        "threat_model_scope": scope_obj.get("threat_model_scope", "explicit_flow_ifc_v1"),
        "analysis_posture": scope_obj.get("analysis_posture"),
        "threat_model_holes": THREAT_MODEL_HOLES,
        "verification_commands": verification_commands,
        "warnings": warnings,
    }

    reason_codes = sorted(set(reason_codes))
    decision = choose_decision(reason_codes)

    receipt_core: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "reason_codes": reason_codes,
        "source_inputs": source_inputs,
        "artifact_refs": artifact_refs,
        "claim_refs": claim_refs,
        "bead_refs": bead_refs,
        "evidence_freshness": {
            "status": "fresh"
            if decision == "supported"
            else ("stale" if "stale_artifact" in reason_codes else "unverified"),
            "freshness_days": 0 if decision == "supported" else None,
            "unavailable_reason": None
            if decision == "supported"
            else "E8 certificate bundles bind to exact contract/input SHA-256 digests rather than wall-clock TTL.",
        },
        "mock_status": "present_fail_closed" if mock_hits else "absent",
        "mock_findings": mock_hits,
        "local_fallback_status": "present_fail_closed" if fallback_hits else "absent",
        "local_fallback_findings": fallback_hits,
        "replay_commands": replay_commands,
        "remediation": sorted(set(remediation)),
        "source_line_refs": [
            {
                "path": "crates/franken-engine/src/non_use_certificate.rs",
                "start_line": 1,
                "end_line": 120,
                "status": "available",
            }
        ],
        "mutation_policy": {
            "mutates_br": False,
            "mutates_agent_mail": False,
            "mutates_file_reservations": False,
            "mutates_remote_workers": False,
            "mutates_evidence_bundles": False,
            "mutates_claim_matrix": False,
            "mutates_git": False,
            "mutates_cargo_targets": False,
            "mutates_runtime_policy": False,
        },
        "renderer_boundary": {
            "future_rich_renderer_provider": "/dp/frankentui",
            "local_rich_renderer_shipped": False,
        },
        "e8_scenario": scenario_view,
    }
    if explicit_refusal_summary is not None:
        receipt_core["e8_refusal_ledger"] = explicit_refusal_summary

    return {
        **receipt_core,
        "receipt_id": f"e8-explain-{canonical_hash(receipt_core)[:16]}",
        "generated_at_utc": now_utc,
    }


def render_human_text(receipt: dict[str, Any]) -> str:
    sc = receipt["e8_scenario"]
    decision = str(receipt["decision"])
    reasons = receipt["reason_codes"]
    lines: list[str] = [
        "# E8 Non-Use / Non-Exfiltration Security Scenario Report",
        f"Receipt ID: {receipt['receipt_id']}",
        f"Decision: {decision.upper()}"
        + (f" (reasons: {', '.join(reasons)})" if reasons else " (explicit-flow scope verified)"),
        f"Extension: {sc.get('extension_id') or 'unknown'} | Contract: {sc.get('contract_id') or 'unknown'}",
        f"Contract SHA-256: {sc.get('contract_hash_hex') or 'missing'}",
        f"Run-Input SHA-256: {sc.get('run_input_content_hash_hex') or 'missing'}",
        f"Authorized Purpose: {sc.get('authorized_purpose') or 'missing'} (contract allows: {', '.join(sc.get('contract_allowed_purposes') or []) or 'none'})",
        f"Certificate Status: {sc.get('certificate_status') or 'missing'} | Refusal Ledger: {sc.get('refusal_ledger_id') or 'none'} ({sc.get('refusal_ledger_result_class') or 'unknown'})",
        f"Signer Metadata: authority={sc['signer'].get('authority_class') or 'unknown'} key_id={sc['signer'].get('key_id') or 'missing'}",
        "",
        "## Data Ingress & Labels",
        "| binding_id | role | label | owner | ingressed | object_ref |",
        "|---|---|---|---|---|---|",
    ]
    for b in sc.get("data_ingress") or []:
        lines.append(
            f"| {b.get('binding_id')} | {b.get('role')} | {b.get('label')} | {b.get('owner')} | {b.get('ingressed')} | {b.get('object_ref')} |"
        )
    if not sc.get("data_ingress"):
        lines.append("| (none) | - | - | - | - | - |")

    caps = sc.get("capabilities") or {}
    lines.extend(
        [
            "",
            "## Capabilities Envelope",
            f"- Contract allowed: {', '.join(caps.get('contract_allowed') or []) or 'none'}",
            f"- Runtime granted: {', '.join(caps.get('runtime_granted') or []) or 'none'}",
            f"- Granted beyond contract (ambient runtime profile): {', '.join(caps.get('granted_beyond_contract') or []) or 'none'}",
            "- Recorded capability uses: "
            + (
                ", ".join(
                    f"{u.get('capability')} ({u.get('evidence')})"
                    for u in (caps.get("recorded_use") or [])
                    if isinstance(u, dict)
                )
                or "none"
            ),
            "",
            "## Allowed & Reached Sinks",
            "| sink_id | clearance | location | allowed_labels | potentially_reached |",
            "|---|---|---|---|---|",
        ]
    )
    for s in sc.get("sinks") or []:
        labels = ", ".join(s.get("allowed_labels") or [])
        lines.append(
            f"| {s.get('sink_id')} | {s.get('clearance')} | {s.get('location')} | {labels} | {s.get('potentially_reached')} |"
        )
    if not sc.get("sinks"):
        lines.append("| (none) | - | - | - | - |")

    lines.extend(
        [
            "",
            "## Required Declassification Routes",
            "| route_id | flow | required_for_claims | exercised | conditions |",
            "|---|---|---|---|---|",
        ]
    )
    for r in sc.get("declassification_routes") or []:
        flow = f"{r.get('source_label')} -> {r.get('target_clearance')}"
        req_for = ", ".join(r.get("required_for_claims") or [])
        conds = "; ".join(r.get("conditions") or [])
        lines.append(
            f"| {r.get('route_id')} | {flow} | {req_for} | {r.get('exercised')} | {conds} |"
        )
    if not sc.get("declassification_routes"):
        lines.append("| (none required) | - | - | - | - |")

    lines.extend(
        [
            "",
            "## Certifier Claim Verdicts",
            "| claim_id | type | evaluation | detail |",
            "|---|---|---|---|",
        ]
    )
    for c in sc.get("certified_claims") or []:
        lines.append(
            f"| {c.get('claim_id')} | {c.get('claim_type')} | {c.get('evaluation')} | {c.get('detail')} |"
        )
    if not sc.get("certified_claims"):
        lines.append("| (no certified claims) | - | - | - |")

    if sc.get("warnings") or receipt.get("remediation"):
        lines.extend(["", "## Fail-Closed Warnings & Remediation"])
        for w in sc.get("warnings") or []:
            lines.append(f"- WARNING: {w}")
        for rem in receipt.get("remediation") or []:
            lines.append(f"- REMEDIATION: {rem}")

    lines.extend(["", "## Threat-Model Holes & Reviewer Boundaries"])
    for hole in sc.get("threat_model_holes") or []:
        lines.append(f"- {hole}")

    lines.extend(["", "## Verification & Replay Commands"])
    for cmd in sc.get("verification_commands") or []:
        lines.append(f"- `{cmd}`")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a deterministic security-review scenario report for an E8 non-use certificate bundle."
    )
    parser.add_argument("--contract", required=True, help="Path to E8 data_contract.json")
    parser.add_argument(
        "--bundle",
        required=True,
        help="Path to E8 certificate bundle directory or non_use_certificate.json",
    )
    parser.add_argument(
        "--refusal-ledger",
        default=None,
        help="Optional standalone E8 refusal ledger JSON path",
    )
    parser.add_argument(
        "--claim-matrix",
        default=None,
        help="Optional claim_to_proof_matrix_v1.json path for claim-reference checking",
    )
    parser.add_argument(
        "--beads-jsonl",
        default=None,
        help="Optional .beads/issues.jsonl path for read-only owning bead status",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format: deterministic JSON receipt or concise human security report",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output when --format json is selected",
    )
    args = parser.parse_args()

    receipt = build_report(
        contract_path=Path(args.contract),
        bundle_arg=Path(args.bundle),
        now_utc=utc_now(),
        refusal_ledger_path=Path(args.refusal_ledger) if args.refusal_ledger else None,
        claim_matrix_path=Path(args.claim_matrix) if args.claim_matrix else None,
        beads_jsonl_path=Path(args.beads_jsonl) if args.beads_jsonl else None,
    )

    if args.format == "text":
        print(render_human_text(receipt), end="")
    elif args.pretty:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))

    return 0 if is_zero_exit(str(receipt["decision"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
