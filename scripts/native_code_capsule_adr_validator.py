#!/usr/bin/env python3
"""Strict ADR-0010 validator and two-phase evidence publisher.

This file intentionally uses a restricted JSON canonicalization profile:
UTF-8, duplicate-free objects, safe-range integers only, no floats, no
unpaired surrogates, sorted keys, and no insignificant whitespace.  That
keeps signature inputs deterministic without silently inheriting Python or jq
number coercions.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import locale
import os
import pathlib
import platform
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover - exercised as a typed tool error
    raise SystemExit(
        "NCC-TOOL-MISSING: Python package 'cryptography' is required"
    ) from exc


SCRIPT_SCHEMA = "franken-engine.native-code-capsule-adr-gate.v2"
EVENT_SCHEMA = "franken-engine.native-code-capsule-adr-event.v2"
CANDIDATE_SCHEMA = "franken-engine.native-code-capsule-adr-candidate.v2"
E2E_RECEIPT_SCHEMA = "franken-engine.native-code-capsule-adr-e2e-receipt.v2"
RUN_MANIFEST_SCHEMA = "franken-engine.native-code-capsule-adr-run-manifest.v2"
DECISION_SCHEMA = "franken-engine.native-code-capsule-decision.v1"
TRUST_ROOT_SCHEMA = "franken-engine.native-code-capsule-owner-trust-root.v1"
EXTERNAL_ANCHOR_SCHEMA = (
    "franken-engine.native-code-capsule-external-owner-anchor.v1"
)
APPROVAL_SCHEMA = "franken-engine.native-code-capsule-adr-approval.v1"
APPROVAL_PREIMAGE_SCHEMA = (
    "franken-engine.native-code-capsule-adr-approval-preimage.v1"
)
ENROLLMENT_PREIMAGE_SCHEMA = (
    "franken-engine.native-code-capsule-owner-key-enrollment-preimage.v1"
)
APPROVAL_DOMAIN = "franken-engine.native-code-capsule-adr-approval.v1"
ENROLLMENT_DOMAIN = "franken-engine.native-code-capsule-owner-key-enrollment.v1"
COMPOSITE_DOMAIN = (
    "franken-engine.native-code-capsule-adr-composite-payload.v1"
)
BEAD_ID = "bd-performance-conformance-bridge-tu32j.6.1"
SOURCE_CUTOFF = "2026-07-24"
DEFAULT_SEED = "1001001"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 384 * 1024 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991

# Updated only after the proposed decision contract is frozen.  The hash is
# over the restricted-canonical decision with state normalized to
# status=proposed, implementation_authorized=false, approval=null.
EXPECTED_PROPOSED_DECISION_SHA256 = (
    "49e766094731ef0a0ac7246634eca31aa927121c0cdb219474c1e698b9b16e49"
)

ADR_HEADER_BEGIN = "<!-- NCC-APPROVAL-STATE-HEADER-BEGIN -->"
ADR_HEADER_END = "<!-- NCC-APPROVAL-STATE-HEADER-END -->"
ADR_NOTICE_BEGIN = "<!-- NCC-APPROVAL-STATE-NOTICE-BEGIN -->"
ADR_NOTICE_END = "<!-- NCC-APPROVAL-STATE-NOTICE-END -->"
ADR_RECORD_BEGIN = "<!-- NCC-APPROVAL-STATE-RECORD-BEGIN -->"
ADR_RECORD_END = "<!-- NCC-APPROVAL-STATE-RECORD-END -->"

PROPOSED_HEADER = (
    "\n- Status: Proposed — explicit project-owner approval is required\n"
)
PROPOSED_NOTICE = """
> [!IMPORTANT]
> This ADR is not accepted yet. It deliberately leaves
> `implementation_authorized=false`. No native backend, executable-memory
> mapper, trampoline, or machine-code invocation may be added on the strength
> of this draft. Acceptance requires an explicit project-owner response
> approving the decision payload identified in the approval record.
"""
PROPOSED_RECORD = """
- decision state: `proposed`
- implementation authorized: `false`
- approved payload digest: absent
- approval authority: project owner
- approval text: absent
"""

INPUT_FILENAMES = {
    "decision": "decision.json",
    "adr": "adr.md",
    "plan": "plan.md",
    "engine_split": "engine_split.md",
    "node_split": "node_split.md",
    "trust_root": "owner_trust_root.json",
    "gate": "gate.sh",
    "validator": "strict_validator.py",
    "e2e": "public_e2e.sh",
}
COMPOSITE_COMPONENT_ORDER = tuple(INPUT_FILENAMES)
SEED_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HEX_NONCE_RE = re.compile(r"^[0-9a-f]{32,128}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
RUST_RAW_STRING_RE = re.compile(r'(?:b|c)?r(#{0,255})"')


class DuplicateKeyError(ValueError):
    pass


class NonCanonicalNumberError(ValueError):
    pass


class GateFailure(RuntimeError):
    def __init__(self, code: str, message: str, details: Any | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details is not None:
            result["details"] = self.details
        return result


@dataclass(frozen=True)
class InputPaths:
    repo_root: pathlib.Path
    node_repo: pathlib.Path
    decision: pathlib.Path
    adr: pathlib.Path
    plan: pathlib.Path
    engine_split: pathlib.Path
    node_split: pathlib.Path
    trust_root: pathlib.Path
    gate: pathlib.Path
    validator: pathlib.Path
    e2e: pathlib.Path

    def logical_paths(self) -> dict[str, pathlib.Path]:
        return {
            "decision": self.decision,
            "adr": self.adr,
            "plan": self.plan,
            "engine_split": self.engine_split,
            "node_split": self.node_split,
            "trust_root": self.trust_root,
            "gate": self.gate,
            "validator": self.validator,
            "e2e": self.e2e,
        }


@dataclass(frozen=True)
class Dataset:
    raw: Mapping[str, bytes]
    decision: Mapping[str, Any]
    trust_root: Mapping[str, Any]
    text: Mapping[str, str]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise NonCanonicalNumberError(f"floating-point number is forbidden: {value}")


def _reject_constant(value: str) -> Any:
    raise NonCanonicalNumberError(f"non-finite JSON number is forbidden: {value}")


def _check_restricted_json(value: Any, *, depth: int = 0) -> None:
    if depth > 128:
        raise GateFailure("NCC-JSON-DEPTH", "JSON nesting exceeds 128 levels")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise GateFailure(
                "NCC-JSON-INTEGER-RANGE",
                "JSON integer exceeds the signed safe canonicalization range",
                value,
            )
        return
    if isinstance(value, float):
        raise GateFailure("NCC-JSON-FLOAT", "JSON floats are forbidden")
    if isinstance(value, str):
        for character in value:
            if 0xD800 <= ord(character) <= 0xDFFF:
                raise GateFailure(
                    "NCC-JSON-UNICODE",
                    "unpaired Unicode surrogate is forbidden",
                )
        return
    if isinstance(value, list):
        for item in value:
            _check_restricted_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GateFailure("NCC-JSON-KEY", "JSON object key is not a string")
            _check_restricted_json(key, depth=depth + 1)
            _check_restricted_json(item, depth=depth + 1)
        return
    raise GateFailure(
        "NCC-JSON-TYPE",
        f"unsupported JSON value type: {type(value).__name__}",
    )


def parse_json_bytes(data: bytes, *, label: str) -> Any:
    if len(data) > MAX_JSON_BYTES:
        raise GateFailure(
            "NCC-INPUT-OVERSIZE",
            f"{label} exceeds the {MAX_JSON_BYTES}-byte JSON limit",
        )
    if data.startswith(b"\xef\xbb\xbf"):
        raise GateFailure("NCC-JSON-BOM", f"{label} contains a forbidden UTF-8 BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise GateFailure("NCC-JSON-UTF8", f"{label} is not strict UTF-8") from exc
    try:
        result = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except DuplicateKeyError as exc:
        raise GateFailure("NCC-JSON-DUPLICATE-KEY", f"{label}: {exc}") from exc
    except NonCanonicalNumberError as exc:
        raise GateFailure("NCC-JSON-NUMBER", f"{label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateFailure(
            "NCC-JSON-MALFORMED",
            f"{label}: malformed JSON at line {exc.lineno}, column {exc.colno}",
        ) from exc
    _check_restricted_json(result)
    return result


def canonical_json_bytes(value: Any) -> bytes:
    _check_restricted_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_string_hash(value: str) -> str:
    return sha256_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def strict_text(data: bytes, *, label: str) -> str:
    if len(data) > MAX_TEXT_BYTES:
        raise GateFailure(
            "NCC-INPUT-OVERSIZE",
            f"{label} exceeds the {MAX_TEXT_BYTES}-byte text limit",
        )
    if data.startswith(b"\xef\xbb\xbf"):
        raise GateFailure("NCC-TEXT-BOM", f"{label} contains a UTF-8 BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise GateFailure("NCC-TEXT-UTF8", f"{label} is not strict UTF-8") from exc
    if "\x00" in text:
        raise GateFailure("NCC-TEXT-NUL", f"{label} contains a NUL byte")
    return text


def read_regular_file(path: pathlib.Path, *, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise GateFailure("NCC-INPUT-MISSING", f"missing {label}: {path}") from exc
    except OSError as exc:
        raise GateFailure(
            "NCC-INPUT-OPEN",
            f"cannot securely open {label}: {path}",
            str(exc),
        ) from exc
    try:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode),
            "NCC-INPUT-NOT-REGULAR",
            f"{label} is not a regular file",
        )
        chunks: list[bytes] = []
        observed = 0
        while observed <= MAX_TEXT_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_TEXT_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "NCC-INPUT-RACE",
            f"{label} changed while it was read",
            str(path),
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_dataset_from_bytes(raw: Mapping[str, bytes]) -> Dataset:
    missing = sorted(set(INPUT_FILENAMES) - set(raw))
    extra = sorted(set(raw) - set(INPUT_FILENAMES))
    if missing or extra:
        raise GateFailure(
            "NCC-INPUT-SET",
            "input set is not exact",
            {"missing": missing, "extra": extra},
        )
    decision = parse_json_bytes(raw["decision"], label="decision")
    trust_root = parse_json_bytes(raw["trust_root"], label="owner trust root")
    text = {
        key: strict_text(raw[key], label=key)
        for key in ("adr", "plan", "engine_split", "node_split", "gate", "validator", "e2e")
    }
    if not isinstance(decision, dict) or not isinstance(trust_root, dict):
        raise GateFailure("NCC-JSON-ROOT", "decision and trust root must be objects")
    return Dataset(raw=dict(raw), decision=decision, trust_root=trust_root, text=text)


def load_dataset(paths: InputPaths) -> Dataset:
    raw = {
        logical_id: read_regular_file(path, label=logical_id)
        for logical_id, path in paths.logical_paths().items()
    }
    return load_dataset_from_bytes(raw)


def replace_marked_region(
    text: str, begin: str, end: str, replacement: str, *, label: str
) -> str:
    if text.count(begin) != 1 or text.count(end) != 1:
        raise GateFailure(
            "NCC-ADR-STATE-MARKERS",
            f"{label} must contain exactly one {begin}/{end} marker pair",
        )
    start = text.index(begin) + len(begin)
    finish = text.index(end, start)
    if finish < start:
        raise GateFailure("NCC-ADR-STATE-MARKERS", f"{label} markers are reversed")
    return text[:start] + replacement + text[finish:]


def normalized_proposed_adr(text: str) -> str:
    result = replace_marked_region(
        text,
        ADR_HEADER_BEGIN,
        ADR_HEADER_END,
        PROPOSED_HEADER,
        label="ADR header state",
    )
    result = replace_marked_region(
        result,
        ADR_NOTICE_BEGIN,
        ADR_NOTICE_END,
        PROPOSED_NOTICE,
        label="ADR notice state",
    )
    return replace_marked_region(
        result,
        ADR_RECORD_BEGIN,
        ADR_RECORD_END,
        PROPOSED_RECORD,
        label="ADR approval record",
    )


def normalized_proposed_decision(decision: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(decision))
    result["status"] = "proposed"
    result["implementation_authorized"] = False
    result["approval"] = None
    return result


def require_exact_keys(value: Mapping[str, Any], expected: Iterable[str], code: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise GateFailure(
            code,
            "object fields are not exact",
            {"missing": sorted(wanted - actual), "extra": sorted(actual - wanted)},
        )


def require(condition: bool, code: str, message: str, details: Any | None = None) -> None:
    if not condition:
        raise GateFailure(code, message, details)


def parse_utc(value: Any, *, code: str, label: str) -> dt.datetime:
    require(isinstance(value, str), code, f"{label} must be a string")
    require(value.endswith("Z"), code, f"{label} must end in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateFailure(code, f"{label} is not RFC3339 UTC") from exc
    require(parsed.tzinfo is not None, code, f"{label} lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def public_key_from_pem(value: Any, *, code: str) -> tuple[Ed25519PublicKey, str]:
    require(isinstance(value, str), code, "public_key_pem must be a string")
    try:
        key = serialization.load_pem_public_key(value.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise GateFailure(code, "public_key_pem is not a valid public key") from exc
    require(isinstance(key, Ed25519PublicKey), code, "public key is not Ed25519")
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, sha256_bytes(der)


def decode_signature(value: Any, *, code: str) -> bytes:
    require(isinstance(value, str), code, "signature must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise GateFailure(code, "signature is not strict base64") from exc
    require(len(decoded) == 64, code, "Ed25519 signature must be 64 bytes")
    return decoded


def validate_decision_contract(decision: Mapping[str, Any]) -> None:
    require_exact_keys(
        decision,
        {
            "schema_version",
            "decision_id",
            "contract_marker",
            "governing_bead",
            "research_cutoff",
            "status",
            "implementation_authorized",
            "approval",
            "approval_policy",
            "repositories",
            "packages",
            "process_roles",
            "dependency_direction",
            "forbidden_dependency_direction",
            "unsafe_boundary",
            "selected_backend",
            "compiler_input",
            "region_code_object",
            "engine_authorization",
            "authority_containment",
            "recovery_eligibility",
            "profile_model",
            "execution_profiles",
            "platform_owners",
            "cache_and_confidentiality",
            "lifecycle",
            "claim_rules",
            "document_sync",
            "source_claims",
            "source_locks",
        },
        "NCC-SCHEMA-TOP-LEVEL",
    )
    require(
        decision.get("schema_version") == DECISION_SCHEMA,
        "NCC-IDENTITY-DRIFT",
        "decision schema version drifted",
    )
    require(
        decision.get("decision_id") == "ADR-0010"
        and decision.get("contract_marker") == "NCC-ADR-0010-V1"
        and decision.get("governing_bead") == BEAD_ID
        and decision.get("research_cutoff") == SOURCE_CUTOFF,
        "NCC-IDENTITY-DRIFT",
        "decision identity, bead, marker, or source cutoff drifted",
    )
    require(
        type(decision.get("implementation_authorized")) is bool,
        "NCC-AUTHORIZED-TYPE",
        "implementation_authorized must be an exact JSON boolean",
    )
    status_value = decision.get("status")
    require(
        status_value in {"proposed", "accepted"},
        "NCC-STATE",
        "decision status must be proposed or accepted",
    )
    if status_value == "proposed":
        require(
            decision["implementation_authorized"] is False
            and decision.get("approval") is None,
            "NCC-PROPOSED-AUTHORITY",
            "proposed state must be unauthorized with a null approval",
        )
    else:
        require(
            decision["implementation_authorized"] is True
            and isinstance(decision.get("approval"), dict),
            "NCC-ACCEPTED-AUTHORITY",
            "accepted state requires boolean true and an approval object",
        )

    expected_repositories = {
        "capsule": "/dp/franken_native_capsule",
        "engine": "/dp/franken_engine",
        "product": "/dp/franken_node",
    }
    expected_packages = {
        "api": "frankenengine-native-capsule-api",
        "runtime": "frankenengine-native-capsule",
        "worker": "franken-native-capsule-worker",
    }
    require(
        decision.get("repositories") == expected_repositories
        and decision.get("packages") == expected_packages,
        "NCC-REPOSITORY-IDENTITY",
        "repository or package ownership drifted",
    )
    require(
        decision.get("dependency_direction")
        == [
            "franken_node -> franken_engine",
            "franken_engine -> franken_native_capsule",
        ]
        and decision.get("forbidden_dependency_direction")
        == [
            "franken_engine -> franken_node",
            "franken_native_capsule -> franken_engine",
            "franken_native_capsule -> franken_node",
            "franken_node -> franken_native_capsule",
        ],
        "NCC-DEPENDENCY-DIRECTION",
        "one-way node-to-engine-to-capsule dependency contract drifted",
    )

    approval_policy = decision.get("approval_policy")
    require(isinstance(approval_policy, dict), "NCC-APPROVAL-POLICY", "missing approval policy")
    require(
        approval_policy.get("signature_scheme") == "ed25519"
        and approval_policy.get("signature_domain") == APPROVAL_DOMAIN
        and approval_policy.get("signature_preimage_schema")
        == APPROVAL_PREIMAGE_SCHEMA
        and approval_policy.get("composite_payload_domain") == COMPOSITE_DOMAIN
        and approval_policy.get("digest_algorithm") == "sha256"
        and approval_policy.get("repository_record_alone_is_identity_proof")
        is False
        and approval_policy.get("accepted_verifier_requires_external_anchor")
        is True
        and approval_policy.get("external_anchor_may_be_sourced_from_repository")
        is False
        and approval_policy.get("accepted_requires_online_source_snapshots")
        is True,
        "NCC-APPROVAL-POLICY",
        "approval cryptography or external-anchor policy drifted",
    )
    require(
        approval_policy.get("signed_payload_components")
        == [
            "canonical-proposed-decision",
            "canonical-proposed-adr",
            "authoritative-plan",
            "engine-split-contract",
            "node-split-contract",
            "owner-trust-root",
            "adr-gate",
            "strict-validator",
            "public-e2e-verifier",
        ],
        "NCC-APPROVAL-COMPONENTS",
        "signed payload component set or order drifted",
    )

    unsafe_boundary = decision.get("unsafe_boundary")
    require(
        isinstance(unsafe_boundary, dict)
        and unsafe_boundary.get("allowed_repository") == "/dp/franken_native_capsule"
        and unsafe_boundary.get("unsafe_allowed_package")
        == "frankenengine-native-capsule"
        and unsafe_boundary.get("unsafe_forbidden_packages")
        == [
            "frankenengine-native-capsule-api",
            "franken-native-capsule-worker",
        ]
        and unsafe_boundary.get("unsafe_forbidden_surfaces")
        == [
            "build-scripts",
            "proc-macros",
            "examples",
            "tests",
            "benches",
            "generated-source",
            "newly-added-unallowlisted-modules",
        ]
        and unsafe_boundary.get("forbidden_repositories")
        == ["/dp/franken_engine", "/dp/franken_node"],
        "NCC-UNSAFE-REPOSITORY",
        "unsafe boundary is not confined to the capsule sibling",
    )
    selected_backend = decision.get("selected_backend")
    require(isinstance(selected_backend, dict), "NCC-BACKEND", "missing backend decision")
    release = selected_backend.get("implementation_release")
    require(isinstance(release, dict), "NCC-BACKEND-LOCK", "missing exact release lock")
    require(
        selected_backend.get("portable_backend") == "cranelift"
        and release.get("cranelift_version") == "0.134.2"
        and release.get("wasmtime_tag") == "v47.0.2"
        and release.get("wasmtime_source_commit")
        == "90fed3c6adf53f112c4dea56851728557bb73799"
        and release.get("minimum_rust_version") == "1.94.0"
        and selected_backend.get("jitmodule_v1_production_eligible") is False
        and selected_backend.get("direct_jitmodule_exposure") is False,
        "NCC-BACKEND-LOCK",
        "Cranelift release, source, Rust floor, or JITModule exclusion drifted",
    )
    production_crates = release.get("production_crates")
    research_crates = release.get("research_only_crates")
    require(
        isinstance(production_crates, list)
        and isinstance(research_crates, list)
        and {item.get("name") for item in production_crates if isinstance(item, dict)}
        == {
            "cranelift-bforest",
            "cranelift-codegen",
            "cranelift-control",
            "cranelift-entity",
            "cranelift-frontend",
            "cranelift-module",
            "cranelift-native",
            "cranelift-object",
        }
        and research_crates
        == [
            {
                "name": "cranelift-jit",
                "version": "0.134.2",
                "crates_io_sha256": "fc96ccb592b046be204bf2fbeb397761384e5da10cbf0c2095078af3eaaebe55",
                "download_url": "https://static.crates.io/crates/cranelift-jit/cranelift-jit-0.134.2.crate",
                "production_dependency_allowed": False,
            }
        ],
        "NCC-BACKEND-DEPENDENCY-SCOPE",
        "production versus research-only backend dependency scope drifted",
    )

    rco = decision.get("region_code_object")
    require(isinstance(rco, dict), "NCC-RCO-CONTRACT", "missing RCO contract")
    require(
        rco.get("contains_live_addresses") is False
        and rco.get("schema_version") == "franken-engine.region-code-object.v1"
        and rco.get("pipeline")
        == [
            "lower",
            "compile-authorize",
            "compile",
            "seal",
            "compile-receipt",
            "activation-authorize",
            "structural-validate",
            "reserve",
            "relocate",
            "final-image-validate",
            "instruction-cache-sync",
            "write-revoke",
            "cfi-unwind-register",
            "prepare",
            "install-dormant-route",
            "commit-admission",
            "enable-entry-atomically",
            "record-entry-enabled",
            "execute",
            "unroute",
            "quiesce",
            "cfi-unwind-unregister",
            "unmap",
            "retire",
        ],
        "NCC-RCO-CONTRACT",
        "address-free RCO admission or lifecycle order drifted",
    )
    require(
        rco.get("forbidden_or_guarded_instruction_classes")
        == [
            "direct-syscall-and-trap-gateways",
            "rdtsc-rdtscp",
            "rdrand-rdseed",
            "privileged-state-changes",
            "unauthorized-tls-or-signal-state-access",
            "architecture-specific-nondeterminism",
        ]
        and rco.get("floating_point_contract")
        == [
            "save-and-restore-x87-mxcsr-fpcr-state",
            "no-unauthorized-ftz-or-daz",
            "no-fma-contraction-without-semantic-proof",
            "spec-exact-nan-and-signed-zero",
            "no-unwind-across-native-abi",
        ],
        "NCC-NATIVE-DETERMINISM",
        "forbidden-instruction or floating-point contract drifted",
    )
    engine_authorization = decision.get("engine_authorization")
    require(
        isinstance(engine_authorization, dict)
        and engine_authorization.get("policy_logic_owner") == "franken_engine"
        and engine_authorization.get("issuer_role")
        == "out-of-cell-control-plane-native-authorization-service"
        and engine_authorization.get("issuer_process_location")
        == "outside-execution-cell"
        and engine_authorization.get("signing_key_location")
        == "outside-execution-cell"
        and engine_authorization.get("execution_cell_role")
        == "unsigned-untrusted-compile-or-activation-proposal-producer-only"
        and engine_authorization.get("in_cell_engine_may_issue_signed_authorization")
        is False
        and engine_authorization.get("signer_unavailable_or_stale_action")
        == "fail-closed-tier-i-or-typed-unavailable-no-unsigned-bypass",
        "NCC-AUTHORIZATION-ISSUER",
        "native authorization issuer, process, key, or fail-closed role drifted",
    )

    profile_model = decision.get("profile_model")
    profiles = decision.get("execution_profiles")
    require(
        isinstance(profile_model, dict)
        and isinstance(profiles, list)
        and profile_model.get("receipt_axes")
        == [
            "code-mode",
            "fault-domain",
            "authority-profile",
            "sandbox-profile",
            "operator-mode",
        ]
        and profile_model.get("operator_modes")
        == ["disabled", "preferred", "required"],
        "NCC-PROFILE-MODEL",
        "execution profile axes or operator modes drifted",
    )
    require(
        [profile.get("id") for profile in profiles if isinstance(profile, dict)]
        == [
            "native-throughput",
            "native-parent-crash-contained",
            "native-crash-contained",
            "portable-tier-i",
        ],
        "NCC-PROFILE-SET",
        "named execution profile set or order drifted",
    )
    for profile_entry in profiles:
        require(isinstance(profile_entry, dict), "NCC-PROFILE-TYPE", "profile is not an object")
        claim_tcb = profile_entry.get("claim_tcb")
        require(isinstance(claim_tcb, dict), "NCC-TCB-MISSING", "profile lacks claim-specific TCB")
        require(
            set(claim_tcb)
            == {
                "semantic_correctness",
                "language_level_capability_and_ifc_semantics",
                "parent_survival",
                "ambient_authority_and_effect_ceiling",
                "broker_proven_effect_prefix_recovery",
            },
            "NCC-TCB-AXES",
            "claim-specific TCB axes drifted",
        )
        require(
            all(item is None or isinstance(item, list) for item in claim_tcb.values()),
            "NCC-TCB-TYPE",
            "claim-specific TCB leaves must be arrays or null",
        )

    platform_owners = decision.get("platform_owners")
    require(
        isinstance(platform_owners, list)
        and [entry.get("platform") for entry in platform_owners if isinstance(entry, dict)]
        == ["linux", "apple", "windows"],
        "NCC-PLATFORM-OWNERS",
        "Linux, Apple, and Windows owners must be exact and ordered",
    )
    authority = decision.get("authority_containment")
    recovery = decision.get("recovery_eligibility")
    require(
        isinstance(authority, dict)
        and authority.get(
            "broker_can_reconstruct_arbitrary_value_level_ifc_from_child_bytes"
        )
        is False
        and authority.get("arbitrary_code_resilient_fine_grained_ifc_claim")
        is False
        and authority.get("forged_child_public_label_action")
        == "ignore-child-label-and-enforce-broker-owned-conservative-label"
        and authority.get("native_ifc_eligibility_rule")
        == "before-entry-prove-all-prospective-effects-accept-cell-high-water-label-else-preferred-tier-i-or-required-typed-denial"
        and authority.get("signed_declassification_owner")
        == "out-of-cell-authority-broker"
        and authority.get(
            "child_supplied_ifc_capability_provenance_evidence_or_commit_assertions_are_authoritative"
        )
        is False
        and authority.get("post_native_child_checkpoint_is_trusted_recovery_root")
        is False
        and authority.get("ambient_filesystem_network_device_or_process_authority")
        is False,
        "NCC-AUTHORITY-CONTAINMENT",
        "broker, checkpoint, or ambient-authority contract drifted",
    )
    require(
        isinstance(recovery, dict)
        and recovery.get("feature_may_be_silently_dropped") is False
        and recovery.get("unknown_state_family_action")
        == "fail-closed-pre-entry-tier-i-or-typed-terminal",
        "NCC-RECOVERY-ELIGIBILITY",
        "recovery-class fail-closed or feature-preservation rule drifted",
    )
    confidentiality = decision.get("cache_and_confidentiality")
    crash_policy = (
        confidentiality.get("crash_artifact_policy")
        if isinstance(confidentiality, dict)
        else None
    )
    require(
        isinstance(confidentiality, dict)
        and confidentiality.get(
            "ordinary_profile_claims_microarchitectural_side_channel_confidentiality"
        )
        is False
        and confidentiality.get("side_channel_evidence_absence_action")
        == "claim-excluded-not-inferred-from-process-or-sandbox-isolation"
        and isinstance(crash_policy, dict)
        and crash_policy.get("ambient_os_core_dumps_enabled") is False
        and crash_policy.get("user_controlled_dump_filenames_allowed") is False
        and crash_policy.get("verified_zero_or_expiry_required") is True,
        "NCC-CONFIDENTIALITY-SCOPE",
        "side-channel or crash-artifact confidentiality boundary drifted",
    )

    source_locks = decision.get("source_locks")
    source_claims = decision.get("source_claims")
    require(
        isinstance(source_locks, list) and isinstance(source_claims, list),
        "NCC-SOURCE-TYPE",
        "source locks and claims must be arrays",
    )
    source_ids: list[str] = []
    for source_lock in source_locks:
        require(isinstance(source_lock, dict), "NCC-SOURCE-LOCK", "source lock is not an object")
        require_exact_keys(
            source_lock,
            {"id", "kind", "url", "version_or_commit", "sha256"},
            "NCC-SOURCE-LOCK-SCHEMA",
        )
        source_id = source_lock.get("id")
        source_url = source_lock.get("url")
        source_hash = source_lock.get("sha256")
        require(
            isinstance(source_id, str)
            and isinstance(source_url, str)
            and source_url.startswith("https://")
            and isinstance(source_hash, str)
            and HEX_64_RE.fullmatch(source_hash) is not None,
            "NCC-SOURCE-LOCK",
            "source lock ID, HTTPS URL, or digest is invalid",
        )
        source_ids.append(source_id)
    require(
        len(source_ids) == len(set(source_ids)),
        "NCC-SOURCE-DUPLICATE",
        "source lock IDs must be unique",
    )
    claim_ids: list[str] = []
    referenced_sources: set[str] = set()
    for claim in source_claims:
        require(isinstance(claim, dict), "NCC-SOURCE-CLAIM", "source claim is not an object")
        require_exact_keys(
            claim,
            {"claim_id", "claim", "evidence_class", "bindings"},
            "NCC-SOURCE-CLAIM-SCHEMA",
        )
        claim_id = claim.get("claim_id")
        require(isinstance(claim_id, str), "NCC-SOURCE-CLAIM", "claim ID is invalid")
        claim_ids.append(claim_id)
        bindings = claim.get("bindings")
        require(isinstance(bindings, list) and bindings, "NCC-SOURCE-BINDING", "claim has no bindings")
        for binding in bindings:
            require(
                isinstance(binding, dict)
                and set(binding) == {"source_id", "locator"}
                and isinstance(binding.get("locator"), str)
                and bool(binding["locator"].strip()),
                "NCC-SOURCE-BINDING",
                "source binding is malformed",
            )
            referenced_sources.add(binding["source_id"])
    require(
        len(claim_ids) == len(set(claim_ids)),
        "NCC-SOURCE-CLAIM-DUPLICATE",
        "source claim IDs must be unique",
    )
    require(
        referenced_sources <= set(source_ids),
        "NCC-SOURCE-BINDING",
        "source claim references an unlocked source",
        sorted(referenced_sources - set(source_ids)),
    )

    normalized_hash = sha256_bytes(
        canonical_json_bytes(normalized_proposed_decision(decision))
    )
    require(
        EXPECTED_PROPOSED_DECISION_SHA256 != "TO_BE_FROZEN"
        and normalized_hash == EXPECTED_PROPOSED_DECISION_SHA256,
        "NCC-DECISION-CONTRACT-DRIFT",
        "normalized decision differs from the frozen recursive contract",
        {
            "expected_sha256": EXPECTED_PROPOSED_DECISION_SHA256,
            "observed_sha256": normalized_hash,
        },
    )


def validate_trust_root(trust_root: Mapping[str, Any]) -> None:
    require_exact_keys(
        trust_root,
        {
            "schema_version",
            "contract_marker",
            "status",
            "signature_scheme",
            "signature_domain",
            "trust_root_epoch",
            "revocation_epoch",
            "trusted_keys",
            "revoked_keys",
            "enrollment_policy",
            "note",
        },
        "NCC-TRUST-ROOT-SCHEMA",
    )
    require(
        trust_root.get("schema_version") == TRUST_ROOT_SCHEMA
        and trust_root.get("contract_marker") == "NCC-OWNER-TRUST-ROOT-0010-V1"
        and trust_root.get("signature_scheme") == "ed25519"
        and trust_root.get("signature_domain") == APPROVAL_DOMAIN,
        "NCC-TRUST-ROOT-IDENTITY",
        "owner trust-root identity drifted",
    )
    require(
        type(trust_root.get("trust_root_epoch")) is int
        and type(trust_root.get("revocation_epoch")) is int
        and trust_root["trust_root_epoch"] >= 0
        and trust_root["revocation_epoch"] >= 0,
        "NCC-TRUST-ROOT-EPOCH",
        "trust-root epochs must be nonnegative integers",
    )
    policy = trust_root.get("enrollment_policy")
    require(
        policy
        == {
            "authority": "project-owner-out-of-band",
            "proof_domain": ENROLLMENT_DOMAIN,
            "accepted_key_algorithms": ["ed25519"],
            "proof_of_possession_required": True,
            "producer_distinct_reviewer_required": True,
            "external_verifier_anchor_required": True,
            "external_anchor_may_be_sourced_from_repository": False,
            "repository_record_alone_is_identity_proof": False,
        },
        "NCC-TRUST-ROOT-POLICY",
        "owner-key enrollment or external-anchor policy drifted",
    )
    trusted_keys = trust_root.get("trusted_keys")
    revoked_keys = trust_root.get("revoked_keys")
    require(
        isinstance(trusted_keys, list) and isinstance(revoked_keys, list),
        "NCC-TRUST-ROOT-KEYS",
        "trusted and revoked keys must be arrays",
    )
    if trust_root.get("status") == "unconfigured":
        require(
            trust_root["trust_root_epoch"] == 0
            and trust_root["revocation_epoch"] == 0
            and trusted_keys == []
            and revoked_keys == [],
            "NCC-TRUST-ROOT-UNCONFIGURED",
            "unconfigured trust root must have epoch zero and no keys",
        )
        return
    require(
        trust_root.get("status") == "active"
        and trust_root["trust_root_epoch"] > 0
        and bool(trusted_keys),
        "NCC-TRUST-ROOT-ACTIVE",
        "active trust root requires a positive epoch and trusted key",
    )
    key_ids: set[str] = set()
    for key_record in trusted_keys:
        validate_trusted_key_record(key_record, trust_root)
        require(
            key_record["key_id"] not in key_ids,
            "NCC-TRUST-ROOT-DUPLICATE-KEY",
            "trusted key IDs must be unique",
        )
        key_ids.add(key_record["key_id"])
    revoked_ids: set[str] = set()
    for revoked in revoked_keys:
        require(
            isinstance(revoked, dict)
            and set(revoked)
            == {"key_id", "revoked_at_utc", "revocation_epoch", "reason"}
            and KEY_ID_RE.fullmatch(str(revoked.get("key_id"))) is not None
            and type(revoked.get("revocation_epoch")) is int
            and 0 < revoked["revocation_epoch"] <= trust_root["revocation_epoch"],
            "NCC-TRUST-ROOT-REVOCATION",
            "revoked key record is malformed",
        )
        parse_utc(
            revoked["revoked_at_utc"],
            code="NCC-TRUST-ROOT-REVOCATION",
            label="revoked_at_utc",
        )
        require(
            revoked["key_id"] not in revoked_ids,
            "NCC-TRUST-ROOT-DUPLICATE-REVOCATION",
            "revoked key IDs must be unique",
        )
        revoked_ids.add(revoked["key_id"])


def enrollment_preimage(key_record: Mapping[str, Any], trust_root: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": ENROLLMENT_PREIMAGE_SCHEMA,
        "signature_domain": ENROLLMENT_DOMAIN,
        "key_id": key_record["key_id"],
        "public_key_spki_sha256": key_record["public_key_spki_sha256"],
        "trust_root_epoch": trust_root["trust_root_epoch"],
        "revocation_epoch": trust_root["revocation_epoch"],
        "enrolled_at_utc": key_record["enrolled_at_utc"],
        "producer_distinct_reviewer_id": key_record[
            "producer_distinct_reviewer_id"
        ],
        "review_receipt_sha256": key_record["review_receipt_sha256"],
    }


def validate_trusted_key_record(
    key_record: Any, trust_root: Mapping[str, Any]
) -> None:
    require(isinstance(key_record, dict), "NCC-TRUSTED-KEY", "trusted key is not an object")
    require_exact_keys(
        key_record,
        {
            "key_id",
            "algorithm",
            "public_key_pem",
            "public_key_spki_sha256",
            "not_before_utc",
            "not_after_utc",
            "enrolled_at_utc",
            "enrollment_preimage_sha256",
            "proof_of_possession_signature_base64",
            "producer_distinct_reviewer_id",
            "review_receipt_sha256",
        },
        "NCC-TRUSTED-KEY-SCHEMA",
    )
    require(
        isinstance(key_record.get("key_id"), str)
        and KEY_ID_RE.fullmatch(key_record["key_id"]) is not None
        and key_record.get("algorithm") == "ed25519"
        and isinstance(key_record.get("producer_distinct_reviewer_id"), str)
        and bool(key_record["producer_distinct_reviewer_id"].strip())
        and isinstance(key_record.get("review_receipt_sha256"), str)
        and HEX_64_RE.fullmatch(key_record["review_receipt_sha256"]) is not None,
        "NCC-TRUSTED-KEY",
        "trusted key identity or enrollment review is malformed",
    )
    public_key, observed_spki_hash = public_key_from_pem(
        key_record.get("public_key_pem"), code="NCC-TRUSTED-KEY"
    )
    require(
        key_record.get("public_key_spki_sha256") == observed_spki_hash,
        "NCC-TRUSTED-KEY-DIGEST",
        "trusted key SPKI digest does not match public key",
    )
    not_before = parse_utc(
        key_record.get("not_before_utc"),
        code="NCC-TRUSTED-KEY-TIME",
        label="not_before_utc",
    )
    not_after = parse_utc(
        key_record.get("not_after_utc"),
        code="NCC-TRUSTED-KEY-TIME",
        label="not_after_utc",
    )
    enrolled_at = parse_utc(
        key_record.get("enrolled_at_utc"),
        code="NCC-TRUSTED-KEY-TIME",
        label="enrolled_at_utc",
    )
    require(
        not_before <= enrolled_at < not_after,
        "NCC-TRUSTED-KEY-TIME",
        "key enrollment time is outside its validity interval",
    )
    preimage_bytes = canonical_json_bytes(enrollment_preimage(key_record, trust_root))
    require(
        key_record.get("enrollment_preimage_sha256") == sha256_bytes(preimage_bytes),
        "NCC-TRUSTED-KEY-PREIMAGE",
        "enrollment preimage digest does not match",
    )
    signature = decode_signature(
        key_record.get("proof_of_possession_signature_base64"),
        code="NCC-TRUSTED-KEY-PROOF",
    )
    try:
        public_key.verify(signature, preimage_bytes)
    except InvalidSignature as exc:
        raise GateFailure(
            "NCC-TRUSTED-KEY-PROOF",
            "owner key proof-of-possession signature is invalid",
        ) from exc


def marked_region(text: str, begin: str, end: str, *, label: str) -> str:
    if text.count(begin) != 1 or text.count(end) != 1:
        raise GateFailure(
            "NCC-ADR-STATE-MARKERS",
            f"{label} must contain exactly one marker pair",
        )
    start = text.index(begin) + len(begin)
    finish = text.index(end, start)
    require(finish >= start, "NCC-ADR-STATE-MARKERS", f"{label} markers are reversed")
    return text[start:finish]


def accepted_header() -> str:
    return "\n- Status: Accepted — project-owner signature verified by the closure gate\n"


def accepted_notice(approval: Mapping[str, Any]) -> str:
    return f"""
> [!IMPORTANT]
> This ADR is accepted and `implementation_authorized=true` only for the
> exact composite payload `{approval["approved_payload_sha256"]}` signed by
> project-owner key `{approval["key_id"]}`. Any normative input change,
> revocation, or trust-root epoch change withdraws that authority until a new
> accepted bundle passes the gate.
"""


def accepted_record(approval: Mapping[str, Any]) -> str:
    return f"""
- decision state: `accepted`
- implementation authorized: `true`
- approved payload digest: `{approval["approved_payload_sha256"]}`
- approval authority: project owner key `{approval["key_id"]}`
- approval text hash: `{approval["approval_text_utf8_json_sha256"]}`
"""


def require_literals(text: str, literals: Sequence[str], *, code: str, label: str) -> None:
    missing = [literal for literal in literals if literal not in text]
    require(not missing, code, f"{label} is missing required contract text", missing)


def validate_documents(dataset: Dataset) -> None:
    adr = dataset.text["adr"]
    plan = dataset.text["plan"]
    engine_split = dataset.text["engine_split"]
    node_split = dataset.text["node_split"]
    decision = dataset.decision

    require_literals(
        adr,
        [
            "NCC-ADR-0010-V1",
            "/dp/franken_native_capsule",
            "native-parent-crash-contained",
            "native-crash-contained",
            "CompileAuthorization",
            "ActivationAuthorization",
            "control-plane native-authorization service",
            "unsigned proposal",
            "post-entry fatal native fault",
            "SharedArrayBuffer",
            "indeterminate-external-effect",
            "producer-distinct",
            "external anchor",
            "Cranelift `0.134.2`",
            "Wasmtime `v47.0.2`",
            "JITModule` is not a v1 production emission path",
        ],
        code="NCC-ADR-DRIFT",
        label="ADR",
    )
    require_literals(
        plan,
        [
            "NCC-PLAN-0010-V1",
            "/dp/franken_native_capsule",
            "franken_node -> franken_engine -> franken_native_capsule",
            "out-of-cell control-plane native-authorization service",
            "unsigned, untrusted proposals",
            "post-entry child checkpoint is only an untrusted proposal",
            "Cranelift `0.134.2`",
            "implementation_authorized=false",
        ],
        code="NCC-PLAN-DRIFT",
        label="authoritative plan",
    )
    require_literals(
        engine_split,
        [
            "NCC-ENGINE-SPLIT-0010-V1",
            "franken_node -> franken_engine -> franken_native_capsule",
            "Both existing repositories remain unsafe-forbidden by repository policy",
            "authorization issuer/key service",
            "not a recovery root",
            "untrusted proposal",
        ],
        code="NCC-ENGINE-SPLIT-DRIFT",
        label="engine split contract",
    )
    require_literals(
        node_split,
        [
            "NCC-NODE-SPLIT-0010-V1",
            "franken_node -> franken_engine -> franken_native_capsule",
            "native-authorization service executes engine-owned policy logic outside",
            "must not",
            "post-native checkpoint",
            "untrusted",
        ],
        code="NCC-NODE-SPLIT-DRIFT",
        label="node split contract",
    )

    header_region = marked_region(
        adr, ADR_HEADER_BEGIN, ADR_HEADER_END, label="ADR header state"
    )
    notice_region = marked_region(
        adr, ADR_NOTICE_BEGIN, ADR_NOTICE_END, label="ADR notice state"
    )
    record_region = marked_region(
        adr, ADR_RECORD_BEGIN, ADR_RECORD_END, label="ADR approval record"
    )
    if decision["status"] == "proposed":
        require(
            header_region == PROPOSED_HEADER
            and notice_region == PROPOSED_NOTICE
            and record_region == PROPOSED_RECORD,
            "NCC-DOCUMENT-STATE",
            "ADR proposed-state regions do not exactly match decision state",
        )
    else:
        approval = decision["approval"]
        require(
            header_region == accepted_header()
            and notice_region == accepted_notice(approval)
            and record_region == accepted_record(approval),
            "NCC-DOCUMENT-STATE",
            "ADR accepted-state regions do not exactly match signed decision",
        )


def composite_components(dataset: Dataset) -> tuple[list[dict[str, Any]], str]:
    component_bytes = {
        "canonical-proposed-decision": canonical_json_bytes(
            normalized_proposed_decision(dataset.decision)
        ),
        "canonical-proposed-adr": normalized_proposed_adr(
            dataset.text["adr"]
        ).encode("utf-8"),
        "authoritative-plan": dataset.raw["plan"],
        "engine-split-contract": dataset.raw["engine_split"],
        "node-split-contract": dataset.raw["node_split"],
        "owner-trust-root": canonical_json_bytes(dataset.trust_root),
        "adr-gate": dataset.raw["gate"],
        "strict-validator": dataset.raw["validator"],
        "public-e2e-verifier": dataset.raw["e2e"],
    }
    expected_order = dataset.decision["approval_policy"]["signed_payload_components"]
    require(
        set(component_bytes) == set(expected_order),
        "NCC-APPROVAL-COMPONENTS",
        "validator and decision disagree on signed component set",
    )
    components = [
        {
            "component_id": component_id,
            "sha256": sha256_bytes(component_bytes[component_id]),
            "bytes": len(component_bytes[component_id]),
        }
        for component_id in expected_order
    ]
    envelope = {
        "schema_version": "franken-engine.native-code-capsule-composite-payload.v1",
        "domain": COMPOSITE_DOMAIN,
        "components": components,
    }
    return components, sha256_bytes(canonical_json_bytes(envelope))


def load_external_anchor(
    anchor_path: pathlib.Path,
    *,
    repo_root: pathlib.Path,
    node_repo: pathlib.Path,
) -> Mapping[str, Any]:
    resolved = anchor_path.resolve(strict=True)
    for forbidden_root in (repo_root.resolve(), node_repo.resolve()):
        try:
            resolved.relative_to(forbidden_root)
        except ValueError:
            continue
        raise GateFailure(
            "NCC-EXTERNAL-ANCHOR-LOCATION",
            "accepted verifier anchor must not be sourced from either repository",
            str(resolved),
        )
    raw = read_regular_file(resolved, label="external owner anchor")
    anchor = parse_json_bytes(raw, label="external owner anchor")
    require(isinstance(anchor, dict), "NCC-EXTERNAL-ANCHOR", "anchor must be an object")
    validate_external_anchor(anchor)
    return anchor


def validate_external_anchor(anchor: Mapping[str, Any]) -> None:
    require_exact_keys(
        anchor,
        {
            "schema_version",
            "key_id",
            "algorithm",
            "public_key_pem",
            "public_key_spki_sha256",
            "minimum_trust_root_epoch",
            "minimum_revocation_epoch",
            "anchor_authority",
        },
        "NCC-EXTERNAL-ANCHOR-SCHEMA",
    )
    require(
        anchor.get("schema_version") == EXTERNAL_ANCHOR_SCHEMA
        and anchor.get("algorithm") == "ed25519"
        and anchor.get("anchor_authority") == "project-owner-out-of-band",
        "NCC-EXTERNAL-ANCHOR",
        "external anchor identity or authority is invalid",
    )
    require(
        isinstance(anchor.get("key_id"), str)
        and KEY_ID_RE.fullmatch(anchor["key_id"]) is not None
        and type(anchor.get("minimum_trust_root_epoch")) is int
        and type(anchor.get("minimum_revocation_epoch")) is int
        and anchor["minimum_trust_root_epoch"] > 0
        and anchor["minimum_revocation_epoch"] >= 0,
        "NCC-EXTERNAL-ANCHOR",
        "external anchor key or minimum epochs are invalid",
    )
    _, observed_hash = public_key_from_pem(
        anchor.get("public_key_pem"), code="NCC-EXTERNAL-ANCHOR"
    )
    require(
        anchor.get("public_key_spki_sha256") == observed_hash,
        "NCC-EXTERNAL-ANCHOR-DIGEST",
        "external anchor SPKI digest does not match its public key",
    )


def approval_preimage(approval: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": APPROVAL_PREIMAGE_SCHEMA,
        "signature_domain": APPROVAL_DOMAIN,
        "approved_payload_sha256": approval["approved_payload_sha256"],
        "approval_text_utf8_json_sha256": approval[
            "approval_text_utf8_json_sha256"
        ],
        "issued_at_utc": approval["issued_at_utc"],
        "nonce": approval["nonce"],
        "key_id": approval["key_id"],
        "public_key_spki_sha256": approval["public_key_spki_sha256"],
        "trust_root_epoch": approval["trust_root_epoch"],
        "revocation_epoch": approval["revocation_epoch"],
        "producer_id": approval["producer_id"],
    }


def validate_approval(
    dataset: Dataset,
    *,
    external_anchor: Mapping[str, Any] | None,
    now: dt.datetime | None = None,
) -> str:
    _, payload_digest = composite_components(dataset)
    if dataset.decision["status"] == "proposed":
        require(
            external_anchor is None or isinstance(external_anchor, Mapping),
            "NCC-EXTERNAL-ANCHOR",
            "invalid external anchor",
        )
        return payload_digest

    require(
        external_anchor is not None,
        "NCC-EXTERNAL-ANCHOR-REQUIRED",
        "accepted state requires an independently provisioned external anchor",
    )
    trust_root = dataset.trust_root
    require(
        trust_root.get("status") == "active",
        "NCC-TRUST-ROOT-UNCONFIGURED",
        "accepted state cannot use an unconfigured owner trust root",
    )
    approval = dataset.decision["approval"]
    require(isinstance(approval, dict), "NCC-APPROVAL", "approval is not an object")
    require_exact_keys(
        approval,
        {
            "schema_version",
            "authority",
            "approved_payload_sha256",
            "approval_text",
            "approval_text_utf8_json_sha256",
            "issued_at_utc",
            "nonce",
            "key_id",
            "public_key_spki_sha256",
            "trust_root_epoch",
            "revocation_epoch",
            "signature_domain",
            "signature_preimage_sha256",
            "signature_base64",
            "producer_id",
            "producer_distinct_review",
        },
        "NCC-APPROVAL-SCHEMA",
    )
    require(
        approval.get("schema_version") == APPROVAL_SCHEMA
        and approval.get("authority") == "project-owner"
        and approval.get("signature_domain") == APPROVAL_DOMAIN,
        "NCC-APPROVAL-IDENTITY",
        "approval schema, authority, or signature domain is invalid",
    )
    require(
        isinstance(approval.get("approved_payload_sha256"), str)
        and HEX_64_RE.fullmatch(approval["approved_payload_sha256"]) is not None
        and approval["approved_payload_sha256"] == payload_digest,
        "NCC-APPROVAL-PAYLOAD",
        "approval does not bind the exact composite payload",
        {
            "expected_sha256": payload_digest,
            "observed_sha256": approval.get("approved_payload_sha256"),
        },
    )
    require(
        isinstance(approval.get("approval_text"), str)
        and approval.get("approval_text_utf8_json_sha256")
        == canonical_json_string_hash(approval["approval_text"]),
        "NCC-APPROVAL-TEXT",
        "approval text hash does not preserve the exact JSON string bytes",
    )
    require(
        isinstance(approval.get("nonce"), str)
        and HEX_NONCE_RE.fullmatch(approval["nonce"]) is not None,
        "NCC-APPROVAL-NONCE",
        "approval nonce must be 16-64 bytes of lowercase hex",
    )
    require(
        isinstance(approval.get("producer_id"), str)
        and bool(approval["producer_id"].strip()),
        "NCC-APPROVAL-PRODUCER",
        "approval producer ID is missing",
    )
    issued_at = parse_utc(
        approval.get("issued_at_utc"),
        code="NCC-APPROVAL-TIME",
        label="issued_at_utc",
    )
    current_time = now or dt.datetime.now(dt.timezone.utc)
    require(
        issued_at <= current_time + dt.timedelta(minutes=5),
        "NCC-APPROVAL-TIME",
        "approval timestamp is unreasonably in the future",
    )
    require(
        type(approval.get("trust_root_epoch")) is int
        and type(approval.get("revocation_epoch")) is int
        and approval["trust_root_epoch"] == trust_root["trust_root_epoch"]
        and approval["revocation_epoch"] == trust_root["revocation_epoch"],
        "NCC-APPROVAL-EPOCH",
        "approval does not bind current trust-root and revocation epochs",
    )
    require(
        trust_root["trust_root_epoch"] >= external_anchor["minimum_trust_root_epoch"]
        and trust_root["revocation_epoch"]
        >= external_anchor["minimum_revocation_epoch"],
        "NCC-EXTERNAL-ANCHOR-EPOCH",
        "repository trust root is older than the external anchor minimum",
    )
    require(
        approval.get("key_id") == external_anchor["key_id"]
        and approval.get("public_key_spki_sha256")
        == external_anchor["public_key_spki_sha256"],
        "NCC-APPROVAL-WRONG-KEY",
        "approval key does not match the independently provisioned anchor",
    )
    revoked_ids = {
        entry["key_id"]
        for entry in trust_root["revoked_keys"]
        if isinstance(entry, dict) and "key_id" in entry
    }
    require(
        approval["key_id"] not in revoked_ids,
        "NCC-APPROVAL-REVOKED-KEY",
        "approval key is revoked",
    )
    matching_keys = [
        record
        for record in trust_root["trusted_keys"]
        if record.get("key_id") == approval["key_id"]
    ]
    require(
        len(matching_keys) == 1,
        "NCC-APPROVAL-UNKNOWN-KEY",
        "approval key is not exactly one active trusted key",
    )
    key_record = matching_keys[0]
    require(
        key_record["public_key_spki_sha256"]
        == external_anchor["public_key_spki_sha256"],
        "NCC-APPROVAL-WRONG-KEY",
        "repository key record does not match external anchor",
    )
    not_before = parse_utc(
        key_record["not_before_utc"],
        code="NCC-APPROVAL-KEY-TIME",
        label="key not_before_utc",
    )
    not_after = parse_utc(
        key_record["not_after_utc"],
        code="NCC-APPROVAL-KEY-TIME",
        label="key not_after_utc",
    )
    require(
        not_before <= issued_at <= current_time < not_after,
        "NCC-APPROVAL-KEY-TIME",
        "approval key is not valid at issuance and verification time",
    )
    review = approval.get("producer_distinct_review")
    require(
        isinstance(review, dict)
        and set(review)
        == {
            "reviewer_id",
            "reviewed_at_utc",
            "external_authorization_sha256",
            "comparison_result",
        }
        and isinstance(review.get("reviewer_id"), str)
        and bool(review["reviewer_id"].strip())
        and review["reviewer_id"] != approval["producer_id"]
        and isinstance(review.get("external_authorization_sha256"), str)
        and HEX_64_RE.fullmatch(review["external_authorization_sha256"]) is not None
        and review.get("comparison_result") == "exact-text-and-payload-match",
        "NCC-APPROVAL-REVIEW",
        "producer-distinct external-authorization review is invalid",
    )
    parse_utc(
        review["reviewed_at_utc"],
        code="NCC-APPROVAL-REVIEW",
        label="reviewed_at_utc",
    )
    preimage_bytes = canonical_json_bytes(approval_preimage(approval))
    require(
        approval.get("signature_preimage_sha256") == sha256_bytes(preimage_bytes),
        "NCC-APPROVAL-PREIMAGE",
        "approval signature preimage digest does not match",
    )
    signature = decode_signature(
        approval.get("signature_base64"), code="NCC-APPROVAL-SIGNATURE"
    )
    public_key, _ = public_key_from_pem(
        external_anchor["public_key_pem"], code="NCC-EXTERNAL-ANCHOR"
    )
    try:
        public_key.verify(signature, preimage_bytes)
    except InvalidSignature as exc:
        raise GateFailure(
            "NCC-APPROVAL-SIGNATURE",
            "project-owner Ed25519 approval signature is invalid",
        ) from exc
    return payload_digest


def strip_rust_noncode(source: str) -> str:
    """Return Rust tokens with comments and string/char literal bodies blanked."""
    output: list[str] = []
    index = 0
    block_depth = 0
    length = len(source)
    while index < length:
        if block_depth:
            if source.startswith("/*", index):
                block_depth += 1
                output.extend("  ")
                index += 2
            elif source.startswith("*/", index):
                block_depth -= 1
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            continue
        if source.startswith("//", index):
            finish = source.find("\n", index)
            if finish == -1:
                output.extend(" " * (length - index))
                break
            output.extend(" " * (finish - index))
            output.append("\n")
            index = finish + 1
            continue
        if source.startswith("/*", index):
            block_depth = 1
            output.extend("  ")
            index += 2
            continue

        raw_match = (
            RUST_RAW_STRING_RE.match(source, index)
            if source[index] in {"b", "c", "r"}
            else None
        )
        if raw_match:
            hashes = raw_match.group(1)
            terminator = '"' + hashes
            finish = source.find(terminator, raw_match.end())
            if finish == -1:
                output.extend(" " * (length - index))
                break
            end = finish + len(terminator)
            segment = source[index:end]
            output.extend("\n" if character == "\n" else " " for character in segment)
            index = end
            continue

        prefix_length = 0
        quote = ""
        if source.startswith('b"', index) or source.startswith('c"', index):
            prefix_length = 1
            quote = '"'
        elif source[index] == '"':
            quote = '"'
        elif source.startswith("b'", index):
            prefix_length = 1
            quote = "'"
        elif source[index] == "'":
            # A lifetime such as 'a is not a character literal.
            if index + 1 < length and re.match(r"[A-Za-z_]", source[index + 1]):
                output.append(source[index])
                index += 1
                continue
            quote = "'"
        if quote:
            cursor = index + prefix_length + 1
            escaped = False
            while cursor < length:
                character = source[cursor]
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    cursor += 1
                    break
                cursor += 1
            segment = source[index:cursor]
            output.extend("\n" if character == "\n" else " " for character in segment)
            index = cursor
            continue
        output.append(source[index])
        index += 1
    return "".join(output)


def strip_exact_cfg_test_items(stripped: str) -> str:
    """Blank items controlled by exactly `#[cfg(test)]`, preserving line offsets."""
    output = list(stripped)
    pattern = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in pattern.finditer(stripped):
        cursor = match.end()
        while True:
            while cursor < len(stripped) and stripped[cursor].isspace():
                cursor += 1
            if cursor >= len(stripped) or not stripped.startswith("#", cursor):
                break
            attribute_end = stripped.find("]", cursor + 1)
            if attribute_end == -1:
                break
            cursor = attribute_end + 1
        brace = stripped.find("{", cursor)
        semicolon = stripped.find(";", cursor)
        if semicolon != -1 and (brace == -1 or semicolon < brace):
            finish = semicolon + 1
        elif brace != -1:
            depth = 0
            finish = len(stripped)
            for index in range(brace, len(stripped)):
                if stripped[index] == "{":
                    depth += 1
                elif stripped[index] == "}":
                    depth -= 1
                    if depth == 0:
                        finish = index + 1
                        break
        else:
            finish = len(stripped)
        for index in range(match.start(), finish):
            if output[index] != "\n":
                output[index] = " "
    return "".join(output)


def rust_unsafe_token_locations(source: str) -> list[int]:
    if "unsafe" not in source:
        return []
    stripped = strip_exact_cfg_test_items(strip_rust_noncode(source))
    return [
        stripped.count("\n", 0, match.start()) + 1
        for match in re.finditer(r"\bunsafe\b", stripped)
    ]


def iter_production_rust_files(repo: pathlib.Path) -> Iterable[pathlib.Path]:
    for crate_root in sorted((repo / "crates").glob("*")):
        source_root = crate_root / "src"
        if source_root.is_dir():
            yield from sorted(source_root.rglob("*.rs"))
        build_script = crate_root / "build.rs"
        if build_script.is_file():
            yield build_script
    root_source = repo / "src"
    if root_source.is_dir():
        yield from sorted(root_source.rglob("*.rs"))
    root_build = repo / "build.rs"
    if root_build.is_file():
        yield root_build


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    timeout_seconds: int = 30,
    max_bytes: int = 2 * 1024 * 1024,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(argv),
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise GateFailure(
            "NCC-COMMAND-TIMEOUT",
            f"command timed out after {timeout_seconds}s",
            list(argv),
        ) from exc
    require(
        len(result.stdout) <= max_bytes and len(result.stderr) <= max_bytes,
        "NCC-COMMAND-OUTPUT-BOUND",
        "command output exceeded evidence bound",
        list(argv),
    )
    return result


def dependency_tables(manifest: Mapping[str, Any]) -> Iterable[tuple[str, Mapping[str, Any]]]:
    for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(table_name, {})
        if isinstance(table, dict):
            yield table_name, table
    target_table = manifest.get("target", {})
    if isinstance(target_table, dict):
        for target_name, target_value in target_table.items():
            if not isinstance(target_value, dict):
                continue
            for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target_value.get(table_name, {})
                if isinstance(table, dict):
                    yield f"target.{target_name}.{table_name}", table


def dependency_mentions_capsule(name: str, value: Any) -> bool:
    fragments = [name]
    if isinstance(value, str):
        fragments.append(value)
    elif isinstance(value, dict):
        for field in ("package", "path", "git"):
            candidate = value.get(field)
            if isinstance(candidate, str):
                fragments.append(candidate)
    joined = " ".join(fragments).lower().replace("-", "_")
    return "franken_native_capsule" in joined or "frankenengine_native_capsule" in joined


def validate_repository_boundary(
    *,
    repo_root: pathlib.Path,
    node_repo: pathlib.Path,
    decision_status: str,
) -> dict[str, Any]:
    scan_records: list[dict[str, Any]] = []
    for repo_label, repo in (("engine", repo_root), ("node", node_repo)):
        require(repo.is_dir(), "NCC-REPOSITORY-MISSING", f"missing {repo_label} repository")
        unsafe_hits: list[dict[str, Any]] = []
        scanned_files = 0
        for rust_file in iter_production_rust_files(repo):
            if rust_file.is_symlink():
                raise GateFailure(
                    "NCC-PRODUCTION-SOURCE-SYMLINK",
                    "production Rust source must not be a symlink",
                    str(rust_file),
                )
            source = rust_file.read_text(encoding="utf-8", errors="strict")
            scanned_files += 1
            for line_number in rust_unsafe_token_locations(source):
                unsafe_hits.append(
                    {
                        "path": str(rust_file.relative_to(repo)),
                        "line": line_number,
                    }
                )
        require(
            not unsafe_hits,
            f"NCC-UNSAFE-{repo_label.upper()}",
            f"production Rust source in {repo_label} contains unsafe tokens",
            unsafe_hits[:100],
        )

        capsule_dependencies: list[dict[str, Any]] = []
        cargo_files = sorted(
            path
            for path in repo.rglob("Cargo.toml")
            if "target" not in path.parts and ".git" not in path.parts
        )
        for cargo_file in cargo_files:
            cargo_bytes = read_regular_file(cargo_file, label="Cargo.toml")
            try:
                cargo_manifest = tomllib.loads(cargo_bytes.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                raise GateFailure(
                    "NCC-CARGO-MANIFEST",
                    f"failed to parse {cargo_file}",
                ) from exc
            for table_name, dependency_table in dependency_tables(cargo_manifest):
                for dependency_name, dependency_value in dependency_table.items():
                    if dependency_mentions_capsule(dependency_name, dependency_value):
                        capsule_dependencies.append(
                            {
                                "path": str(cargo_file.relative_to(repo)),
                                "table": table_name,
                                "dependency": dependency_name,
                            }
                        )
        if repo_label == "node":
            require(
                not capsule_dependencies,
                "NCC-DIRECT-NODE-CAPSULE-DEPENDENCY",
                "franken_node must not depend on the capsule directly",
                capsule_dependencies,
            )
        elif decision_status == "proposed":
            require(
                not capsule_dependencies,
                "NCC-PREMATURE-ENGINE-CAPSULE-DEPENDENCY",
                "proposed ADR state cannot add a capsule dependency",
                capsule_dependencies,
            )

        metadata_result = run_bounded(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=repo,
            timeout_seconds=45,
            max_bytes=8 * 1024 * 1024,
        )
        require(
            metadata_result.returncode == 0,
            "NCC-CARGO-METADATA",
            f"{repo_label} cargo metadata failed",
            metadata_result.stderr.decode("utf-8", errors="replace")[-4000:],
        )
        metadata = parse_json_bytes(
            metadata_result.stdout, label=f"{repo_label} cargo metadata"
        )
        require(
            isinstance(metadata, dict) and isinstance(metadata.get("packages"), list),
            "NCC-CARGO-METADATA",
            f"{repo_label} cargo metadata shape is invalid",
        )
        scan_records.append(
            {
                "repository": repo_label,
                "production_rust_files_scanned": scanned_files,
                "cargo_manifests_scanned": len(cargo_files),
                "cargo_packages": len(metadata["packages"]),
                "capsule_dependencies": capsule_dependencies,
                "metadata_sha256": sha256_bytes(metadata_result.stdout),
            }
        )
    return {"schema_version": "franken-engine.native-boundary-scan.v1", "records": scan_records}


def validate_dataset(
    dataset: Dataset,
    *,
    external_anchor: Mapping[str, Any] | None,
    repo_root: pathlib.Path | None = None,
    node_repo: pathlib.Path | None = None,
    scan_repositories: bool = False,
) -> dict[str, Any]:
    validate_decision_contract(dataset.decision)
    validate_trust_root(dataset.trust_root)
    validate_documents(dataset)
    payload_digest = validate_approval(
        dataset,
        external_anchor=external_anchor,
    )
    repository_scan = None
    if scan_repositories:
        require(
            repo_root is not None and node_repo is not None,
            "NCC-REPOSITORY-SCAN",
            "repository roots are required for production boundary scan",
        )
        repository_scan = validate_repository_boundary(
            repo_root=repo_root,
            node_repo=node_repo,
            decision_status=dataset.decision["status"],
        )
    return {
        "schema_version": SCRIPT_SCHEMA,
        "decision_status": dataset.decision["status"],
        "implementation_authorized": dataset.decision[
            "implementation_authorized"
        ],
        "composite_payload_sha256": payload_digest,
        "input_hashes": {
            logical_id: sha256_bytes(data)
            for logical_id, data in sorted(dataset.raw.items())
        },
        "repository_boundary_scan": repository_scan,
    }


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, str, int | None]):
        super().__init__()
        self.allowed_origin = allowed_origin

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Mapping[str, str],
        new_url: str,
    ) -> urllib.request.Request | None:
        parsed = urllib.parse.urlsplit(new_url)
        new_origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port)
        if new_origin != self.allowed_origin:
            raise GateFailure(
                "NCC-SOURCE-REDIRECT",
                "source redirect changed the declared HTTPS origin",
                {"from": request.full_url, "to": new_url},
            )
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def download_https_bytes(url: str) -> tuple[bytes, dict[str, Any]]:
    parsed = urllib.parse.urlsplit(url)
    require(
        parsed.scheme == "https" and bool(parsed.hostname),
        "NCC-SOURCE-URL",
        "source URL must use HTTPS with an explicit host",
        url,
    )
    origin = (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port)
    opener = urllib.request.build_opener(SameOriginRedirectHandler(origin))
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "franken-engine-native-capsule-source-verifier/1.0",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    started = time.monotonic_ns()
    try:
        with opener.open(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                require(
                    int(content_length) <= MAX_SOURCE_BYTES,
                    "NCC-SOURCE-OVERSIZE",
                    "declared source size exceeds per-source limit",
                    {"url": url, "content_length": content_length},
                )
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                require(
                    observed <= MAX_SOURCE_BYTES,
                    "NCC-SOURCE-OVERSIZE",
                    "source bytes exceed per-source limit",
                    url,
                )
                chunks.append(chunk)
            body = b"".join(chunks)
            final_url = response.geturl()
            metadata = {
                "requested_url": url,
                "final_url": final_url,
                "http_status": response.status,
                "content_type": response.headers.get("Content-Type"),
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "duration_ms": max(1, (time.monotonic_ns() - started) // 1_000_000),
            }
    except GateFailure:
        raise
    except Exception as exc:
        raise GateFailure(
            "NCC-SOURCE-FETCH",
            "source retrieval failed",
            {"url": url, "error": f"{type(exc).__name__}: {exc}"},
        ) from exc
    final_parsed = urllib.parse.urlsplit(final_url)
    final_origin = (
        final_parsed.scheme.lower(),
        (final_parsed.hostname or "").lower(),
        final_parsed.port,
    )
    require(
        final_origin == origin,
        "NCC-SOURCE-REDIRECT",
        "source final URL changed the declared HTTPS origin",
        {"requested": url, "final": final_url},
    )
    return body, metadata


def online_source_specs(decision: Mapping[str, Any]) -> list[dict[str, str]]:
    specs = [
        {
            "source_id": source["id"],
            "kind": source["kind"],
            "url": source["url"],
            "sha256": source["sha256"],
        }
        for source in decision["source_locks"]
    ]
    release = decision["selected_backend"]["implementation_release"]
    for crate in release["production_crates"] + release["research_only_crates"]:
        specs.append(
            {
                "source_id": f"crate-{crate['name']}-{crate['version']}",
                "kind": (
                    "crates-io-production-archive"
                    if crate in release["production_crates"]
                    else "crates-io-research-only-archive"
                ),
                "url": crate["download_url"],
                "sha256": crate["crates_io_sha256"],
            }
        )
    identifiers = [spec["source_id"] for spec in specs]
    require(
        len(identifiers) == len(set(identifiers)),
        "NCC-SOURCE-DUPLICATE",
        "online source snapshot IDs must be unique",
    )
    return specs


def verify_sources_online(
    decision: Mapping[str, Any],
    *,
    snapshot_dir: pathlib.Path | None,
) -> dict[str, Any]:
    receipts: list[dict[str, Any]] = []
    total_bytes = 0
    if snapshot_dir is not None:
        create_private_directory(snapshot_dir)
    for index, spec in enumerate(online_source_specs(decision), start=1):
        body, metadata = download_https_bytes(spec["url"])
        total_bytes += len(body)
        require(
            total_bytes <= MAX_TOTAL_SOURCE_BYTES,
            "NCC-SOURCE-TOTAL-OVERSIZE",
            "source snapshots exceed aggregate byte limit",
        )
        observed_hash = sha256_bytes(body)
        require(
            observed_hash == spec["sha256"],
            "NCC-SOURCE-HASH",
            "retrieved source bytes do not match the decision lock",
            {
                "source_id": spec["source_id"],
                "expected_sha256": spec["sha256"],
                "observed_sha256": observed_hash,
            },
        )
        filename = f"{index:03d}-{spec['source_id']}.bin"
        require(
            re.fullmatch(r"[0-9]{3}-[A-Za-z0-9._-]+\.bin", filename) is not None,
            "NCC-SOURCE-ID",
            "source ID is unsafe for snapshot path",
            spec["source_id"],
        )
        if snapshot_dir is not None:
            target = snapshot_dir / filename
            write_new_bytes(target, body)
        receipts.append(
            {
                **spec,
                **metadata,
                "snapshot_path": f"source_snapshots/{filename}",
                "bytes": len(body),
                "observed_sha256": observed_hash,
                "decision": "verified",
            }
        )
    return {
        "schema_version": "franken-engine.native-code-source-snapshots.v1",
        "source_cutoff": SOURCE_CUTOFF,
        "verification_mode": "online-exact-bytes-retained",
        "total_bytes": total_bytes,
        "receipts": receipts,
    }


TEST_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILZEFGLpzzURlvg7l8cqIYGX5dXFYnRQv2J/HnAVuNSs
-----END PRIVATE KEY-----
"""


def json_file_bytes(value: Any) -> bytes:
    _check_restricted_json(value)
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")


def render_accepted_adr(text: str, approval: Mapping[str, Any]) -> str:
    result = replace_marked_region(
        text,
        ADR_HEADER_BEGIN,
        ADR_HEADER_END,
        accepted_header(),
        label="ADR header state",
    )
    result = replace_marked_region(
        result,
        ADR_NOTICE_BEGIN,
        ADR_NOTICE_END,
        accepted_notice(approval),
        label="ADR notice state",
    )
    return replace_marked_region(
        result,
        ADR_RECORD_BEGIN,
        ADR_RECORD_END,
        accepted_record(approval),
        label="ADR approval record",
    )


def make_test_accepted_dataset(
    proposed: Dataset,
) -> tuple[Dataset, Mapping[str, Any]]:
    private_key = serialization.load_pem_private_key(TEST_PRIVATE_KEY_PEM, password=None)
    require(
        isinstance(private_key, Ed25519PrivateKey),
        "NCC-SELF-TEST-KEY",
        "embedded test key is not Ed25519",
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_hash = sha256_bytes(public_der)
    key_id = "test-owner-ed25519-001"
    reviewer_id = "test-producer-distinct-reviewer"
    review_hash = sha256_bytes(b"test-only producer-distinct enrollment review")
    trust_root = copy.deepcopy(dict(proposed.trust_root))
    trust_root.update(
        {
            "status": "active",
            "trust_root_epoch": 1,
            "revocation_epoch": 0,
            "trusted_keys": [],
            "revoked_keys": [],
            "note": "TEST ONLY active owner key used solely by the in-process mutation suite.",
        }
    )
    key_record: dict[str, Any] = {
        "key_id": key_id,
        "algorithm": "ed25519",
        "public_key_pem": public_pem,
        "public_key_spki_sha256": spki_hash,
        "not_before_utc": "2020-01-01T00:00:00Z",
        "not_after_utc": "2099-01-01T00:00:00Z",
        "enrolled_at_utc": "2026-07-24T12:00:00Z",
        "enrollment_preimage_sha256": "",
        "proof_of_possession_signature_base64": "",
        "producer_distinct_reviewer_id": reviewer_id,
        "review_receipt_sha256": review_hash,
    }
    enrollment_bytes = canonical_json_bytes(enrollment_preimage(key_record, trust_root))
    key_record["enrollment_preimage_sha256"] = sha256_bytes(enrollment_bytes)
    key_record["proof_of_possession_signature_base64"] = base64.b64encode(
        private_key.sign(enrollment_bytes)
    ).decode("ascii")
    trust_root["trusted_keys"] = [key_record]

    decision = copy.deepcopy(dict(proposed.decision))
    decision["status"] = "accepted"
    decision["implementation_authorized"] = True
    decision["approval"] = {}
    raw_for_digest = dict(proposed.raw)
    raw_for_digest["decision"] = json_file_bytes(decision)
    raw_for_digest["trust_root"] = json_file_bytes(trust_root)
    digest_dataset = load_dataset_from_bytes(raw_for_digest)
    _, payload_digest = composite_components(digest_dataset)

    approval: dict[str, Any] = {
        "schema_version": APPROVAL_SCHEMA,
        "authority": "project-owner",
        "approved_payload_sha256": payload_digest,
        "approval_text": (
            "TEST ONLY: approve the exact ADR-0010 composite payload for "
            "validator mutation coverage."
        ),
        "approval_text_utf8_json_sha256": "",
        "issued_at_utc": "2026-07-24T12:30:00Z",
        "nonce": "0123456789abcdef0123456789abcdef",
        "key_id": key_id,
        "public_key_spki_sha256": spki_hash,
        "trust_root_epoch": 1,
        "revocation_epoch": 0,
        "signature_domain": APPROVAL_DOMAIN,
        "signature_preimage_sha256": "",
        "signature_base64": "",
        "producer_id": "test-artifact-producer",
        "producer_distinct_review": {
            "reviewer_id": "test-approval-reviewer",
            "reviewed_at_utc": "2026-07-24T12:35:00Z",
            "external_authorization_sha256": sha256_bytes(
                b"test-only external project-owner authorization"
            ),
            "comparison_result": "exact-text-and-payload-match",
        },
    }
    approval["approval_text_utf8_json_sha256"] = canonical_json_string_hash(
        approval["approval_text"]
    )
    approval_bytes = canonical_json_bytes(approval_preimage(approval))
    approval["signature_preimage_sha256"] = sha256_bytes(approval_bytes)
    approval["signature_base64"] = base64.b64encode(
        private_key.sign(approval_bytes)
    ).decode("ascii")
    decision["approval"] = approval
    accepted_adr = render_accepted_adr(proposed.text["adr"], approval)
    accepted_raw = dict(proposed.raw)
    accepted_raw["decision"] = json_file_bytes(decision)
    accepted_raw["trust_root"] = json_file_bytes(trust_root)
    accepted_raw["adr"] = accepted_adr.encode("utf-8")
    accepted_dataset = load_dataset_from_bytes(accepted_raw)
    anchor = {
        "schema_version": EXTERNAL_ANCHOR_SCHEMA,
        "key_id": key_id,
        "algorithm": "ed25519",
        "public_key_pem": public_pem,
        "public_key_spki_sha256": spki_hash,
        "minimum_trust_root_epoch": 1,
        "minimum_revocation_epoch": 0,
        "anchor_authority": "project-owner-out-of-band",
    }
    return accepted_dataset, anchor


def mutate_decision(
    dataset: Dataset, mutator: Callable[[dict[str, Any]], None]
) -> Dataset:
    decision = copy.deepcopy(dict(dataset.decision))
    mutator(decision)
    raw = dict(dataset.raw)
    raw["decision"] = json_file_bytes(decision)
    return load_dataset_from_bytes(raw)


def mutate_trust_root(
    dataset: Dataset, mutator: Callable[[dict[str, Any]], None]
) -> Dataset:
    trust_root = copy.deepcopy(dict(dataset.trust_root))
    mutator(trust_root)
    raw = dict(dataset.raw)
    raw["trust_root"] = json_file_bytes(trust_root)
    return load_dataset_from_bytes(raw)


def mutate_text(dataset: Dataset, logical_id: str, old: str, new: str) -> Dataset:
    raw = dict(dataset.raw)
    text = strict_text(raw[logical_id], label=logical_id)
    require(old in text, "NCC-SELF-TEST-FIXTURE", f"mutation source text absent: {old}")
    raw[logical_id] = text.replace(old, new, 1).encode("utf-8")
    return load_dataset_from_bytes(raw)


def update_accepted_approval(
    dataset: Dataset,
    mutator: Callable[[dict[str, Any]], None],
    *,
    resign: bool,
) -> Dataset:
    decision = copy.deepcopy(dict(dataset.decision))
    approval = copy.deepcopy(decision["approval"])
    mutator(approval)
    if resign:
        private_key = serialization.load_pem_private_key(
            TEST_PRIVATE_KEY_PEM, password=None
        )
        require(
            isinstance(private_key, Ed25519PrivateKey),
            "NCC-SELF-TEST-KEY",
            "embedded test key is not Ed25519",
        )
        preimage_bytes = canonical_json_bytes(approval_preimage(approval))
        approval["signature_preimage_sha256"] = sha256_bytes(preimage_bytes)
        approval["signature_base64"] = base64.b64encode(
            private_key.sign(preimage_bytes)
        ).decode("ascii")
    decision["approval"] = approval
    raw = dict(dataset.raw)
    raw["decision"] = json_file_bytes(decision)
    raw["adr"] = render_accepted_adr(dataset.text["adr"], approval).encode("utf-8")
    return load_dataset_from_bytes(raw)


def accepted_with_revoked_test_key(dataset: Dataset) -> Dataset:
    private_key = serialization.load_pem_private_key(TEST_PRIVATE_KEY_PEM, password=None)
    require(
        isinstance(private_key, Ed25519PrivateKey),
        "NCC-SELF-TEST-KEY",
        "embedded test key is not Ed25519",
    )
    trust_root = copy.deepcopy(dict(dataset.trust_root))
    trust_root["revocation_epoch"] = 1
    trust_root["revoked_keys"] = [
        {
            "key_id": dataset.decision["approval"]["key_id"],
            "revoked_at_utc": "2026-07-24T12:40:00Z",
            "revocation_epoch": 1,
            "reason": "test-only revocation challenge",
        }
    ]
    for key_record in trust_root["trusted_keys"]:
        enrollment_bytes = canonical_json_bytes(
            enrollment_preimage(key_record, trust_root)
        )
        key_record["enrollment_preimage_sha256"] = sha256_bytes(enrollment_bytes)
        key_record["proof_of_possession_signature_base64"] = base64.b64encode(
            private_key.sign(enrollment_bytes)
        ).decode("ascii")
    decision = copy.deepcopy(dict(dataset.decision))
    decision["approval"]["revocation_epoch"] = 1
    raw = dict(dataset.raw)
    raw["trust_root"] = json_file_bytes(trust_root)
    raw["decision"] = json_file_bytes(decision)
    digest_dataset = load_dataset_from_bytes(raw)
    _, payload_digest = composite_components(digest_dataset)
    approval = decision["approval"]
    approval["approved_payload_sha256"] = payload_digest
    preimage_bytes = canonical_json_bytes(approval_preimage(approval))
    approval["signature_preimage_sha256"] = sha256_bytes(preimage_bytes)
    approval["signature_base64"] = base64.b64encode(
        private_key.sign(preimage_bytes)
    ).decode("ascii")
    raw["decision"] = json_file_bytes(decision)
    raw["adr"] = render_accepted_adr(dataset.text["adr"], approval).encode("utf-8")
    return load_dataset_from_bytes(raw)


def accepted_with_rotated_test_epoch(dataset: Dataset) -> Dataset:
    private_key = serialization.load_pem_private_key(
        TEST_PRIVATE_KEY_PEM,
        password=None,
    )
    require(
        isinstance(private_key, Ed25519PrivateKey),
        "NCC-SELF-TEST-KEY",
        "embedded test key is not Ed25519",
    )
    trust_root = copy.deepcopy(dict(dataset.trust_root))
    trust_root["trust_root_epoch"] += 1
    key_record = trust_root["trusted_keys"][0]
    enrollment_bytes = canonical_json_bytes(
        enrollment_preimage(key_record, trust_root)
    )
    key_record["enrollment_preimage_sha256"] = sha256_bytes(enrollment_bytes)
    key_record["proof_of_possession_signature_base64"] = base64.b64encode(
        private_key.sign(enrollment_bytes)
    ).decode("ascii")
    raw = dict(dataset.raw)
    raw["trust_root"] = json_file_bytes(trust_root)
    return load_dataset_from_bytes(raw)


@dataclass(frozen=True)
class SelfTestCase:
    test_id: str
    scenario_id: str
    expected_code: str | None
    exercise: Callable[[], None]
    mutation_path: str


def expect_direct(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GateFailure(code, message)


def run_self_tests(
    proposed: Dataset,
    *,
    seed: str,
) -> dict[str, Any]:
    accepted, anchor = make_test_accepted_dataset(proposed)
    enrolled_proposed = load_dataset_from_bytes(
        {
            **proposed.raw,
            "trust_root": accepted.raw["trust_root"],
        }
    )

    def validate_proposed(candidate: Dataset = proposed) -> None:
        validate_dataset(candidate, external_anchor=None)

    def validate_accepted(candidate: Dataset = accepted, chosen_anchor: Mapping[str, Any] = anchor) -> None:
        validate_dataset(candidate, external_anchor=chosen_anchor)

    def require_enrollment_changes_payload() -> None:
        before = validate_dataset(
            proposed,
            external_anchor=None,
        )["composite_payload_sha256"]
        after = validate_dataset(
            enrolled_proposed,
            external_anchor=None,
        )["composite_payload_sha256"]
        expect_direct(
            before != after,
            "NCC-SELF-TEST-ENROLLMENT-DIGEST",
            "owner-key enrollment failed to change the signed payload",
        )

    def require_acceptance_state_digest_stability() -> None:
        proposed_digest = validate_dataset(
            enrolled_proposed,
            external_anchor=None,
        )["composite_payload_sha256"]
        accepted_digest = validate_dataset(
            accepted,
            external_anchor=anchor,
        )["composite_payload_sha256"]
        expect_direct(
            proposed_digest == accepted_digest,
            "NCC-SELF-TEST-APPROVAL-DIGEST",
            "normalized acceptance-state writes changed the approved payload",
        )

    def raw_decision_mutation(transform: Callable[[bytes], bytes]) -> Dataset:
        raw = dict(proposed.raw)
        raw["decision"] = transform(raw["decision"])
        return load_dataset_from_bytes(raw)

    cases: list[SelfTestCase] = [
        SelfTestCase(
            "valid-proposed",
            "state/proposed",
            None,
            validate_proposed,
            "none",
        ),
        SelfTestCase(
            "valid-accepted-ed25519",
            "state/accepted",
            None,
            validate_accepted,
            "test-only in-memory accepted fixture",
        ),
        SelfTestCase(
            "valid-proposed-with-enrolled-owner-key",
            "approval/first-enrollment-before-approval",
            None,
            lambda: validate_dataset(
                enrolled_proposed,
                external_anchor=None,
            ),
            "trust_root.status=active;decision.status=proposed",
        ),
        SelfTestCase(
            "owner-enrollment-changes-composite-payload",
            "approval/enrollment-order",
            None,
            require_enrollment_changes_payload,
            "owner_trust_root.json",
        ),
        SelfTestCase(
            "acceptance-state-normalization-preserves-approved-digest",
            "approval/digest-stability",
            None,
            require_acceptance_state_digest_stability,
            "decision.status+approval;adr.marked-regions",
        ),
        SelfTestCase(
            "duplicate-json-key",
            "parser/duplicate-key",
            "NCC-JSON-DUPLICATE-KEY",
            lambda: validate_proposed(
                raw_decision_mutation(
                    lambda data: data.replace(
                        b'"schema_version":',
                        b'"schema_version":"forged","schema_version":',
                        1,
                    )
                )
            ),
            "$.schema_version",
        ),
        SelfTestCase(
            "reject-nan",
            "parser/nonfinite",
            "NCC-JSON-NUMBER",
            lambda: parse_json_bytes(b'{"value":NaN}', label="NaN mutant"),
            "$.value",
        ),
        SelfTestCase(
            "reject-infinity",
            "parser/nonfinite",
            "NCC-JSON-NUMBER",
            lambda: parse_json_bytes(b'{"value":Infinity}', label="Infinity mutant"),
            "$.value",
        ),
        SelfTestCase(
            "reject-float",
            "parser/float",
            "NCC-JSON-NUMBER",
            lambda: parse_json_bytes(b'{"value":0.1}', label="float mutant"),
            "$.value",
        ),
        SelfTestCase(
            "reject-oversize-integer",
            "parser/integer-range",
            "NCC-JSON-INTEGER-RANGE",
            lambda: parse_json_bytes(
                b'{"value":9007199254740992}', label="large integer mutant"
            ),
            "$.value",
        ),
        SelfTestCase(
            "reject-unpaired-surrogate",
            "parser/unicode",
            "NCC-JSON-UNICODE",
            lambda: parse_json_bytes(
                b'{"value":"\\ud800"}', label="surrogate mutant"
            ),
            "$.value",
        ),
        SelfTestCase(
            "implementation-authorized-null",
            "schema/strict-boolean",
            "NCC-AUTHORIZED-TYPE",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value.__setitem__(
                        "implementation_authorized", None
                    ),
                )
            ),
            "$.implementation_authorized",
        ),
        SelfTestCase(
            "implementation-authorized-string",
            "schema/strict-boolean",
            "NCC-AUTHORIZED-TYPE",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value.__setitem__(
                        "implementation_authorized", "false"
                    ),
                )
            ),
            "$.implementation_authorized",
        ),
        SelfTestCase(
            "unknown-nested-backend-field",
            "schema/closed-nested-object",
            "NCC-DECISION-CONTRACT-DRIFT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["selected_backend"].__setitem__(
                        "escape_hatch", True
                    ),
                )
            ),
            "$.selected_backend.escape_hatch",
        ),
        SelfTestCase(
            "enable-jitmodule-production",
            "backend/admission-order",
            "NCC-BACKEND-LOCK",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["selected_backend"].__setitem__(
                        "jitmodule_v1_production_eligible", True
                    ),
                )
            ),
            "$.selected_backend.jitmodule_v1_production_eligible",
        ),
        SelfTestCase(
            "tamper-source-url",
            "sources/url",
            "NCC-DECISION-CONTRACT-DRIFT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["source_locks"][0].__setitem__(
                        "url", "https://example.invalid/forged"
                    ),
                )
            ),
            "$.source_locks[0].url",
        ),
        SelfTestCase(
            "tamper-source-hash",
            "sources/hash",
            "NCC-DECISION-CONTRACT-DRIFT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["source_locks"][0].__setitem__(
                        "sha256", "0" * 64
                    ),
                )
            ),
            "$.source_locks[0].sha256",
        ),
        SelfTestCase(
            "rewrite-source-claim",
            "sources/claim",
            "NCC-DECISION-CONTRACT-DRIFT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["source_claims"][0].__setitem__(
                        "claim", "forged memory-safety claim"
                    ),
                )
            ),
            "$.source_claims[0].claim",
        ),
        SelfTestCase(
            "swap-source-binding",
            "sources/binding",
            "NCC-DECISION-CONTRACT-DRIFT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["source_claims"][0]["bindings"][0].__setitem__(
                        "source_id", value["source_locks"][-1]["id"]
                    ),
                )
            ),
            "$.source_claims[0].bindings[0].source_id",
        ),
        SelfTestCase(
            "remove-platform-control",
            "platform/closed-controls",
            "NCC-DECISION-CONTRACT-DRIFT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["platform_owners"][0][
                        "required_controls"
                    ].pop(),
                )
            ),
            "$.platform_owners[0].required_controls[-1]",
        ),
        SelfTestCase(
            "profile-tcb-string",
            "profiles/tcb-types",
            "NCC-TCB-TYPE",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["execution_profiles"][-1]["claim_tcb"].__setitem__(
                        "parent_survival", "inherit"
                    ),
                )
            ),
            "$.execution_profiles[3].claim_tcb.parent_survival",
        ),
        SelfTestCase(
            "reorder-rco-pipeline",
            "rco/order",
            "NCC-RCO-CONTRACT",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["region_code_object"]["pipeline"].reverse(),
                )
            ),
            "$.region_code_object.pipeline",
        ),
        SelfTestCase(
            "move-unsafe-boundary",
            "ownership/unsafe",
            "NCC-UNSAFE-REPOSITORY",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value["unsafe_boundary"].__setitem__(
                        "allowed_repository", "/dp/franken_engine"
                    ),
                )
            ),
            "$.unsafe_boundary.allowed_repository",
        ),
        SelfTestCase(
            "reverse-dependency",
            "ownership/dependency",
            "NCC-DEPENDENCY-DIRECTION",
            lambda: validate_proposed(
                mutate_decision(
                    proposed,
                    lambda value: value.__setitem__(
                        "dependency_direction",
                        ["franken_engine -> franken_node"],
                    ),
                )
            ),
            "$.dependency_direction",
        ),
        SelfTestCase(
            "stale-plan-marker",
            "documents/plan",
            "NCC-PLAN-DRIFT",
            lambda: validate_proposed(
                mutate_text(proposed, "plan", "NCC-PLAN-0010-V1", "NCC-PLAN-STALE")
            ),
            "plan:NCC-PLAN-0010-V1",
        ),
        SelfTestCase(
            "stale-engine-split-marker",
            "documents/engine-split",
            "NCC-ENGINE-SPLIT-DRIFT",
            lambda: validate_proposed(
                mutate_text(
                    proposed,
                    "engine_split",
                    "NCC-ENGINE-SPLIT-0010-V1",
                    "NCC-ENGINE-SPLIT-STALE",
                )
            ),
            "engine_split:NCC-ENGINE-SPLIT-0010-V1",
        ),
        SelfTestCase(
            "stale-node-split-marker",
            "documents/node-split",
            "NCC-NODE-SPLIT-DRIFT",
            lambda: validate_proposed(
                mutate_text(
                    proposed,
                    "node_split",
                    "NCC-NODE-SPLIT-0010-V1",
                    "NCC-NODE-SPLIT-STALE",
                )
            ),
            "node_split:NCC-NODE-SPLIT-0010-V1",
        ),
        SelfTestCase(
            "adr-state-mismatch",
            "documents/state",
            "NCC-DOCUMENT-STATE",
            lambda: validate_proposed(
                mutate_text(
                    proposed,
                    "adr",
                    "- Status: Proposed — explicit project-owner approval is required",
                    "- Status: Accepted — forged",
                )
            ),
            "adr:approval-state-header",
        ),
        SelfTestCase(
            "accepted-with-unconfigured-root",
            "approval/unconfigured",
            "NCC-TRUST-ROOT-UNCONFIGURED",
            lambda: validate_accepted(
                load_dataset_from_bytes(
                    {**accepted.raw, "trust_root": proposed.raw["trust_root"]}
                )
            ),
            "trust_root.status",
        ),
        SelfTestCase(
            "approval-signature-tamper",
            "approval/signature",
            "NCC-APPROVAL-SIGNATURE",
            lambda: validate_accepted(
                update_accepted_approval(
                    accepted,
                    lambda value: value.__setitem__(
                        "signature_base64",
                        base64.b64encode(b"\\x00" * 64).decode("ascii"),
                    ),
                    resign=False,
                )
            ),
            "$.approval.signature_base64",
        ),
        SelfTestCase(
            "approval-text-tamper",
            "approval/text",
            "NCC-APPROVAL-TEXT",
            lambda: validate_accepted(
                update_accepted_approval(
                    accepted,
                    lambda value: value.__setitem__(
                        "approval_text", value["approval_text"] + "\\nforged"
                    ),
                    resign=False,
                )
            ),
            "$.approval.approval_text",
        ),
        SelfTestCase(
            "approval-payload-tamper",
            "approval/payload",
            "NCC-APPROVAL-PAYLOAD",
            lambda: validate_accepted(
                update_accepted_approval(
                    accepted,
                    lambda value: value.__setitem__(
                        "approved_payload_sha256", "0" * 64
                    ),
                    resign=False,
                )
            ),
            "$.approval.approved_payload_sha256",
        ),
        SelfTestCase(
            "approval-wrong-domain",
            "approval/domain",
            "NCC-APPROVAL-IDENTITY",
            lambda: validate_accepted(
                update_accepted_approval(
                    accepted,
                    lambda value: value.__setitem__(
                        "signature_domain", "forged.domain"
                    ),
                    resign=False,
                )
            ),
            "$.approval.signature_domain",
        ),
        SelfTestCase(
            "approval-stale-epoch",
            "approval/epoch",
            "NCC-APPROVAL-EPOCH",
            lambda: validate_accepted(
                update_accepted_approval(
                    accepted,
                    lambda value: value.__setitem__("trust_root_epoch", 0),
                    resign=True,
                )
            ),
            "$.approval.trust_root_epoch",
        ),
        SelfTestCase(
            "approval-non-distinct-reviewer",
            "approval/reviewer",
            "NCC-APPROVAL-REVIEW",
            lambda: validate_accepted(
                update_accepted_approval(
                    accepted,
                    lambda value: value["producer_distinct_review"].__setitem__(
                        "reviewer_id", value["producer_id"]
                    ),
                    resign=True,
                )
            ),
            "$.approval.producer_distinct_review.reviewer_id",
        ),
        SelfTestCase(
            "approval-wrong-external-anchor",
            "approval/external-anchor",
            "NCC-APPROVAL-WRONG-KEY",
            lambda: validate_accepted(
                accepted,
                {
                    **anchor,
                    "key_id": "test-other-owner-key",
                },
            ),
            "external_anchor.key_id",
        ),
        SelfTestCase(
            "approval-revoked-key",
            "approval/revocation",
            "NCC-APPROVAL-REVOKED-KEY",
            lambda: validate_accepted(accepted_with_revoked_test_key(accepted)),
            "trust_root.revoked_keys",
        ),
        SelfTestCase(
            "approval-prior-payload-after-key-rotation",
            "approval/rotation",
            "NCC-APPROVAL-PAYLOAD",
            lambda: validate_accepted(
                accepted_with_rotated_test_epoch(accepted)
            ),
            "trust_root.trust_root_epoch",
        ),
        SelfTestCase(
            "rust-unsafe-token",
            "repository/unsafe-token",
            None,
            lambda: expect_direct(
                rust_unsafe_token_locations("pub unsafe fn invoke() {}") == [1],
                "NCC-SELF-TEST-UNSAFE-SCANNER",
                "unsafe token scanner missed real code",
            ),
            "fixture.rs:1",
        ),
        SelfTestCase(
            "rust-unsafe-comment-and-string",
            "repository/unsafe-false-positive",
            None,
            lambda: expect_direct(
                rust_unsafe_token_locations(
                    '// unsafe\\nconst S: &str = r#"unsafe { forged() }"#;'
                )
                == [],
                "NCC-SELF-TEST-UNSAFE-SCANNER",
                "unsafe token scanner flagged comment or string",
            ),
            "fixture.rs:comment-and-raw-string",
        ),
        SelfTestCase(
            "rust-unsafe-exact-cfg-test-item",
            "repository/unsafe-test-only",
            None,
            lambda: expect_direct(
                rust_unsafe_token_locations(
                    "#[cfg(test)]\nmod tests {\n"
                    "  fn set_env() { unsafe { std::env::set_var(\"K\", \"V\") }; }\n"
                    "}\n"
                )
                == [],
                "NCC-SELF-TEST-UNSAFE-SCANNER",
                "unsafe scanner treated exact cfg(test) code as shipped code",
            ),
            "fixture.rs:cfg-test-module",
        ),
        SelfTestCase(
            "rust-unsafe-after-cfg-test-item",
            "repository/unsafe-test-boundary",
            None,
            lambda: expect_direct(
                rust_unsafe_token_locations(
                    "#[cfg(test)]\nmod tests { unsafe fn helper() {} }\n"
                    "pub unsafe fn shipped() {}\n"
                )
                == [3],
                "NCC-SELF-TEST-UNSAFE-SCANNER",
                "unsafe scanner swallowed production code after a test-only item",
            ),
            "fixture.rs:3",
        ),
        SelfTestCase(
            "cargo-direct-capsule-dependency",
            "repository/dependency-parser",
            None,
            lambda: expect_direct(
                dependency_mentions_capsule(
                    "native_capsule",
                    {"package": "frankenengine-native-capsule-api"},
                ),
                "NCC-SELF-TEST-CARGO-SCANNER",
                "Cargo dependency scanner missed capsule package",
            ),
            "Cargo.toml:dependencies",
        ),
    ]

    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for sequence, case in enumerate(cases, start=1):
        started = time.monotonic_ns()
        observed_code: str | None = None
        observed_message = "completed without error"
        try:
            case.exercise()
        except GateFailure as exc:
            observed_code = exc.code
            observed_message = exc.message
        except Exception as exc:  # retain unexpected diagnostics without hiding them
            observed_code = "NCC-SELF-TEST-UNEXPECTED-EXCEPTION"
            observed_message = f"{type(exc).__name__}: {exc}"
        duration_ms = max(1, (time.monotonic_ns() - started) // 1_000_000)
        passed = observed_code == case.expected_code
        result = {
            "sequence": sequence,
            "test_id": case.test_id,
            "scenario_id": case.scenario_id,
            "seed": seed,
            "attempt": 1,
            "mutation_path": case.mutation_path,
            "expected_code": case.expected_code,
            "observed_code": observed_code,
            "observed_message": observed_message[:1000],
            "duration_ms": duration_ms,
            "decision": "assertion-pass" if passed else "assertion-fail",
        }
        results.append(result)
        if not passed:
            failures.append(result)
    report = {
        "schema_version": "franken-engine.native-code-capsule-adr-self-test.v2",
        "seed": seed,
        "total": len(results),
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "results": results,
    }
    if failures:
        raise GateFailure(
            "NCC-SELF-TEST-FAILED",
            "one or more validator mutation tests failed",
            report,
        )
    return report


def safe_relative_path(value: str) -> pathlib.PurePosixPath:
    require(
        isinstance(value, str)
        and value
        and "\\" not in value
        and "\x00" not in value,
        "NCC-ARTIFACT-PATH",
        "artifact path is empty or contains forbidden separators",
        value,
    )
    candidate = pathlib.PurePosixPath(value)
    require(
        not candidate.is_absolute()
        and all(part not in {"", ".", ".."} for part in candidate.parts),
        "NCC-ARTIFACT-PATH",
        "artifact path is absolute or traverses the bundle",
        value,
    )
    return candidate


def fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_bytes(path: pathlib.Path, data: bytes, *, mode: int = 0o400) -> None:
    require(
        path.parent.is_dir() and not path.parent.is_symlink(),
        "NCC-ARTIFACT-PARENT",
        "artifact parent is absent or a symlink",
        str(path.parent),
    )
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
    except FileExistsError as exc:
        raise GateFailure(
            "NCC-ARTIFACT-OVERWRITE",
            "evidence publication never overwrites an existing file",
            str(path),
        ) from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def write_new_json(path: pathlib.Path, value: Any, *, mode: int = 0o400) -> None:
    write_new_bytes(path, json_file_bytes(value), mode=mode)


def create_private_directory(path: pathlib.Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise GateFailure(
            "NCC-ARTIFACT-DIRECTORY-EXISTS",
            "evidence directory already exists",
            str(path),
        ) from exc
    os.chmod(path, 0o700)
    fsync_directory(path.parent)


def file_record(root: pathlib.Path, file_path: pathlib.Path) -> dict[str, Any]:
    relative = file_path.relative_to(root).as_posix()
    safe_relative_path(relative)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(file_path, flags)
    except OSError as exc:
        raise GateFailure(
            "NCC-ARTIFACT-OPEN",
            "bundle artifact could not be securely opened",
            {"path": relative, "error": str(exc)},
        ) from exc
    try:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode),
            "NCC-ARTIFACT-NOT-REGULAR",
            "bundle artifacts must be non-symlink regular files",
            relative,
        )
        digest = hashlib.sha256()
        observed_bytes = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            observed_bytes += len(chunk)
        after = os.fstat(descriptor)
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_mode,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_mode,
            )
            and observed_bytes == before.st_size,
            "NCC-ARTIFACT-RACE",
            "bundle artifact changed while it was hashed",
            relative,
        )
    finally:
        os.close(descriptor)
    return {
        "path": relative,
        "sha256": digest.hexdigest(),
        "bytes": before.st_size,
        "mode": stat.S_IMODE(before.st_mode),
    }


def collect_file_records(
    root: pathlib.Path,
    *,
    excluded: set[str] | None = None,
) -> list[dict[str, Any]]:
    excluded_paths = excluded or set()
    records = [
        file_record(root, file_path)
        for file_path in sorted(root.rglob("*"))
        if file_path.is_file()
        and file_path.relative_to(root).as_posix() not in excluded_paths
    ]
    relative_paths = [record["path"] for record in records]
    require(
        len(relative_paths) == len(set(relative_paths)),
        "NCC-ARTIFACT-DUPLICATE",
        "artifact registry contains duplicate paths",
    )
    return records


def command_version(tool_path: str) -> str:
    result = run_bounded(
        [tool_path, "--version"],
        cwd=pathlib.Path.cwd(),
        timeout_seconds=10,
        max_bytes=64 * 1024,
    )
    combined = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    return combined.strip()[:1000]


def environment_record() -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    for tool_name in ("python3", "bash", "cargo", "git", "curl", "openssl"):
        resolved = shutil.which(tool_name)
        if resolved is None:
            tools.append({"name": tool_name, "available": False})
            continue
        tool_path = pathlib.Path(resolved).resolve()
        tools.append(
            {
                "name": tool_name,
                "available": True,
                "path": str(tool_path),
                "sha256": sha256_file(tool_path),
                "version": command_version(str(tool_path)),
            }
        )
    return {
        "schema_version": "franken-engine.native-code-capsule-adr-env.v2",
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version,
        "executable": sys.executable,
        "locale": locale.setlocale(locale.LC_ALL, None),
        "preferred_encoding": locale.getpreferredencoding(False),
        "timezone": list(time.tzname),
        "cpu_count": os.cpu_count(),
        "tools": tools,
    }


def git_output(
    repo: pathlib.Path,
    arguments: Sequence[str],
    *,
    max_bytes: int = 4 * 1024 * 1024,
) -> bytes:
    result = run_bounded(
        ["git", *arguments],
        cwd=repo,
        timeout_seconds=30,
        max_bytes=max_bytes,
    )
    require(
        result.returncode == 0,
        "NCC-GIT-STATE",
        "git state command failed",
        {
            "repo": str(repo),
            "argv": ["git", *arguments],
            "stderr": result.stderr.decode("utf-8", errors="replace")[-2000:],
        },
    )
    return result.stdout


def capture_repository_state(
    repo: pathlib.Path,
    *,
    label: str,
    normative_paths: Sequence[str],
) -> tuple[dict[str, Any], bytes, bytes]:
    commit = git_output(repo, ["rev-parse", "HEAD"], max_bytes=4096).decode().strip()
    branch = git_output(
        repo, ["branch", "--show-current"], max_bytes=4096
    ).decode().strip()
    status_bytes = git_output(
        repo,
        ["status", "--porcelain=v2", "--branch", "--untracked-files=all"],
    )
    diff_bytes = git_output(
        repo,
        ["diff", "--binary", "--", *normative_paths],
    )
    record = {
        "schema_version": "franken-engine.native-code-capsule-repo-state.v2",
        "repository": label,
        "path": str(repo.resolve()),
        "commit": commit,
        "branch": branch,
        "dirty": bool(
            [
                line
                for line in status_bytes.decode("utf-8", errors="strict").splitlines()
                if not line.startswith("#")
            ]
        ),
        "status_sha256": sha256_bytes(status_bytes),
        "status_bytes": len(status_bytes),
        "normative_diff_sha256": sha256_bytes(diff_bytes),
        "normative_diff_bytes": len(diff_bytes),
        "normative_paths": list(normative_paths),
    }
    return record, status_bytes, diff_bytes


def make_events(
    *,
    run_id: str,
    trace_id: str,
    seed: str,
    validation: Mapping[str, Any],
    self_tests: Mapping[str, Any],
    source_receipts: Mapping[str, Any],
    validation_duration_ms: int,
) -> list[dict[str, Any]]:
    common = {
        "schema_version": EVENT_SCHEMA,
        "run_id": run_id,
        "trace_id": trace_id,
        "seed": seed,
        "attempt": 1,
        "source_cutoff": SOURCE_CUTOFF,
        "platform": platform.system().lower() or "unknown",
        "target": platform.machine().lower() or "unknown",
        "tier": "architecture-contract",
        "profile": "adr-approval",
    }
    events: list[dict[str, Any]] = []
    events.append(
        {
            **common,
            "test_id": "real-contract-validation",
            "scenario_id": "current-input-snapshot",
            "phase": "validate",
            "sequence": 1,
            "event": "contract-validation",
            "decision": "validation-pass",
            "reason_code": "NCC-CONTRACT-VALID",
            "duration_ms": max(1, validation_duration_ms),
            "artifact_hashes": validation["input_hashes"],
        }
    )
    for result in self_tests["results"]:
        events.append(
            {
                **common,
                "test_id": result["test_id"],
                "scenario_id": result["scenario_id"],
                "phase": "mutation-test",
                "sequence": len(events) + 1,
                "event": "mutation-assertion",
                "decision": result["decision"],
                "reason_code": result["observed_code"]
                or "NCC-EXPECTED-VALID",
                "duration_ms": result["duration_ms"],
                "artifact_hashes": validation["input_hashes"],
                "mutation_path": result["mutation_path"],
                "expected_code": result["expected_code"],
                "observed_code": result["observed_code"],
                "observed_message": result["observed_message"],
            }
        )
    for receipt in source_receipts.get("receipts", []):
        events.append(
            {
                **common,
                "test_id": f"source-{receipt['source_id']}",
                "scenario_id": "online-source-lock",
                "phase": "source-verification",
                "sequence": len(events) + 1,
                "event": "source-snapshot",
                "decision": "source-verified",
                "reason_code": "NCC-SOURCE-HASH-MATCH",
                "duration_ms": receipt["duration_ms"],
                "artifact_hashes": {
                    "source": receipt["observed_sha256"],
                    **validation["input_hashes"],
                },
                "source_id": receipt["source_id"],
            }
        )
    return events


def validate_events(
    events: Sequence[Mapping[str, Any]],
    *,
    run_id: str,
    trace_id: str,
    seed: str,
    expected_self_test_ids: Sequence[str],
    expected_source_ids: Sequence[str],
) -> None:
    require(bool(events), "NCC-EVENTS-EMPTY", "event stream is empty")
    require(
        [event.get("sequence") for event in events]
        == list(range(1, len(events) + 1)),
        "NCC-EVENT-SEQUENCE",
        "event sequence is not contiguous and monotonic",
    )
    for event in events:
        require(
            event.get("schema_version") == EVENT_SCHEMA
            and event.get("run_id") == run_id
            and event.get("trace_id") == trace_id
            and event.get("seed") == seed
            and event.get("source_cutoff") == SOURCE_CUTOFF
            and type(event.get("duration_ms")) is int
            and event["duration_ms"] >= 1
            and isinstance(event.get("artifact_hashes"), dict),
            "NCC-EVENT-COHERENCE",
            "event identity, timing, or artifact linkage is incoherent",
            event.get("test_id"),
        )
        require(
            event.get("decision")
            in {"validation-pass", "assertion-pass", "source-verified"},
            "NCC-EVENT-FAILURE",
            "event stream contains a failed or unknown decision",
            event.get("test_id"),
        )
    mutation_ids = [
        event["test_id"] for event in events if event.get("phase") == "mutation-test"
    ]
    source_ids = [
        event["source_id"]
        for event in events
        if event.get("phase") == "source-verification"
    ]
    require(
        mutation_ids == list(expected_self_test_ids),
        "NCC-EVENT-TEST-INVENTORY",
        "mutation event inventory is missing, extra, duplicated, or reordered",
    )
    require(
        source_ids == list(expected_source_ids),
        "NCC-EVENT-SOURCE-INVENTORY",
        "source event inventory is missing, extra, duplicated, or reordered",
    )


def ensure_output_root(output_root: pathlib.Path) -> pathlib.Path:
    if output_root.exists():
        require(
            output_root.is_dir() and not output_root.is_symlink(),
            "NCC-OUTPUT-ROOT",
            "output root must be a non-symlink directory",
            str(output_root),
        )
    else:
        output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    resolved = output_root.resolve()
    require(
        resolved != pathlib.Path(resolved.anchor),
        "NCC-OUTPUT-ROOT",
        "filesystem root cannot be used as evidence output",
    )
    return resolved


def candidate_identifier() -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"native-code-capsule-adr-{timestamp}-{uuid.uuid4().hex}"


def create_candidate_bundle(
    paths: InputPaths,
    *,
    output_root: pathlib.Path,
    seed: str,
    require_authorized: bool,
    verify_sources: bool,
    external_anchor_path: pathlib.Path | None,
    argv: Sequence[str],
) -> pathlib.Path:
    require(
        SEED_RE.fullmatch(seed) is not None,
        "NCC-SEED",
        "seed must be 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen",
    )
    dataset = load_dataset(paths)
    if require_authorized:
        require(
            dataset.decision["status"] == "accepted"
            and dataset.decision["implementation_authorized"] is True,
            "NCC-AUTHORIZATION-REQUIRED",
            "authorized mode rejects a proposed decision",
        )
    if dataset.decision["status"] == "accepted":
        require(
            require_authorized,
            "NCC-ACCEPTED-REQUIRES-AUTHORIZED-MODE",
            "accepted decisions must be checked with --require-authorized",
        )
        require(
            verify_sources,
            "NCC-ACCEPTED-SOURCES",
            "accepted closure requires online exact source snapshots",
        )
        require(
            external_anchor_path is not None,
            "NCC-EXTERNAL-ANCHOR-REQUIRED",
            "accepted closure requires --owner-anchor",
        )
    else:
        require(
            not require_authorized,
            "NCC-AUTHORIZATION-REQUIRED",
            "proposed closure cannot run in authorized mode",
        )
        require(
            external_anchor_path is None,
            "NCC-PROPOSED-ANCHOR",
            "proposed closure must not imply an owner anchor or approval",
        )
    external_anchor = (
        load_external_anchor(
            external_anchor_path,
            repo_root=paths.repo_root,
            node_repo=paths.node_repo,
        )
        if external_anchor_path is not None
        else None
    )

    output = ensure_output_root(output_root)
    candidate_dir = output / candidate_identifier()
    create_private_directory(candidate_dir)
    run_id = f"ncc-{uuid.uuid4().hex}"
    trace_id = f"ncc-trace-{uuid.uuid4().hex}"
    started_utc = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        inputs_dir = candidate_dir / "inputs"
        create_private_directory(inputs_dir)
        input_records: list[dict[str, Any]] = []
        for logical_id in COMPOSITE_COMPONENT_ORDER:
            snapshot_name = INPUT_FILENAMES[logical_id]
            snapshot_path = inputs_dir / snapshot_name
            write_new_bytes(snapshot_path, dataset.raw[logical_id])
            input_records.append(
                {
                    "logical_id": logical_id,
                    "source_path": str(paths.logical_paths()[logical_id]),
                    "snapshot_path": f"inputs/{snapshot_name}",
                    "sha256": sha256_bytes(dataset.raw[logical_id]),
                    "bytes": len(dataset.raw[logical_id]),
                }
            )
        write_new_json(
            candidate_dir / "input_manifest.json",
            {
                "schema_version": "franken-engine.native-code-capsule-inputs.v2",
                "inputs": input_records,
            },
        )

        validation_started = time.monotonic_ns()
        validation = validate_dataset(
            dataset,
            external_anchor=external_anchor,
            repo_root=paths.repo_root,
            node_repo=paths.node_repo,
            scan_repositories=True,
        )
        validation_duration_ms = max(
            1, (time.monotonic_ns() - validation_started) // 1_000_000
        )
        write_new_json(candidate_dir / "validation.json", validation)

        self_tests = run_self_tests(dataset, seed=seed)
        write_new_json(candidate_dir / "mutation_results.json", self_tests)

        if verify_sources:
            source_receipts = verify_sources_online(
                dataset.decision,
                snapshot_dir=candidate_dir / "source_snapshots",
            )
        else:
            source_receipts = {
                "schema_version": "franken-engine.native-code-source-snapshots.v1",
                "source_cutoff": SOURCE_CUTOFF,
                "verification_mode": "not-performed",
                "total_bytes": 0,
                "receipts": [],
            }
        write_new_json(candidate_dir / "source_receipts.json", source_receipts)

        events = make_events(
            run_id=run_id,
            trace_id=trace_id,
            seed=seed,
            validation=validation,
            self_tests=self_tests,
            source_receipts=source_receipts,
            validation_duration_ms=validation_duration_ms,
        )
        validate_events(
            events,
            run_id=run_id,
            trace_id=trace_id,
            seed=seed,
            expected_self_test_ids=[
                result["test_id"] for result in self_tests["results"]
            ],
            expected_source_ids=[
                receipt["source_id"] for receipt in source_receipts["receipts"]
            ],
        )
        event_bytes = b"".join(
            canonical_json_bytes(event) + b"\n" for event in events
        )
        write_new_bytes(candidate_dir / "events.jsonl", event_bytes)

        repo_state_dir = candidate_dir / "repo_state"
        create_private_directory(repo_state_dir)
        engine_record, engine_status, engine_diff = capture_repository_state(
            paths.repo_root,
            label="franken_engine",
            normative_paths=[
                "docs/adr/ADR-0010-native-code-capsule-trust-boundary.md",
                "docs/adr/native_code_capsule_decision_v1.json",
                "docs/adr/native_code_capsule_owner_trust_root_v1.json",
                "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md",
                "docs/REPO_SPLIT_CONTRACT.md",
                "scripts/run_native_code_capsule_adr_gate.sh",
                "scripts/native_code_capsule_adr_validator.py",
                "scripts/e2e/native_code_capsule_adr_contract_smoke.sh",
            ],
        )
        node_record, node_status, node_diff = capture_repository_state(
            paths.node_repo,
            label="franken_node",
            normative_paths=["docs/ENGINE_SPLIT_CONTRACT.md"],
        )
        for repo_label, record, status_bytes, diff_bytes in (
            ("engine", engine_record, engine_status, engine_diff),
            ("node", node_record, node_status, node_diff),
        ):
            write_new_json(repo_state_dir / f"{repo_label}.json", record)
            write_new_bytes(repo_state_dir / f"{repo_label}.status.txt", status_bytes)
            write_new_bytes(repo_state_dir / f"{repo_label}.normative.diff", diff_bytes)
        if dataset.decision["status"] == "accepted":
            require(
                not engine_record["dirty"] and not node_record["dirty"],
                "NCC-ACCEPTED-DIRTY-WORKTREE",
                "accepted closure requires clean engine and node repositories",
                {
                    "engine_dirty": engine_record["dirty"],
                    "node_dirty": node_record["dirty"],
                },
            )

        environment = environment_record()
        write_new_json(candidate_dir / "env.json", environment)
        command_record = {
            "schema_version": "franken-engine.native-code-capsule-commands.v2",
            "producer_argv": list(argv),
            "producer_argv_shell": shlex.join(argv),
            "reproduction_argv": [
                "scripts/e2e/native_code_capsule_adr_contract_smoke.sh",
                "--output-root",
                str(output),
                "--seed",
                seed,
                *(["--verify-sources-online"] if verify_sources else []),
                *(["--require-authorized"] if require_authorized else []),
                *(
                    ["--owner-anchor", str(external_anchor_path)]
                    if external_anchor_path is not None
                    else []
                ),
            ],
        }
        write_new_json(candidate_dir / "commands.json", command_record)
        command_lines = [
            shlex.join(command_record["producer_argv"]),
            shlex.join(command_record["reproduction_argv"]),
        ]
        write_new_bytes(
            candidate_dir / "commands.txt",
            ("\n".join(command_lines) + "\n").encode("utf-8"),
        )
        write_new_json(
            candidate_dir / "review_record.json",
            {
                "schema_version": "franken-engine.native-code-capsule-review.v2",
                "decision_status": dataset.decision["status"],
                "implementation_authorized": dataset.decision[
                    "implementation_authorized"
                ],
                "approval_decision": (
                    "authenticated-project-owner-approval"
                    if dataset.decision["status"] == "accepted"
                    else "not-approved"
                ),
                "reviewer": (
                    dataset.decision["approval"]["producer_distinct_review"][
                        "reviewer_id"
                    ]
                    if dataset.decision["status"] == "accepted"
                    else None
                ),
                "external_anchor_spki_sha256": (
                    external_anchor["public_key_spki_sha256"]
                    if external_anchor is not None
                    else None
                ),
            },
        )
        write_new_json(
            candidate_dir / "provenance_graph.json",
            {
                "schema_version": "franken-engine.native-code-capsule-provenance.v2",
                "nodes": [
                    {
                        "id": record["logical_id"],
                        "kind": "normative-input",
                        "sha256": record["sha256"],
                    }
                    for record in input_records
                ]
                + [
                    {
                        "id": "validation",
                        "kind": "derived-check",
                        "sha256": sha256_file(candidate_dir / "validation.json"),
                    },
                    {
                        "id": "mutation-results",
                        "kind": "derived-check",
                        "sha256": sha256_file(candidate_dir / "mutation_results.json"),
                    },
                    {
                        "id": "source-receipts",
                        "kind": "derived-check",
                        "sha256": sha256_file(candidate_dir / "source_receipts.json"),
                    },
                ],
                "edges": [
                    {
                        "from": record["logical_id"],
                        "to": "validation",
                        "relation": "validated-by",
                    }
                    for record in input_records
                ]
                + [
                    {
                        "from": "validation",
                        "to": "mutation-results",
                        "relation": "challenged-by",
                    },
                    {
                        "from": "decision",
                        "to": "source-receipts",
                        "relation": "locks",
                    },
                ],
            },
        )
        legal_text = (
            "# ADR-0010 evidence legal record\n\n"
            f"- Source cutoff: {SOURCE_CUTOFF}\n"
            "- Cranelift/Wasmtime evaluated license: Apache-2.0 WITH LLVM-exception\n"
            "- Research papers and platform documentation remain source inputs; "
            "their inclusion is not redistribution permission or runtime evidence.\n"
            "- Exact retrieved bytes, URLs, digests, kinds, and declared versions "
            "are recorded in source_receipts.json when online verification runs.\n"
            "- No capsule binary, backend implementation, signing entitlement, or "
            "external release is authorized by a proposed-state bundle.\n"
        )
        write_new_bytes(candidate_dir / "LEGAL.md", legal_text.encode("utf-8"))

        pre_lock_records = collect_file_records(candidate_dir)
        write_new_json(
            candidate_dir / "repro.lock",
            {
                "schema_version": "franken-engine.native-code-capsule-repro-lock.v2",
                "artifacts": pre_lock_records,
            },
        )
        artifact_records = collect_file_records(candidate_dir)
        candidate_core = {
            "schema_version": CANDIDATE_SCHEMA,
            "candidate_id": candidate_dir.name,
            "run_id": run_id,
            "trace_id": trace_id,
            "seed": seed,
            "attempt": 1,
            "source_cutoff": SOURCE_CUTOFF,
            "started_at_utc": started_utc,
            "decision_status": dataset.decision["status"],
            "implementation_authorized": dataset.decision[
                "implementation_authorized"
            ],
            "source_verification_mode": source_receipts["verification_mode"],
            "publication_phase": "candidate-awaiting-independent-e2e",
            "complete": False,
            "artifacts": artifact_records,
        }
        candidate_core["candidate_root_sha256"] = sha256_bytes(
            canonical_json_bytes(candidate_core)
        )
        write_new_json(candidate_dir / "generator_manifest.json", candidate_core)
        fsync_directory(candidate_dir)
    except Exception as exc:
        failure = (
            exc
            if isinstance(exc, GateFailure)
            else GateFailure(
                "NCC-CANDIDATE-UNEXPECTED",
                f"{type(exc).__name__}: {exc}",
            )
        )
        failure_path = candidate_dir / "failure.json"
        if not failure_path.exists():
            try:
                write_new_json(
                    failure_path,
                    {
                        "schema_version": "franken-engine.native-code-capsule-candidate-failure.v2",
                        "candidate_id": candidate_dir.name,
                        "run_id": run_id,
                        "trace_id": trace_id,
                        "complete": False,
                        "error": failure.as_dict(),
                    },
                )
            except Exception:
                pass
        raise failure
    return candidate_dir


def load_canonical_json_file(path: pathlib.Path, *, label: str) -> Any:
    raw = read_regular_file(path, label=label)
    value = parse_json_bytes(raw, label=label)
    require(
        raw == json_file_bytes(value),
        "NCC-ARTIFACT-JSON-NONCANONICAL",
        f"{label} is not restricted-canonical JSON with one trailing newline",
        str(path),
    )
    return value


def validate_artifact_record(
    value: Any,
    *,
    code: str = "NCC-ARTIFACT-RECORD",
) -> dict[str, Any]:
    require(isinstance(value, dict), code, "artifact record must be an object")
    require_exact_keys(value, {"path", "sha256", "bytes", "mode"}, code)
    path = value.get("path")
    safe_relative_path(path)
    require(
        isinstance(value.get("sha256"), str)
        and HEX_64_RE.fullmatch(value["sha256"]) is not None
        and type(value.get("bytes")) is int
        and value["bytes"] >= 0
        and type(value.get("mode")) is int
        and value["mode"] == 0o400,
        code,
        "artifact digest, byte count, or sealed mode is invalid",
        path,
    )
    return dict(value)


def validate_artifact_records(
    values: Any,
    *,
    code: str = "NCC-ARTIFACT-REGISTRY",
) -> list[dict[str, Any]]:
    require(isinstance(values, list), code, "artifact registry must be an array")
    records = [
        validate_artifact_record(value, code=code)
        for value in values
    ]
    paths = [record["path"] for record in records]
    require(
        paths == sorted(paths) and len(paths) == len(set(paths)),
        code,
        "artifact paths must be unique and sorted",
        paths,
    )
    return records


def discover_bundle_tree(
    root: pathlib.Path,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    try:
        root_stat = root.lstat()
    except FileNotFoundError as exc:
        raise GateFailure(
            "NCC-CANDIDATE-MISSING",
            "candidate directory does not exist",
            str(root),
        ) from exc
    require(
        stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode),
        "NCC-CANDIDATE-DIRECTORY",
        "candidate must be a non-symlink directory",
        str(root),
    )
    files: dict[str, dict[str, Any]] = {}
    directories: set[str] = set()

    def visit(directory: pathlib.Path, relative_directory: pathlib.PurePosixPath | None) -> None:
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name)
        for entry in ordered:
            relative = (
                pathlib.PurePosixPath(entry.name)
                if relative_directory is None
                else relative_directory / entry.name
            )
            relative_text = relative.as_posix()
            safe_relative_path(relative_text)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except FileNotFoundError as exc:
                raise GateFailure(
                    "NCC-ARTIFACT-RACE",
                    "bundle entry changed during discovery",
                    relative_text,
                ) from exc
            require(
                not stat.S_ISLNK(entry_stat.st_mode),
                "NCC-ARTIFACT-SYMLINK",
                "bundle contains a symlink",
                relative_text,
            )
            if stat.S_ISDIR(entry_stat.st_mode):
                directories.add(relative_text)
                visit(pathlib.Path(entry.path), relative)
            elif stat.S_ISREG(entry_stat.st_mode):
                require(
                    relative_text not in files,
                    "NCC-ARTIFACT-DUPLICATE",
                    "bundle discovery found a duplicate path",
                    relative_text,
                )
                files[relative_text] = file_record(root, pathlib.Path(entry.path))
            else:
                raise GateFailure(
                    "NCC-ARTIFACT-SPECIAL-FILE",
                    "bundle contains a non-regular, non-directory entry",
                    relative_text,
                )

    visit(root, None)
    return files, directories


def artifact_registry_root(records: Sequence[Mapping[str, Any]]) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": "franken-engine.native-code-capsule-artifact-registry.v1",
                "artifacts": [dict(record) for record in records],
            }
        )
    )


def require_registry_matches_tree(
    *,
    expected_records: Sequence[Mapping[str, Any]],
    actual_files: Mapping[str, Mapping[str, Any]],
    allowed_unregistered_files: set[str],
) -> None:
    expected = {record["path"]: dict(record) for record in expected_records}
    actual_paths = set(actual_files)
    wanted_paths = set(expected) | allowed_unregistered_files
    require(
        actual_paths == wanted_paths,
        "NCC-ARTIFACT-CLOSURE",
        "candidate file closure is missing, extra, or duplicated",
        {
            "missing": sorted(wanted_paths - actual_paths),
            "extra": sorted(actual_paths - wanted_paths),
        },
    )
    for path, expected_record in expected.items():
        require(
            dict(actual_files[path]) == expected_record,
            "NCC-ARTIFACT-METADATA",
            "artifact bytes, digest, or mode differ from the registry",
            {
                "path": path,
                "expected": expected_record,
                "observed": actual_files[path],
            },
        )


def validate_generator_manifest(
    manifest: Any,
    *,
    candidate_name: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    require(
        isinstance(manifest, dict),
        "NCC-CANDIDATE-MANIFEST",
        "generator manifest must be an object",
    )
    require_exact_keys(
        manifest,
        {
            "schema_version",
            "candidate_id",
            "run_id",
            "trace_id",
            "seed",
            "attempt",
            "source_cutoff",
            "started_at_utc",
            "decision_status",
            "implementation_authorized",
            "source_verification_mode",
            "publication_phase",
            "complete",
            "artifacts",
            "candidate_root_sha256",
        },
        "NCC-CANDIDATE-MANIFEST",
    )
    require(
        manifest.get("schema_version") == CANDIDATE_SCHEMA
        and manifest.get("candidate_id") == candidate_name
        and isinstance(manifest.get("run_id"), str)
        and manifest["run_id"].startswith("ncc-")
        and isinstance(manifest.get("trace_id"), str)
        and manifest["trace_id"].startswith("ncc-trace-")
        and isinstance(manifest.get("seed"), str)
        and SEED_RE.fullmatch(manifest["seed"]) is not None
        and manifest.get("attempt") == 1
        and manifest.get("source_cutoff") == SOURCE_CUTOFF
        and manifest.get("decision_status") in {"proposed", "accepted"}
        and type(manifest.get("implementation_authorized")) is bool
        and manifest.get("source_verification_mode")
        in {"not-performed", "online-exact-bytes-retained"}
        and manifest.get("publication_phase")
        == "candidate-awaiting-independent-e2e"
        and manifest.get("complete") is False,
        "NCC-CANDIDATE-MANIFEST",
        "generator manifest identity or state is invalid",
    )
    parse_utc(
        manifest.get("started_at_utc"),
        code="NCC-CANDIDATE-MANIFEST",
        label="candidate started_at_utc",
    )
    require(
        manifest["implementation_authorized"]
        is (manifest["decision_status"] == "accepted"),
        "NCC-CANDIDATE-MANIFEST",
        "candidate authorization boolean disagrees with decision status",
    )
    records = validate_artifact_records(manifest.get("artifacts"))
    root_hash = manifest.get("candidate_root_sha256")
    require(
        isinstance(root_hash, str) and HEX_64_RE.fullmatch(root_hash) is not None,
        "NCC-CANDIDATE-ROOT",
        "candidate root digest is invalid",
    )
    core = dict(manifest)
    del core["candidate_root_sha256"]
    require(
        sha256_bytes(canonical_json_bytes(core)) == root_hash,
        "NCC-CANDIDATE-ROOT",
        "candidate root digest does not match the manifest core",
    )
    return dict(manifest), records


def load_candidate_dataset(
    candidate: pathlib.Path,
) -> tuple[Dataset, Mapping[str, Any]]:
    input_manifest = load_canonical_json_file(
        candidate / "input_manifest.json",
        label="candidate input manifest",
    )
    require(
        isinstance(input_manifest, dict),
        "NCC-INPUT-MANIFEST",
        "candidate input manifest must be an object",
    )
    require_exact_keys(
        input_manifest,
        {"schema_version", "inputs"},
        "NCC-INPUT-MANIFEST",
    )
    require(
        input_manifest.get("schema_version")
        == "franken-engine.native-code-capsule-inputs.v2"
        and isinstance(input_manifest.get("inputs"), list)
        and len(input_manifest["inputs"]) == len(COMPOSITE_COMPONENT_ORDER),
        "NCC-INPUT-MANIFEST",
        "candidate input manifest schema or cardinality is invalid",
    )
    raw: dict[str, bytes] = {}
    for expected_id, record in zip(
        COMPOSITE_COMPONENT_ORDER,
        input_manifest["inputs"],
        strict=True,
    ):
        require(
            isinstance(record, dict),
            "NCC-INPUT-MANIFEST",
            "input record must be an object",
        )
        require_exact_keys(
            record,
            {
                "logical_id",
                "source_path",
                "snapshot_path",
                "sha256",
                "bytes",
            },
            "NCC-INPUT-MANIFEST",
        )
        expected_snapshot = f"inputs/{INPUT_FILENAMES[expected_id]}"
        require(
            record.get("logical_id") == expected_id
            and isinstance(record.get("source_path"), str)
            and bool(record["source_path"])
            and record.get("snapshot_path") == expected_snapshot
            and isinstance(record.get("sha256"), str)
            and HEX_64_RE.fullmatch(record["sha256"]) is not None
            and type(record.get("bytes")) is int
            and record["bytes"] >= 0,
            "NCC-INPUT-MANIFEST",
            "input record identity or metadata is invalid",
            expected_id,
        )
        snapshot_path = candidate / safe_relative_path(expected_snapshot)
        snapshot = read_regular_file(snapshot_path, label=f"snapshot {expected_id}")
        require(
            len(snapshot) == record["bytes"]
            and sha256_bytes(snapshot) == record["sha256"],
            "NCC-INPUT-SNAPSHOT",
            "input snapshot bytes do not match the input manifest",
            expected_id,
        )
        raw[expected_id] = snapshot
    return load_dataset_from_bytes(raw), input_manifest


def validate_repro_lock(
    candidate: pathlib.Path,
    generator_records: Sequence[Mapping[str, Any]],
) -> None:
    repro_lock = load_canonical_json_file(
        candidate / "repro.lock",
        label="candidate reproduction lock",
    )
    require(
        isinstance(repro_lock, dict),
        "NCC-REPRO-LOCK",
        "reproduction lock must be an object",
    )
    require_exact_keys(
        repro_lock,
        {"schema_version", "artifacts"},
        "NCC-REPRO-LOCK",
    )
    lock_records = validate_artifact_records(
        repro_lock.get("artifacts"),
        code="NCC-REPRO-LOCK",
    )
    expected = [
        dict(record)
        for record in generator_records
        if record["path"] != "repro.lock"
    ]
    require(
        lock_records == expected
        and repro_lock.get("schema_version")
        == "franken-engine.native-code-capsule-repro-lock.v2",
        "NCC-REPRO-LOCK",
        "reproduction lock is stale, reordered, or incomplete",
    )


def load_events(path: pathlib.Path) -> list[Mapping[str, Any]]:
    raw = read_regular_file(path, label="candidate event stream")
    require(
        raw.endswith(b"\n") and raw != b"\n",
        "NCC-EVENT-FORMAT",
        "event stream must be non-empty and newline terminated",
    )
    lines = raw.splitlines(keepends=True)
    events: list[Mapping[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        require(
            line not in {b"", b"\n"},
            "NCC-EVENT-FORMAT",
            "event stream contains a blank line",
            index,
        )
        value = parse_json_bytes(line[:-1], label=f"event line {index}")
        require(
            isinstance(value, dict)
            and line == canonical_json_bytes(value) + b"\n",
            "NCC-EVENT-FORMAT",
            "event line is not restricted-canonical JSON",
            index,
        )
        events.append(value)
    return events


def validate_self_test_report(report: Any, *, seed: str) -> list[Mapping[str, Any]]:
    require(
        isinstance(report, dict),
        "NCC-SELF-TEST-REPORT",
        "self-test report must be an object",
    )
    require_exact_keys(
        report,
        {"schema_version", "seed", "total", "passed", "failed", "results"},
        "NCC-SELF-TEST-REPORT",
    )
    require(
        report.get("schema_version")
        == "franken-engine.native-code-capsule-adr-self-test.v2"
        and report.get("seed") == seed
        and type(report.get("total")) is int
        and type(report.get("passed")) is int
        and type(report.get("failed")) is int
        and isinstance(report.get("results"), list)
        and report["total"] == len(report["results"])
        and report["passed"] == report["total"]
        and report["failed"] == 0,
        "NCC-SELF-TEST-REPORT",
        "self-test summary is inconsistent or contains failures",
    )
    test_ids: list[str] = []
    for sequence, result in enumerate(report["results"], start=1):
        require(
            isinstance(result, dict),
            "NCC-SELF-TEST-REPORT",
            "self-test result must be an object",
        )
        require_exact_keys(
            result,
            {
                "sequence",
                "test_id",
                "scenario_id",
                "seed",
                "attempt",
                "mutation_path",
                "expected_code",
                "observed_code",
                "observed_message",
                "duration_ms",
                "decision",
            },
            "NCC-SELF-TEST-REPORT",
        )
        require(
            result.get("sequence") == sequence
            and isinstance(result.get("test_id"), str)
            and bool(result["test_id"])
            and isinstance(result.get("scenario_id"), str)
            and bool(result["scenario_id"])
            and result.get("seed") == seed
            and result.get("attempt") == 1
            and isinstance(result.get("mutation_path"), str)
            and (
                result.get("expected_code") is None
                or isinstance(result.get("expected_code"), str)
            )
            and (
                result.get("observed_code") is None
                or isinstance(result.get("observed_code"), str)
            )
            and isinstance(result.get("observed_message"), str)
            and type(result.get("duration_ms")) is int
            and result["duration_ms"] >= 1
            and result.get("decision") == "assertion-pass"
            and result.get("expected_code") == result.get("observed_code"),
            "NCC-SELF-TEST-REPORT",
            "self-test result identity, timing, or assertion is invalid",
            result.get("test_id"),
        )
        test_ids.append(result["test_id"])
    require(
        len(test_ids) == len(set(test_ids)),
        "NCC-SELF-TEST-REPORT",
        "self-test IDs must be unique",
    )
    return list(report["results"])


def normalized_self_test_report(report: Mapping[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(dict(report))
    for result in normalized["results"]:
        result["duration_ms"] = 1
    return normalized


def validate_event_details(
    events: Sequence[Mapping[str, Any]],
    *,
    manifest: Mapping[str, Any],
    validation: Mapping[str, Any],
    self_tests: Mapping[str, Any],
    source_receipts: Mapping[str, Any],
) -> None:
    self_test_results = validate_self_test_report(
        self_tests,
        seed=manifest["seed"],
    )
    validate_events(
        events,
        run_id=manifest["run_id"],
        trace_id=manifest["trace_id"],
        seed=manifest["seed"],
        expected_self_test_ids=[
            result["test_id"] for result in self_test_results
        ],
        expected_source_ids=[
            receipt["source_id"] for receipt in source_receipts["receipts"]
        ],
    )
    input_hashes = validation.get("input_hashes")
    require(
        isinstance(input_hashes, dict),
        "NCC-EVENT-DETAILS",
        "validation input hashes are missing",
    )
    expected_common_keys = {
        "schema_version",
        "run_id",
        "trace_id",
        "seed",
        "attempt",
        "source_cutoff",
        "platform",
        "target",
        "tier",
        "profile",
        "test_id",
        "scenario_id",
        "phase",
        "sequence",
        "event",
        "decision",
        "reason_code",
        "duration_ms",
        "artifact_hashes",
    }
    for event in events:
        phase = event.get("phase")
        phase_keys = set(expected_common_keys)
        if phase == "mutation-test":
            phase_keys |= {
                "mutation_path",
                "expected_code",
                "observed_code",
                "observed_message",
            }
        elif phase == "source-verification":
            phase_keys.add("source_id")
        elif phase != "validate":
            raise GateFailure(
                "NCC-EVENT-DETAILS",
                "event phase is unknown",
                phase,
            )
        require_exact_keys(event, phase_keys, "NCC-EVENT-DETAILS")
        require(
            event.get("attempt") == 1
            and isinstance(event.get("platform"), str)
            and bool(event["platform"])
            and event.get("platform") == events[0].get("platform")
            and isinstance(event.get("target"), str)
            and bool(event["target"])
            and event.get("target") == events[0].get("target")
            and event.get("tier") == "architecture-contract"
            and event.get("profile") == "adr-approval",
            "NCC-EVENT-DETAILS",
            "event execution context is invalid",
            event.get("test_id"),
        )
    validation_event = events[0]
    require(
        validation_event.get("test_id") == "real-contract-validation"
        and validation_event.get("scenario_id") == "current-input-snapshot"
        and validation_event.get("phase") == "validate"
        and validation_event.get("event") == "contract-validation"
        and validation_event.get("decision") == "validation-pass"
        and validation_event.get("reason_code") == "NCC-CONTRACT-VALID"
        and validation_event.get("artifact_hashes") == input_hashes,
        "NCC-EVENT-DETAILS",
        "contract-validation event does not bind the validated input snapshot",
    )
    mutation_events = [
        event for event in events if event.get("phase") == "mutation-test"
    ]
    for event, result in zip(mutation_events, self_test_results, strict=True):
        require(
            event.get("scenario_id") == result["scenario_id"]
            and event.get("event") == "mutation-assertion"
            and event.get("decision") == result["decision"]
            and event.get("reason_code")
            == (result["observed_code"] or "NCC-EXPECTED-VALID")
            and event.get("duration_ms") == result["duration_ms"]
            and event.get("artifact_hashes") == input_hashes
            and event.get("mutation_path") == result["mutation_path"]
            and event.get("expected_code") == result["expected_code"]
            and event.get("observed_code") == result["observed_code"]
            and event.get("observed_message") == result["observed_message"],
            "NCC-EVENT-DETAILS",
            "mutation event and self-test report disagree",
            result["test_id"],
        )
    source_events = [
        event for event in events if event.get("phase") == "source-verification"
    ]
    for event, receipt in zip(
        source_events,
        source_receipts["receipts"],
        strict=True,
    ):
        require(
            event.get("test_id") == f"source-{receipt['source_id']}"
            and event.get("scenario_id") == "online-source-lock"
            and event.get("event") == "source-snapshot"
            and event.get("decision") == "source-verified"
            and event.get("reason_code") == "NCC-SOURCE-HASH-MATCH"
            and event.get("duration_ms") == receipt["duration_ms"]
            and event.get("artifact_hashes")
            == {"source": receipt["observed_sha256"], **input_hashes},
            "NCC-EVENT-DETAILS",
            "source event and retained source receipt disagree",
            receipt["source_id"],
        )


def validate_source_receipts(
    candidate: pathlib.Path,
    *,
    decision: Mapping[str, Any],
    recorded: Any,
    expected_mode: str,
) -> list[Mapping[str, Any]]:
    require(
        isinstance(recorded, dict),
        "NCC-SOURCE-RECEIPTS",
        "source receipt report must be an object",
    )
    require_exact_keys(
        recorded,
        {
            "schema_version",
            "source_cutoff",
            "verification_mode",
            "total_bytes",
            "receipts",
        },
        "NCC-SOURCE-RECEIPTS",
    )
    require(
        recorded.get("schema_version")
        == "franken-engine.native-code-source-snapshots.v1"
        and recorded.get("source_cutoff") == SOURCE_CUTOFF
        and recorded.get("verification_mode") == expected_mode
        and type(recorded.get("total_bytes")) is int
        and recorded["total_bytes"] >= 0
        and isinstance(recorded.get("receipts"), list),
        "NCC-SOURCE-RECEIPTS",
        "source receipt summary is invalid",
    )
    if expected_mode == "not-performed":
        require(
            recorded["total_bytes"] == 0 and recorded["receipts"] == [],
            "NCC-SOURCE-RECEIPTS",
            "not-performed source verification cannot retain receipts",
        )
        return []
    specs = online_source_specs(decision)
    require(
        len(recorded["receipts"]) == len(specs),
        "NCC-SOURCE-RECEIPTS",
        "source receipt inventory is incomplete or has extras",
    )
    total = 0
    for index, (receipt, spec) in enumerate(
        zip(recorded["receipts"], specs, strict=True),
        start=1,
    ):
        require(
            isinstance(receipt, dict),
            "NCC-SOURCE-RECEIPTS",
            "source receipt must be an object",
        )
        require_exact_keys(
            receipt,
            {
                "source_id",
                "kind",
                "url",
                "sha256",
                "requested_url",
                "final_url",
                "http_status",
                "content_type",
                "etag",
                "last_modified",
                "duration_ms",
                "snapshot_path",
                "bytes",
                "observed_sha256",
                "decision",
            },
            "NCC-SOURCE-RECEIPTS",
        )
        expected_path = f"source_snapshots/{index:03d}-{spec['source_id']}.bin"
        requested_url = urllib.parse.urlsplit(spec["url"])
        final_url_value = receipt.get("final_url")
        final_url = (
            urllib.parse.urlsplit(final_url_value)
            if isinstance(final_url_value, str)
            else urllib.parse.SplitResult("", "", "", "", "")
        )
        require(
            {key: receipt.get(key) for key in ("source_id", "kind", "url", "sha256")}
            == spec
            and receipt.get("requested_url") == spec["url"]
            and final_url.scheme.lower() == requested_url.scheme.lower() == "https"
            and (final_url.hostname or "").lower()
            == (requested_url.hostname or "").lower()
            and final_url.port == requested_url.port
            and receipt.get("http_status") == 200
            and (
                receipt.get("content_type") is None
                or isinstance(receipt.get("content_type"), str)
            )
            and (
                receipt.get("etag") is None
                or isinstance(receipt.get("etag"), str)
            )
            and (
                receipt.get("last_modified") is None
                or isinstance(receipt.get("last_modified"), str)
            )
            and type(receipt.get("duration_ms")) is int
            and receipt["duration_ms"] >= 1
            and receipt.get("snapshot_path") == expected_path
            and type(receipt.get("bytes")) is int
            and receipt["bytes"] >= 0
            and receipt.get("observed_sha256") == spec["sha256"]
            and receipt.get("decision") == "verified",
            "NCC-SOURCE-RECEIPTS",
            "source receipt identity, transport, or lock binding is invalid",
            spec["source_id"],
        )
        snapshot_path = candidate / safe_relative_path(expected_path)
        snapshot_record = file_record(candidate, snapshot_path)
        require(
            snapshot_record["bytes"] == receipt["bytes"]
            and snapshot_record["sha256"] == receipt["observed_sha256"]
            and snapshot_record["mode"] == 0o400,
            "NCC-SOURCE-SNAPSHOT",
            "retained source bytes do not match their receipt",
            spec["source_id"],
        )
        total += receipt["bytes"]
    require(
        total == recorded["total_bytes"] and total <= MAX_TOTAL_SOURCE_BYTES,
        "NCC-SOURCE-RECEIPTS",
        "source receipt aggregate byte count is invalid",
    )
    return list(recorded["receipts"])


def validate_repository_state_snapshot(
    candidate: pathlib.Path,
    *,
    paths: InputPaths,
) -> None:
    specifications = (
        (
            "engine",
            paths.repo_root,
            [
                "docs/adr/ADR-0010-native-code-capsule-trust-boundary.md",
                "docs/adr/native_code_capsule_decision_v1.json",
                "docs/adr/native_code_capsule_owner_trust_root_v1.json",
                "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md",
                "docs/REPO_SPLIT_CONTRACT.md",
                "scripts/run_native_code_capsule_adr_gate.sh",
                "scripts/native_code_capsule_adr_validator.py",
                "scripts/e2e/native_code_capsule_adr_contract_smoke.sh",
            ],
        ),
        (
            "node",
            paths.node_repo,
            ["docs/ENGINE_SPLIT_CONTRACT.md"],
        ),
    )
    for label, repo, normative_paths in specifications:
        recorded = load_canonical_json_file(
            candidate / "repo_state" / f"{label}.json",
            label=f"{label} repository state",
        )
        require(
            isinstance(recorded, dict),
            "NCC-REPOSITORY-STATE",
            "repository-state record must be an object",
        )
        require_exact_keys(
            recorded,
            {
                "schema_version",
                "repository",
                "path",
                "commit",
                "branch",
                "dirty",
                "status_sha256",
                "status_bytes",
                "normative_diff_sha256",
                "normative_diff_bytes",
                "normative_paths",
            },
            "NCC-REPOSITORY-STATE",
        )
        status_path = candidate / "repo_state" / f"{label}.status.txt"
        diff_path = candidate / "repo_state" / f"{label}.normative.diff"
        recorded_status = read_regular_file(
            status_path,
            label=f"{label} recorded git status",
        )
        recorded_diff = read_regular_file(
            diff_path,
            label=f"{label} recorded normative diff",
        )
        require(
            recorded.get("schema_version")
            == "franken-engine.native-code-capsule-repo-state.v2"
            and recorded.get("repository")
            == ("franken_engine" if label == "engine" else "franken_node")
            and recorded.get("path") == str(repo.resolve())
            and isinstance(recorded.get("commit"), str)
            and GIT_OID_RE.fullmatch(recorded["commit"]) is not None
            and isinstance(recorded.get("branch"), str)
            and recorded["branch"] == "main"
            and type(recorded.get("dirty")) is bool
            and recorded.get("status_sha256") == sha256_bytes(recorded_status)
            and recorded.get("status_bytes") == len(recorded_status)
            and recorded.get("normative_diff_sha256") == sha256_bytes(recorded_diff)
            and recorded.get("normative_diff_bytes") == len(recorded_diff)
            and recorded.get("normative_paths") == normative_paths,
            "NCC-REPOSITORY-STATE",
            "recorded repository identity, branch, or byte evidence is invalid",
            label,
        )
        observed, observed_status, observed_diff = capture_repository_state(
            repo,
            label=recorded["repository"],
            normative_paths=normative_paths,
        )
        require(
            observed == recorded
            and observed_status == recorded_status
            and observed_diff == recorded_diff,
            "NCC-REPOSITORY-STATE-CHANGED",
            "repository state changed between candidate production and E2E verification",
            {
                "repository": label,
                "recorded": recorded,
                "observed": observed,
            },
        )


def validate_live_inputs_match_snapshot(
    *,
    paths: InputPaths,
    dataset: Dataset,
) -> None:
    for logical_id, live_path in paths.logical_paths().items():
        observed = read_regular_file(live_path, label=f"live {logical_id}")
        require(
            observed == dataset.raw[logical_id],
            "NCC-LIVE-INPUT-CHANGED",
            "normative input changed after candidate snapshot",
            {
                "logical_id": logical_id,
                "live_path": str(live_path),
                "snapshot_sha256": sha256_bytes(dataset.raw[logical_id]),
                "live_sha256": sha256_bytes(observed),
            },
        )


def verify_registry_fixture(
    records: Sequence[Mapping[str, Any]],
    actual: Mapping[str, Mapping[str, Any]],
) -> None:
    validated = validate_artifact_records(
        list(records),
        code="NCC-E2E-MUTATION",
    )
    require_registry_matches_tree(
        expected_records=validated,
        actual_files=actual,
        allowed_unregistered_files=set(),
    )


@dataclass(frozen=True)
class E2EMutationCase:
    test_id: str
    expected_code: str
    exercise: Callable[[], None]
    mutation_path: str


def run_e2e_mutation_tests(*, seed: str) -> dict[str, Any]:
    original_bytes = b"alpha\n"
    original_record = {
        "path": "inputs/alpha.txt",
        "sha256": sha256_bytes(original_bytes),
        "bytes": len(original_bytes),
        "mode": 0o400,
    }
    original_actual = {"inputs/alpha.txt": dict(original_record)}
    base_event = {
        "schema_version": EVENT_SCHEMA,
        "run_id": "ncc-fixture-run",
        "trace_id": "ncc-trace-fixture",
        "seed": seed,
        "attempt": 1,
        "source_cutoff": SOURCE_CUTOFF,
        "platform": platform.system().lower() or "unknown",
        "target": platform.machine().lower() or "unknown",
        "tier": "architecture-contract",
        "profile": "adr-approval",
        "test_id": "real-contract-validation",
        "scenario_id": "current-input-snapshot",
        "phase": "validate",
        "sequence": 1,
        "event": "contract-validation",
        "decision": "validation-pass",
        "reason_code": "NCC-CONTRACT-VALID",
        "duration_ms": 1,
        "artifact_hashes": {"decision": "0" * 64},
    }
    cases = [
        E2EMutationCase(
            "bundle-valid-fixture",
            "",
            lambda: verify_registry_fixture([original_record], original_actual),
            "fixture",
        ),
        E2EMutationCase(
            "bundle-duplicate-record",
            "NCC-E2E-MUTATION",
            lambda: verify_registry_fixture(
                [original_record, original_record],
                original_actual,
            ),
            "$.artifacts[1].path",
        ),
        E2EMutationCase(
            "bundle-path-traversal",
            "NCC-ARTIFACT-PATH",
            lambda: verify_registry_fixture(
                [{**original_record, "path": "../escape"}],
                {"../escape": {**original_record, "path": "../escape"}},
            ),
            "$.artifacts[0].path",
        ),
        E2EMutationCase(
            "bundle-unknown-extra-file",
            "NCC-ARTIFACT-CLOSURE",
            lambda: verify_registry_fixture(
                [original_record],
                {
                    **original_actual,
                    "unknown.txt": {
                        "path": "unknown.txt",
                        "sha256": "1" * 64,
                        "bytes": 1,
                        "mode": 0o400,
                    },
                },
            ),
            "unknown.txt",
        ),
        E2EMutationCase(
            "bundle-missing-file",
            "NCC-ARTIFACT-CLOSURE",
            lambda: verify_registry_fixture([original_record], {}),
            "inputs/alpha.txt",
        ),
        E2EMutationCase(
            "bundle-hash-rewrite",
            "NCC-ARTIFACT-METADATA",
            lambda: verify_registry_fixture(
                [{**original_record, "sha256": "2" * 64}],
                original_actual,
            ),
            "$.artifacts[0].sha256",
        ),
        E2EMutationCase(
            "bundle-byte-rewrite",
            "NCC-ARTIFACT-METADATA",
            lambda: verify_registry_fixture(
                [original_record],
                {
                    "inputs/alpha.txt": {
                        **original_record,
                        "sha256": sha256_bytes(b"beta\n"),
                    }
                },
            ),
            "inputs/alpha.txt",
        ),
        E2EMutationCase(
            "event-missing-validation",
            "NCC-EVENTS-EMPTY",
            lambda: validate_events(
                [],
                run_id="ncc-fixture-run",
                trace_id="ncc-trace-fixture",
                seed=seed,
                expected_self_test_ids=[],
                expected_source_ids=[],
            ),
            "events.jsonl",
        ),
        E2EMutationCase(
            "event-sequence-gap",
            "NCC-EVENT-SEQUENCE",
            lambda: validate_events(
                [{**base_event, "sequence": 2}],
                run_id="ncc-fixture-run",
                trace_id="ncc-trace-fixture",
                seed=seed,
                expected_self_test_ids=[],
                expected_source_ids=[],
            ),
            "$.sequence",
        ),
        E2EMutationCase(
            "event-run-id-rewrite",
            "NCC-EVENT-COHERENCE",
            lambda: validate_events(
                [{**base_event, "run_id": "ncc-forged"}],
                run_id="ncc-fixture-run",
                trace_id="ncc-trace-fixture",
                seed=seed,
                expected_self_test_ids=[],
                expected_source_ids=[],
            ),
            "$.run_id",
        ),
    ]
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for sequence, case in enumerate(cases, start=1):
        started = time.monotonic_ns()
        observed_code = ""
        observed_message = "completed without error"
        try:
            case.exercise()
        except GateFailure as exc:
            observed_code = exc.code
            observed_message = exc.message
        except Exception as exc:
            observed_code = "NCC-E2E-MUTATION-UNEXPECTED"
            observed_message = f"{type(exc).__name__}: {exc}"
        duration_ms = max(1, (time.monotonic_ns() - started) // 1_000_000)
        passed = observed_code == case.expected_code
        result = {
            "sequence": sequence,
            "test_id": case.test_id,
            "seed": seed,
            "attempt": 1,
            "mutation_path": case.mutation_path,
            "expected_code": case.expected_code,
            "observed_code": observed_code,
            "observed_message": observed_message[:1000],
            "duration_ms": duration_ms,
            "decision": "assertion-pass" if passed else "assertion-fail",
        }
        results.append(result)
        if not passed:
            failures.append(result)
    report = {
        "schema_version": "franken-engine.native-code-capsule-e2e-mutations.v1",
        "seed": seed,
        "total": len(results),
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "results": results,
    }
    if failures:
        raise GateFailure(
            "NCC-E2E-MUTATIONS-FAILED",
            "independent bundle-verifier mutation suite failed",
            report,
        )
    return report


def validate_auxiliary_evidence(
    candidate: pathlib.Path,
    *,
    dataset: Dataset,
    input_manifest: Mapping[str, Any],
    validation: Mapping[str, Any],
    self_tests: Mapping[str, Any],
    source_receipts: Mapping[str, Any],
    external_anchor: Mapping[str, Any] | None,
) -> None:
    commands = load_canonical_json_file(
        candidate / "commands.json",
        label="candidate command record",
    )
    require(
        isinstance(commands, dict),
        "NCC-COMMAND-RECORD",
        "command record must be an object",
    )
    require_exact_keys(
        commands,
        {
            "schema_version",
            "producer_argv",
            "producer_argv_shell",
            "reproduction_argv",
        },
        "NCC-COMMAND-RECORD",
    )
    producer_argv = commands.get("producer_argv")
    reproduction_argv = commands.get("reproduction_argv")
    require(
        commands.get("schema_version")
        == "franken-engine.native-code-capsule-commands.v2"
        and isinstance(producer_argv, list)
        and bool(producer_argv)
        and all(isinstance(value, str) and "\x00" not in value for value in producer_argv)
        and isinstance(reproduction_argv, list)
        and bool(reproduction_argv)
        and all(
            isinstance(value, str) and "\x00" not in value
            for value in reproduction_argv
        )
        and commands.get("producer_argv_shell") == shlex.join(producer_argv),
        "NCC-COMMAND-RECORD",
        "command record argv or shell rendering is invalid",
    )
    expected_commands_text = (
        shlex.join(producer_argv)
        + "\n"
        + shlex.join(reproduction_argv)
        + "\n"
    ).encode("utf-8")
    require(
        read_regular_file(
            candidate / "commands.txt",
            label="candidate command transcript",
        )
        == expected_commands_text,
        "NCC-COMMAND-RECORD",
        "command transcript disagrees with the structured argv record",
    )

    review = load_canonical_json_file(
        candidate / "review_record.json",
        label="candidate review record",
    )
    require(
        isinstance(review, dict),
        "NCC-REVIEW-RECORD",
        "review record must be an object",
    )
    require_exact_keys(
        review,
        {
            "schema_version",
            "decision_status",
            "implementation_authorized",
            "approval_decision",
            "reviewer",
            "external_anchor_spki_sha256",
        },
        "NCC-REVIEW-RECORD",
    )
    expected_accepted = dataset.decision["status"] == "accepted"
    require(
        review.get("schema_version")
        == "franken-engine.native-code-capsule-review.v2"
        and review.get("decision_status") == dataset.decision["status"]
        and review.get("implementation_authorized") is expected_accepted
        and review.get("approval_decision")
        == (
            "authenticated-project-owner-approval"
            if expected_accepted
            else "not-approved"
        )
        and review.get("reviewer")
        == (
            dataset.decision["approval"]["producer_distinct_review"]["reviewer_id"]
            if expected_accepted
            else None
        )
        and review.get("external_anchor_spki_sha256")
        == (
            external_anchor["public_key_spki_sha256"]
            if external_anchor is not None
            else None
        ),
        "NCC-REVIEW-RECORD",
        "review record disagrees with authenticated decision state",
    )

    provenance = load_canonical_json_file(
        candidate / "provenance_graph.json",
        label="candidate provenance graph",
    )
    expected_nodes = [
        {
            "id": record["logical_id"],
            "kind": "normative-input",
            "sha256": record["sha256"],
        }
        for record in input_manifest["inputs"]
    ] + [
        {
            "id": "validation",
            "kind": "derived-check",
            "sha256": sha256_file(candidate / "validation.json"),
        },
        {
            "id": "mutation-results",
            "kind": "derived-check",
            "sha256": sha256_file(candidate / "mutation_results.json"),
        },
        {
            "id": "source-receipts",
            "kind": "derived-check",
            "sha256": sha256_file(candidate / "source_receipts.json"),
        },
    ]
    expected_edges = [
        {
            "from": record["logical_id"],
            "to": "validation",
            "relation": "validated-by",
        }
        for record in input_manifest["inputs"]
    ] + [
        {
            "from": "validation",
            "to": "mutation-results",
            "relation": "challenged-by",
        },
        {
            "from": "decision",
            "to": "source-receipts",
            "relation": "locks",
        },
    ]
    require(
        provenance
        == {
            "schema_version": "franken-engine.native-code-capsule-provenance.v2",
            "nodes": expected_nodes,
            "edges": expected_edges,
        },
        "NCC-PROVENANCE-GRAPH",
        "provenance graph is stale, reordered, or incomplete",
    )

    environment = load_canonical_json_file(
        candidate / "env.json",
        label="candidate environment record",
    )
    require(
        isinstance(environment, dict),
        "NCC-ENVIRONMENT",
        "environment record must be an object",
    )
    require_exact_keys(
        environment,
        {
            "schema_version",
            "platform",
            "system",
            "release",
            "machine",
            "processor",
            "python",
            "executable",
            "locale",
            "preferred_encoding",
            "timezone",
            "cpu_count",
            "tools",
        },
        "NCC-ENVIRONMENT",
    )
    require(
        environment.get("schema_version")
        == "franken-engine.native-code-capsule-adr-env.v2"
        and isinstance(environment.get("platform"), str)
        and isinstance(environment.get("system"), str)
        and isinstance(environment.get("release"), str)
        and isinstance(environment.get("machine"), str)
        and isinstance(environment.get("processor"), str)
        and isinstance(environment.get("python"), str)
        and isinstance(environment.get("executable"), str)
        and isinstance(environment.get("locale"), str)
        and isinstance(environment.get("preferred_encoding"), str)
        and isinstance(environment.get("timezone"), list)
        and all(isinstance(value, str) for value in environment["timezone"])
        and (
            environment.get("cpu_count") is None
            or (
                type(environment.get("cpu_count")) is int
                and environment["cpu_count"] > 0
            )
        )
        and isinstance(environment.get("tools"), list),
        "NCC-ENVIRONMENT",
        "environment record types are invalid",
    )
    expected_tool_names = ["python3", "bash", "cargo", "git", "curl", "openssl"]
    require(
        [tool.get("name") for tool in environment["tools"] if isinstance(tool, dict)]
        == expected_tool_names,
        "NCC-ENVIRONMENT",
        "environment tool inventory is missing, extra, or reordered",
    )
    for tool in environment["tools"]:
        require(
            isinstance(tool, dict)
            and type(tool.get("available")) is bool,
            "NCC-ENVIRONMENT",
            "tool record is malformed",
        )
        if tool["available"]:
            require_exact_keys(
                tool,
                {"name", "available", "path", "sha256", "version"},
                "NCC-ENVIRONMENT",
            )
            tool_path = pathlib.Path(tool["path"])
            require(
                tool_path.is_absolute()
                and isinstance(tool.get("version"), str)
                and isinstance(tool.get("sha256"), str)
                and HEX_64_RE.fullmatch(tool["sha256"]) is not None
                and sha256_file(tool_path) == tool["sha256"],
                "NCC-ENVIRONMENT-TOOL-CHANGED",
                "recorded tool binary is missing or changed before E2E",
                tool.get("name"),
            )
        else:
            require_exact_keys(
                tool,
                {"name", "available"},
                "NCC-ENVIRONMENT",
            )

    expected_legal = (
        "# ADR-0010 evidence legal record\n\n"
        f"- Source cutoff: {SOURCE_CUTOFF}\n"
        "- Cranelift/Wasmtime evaluated license: Apache-2.0 WITH LLVM-exception\n"
        "- Research papers and platform documentation remain source inputs; "
        "their inclusion is not redistribution permission or runtime evidence.\n"
        "- Exact retrieved bytes, URLs, digests, kinds, and declared versions "
        "are recorded in source_receipts.json when online verification runs.\n"
        "- No capsule binary, backend implementation, signing entitlement, or "
        "external release is authorized by a proposed-state bundle.\n"
    ).encode("utf-8")
    require(
        read_regular_file(candidate / "LEGAL.md", label="candidate legal record")
        == expected_legal,
        "NCC-LEGAL-RECORD",
        "legal/source-use record is missing or altered",
    )

    require(
        validation.get("input_hashes")
        == {
            logical_id: sha256_bytes(data)
            for logical_id, data in sorted(dataset.raw.items())
        },
        "NCC-VALIDATION-INPUTS",
        "validation record does not bind every normative input",
    )
    validate_self_test_report(
        self_tests,
        seed=self_tests.get("seed") if isinstance(self_tests, dict) else "",
    )
    validate_source_receipts(
        candidate,
        decision=dataset.decision,
        recorded=source_receipts,
        expected_mode=source_receipts["verification_mode"],
    )


def seal_candidate_tree(candidate: pathlib.Path) -> None:
    files, directories = discover_bundle_tree(candidate)
    for relative in sorted(files):
        os.chmod(candidate / safe_relative_path(relative), 0o400)
    ordered_directories = sorted(
        directories,
        key=lambda value: (len(pathlib.PurePosixPath(value).parts), value),
        reverse=True,
    )
    for relative in ordered_directories:
        directory = candidate / safe_relative_path(relative)
        os.chmod(directory, 0o500)
        fsync_directory(directory)
    os.chmod(candidate, 0o500)
    fsync_directory(candidate)
    fsync_directory(candidate.parent)


def verify_and_finalize_candidate(
    paths: InputPaths,
    *,
    candidate: pathlib.Path,
    expected_seed: str,
    require_authorized: bool,
    external_anchor_path: pathlib.Path | None,
    argv: Sequence[str],
) -> pathlib.Path:
    started_ns = time.monotonic_ns()
    candidate_path = candidate.resolve(strict=True)
    require(
        not candidate_path.is_symlink(),
        "NCC-CANDIDATE-DIRECTORY",
        "candidate path must not be a symlink",
        str(candidate),
    )
    for forbidden in (
        "run_manifest.json",
        "e2e_receipt.json",
        "e2e_failure.json",
        "failure.json",
    ):
        require(
            not (candidate_path / forbidden).exists(),
            "NCC-CANDIDATE-TERMINAL-STATE",
            "candidate is already finalized or permanently failed",
            forbidden,
        )
    try:
        manifest_value = load_canonical_json_file(
            candidate_path / "generator_manifest.json",
            label="candidate generator manifest",
        )
        manifest, generator_records = validate_generator_manifest(
            manifest_value,
            candidate_name=candidate_path.name,
        )
        require(
            manifest["seed"] == expected_seed,
            "NCC-SEED-MISMATCH",
            "finalizer seed does not match the candidate seed",
            {
                "candidate_seed": manifest["seed"],
                "finalizer_seed": expected_seed,
            },
        )
        actual_files, directories = discover_bundle_tree(candidate_path)
        require_registry_matches_tree(
            expected_records=generator_records,
            actual_files=actual_files,
            allowed_unregistered_files={"generator_manifest.json"},
        )
        require(
            actual_files["generator_manifest.json"]["mode"] == 0o400,
            "NCC-ARTIFACT-MODE",
            "generator manifest must be sealed read-only before E2E",
        )
        expected_directories: set[str] = set()
        for relative in actual_files:
            parent = pathlib.PurePosixPath(relative).parent
            while parent != pathlib.PurePosixPath("."):
                expected_directories.add(parent.as_posix())
                parent = parent.parent
        require(
            directories == expected_directories,
            "NCC-ARTIFACT-DIRECTORY-CLOSURE",
            "candidate contains an unknown or empty directory",
            {
                "missing": sorted(expected_directories - directories),
                "extra": sorted(directories - expected_directories),
            },
        )
        for relative in directories:
            directory_stat = (candidate_path / safe_relative_path(relative)).lstat()
            require(
                stat.S_IMODE(directory_stat.st_mode) == 0o700,
                "NCC-ARTIFACT-DIRECTORY-MODE",
                "candidate directories must be private and writable only for finalization",
                relative,
            )
        validate_repro_lock(candidate_path, generator_records)

        dataset, input_manifest = load_candidate_dataset(candidate_path)
        require(
            manifest["decision_status"] == dataset.decision["status"]
            and manifest["implementation_authorized"]
            is dataset.decision["implementation_authorized"],
            "NCC-CANDIDATE-STATE",
            "candidate manifest and snapshotted decision state disagree",
        )
        if dataset.decision["status"] == "accepted":
            require(
                require_authorized,
                "NCC-AUTHORIZATION-REQUIRED",
                "accepted candidate finalization requires --require-authorized",
            )
            require(
                manifest["source_verification_mode"]
                == "online-exact-bytes-retained",
                "NCC-ACCEPTED-SOURCES",
                "accepted candidate lacks retained exact source bytes",
            )
            require(
                external_anchor_path is not None,
                "NCC-EXTERNAL-ANCHOR-REQUIRED",
                "accepted candidate finalization requires --owner-anchor",
            )
        else:
            require(
                not require_authorized,
                "NCC-AUTHORIZATION-REQUIRED",
                "proposed candidate cannot be finalized in authorized mode",
            )
            require(
                external_anchor_path is None,
                "NCC-PROPOSED-ANCHOR",
                "proposed candidate must not imply an owner anchor or approval",
            )
        external_anchor = (
            load_external_anchor(
                external_anchor_path,
                repo_root=paths.repo_root,
                node_repo=paths.node_repo,
            )
            if external_anchor_path is not None
            else None
        )

        validate_live_inputs_match_snapshot(paths=paths, dataset=dataset)
        validate_repository_state_snapshot(
            candidate_path,
            paths=paths,
        )
        observed_validation = validate_dataset(
            dataset,
            external_anchor=external_anchor,
            repo_root=paths.repo_root,
            node_repo=paths.node_repo,
            scan_repositories=True,
        )
        recorded_validation = load_canonical_json_file(
            candidate_path / "validation.json",
            label="candidate validation record",
        )
        require(
            observed_validation == recorded_validation,
            "NCC-VALIDATION-REPLAY",
            "independent validation differs from the candidate result",
            {
                "recorded_sha256": sha256_bytes(
                    canonical_json_bytes(recorded_validation)
                ),
                "observed_sha256": sha256_bytes(
                    canonical_json_bytes(observed_validation)
                ),
            },
        )

        recorded_self_tests = load_canonical_json_file(
            candidate_path / "mutation_results.json",
            label="candidate mutation-test report",
        )
        validate_self_test_report(recorded_self_tests, seed=manifest["seed"])
        rerun_self_tests = run_self_tests(dataset, seed=manifest["seed"])
        require(
            normalized_self_test_report(recorded_self_tests)
            == normalized_self_test_report(rerun_self_tests),
            "NCC-SELF-TEST-REPLAY",
            "independent mutation-test semantics differ from the candidate run",
        )
        source_receipts = load_canonical_json_file(
            candidate_path / "source_receipts.json",
            label="candidate source receipts",
        )
        validate_source_receipts(
            candidate_path,
            decision=dataset.decision,
            recorded=source_receipts,
            expected_mode=manifest["source_verification_mode"],
        )
        events = load_events(candidate_path / "events.jsonl")
        validate_event_details(
            events,
            manifest=manifest,
            validation=recorded_validation,
            self_tests=recorded_self_tests,
            source_receipts=source_receipts,
        )
        validate_auxiliary_evidence(
            candidate_path,
            dataset=dataset,
            input_manifest=input_manifest,
            validation=recorded_validation,
            self_tests=recorded_self_tests,
            source_receipts=source_receipts,
            external_anchor=external_anchor,
        )
        e2e_mutations = run_e2e_mutation_tests(seed=manifest["seed"])

        verified_at = dt.datetime.now(dt.timezone.utc).isoformat().replace(
            "+00:00",
            "Z",
        )
        e2e_receipt = {
            "schema_version": E2E_RECEIPT_SCHEMA,
            "candidate_id": manifest["candidate_id"],
            "candidate_root_sha256": manifest["candidate_root_sha256"],
            "run_id": manifest["run_id"],
            "trace_id": manifest["trace_id"],
            "seed": manifest["seed"],
            "attempt": 1,
            "source_cutoff": SOURCE_CUTOFF,
            "verified_at_utc": verified_at,
            "verifier_argv": list(argv),
            "verifier_sha256": sha256_file(
                candidate_path / "inputs" / INPUT_FILENAMES["validator"]
            ),
            "artifact_registry_sha256": artifact_registry_root(generator_records),
            "decision_status": dataset.decision["status"],
            "implementation_authorized": dataset.decision[
                "implementation_authorized"
            ],
            "composite_payload_sha256": recorded_validation[
                "composite_payload_sha256"
            ],
            "input_snapshot_outcome": "pass",
            "artifact_closure_outcome": "pass",
            "repository_state_outcome": "pass",
            "repository_boundary_outcome": "pass",
            "source_snapshot_outcome": (
                "pass"
                if manifest["source_verification_mode"]
                == "online-exact-bytes-retained"
                else "not-requested"
            ),
            "contract_revalidation_outcome": "pass",
            "self_test_replay_outcome": "pass",
            "event_coherence_outcome": "pass",
            "bundle_mutation_outcome": "pass",
            "recorded_self_test_count": recorded_self_tests["total"],
            "bundle_mutation_test_count": e2e_mutations["total"],
            "bundle_mutation_results": e2e_mutations["results"],
            "duration_ms": max(1, (time.monotonic_ns() - started_ns) // 1_000_000),
        }
        write_new_json(candidate_path / "e2e_receipt.json", e2e_receipt)
        fsync_directory(candidate_path)

        published_files, published_directories = discover_bundle_tree(candidate_path)
        expected_published_paths = (
            {record["path"] for record in generator_records}
            | {"generator_manifest.json", "e2e_receipt.json"}
        )
        require(
            set(published_files) == expected_published_paths
            and published_directories == expected_directories,
            "NCC-PUBLICATION-CLOSURE",
            "candidate changed while publishing the E2E receipt",
        )
        published_records = [
            published_files[path]
            for path in sorted(published_files)
        ]
        run_manifest = {
            "schema_version": RUN_MANIFEST_SCHEMA,
            "candidate_id": manifest["candidate_id"],
            "candidate_root_sha256": manifest["candidate_root_sha256"],
            "publication_root_sha256": artifact_registry_root(published_records),
            "run_id": manifest["run_id"],
            "trace_id": manifest["trace_id"],
            "seed": manifest["seed"],
            "attempt": 1,
            "source_cutoff": SOURCE_CUTOFF,
            "started_at_utc": manifest["started_at_utc"],
            "completed_at_utc": verified_at,
            "decision_status": dataset.decision["status"],
            "implementation_authorized": dataset.decision[
                "implementation_authorized"
            ],
            "source_verification_mode": manifest["source_verification_mode"],
            "publication_phase": "independently-verified-final",
            "validation_outcome": "pass",
            "self_test_outcome": "pass",
            "e2e_outcome": "pass",
            "complete": True,
            "artifacts": published_records,
        }
        write_new_json(candidate_path / "run_manifest.json", run_manifest)
        fsync_directory(candidate_path)

        final_files, final_directories = discover_bundle_tree(candidate_path)
        require(
            set(final_files) == expected_published_paths | {"run_manifest.json"}
            and final_directories == expected_directories
            and final_files["run_manifest.json"]["mode"] == 0o400,
            "NCC-PUBLICATION-CLOSURE",
            "run manifest was not the sole final publication artifact",
        )
        require(
            load_canonical_json_file(
                candidate_path / "run_manifest.json",
                label="final run manifest",
            )
            == run_manifest,
            "NCC-PUBLICATION-MANIFEST",
            "final run manifest changed during publication",
        )
        seal_candidate_tree(candidate_path)
    except Exception as exc:
        failure = (
            exc
            if isinstance(exc, GateFailure)
            else GateFailure(
                "NCC-E2E-UNEXPECTED",
                f"{type(exc).__name__}: {exc}",
            )
        )
        failure_path = candidate_path / "e2e_failure.json"
        if (
            candidate_path.is_dir()
            and not candidate_path.is_symlink()
            and not failure_path.exists()
            and not (candidate_path / "run_manifest.json").exists()
        ):
            try:
                write_new_json(
                    failure_path,
                    {
                        "schema_version": "franken-engine.native-code-capsule-e2e-failure.v2",
                        "candidate_id": candidate_path.name,
                        "complete": False,
                        "error": failure.as_dict(),
                    },
                )
                fsync_directory(candidate_path)
            except Exception:
                pass
        raise failure
    return candidate_path


def build_input_paths(arguments: argparse.Namespace) -> InputPaths:
    repo_root = pathlib.Path(arguments.repo_root).resolve()
    node_repo = pathlib.Path(arguments.node_repo).resolve()

    def chosen(value: str | None, default: pathlib.Path) -> pathlib.Path:
        return pathlib.Path(value).resolve() if value is not None else default

    return InputPaths(
        repo_root=repo_root,
        node_repo=node_repo,
        decision=chosen(
            arguments.decision,
            repo_root / "docs" / "adr" / "native_code_capsule_decision_v1.json",
        ),
        adr=chosen(
            arguments.adr,
            repo_root
            / "docs"
            / "adr"
            / "ADR-0010-native-code-capsule-trust-boundary.md",
        ),
        plan=chosen(
            arguments.plan,
            repo_root / "docs" / "plans" / "PLAN_TO_CREATE_FRANKEN_ENGINE.md",
        ),
        engine_split=chosen(
            arguments.engine_split,
            repo_root / "docs" / "REPO_SPLIT_CONTRACT.md",
        ),
        node_split=chosen(
            arguments.node_split,
            node_repo / "docs" / "ENGINE_SPLIT_CONTRACT.md",
        ),
        trust_root=chosen(
            arguments.trust_root,
            repo_root
            / "docs"
            / "adr"
            / "native_code_capsule_owner_trust_root_v1.json",
        ),
        gate=chosen(
            arguments.gate,
            repo_root / "scripts" / "run_native_code_capsule_adr_gate.sh",
        ),
        validator=chosen(
            arguments.validator,
            repo_root / "scripts" / "native_code_capsule_adr_validator.py",
        ),
        e2e=chosen(
            arguments.e2e,
            repo_root
            / "scripts"
            / "e2e"
            / "native_code_capsule_adr_contract_smoke.sh",
        ),
    )


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    live_repo = pathlib.Path(__file__).resolve().parent.parent
    parser.add_argument("--repo-root", default=str(live_repo))
    parser.add_argument("--node-repo", default=str(live_repo.parent / "franken_node"))
    parser.add_argument("--decision")
    parser.add_argument("--adr")
    parser.add_argument("--plan")
    parser.add_argument("--engine-split")
    parser.add_argument("--node-split")
    parser.add_argument("--trust-root")
    parser.add_argument("--gate")
    parser.add_argument("--validator")
    parser.add_argument("--e2e")
    parser.add_argument("--seed", default=os.environ.get("NATIVE_CAPSULE_ADR_SEED", DEFAULT_SEED))
    parser.add_argument("--require-authorized", action="store_true")
    parser.add_argument("--owner-anchor")


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strict ADR-0010 contract and evidence validator",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("check", "self-test", "ci", "finalize-candidate"):
        child = subparsers.add_parser(mode)
        add_common_arguments(child)
        if mode == "ci":
            child.add_argument(
                "--output-root",
                default=str(
                    pathlib.Path(__file__).resolve().parent.parent
                    / "artifacts"
                    / "native_code_capsule_adr"
                ),
            )
            child.add_argument("--verify-sources-online", action="store_true")
        elif mode == "check":
            child.add_argument("--verify-sources-online", action="store_true")
        elif mode == "finalize-candidate":
            child.add_argument("--candidate", required=True)
    return parser.parse_args(list(argv))


def require_mode_state(
    dataset: Dataset,
    *,
    require_authorized: bool,
    external_anchor_path: pathlib.Path | None,
    verify_sources: bool,
) -> None:
    if dataset.decision["status"] == "accepted":
        require(
            require_authorized,
            "NCC-AUTHORIZATION-REQUIRED",
            "accepted state must be checked with --require-authorized",
        )
        require(
            external_anchor_path is not None,
            "NCC-EXTERNAL-ANCHOR-REQUIRED",
            "accepted state requires --owner-anchor",
        )
        require(
            verify_sources,
            "NCC-ACCEPTED-SOURCES",
            "accepted state requires online exact source verification",
        )
    else:
        require(
            not require_authorized,
            "NCC-AUTHORIZATION-REQUIRED",
            "proposed state cannot pass --require-authorized",
        )
        require(
            external_anchor_path is None,
            "NCC-PROPOSED-ANCHOR",
            "proposed state must not imply an owner anchor or approval",
        )


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    arguments = parse_arguments(raw_argv)
    paths = build_input_paths(arguments)
    require(
        SEED_RE.fullmatch(arguments.seed) is not None,
        "NCC-SEED",
        "seed must be 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen",
    )
    external_anchor_path = (
        pathlib.Path(arguments.owner_anchor)
        if arguments.owner_anchor is not None
        else None
    )
    if arguments.mode == "finalize-candidate":
        finalized = verify_and_finalize_candidate(
            paths,
            candidate=pathlib.Path(arguments.candidate),
            expected_seed=arguments.seed,
            require_authorized=arguments.require_authorized,
            external_anchor_path=external_anchor_path,
            argv=[str(pathlib.Path(__file__).resolve()), *raw_argv],
        )
        print(
            canonical_json_bytes(
                {
                    "outcome": "pass",
                    "bundle_dir": str(finalized),
                    "run_manifest": str(finalized / "run_manifest.json"),
                }
            ).decode("utf-8")
        )
        return 0

    dataset = load_dataset(paths)
    verify_sources = bool(
        getattr(arguments, "verify_sources_online", False)
    )
    require_mode_state(
        dataset,
        require_authorized=arguments.require_authorized,
        external_anchor_path=external_anchor_path,
        verify_sources=verify_sources,
    )
    external_anchor = (
        load_external_anchor(
            external_anchor_path,
            repo_root=paths.repo_root,
            node_repo=paths.node_repo,
        )
        if external_anchor_path is not None
        else None
    )
    if arguments.mode == "ci":
        candidate = create_candidate_bundle(
            paths,
            output_root=pathlib.Path(arguments.output_root),
            seed=arguments.seed,
            require_authorized=arguments.require_authorized,
            verify_sources=verify_sources,
            external_anchor_path=external_anchor_path,
            argv=[str(pathlib.Path(__file__).resolve()), *raw_argv],
        )
        print(
            canonical_json_bytes(
                {
                    "outcome": "candidate",
                    "candidate_dir": str(candidate),
                    "generator_manifest": str(
                        candidate / "generator_manifest.json"
                    ),
                }
            ).decode("utf-8")
        )
        return 0

    validation = validate_dataset(
        dataset,
        external_anchor=external_anchor,
        repo_root=paths.repo_root,
        node_repo=paths.node_repo,
        scan_repositories=arguments.mode == "check",
    )
    result: dict[str, Any] = {
        "outcome": "pass",
        "mode": arguments.mode,
        "validation": validation,
    }
    if arguments.mode == "self-test":
        result["self_tests"] = run_self_tests(dataset, seed=arguments.seed)
    elif verify_sources:
        result["source_receipts"] = verify_sources_online(
            dataset.decision,
            snapshot_dir=None,
        )
    print(canonical_json_bytes(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as failure:
        print(
            canonical_json_bytes(
                {
                    "outcome": "fail",
                    "error": failure.as_dict(),
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        raise SystemExit(1)
