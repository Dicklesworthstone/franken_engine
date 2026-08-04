#!/usr/bin/env python3
"""Offline evidence bundle doctor for external trust artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "franken-engine.external-trust-artifact-bundle-doctor.v1"
E8_REFUSAL_LEDGER_SCHEMA = "franken-engine.e8-refusal-ledger.v1"

SUPPORTED_SCHEMAS = {
    "franken-engine.proof-artifact-bundle.v1",
    "franken-engine.benchmark-evidence-bundle.v1",
    "franken-engine.rgc-metadata-bundle.v1",
    "franken-engine.e2-differential-bundle.v1",
    "franken-engine.e3-recorder-bundle.v1",
    "franken-engine.e8-certificate-bundle.v1",
    E8_REFUSAL_LEDGER_SCHEMA,
}

DEFAULT_REQUIRED_MEMBERS = ("events.jsonl", "commands.txt")
PATH_ESCAPE_REASON = "path_escape"
MALFORMED_MANIFEST_REASON = "malformed_manifest"
INVALID_REPLAY_COMMAND_REASON = "invalid_replay_command"
INVALID_REQUIRED_MEMBER_REASON = "invalid_required_member"
EXPLICIT_E8_REFUSAL_REASON = "explicit_e8_uncertified_refusal"
MALFORMED_E8_REFUSAL_REASON = "malformed_e8_refusal_ledger"

E8_RESULT_CLASSES = {
    "certifiable_subset",
    "uncertified",
    "degraded",
    "fail_closed",
    "out_of_scope",
}
E8_NON_CERTIFIABLE_RESULT_CLASSES = {
    "uncertified",
    "degraded",
    "fail_closed",
    "out_of_scope",
}
E8_REFUSAL_CODE_CLASSES_BY_CODE = {
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
E8_REFUSAL_CODE_FIELDS = {"code", "class", "source_ref_id", "remediation"}
E8_SOURCE_REF_FIELDS = {"id", "surface", "path", "symbol", "span"}
E8_EVIDENCE_REF_FIELDS = {"id", "kind", "status", "artifact_path", "content_hash_hex"}
E8_EVIDENCE_REF_STATUSES = {"present", "missing", "degraded", "malformed", "out_of_scope"}
E8_COUNT_FIELDS = (
    "analyzed_surface_count",
    "unanalyzed_surface_count",
    "degraded_surface_count",
)

MOCK_MARKERS = (
    "MockCertificate",
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


def utc_now() -> str:
    override = os.environ.get("BUNDLE_DOCTOR_NOW_UTC")
    if override:
        return normalize_utc(override)
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_utc(value: str) -> str:
    parsed = parse_utc(value)
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(data)


def is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def load_manifest(path: Path) -> dict[str, Any]:
    if path.suffix == ".toml":
        with path.open("rb") as handle:
            loaded = tomllib.load(handle)
    else:
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain an object/table")
    return loaded


def is_e8_refusal_ledger(manifest: dict[str, Any] | None) -> bool:
    return bool(manifest) and manifest.get("schema_version") == E8_REFUSAL_LEDGER_SCHEMA


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def display_path(path: Path) -> str:
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def resolve_bundle_member_path(base_dir: Path, raw_path: str) -> tuple[Path, bool]:
    path = Path(raw_path)
    if path.is_absolute():
        return path, False
    display_candidate = base_dir / path
    base_resolved = base_dir.resolve(strict=False)
    candidate_resolved = display_candidate.resolve(strict=False)
    try:
        candidate_resolved.relative_to(base_resolved)
    except ValueError:
        return display_candidate, False
    return candidate_resolved, True


def find_manifest(bundle_path: Path) -> tuple[Path | None, dict[str, Any] | None, str | None]:
    if bundle_path.is_file():
        try:
            return bundle_path, load_manifest(bundle_path), None
        except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as err:
            return bundle_path, None, str(err)
    for name in (
        "bundle.json",
        "bundle.toml",
        "run_manifest.json",
        "run_manifest.toml",
        "manifest.json",
        "manifest.toml",
    ):
        candidate = bundle_path / name
        if candidate.is_file():
            try:
                return candidate, load_manifest(candidate), None
            except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as err:
                return candidate, None, str(err)
    return None, None, None


def required_members(manifest: dict[str, Any] | None) -> tuple[list[dict[str, Any]], bool]:
    if not manifest:
        return [{"path": member, "required": True} for member in DEFAULT_REQUIRED_MEMBERS], False
    if is_e8_refusal_ledger(manifest) and "required_members" not in manifest:
        return [], False

    def declared_member_hash(raw_member: dict[str, Any]) -> tuple[str | None, bool]:
        declared_hashes: list[str] = []
        malformed_hash = False
        for field in ("sha256", "expected_sha256"):
            if field not in raw_member:
                continue
            value = raw_member.get(field)
            if not isinstance(value, str) or not value.strip():
                malformed_hash = True
                continue
            declared_hash = value.strip()
            if not is_sha256_hex(declared_hash):
                malformed_hash = True
                continue
            declared_hashes.append(declared_hash)
        if len(set(declared_hashes)) > 1:
            malformed_hash = True
        expected_hash = declared_hashes[0] if declared_hashes else None
        return expected_hash, malformed_hash

    def declared_member_required(raw_member: dict[str, Any]) -> tuple[bool, bool]:
        if "required" not in raw_member:
            return True, False
        required = raw_member.get("required")
        if isinstance(required, bool):
            return required, False
        return True, True

    raw_members = manifest.get("required_members")
    if "required_members" in manifest:
        members: list[dict[str, Any]] = []
        malformed = False
        if not isinstance(raw_members, list) or not raw_members:
            return members, True
        for raw in raw_members:
            if isinstance(raw, str) and raw.strip():
                members.append({"path": raw, "required": True})
            elif (
                isinstance(raw, dict)
                and isinstance(raw.get("path"), str)
                and raw["path"].strip()
            ):
                expected_hash, malformed_hash = declared_member_hash(raw)
                required, malformed_required = declared_member_required(raw)
                malformed = malformed or malformed_hash or malformed_required
                members.append(
                    {
                        "path": raw["path"],
                        "required": required,
                        "sha256": expected_hash,
                    }
                )
            else:
                malformed = True
        return members, malformed

    return [{"path": member, "required": True} for member in DEFAULT_REQUIRED_MEMBERS], False


def manifest_replay_commands(manifest: dict[str, Any]) -> tuple[list[str], bool]:
    def parse_command_field(raw_commands: Any) -> tuple[list[str], bool]:
        if isinstance(raw_commands, str):
            command = raw_commands.strip()
            return ([command], False) if command else ([], True)
        if isinstance(raw_commands, list):
            commands: list[str] = []
            malformed = False
            if not raw_commands:
                return [], True
            for raw_command in raw_commands:
                if not isinstance(raw_command, str):
                    malformed = True
                    continue
                command = raw_command.strip()
                if command:
                    commands.append(command)
                else:
                    malformed = True
            return commands, malformed
        return [], True

    replay_fields = [
        manifest[field]
        for field in ("replay_commands", "replay_command")
        if field in manifest
    ]
    if not replay_fields:
        return [], False

    commands: list[str] = []
    malformed = False
    for raw_commands in replay_fields:
        parsed_commands, parsed_malformed = parse_command_field(raw_commands)
        malformed = malformed or parsed_malformed
        commands.extend(parsed_commands)

    deduped_commands = list(dict.fromkeys(commands))
    return deduped_commands, malformed


def manifest_freshness(
    manifest: dict[str, Any],
    now_utc: str,
) -> tuple[dict[str, Any], bool]:
    freshness = {"status": "unavailable", "fresh_until_utc": None, "now_utc": now_utc}
    freshness_fields = [
        (field, manifest[field])
        for field in ("fresh_until_utc", "expires_at_utc")
        if field in manifest
    ]
    if not freshness_fields:
        return freshness, False

    now = parse_utc(now_utc)
    parsed_values: list[datetime] = []
    invalid_values: list[str] = []
    stale_or_unfresh = False

    for _field, raw_value in freshness_fields:
        if isinstance(raw_value, str) and raw_value.strip():
            try:
                parsed_value = parse_utc(raw_value)
            except ValueError:
                invalid_values.append(raw_value.strip())
                stale_or_unfresh = True
            else:
                parsed_values.append(parsed_value)
                if parsed_value < now:
                    stale_or_unfresh = True
        else:
            invalid_values.append(
                raw_value
                if isinstance(raw_value, str)
                else json.dumps(raw_value, sort_keys=True, separators=(",", ":"))
            )
            stale_or_unfresh = True

    if invalid_values:
        freshness["fresh_until_utc"] = invalid_values[0]
    elif parsed_values:
        earliest = min(parsed_values)
        freshness["fresh_until_utc"] = (
            earliest.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )

    freshness["status"] = "stale_or_unfresh" if stale_or_unfresh else "fresh"
    return freshness, stale_or_unfresh


def read_text_if_small(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > 1_000_000:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def scan_markers(paths: list[Path], markers: tuple[str, ...]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in sorted(paths, key=lambda item: item.as_posix()):
        text = read_text_if_small(path)
        lower_text = text.lower()
        for marker in markers:
            if marker.lower() in lower_text:
                findings.append({"path": display_path(path), "marker": marker})
                break
    return findings


def collect_files(
    bundle_path: Path,
    manifest_path: Path | None,
    member_paths: list[Path],
    extra_paths: list[Path] | None = None,
) -> list[Path]:
    files: dict[str, Path] = {}
    if manifest_path and manifest_path.is_file():
        files[manifest_path.resolve().as_posix()] = manifest_path
    if bundle_path.is_file():
        files[bundle_path.resolve().as_posix()] = bundle_path
    for path in member_paths:
        if path.is_file():
            files[path.resolve().as_posix()] = path
    for path in extra_paths or []:
        if path.is_file():
            files[path.resolve().as_posix()] = path
    return list(files.values())


def choose_decision(reason_codes: list[str]) -> str:
    fail_closed_reasons = {
        "missing_required_member",
        "hash_mismatch",
        "mock_contaminated",
        "local_fallback_contaminated",
        "replay_command_missing",
        PATH_ESCAPE_REASON,
        MALFORMED_MANIFEST_REASON,
        INVALID_REPLAY_COMMAND_REASON,
        INVALID_REQUIRED_MEMBER_REASON,
        MALFORMED_E8_REFUSAL_REASON,
    }
    if any(reason in fail_closed_reasons for reason in reason_codes):
        return "fail_closed"
    if "unsupported_schema" in reason_codes:
        return "unsupported"
    if EXPLICIT_E8_REFUSAL_REASON in reason_codes:
        return "not_promotable"
    if "stale_or_unfresh" in reason_codes:
        return "degraded"
    return "supported"


def e8_refusal_ledger_view(manifest: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    refusal_codes = manifest.get("refusal_codes")
    source_refs = manifest.get("source_refs")
    evidence_refs = manifest.get("evidence_refs")
    remediation_actions = manifest.get("remediation_actions")

    view = {
        "ledger_id": manifest.get("ledger_id"),
        "run_id": manifest.get("run_id"),
        "contract_id": manifest.get("contract_id"),
        "result_class": manifest.get("result_class"),
        "threat_model_scope": manifest.get("threat_model_scope"),
        "certifier_input_allowed": manifest.get("certifier_input_allowed"),
        "positive_non_use_claim_allowed": manifest.get("positive_non_use_claim_allowed"),
        "must_block_certificate": manifest.get("must_block_certificate"),
        "analyzed_surface_count": manifest.get("analyzed_surface_count"),
        "unanalyzed_surface_count": manifest.get("unanalyzed_surface_count"),
        "degraded_surface_count": manifest.get("degraded_surface_count"),
        "refusal_codes": refusal_codes if isinstance(refusal_codes, list) else [],
        "source_refs": source_refs if isinstance(source_refs, list) else [],
        "evidence_refs": evidence_refs if isinstance(evidence_refs, list) else [],
        "remediation_actions": (
            remediation_actions if isinstance(remediation_actions, list) else []
        ),
    }

    malformed = False
    for field in ("ledger_id", "run_id", "contract_id", "threat_model_scope"):
        malformed = malformed or not non_empty_string(manifest.get(field))
    result_class = manifest.get("result_class")
    malformed = malformed or not isinstance(result_class, str)
    malformed = malformed or (
        isinstance(result_class, str) and result_class not in E8_RESULT_CLASSES
    )
    malformed = malformed or manifest.get("threat_model_scope") != "explicit_flow_ifc_v1"
    malformed = malformed or manifest.get("positive_non_use_claim_allowed") is not False
    malformed = malformed or not isinstance(refusal_codes, list)
    malformed = malformed or not isinstance(source_refs, list) or len(source_refs) == 0
    malformed = malformed or not isinstance(evidence_refs, list)
    malformed = malformed or not isinstance(remediation_actions, list)
    for field in E8_COUNT_FIELDS:
        count = manifest.get(field)
        malformed = malformed or type(count) is not int or count < 0

    source_ids: set[str] = set()
    if isinstance(source_refs, list):
        for source_ref in source_refs:
            if not isinstance(source_ref, dict):
                malformed = True
                continue
            if set(source_ref) - E8_SOURCE_REF_FIELDS:
                malformed = True
            source_id = source_ref.get("id")
            if not non_empty_string(source_id):
                malformed = True
                continue
            source_ids.add(str(source_id))
            for field in ("surface", "path"):
                malformed = malformed or not non_empty_string(source_ref.get(field))
            for field in ("symbol", "span"):
                if field in source_ref and not isinstance(source_ref.get(field), str):
                    malformed = True

    if isinstance(refusal_codes, list):
        for refusal_code in refusal_codes:
            if not isinstance(refusal_code, dict):
                malformed = True
                continue
            if set(refusal_code) - E8_REFUSAL_CODE_FIELDS:
                malformed = True
            for field in ("code", "class", "source_ref_id", "remediation"):
                malformed = malformed or not non_empty_string(refusal_code.get(field))
            code = refusal_code.get("code")
            refusal_class = refusal_code.get("class")
            expected_class = (
                E8_REFUSAL_CODE_CLASSES_BY_CODE.get(str(code))
                if non_empty_string(code)
                else None
            )
            malformed = malformed or expected_class is None
            malformed = malformed or (
                non_empty_string(refusal_class) and refusal_class != expected_class
            )
            source_ref_id = refusal_code.get("source_ref_id")
            if non_empty_string(source_ref_id) and str(source_ref_id) not in source_ids:
                malformed = True

    if isinstance(evidence_refs, list):
        for evidence_ref in evidence_refs:
            if not isinstance(evidence_ref, dict):
                malformed = True
                continue
            if set(evidence_ref) - E8_EVIDENCE_REF_FIELDS:
                malformed = True
            for field in ("id", "kind"):
                malformed = malformed or not non_empty_string(evidence_ref.get(field))
            status = evidence_ref.get("status")
            malformed = malformed or not isinstance(status, str)
            malformed = malformed or (
                isinstance(status, str) and status not in E8_EVIDENCE_REF_STATUSES
            )
            for field in ("artifact_path", "content_hash_hex"):
                if field in evidence_ref and not isinstance(evidence_ref.get(field), str):
                    malformed = True

    if isinstance(remediation_actions, list):
        for remediation_action in remediation_actions:
            malformed = malformed or not non_empty_string(remediation_action)

    if isinstance(result_class, str) and result_class in E8_NON_CERTIFIABLE_RESULT_CLASSES:
        malformed = malformed or manifest.get("certifier_input_allowed") is not False
        malformed = malformed or manifest.get("must_block_certificate") is not True
        malformed = malformed or not isinstance(refusal_codes, list) or len(refusal_codes) == 0
    elif result_class == "certifiable_subset":
        malformed = malformed or manifest.get("certifier_input_allowed") is not True
        malformed = malformed or manifest.get("must_block_certificate") is not False
        malformed = malformed or not isinstance(refusal_codes, list) or len(refusal_codes) != 0

    return view, malformed


def is_success_exit(decision: str) -> bool:
    return decision in {"supported", "degraded"}


def build_receipt(bundle_path: Path, now_utc: str) -> dict[str, Any]:
    bundle_path = bundle_path.resolve()
    reason_codes: list[str] = []
    remediation: list[str] = []
    e8_refusal_ledger: dict[str, Any] | None = None

    manifest_path, manifest, manifest_load_error = find_manifest(bundle_path)
    schema_version = str(manifest.get("schema_version", "")) if manifest else ""
    bundle_type = str(
        (manifest or {}).get("bundle_type")
        or (manifest or {}).get("bundle_family")
        or (manifest or {}).get("kind")
        or "unknown"
    )

    if manifest_load_error:
        reason_codes.append(MALFORMED_MANIFEST_REASON)
        remediation.append("Fix the bundle manifest so it parses as a JSON/TOML object.")
    elif manifest is None:
        reason_codes.append("missing_required_member")
        remediation.append("Add bundle/run_manifest/manifest JSON or TOML.")
    elif schema_version not in SUPPORTED_SCHEMAS:
        reason_codes.append("unsupported_schema")
        remediation.append("Use a V1-supported evidence bundle schema or add explicit support.")

    if manifest and is_e8_refusal_ledger(manifest):
        e8_refusal_ledger, malformed_e8_refusal = e8_refusal_ledger_view(manifest)
        if malformed_e8_refusal:
            reason_codes.append(MALFORMED_E8_REFUSAL_REASON)
            remediation.append("Treat the E8 refusal ledger as untrusted and rerun the E8 producer.")
        elif e8_refusal_ledger["result_class"] in E8_NON_CERTIFIABLE_RESULT_CLASSES:
            reason_codes.append(EXPLICIT_E8_REFUSAL_REASON)
            remediation.extend(
                action
                for action in e8_refusal_ledger["remediation_actions"]
                if non_empty_string(action)
            )
            remediation.append(
                "Preserve ledger_id, refusal code, class, source reference, and remediation "
                "while blocking positive non-use wording."
            )

    invalid_required_member = False
    if manifest_load_error:
        members = []
    else:
        members, invalid_required_member = required_members(manifest)
    if invalid_required_member:
        reason_codes.append(INVALID_REQUIRED_MEMBER_REASON)
        remediation.append(
            "Fix required_members so it is a non-empty list of root-relative path "
            "strings or path objects with boolean required flags and valid, "
            "non-conflicting SHA-256 hex hash fields."
        )
    artifact_refs: list[dict[str, Any]] = []
    present_member_paths: list[Path] = []

    base_dir = bundle_path if bundle_path.is_dir() else bundle_path.parent
    for member in members:
        member_path, path_safe = resolve_bundle_member_path(base_dir, str(member["path"]))
        present = path_safe and member_path.is_file()
        expected_hash = member.get("sha256")
        actual_hash = file_hash(member_path) if present else None
        hash_status = "not_declared"

        if not path_safe:
            if PATH_ESCAPE_REASON not in reason_codes:
                reason_codes.append(PATH_ESCAPE_REASON)
                remediation.append(
                    "Reject bundle manifest member paths that resolve outside the bundle root."
                )
            hash_status = PATH_ESCAPE_REASON
        elif present:
            present_member_paths.append(member_path)
            if isinstance(expected_hash, str) and expected_hash:
                hash_status = "match" if expected_hash == actual_hash else "mismatch"
                if hash_status == "mismatch" and "hash_mismatch" not in reason_codes:
                    reason_codes.append("hash_mismatch")
                    remediation.append("Regenerate the bundle or fix the declared member hash.")
            else:
                hash_status = "computed"
        elif member.get("required", True):
            if "missing_required_member" not in reason_codes:
                reason_codes.append("missing_required_member")
                remediation.append("Regenerate the upstream bundle with all required members.")
            hash_status = "missing"

        artifact_refs.append(
            {
                "path": display_path(member_path),
                "required": bool(member.get("required", True)),
                "present": present,
                "content_hash": actual_hash,
                "expected_hash": expected_hash,
                "hash_status": hash_status,
            }
        )

    freshness = {"status": "unavailable", "fresh_until_utc": None, "now_utc": now_utc}
    if manifest:
        freshness, stale_or_unfresh = manifest_freshness(manifest, now_utc)
        if stale_or_unfresh:
            reason_codes.append("stale_or_unfresh")
            remediation.append("Fix the freshness timestamp or regenerate evidence.")

    replay_commands = []
    invalid_replay_command = False
    if manifest:
        replay_commands, invalid_replay_command = manifest_replay_commands(manifest)
        if invalid_replay_command:
            reason_codes.append(INVALID_REPLAY_COMMAND_REASON)
            remediation.append(
                "Fix replay_command/replay_commands so every declared command is an "
                "exact non-empty command string."
            )

    command_member = base_dir / "commands.txt"
    if not replay_commands and not invalid_replay_command and command_member.is_file():
        replay_commands = [
            line.strip()
            for line in command_member.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if (
        not replay_commands
        and not invalid_replay_command
        and not is_e8_refusal_ledger(manifest)
    ):
        reason_codes.append("replay_command_missing")
        remediation.append("Add an exact replay command to the manifest or commands.txt.")

    scanned_files = collect_files(
        bundle_path,
        manifest_path,
        present_member_paths,
        [command_member],
    )
    mock_findings = scan_markers(scanned_files, MOCK_MARKERS)
    if mock_findings:
        reason_codes.append("mock_contaminated")
        remediation.append("Replace mock, simulated, placeholder, or fixture-only proof evidence.")

    local_fallback_findings = scan_markers(scanned_files, LOCAL_FALLBACK_MARKERS)
    if local_fallback_findings:
        reason_codes.append("local_fallback_contaminated")
        remediation.append("Re-run heavy proof commands through rch and attach remote proof artifacts.")

    reason_codes = sorted(set(reason_codes))
    decision = choose_decision(reason_codes)
    bundle_hash_inputs = {
        "manifest": file_hash(manifest_path) if manifest_path else None,
        "members": [
            {"path": ref["path"], "content_hash": ref["content_hash"]}
            for ref in artifact_refs
            if ref["present"]
        ],
    }
    missing_required = [
        ref["path"] for ref in artifact_refs if ref["required"] and not ref["present"]
    ]
    command_transcript_refs = []
    if command_member.is_file():
        command_lines = [
            line
            for line in command_member.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        command_transcript_refs.append(
            {
                "path": display_path(command_member),
                "content_hash": file_hash(command_member),
                "line_count": len(command_lines),
            }
        )

    bundle_info = {
        "path": display_path(bundle_path),
        "manifest_path": display_path(manifest_path) if manifest_path else None,
        "bundle_type": bundle_type,
        "schema_version": schema_version or None,
        "content_hash": canonical_hash(bundle_hash_inputs),
    }
    if manifest_load_error:
        bundle_info["manifest_error"] = manifest_load_error

    receipt_core = {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "reason_codes": reason_codes,
        "bundle": bundle_info,
        "artifact_completeness": {
            "required_count": sum(1 for ref in artifact_refs if ref["required"]),
            "present_required_count": sum(
                1 for ref in artifact_refs if ref["required"] and ref["present"]
            ),
            "missing_required_members": missing_required,
        },
        "artifact_refs": artifact_refs,
        "command_transcript_refs": command_transcript_refs,
        "evidence_freshness": freshness,
        "mock_status": "present_fail_closed" if mock_findings else "absent",
        "mock_findings": mock_findings,
        "local_fallback_status": (
            "present_fail_closed" if local_fallback_findings else "absent"
        ),
        "local_fallback_findings": local_fallback_findings,
        "replay_commands": replay_commands,
        "remediation": sorted(set(remediation)),
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
        "source_line_refs": [],
        "renderer_boundary": {
            "future_rich_renderer_provider": "/dp/frankentui",
            "local_rich_renderer_shipped": False,
        },
    }
    if e8_refusal_ledger is not None:
        receipt_core["e8_refusal_ledger"] = e8_refusal_ledger
    return {
        **receipt_core,
        "receipt_id": f"bundle-doctor-{canonical_hash(receipt_core)[:16]}",
        "generated_at_utc": now_utc,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect a preserved evidence bundle without contacting live services."
    )
    parser.add_argument("--bundle", required=True, help="Bundle directory or manifest JSON path.")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Emit indented JSON. Compact sorted JSON is the default.",
    )
    args = parser.parse_args()

    receipt = build_receipt(Path(args.bundle), utc_now())
    if args.pretty:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if is_success_exit(str(receipt["decision"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
