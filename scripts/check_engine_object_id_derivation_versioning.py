#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs/engine_object_id_derivation_contract_v2.json"
ENGINE_SOURCE = ROOT / "crates/franken-engine/src/engine_object_id.rs"
CORE_SOURCE = ROOT / "crates/franken-core/src/engine_object_id.rs"
SCAN_ROOTS = (
    ROOT / "crates/franken-engine/src",
    ROOT / "crates/franken-core/src",
    ROOT / "crates/franken-extension-host/src",
)
REPORT_SCHEMA = "franken-engine.engine-object-id-consumer-versioning-report.v4"
RAW_ID_PATTERN = re.compile(r"\b(?:EngineObjectId|SchemaId)\b")
VERSION_FIELD_PATTERN = re.compile(
    r"\bderivation_version\s*:\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*ObjectIdDerivationVersion\b"
)
CURRENT_DEFAULT_PATTERN = re.compile(
    r"CURRENT_OBJECT_ID_DERIVATION_VERSION\s*:\s*ObjectIdDerivationVersion\s*=\s*"
    r"ObjectIdDerivationVersion::(LegacyV1|Sha256V2)",
    re.MULTILINE,
)
TYPE_PATTERN = re.compile(
    r"(?P<attrs>(?:\s*#\s*\[[^\]]*\]\s*)*)"
    r"(?:(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?)?"
    r"(?P<kind>struct|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)
DERIVE_PATTERN = re.compile(r"#\s*\[\s*derive\s*\((?P<body>.*?)\)\s*\]", re.DOTALL)
MANUAL_SERDE_IMPL_PATTERN = re.compile(
    r"\bimpl(?:\s*<[^{};]*>)?\s+[^{};]*?\b(?P<trait>Serialize|Deserialize)\b"
    r"[^{};]*?\bfor\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b[^{};]*\{",
    re.MULTILINE,
)
SIGNATURE_IMPL_PATTERN = re.compile(
    r"\bimpl(?:\s*<[^{};]*>)?\s+[^{};]*?\bSignaturePreimage\b"
    r"[^{};]*?\bfor\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b[^{};]*\{",
    re.MULTILINE,
)
EXCLUDED_FILES = {
    "crates/franken-engine/src/engine_object_id.rs",
    "crates/franken-engine/src/engine_object_id/compat.rs",
    "crates/franken-engine/src/engine_object_id/versioned.rs",
    "crates/franken-engine/src/engine_object_id/wire.rs",
    "crates/franken-core/src/engine_object_id.rs",
    "crates/franken-core/src/engine_object_id/compat.rs",
    "crates/franken-core/src/engine_object_id/versioned.rs",
    "crates/franken-core/src/engine_object_id/wire.rs",
    "crates/franken-engine/src/bin/franken_engine_object_id_migration.rs",
}


class GuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class RawIdOccurrence:
    symbol: str
    line: int
    source: str


@dataclass(frozen=True)
class ConsumerFinding:
    path: str
    type_name: str
    type_kind: str
    line: int
    derives: tuple[str, ...]
    manual_serde_traits: tuple[str, ...]
    serialized: bool
    signed: bool
    raw_id_occurrences: tuple[RawIdOccurrence, ...]
    declares_derivation_version: bool
    derivation_version_bound_to_signature: bool | None
    classification: str
    blocking_reasons: tuple[str, ...]
    blocks_default_flip: bool


@dataclass(frozen=True)
class SourceDefaultState:
    path: str
    selected_default: str | None
    legacy_schema_default_visible: bool
    legacy_object_default_visible: bool
    sha256_v2_default_visible: bool
    sha256_v2_schema_api_visible: bool
    sha256_v2_object_api_visible: bool
    versioned_source_path: str
    versioned_source_sha256: str
    wire_source_path: str
    wire_source_sha256: str
    wire_api_visible: bool


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise GuardError(f"failed to read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise GuardError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise GuardError(f"{path} must contain a JSON object")
    if value.get("schema_version") != "franken-engine.engine-object-id-derivation-contract.v2":
        raise GuardError(f"unexpected derivation contract schema: {value.get('schema_version')!r}")
    return value


def relative(path: Path, root: Path = ROOT) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def iter_rust_files(scan_roots: Iterable[Path]) -> Iterable[Path]:
    for scan_root in scan_roots:
        if not scan_root.is_dir():
            continue
        yield from sorted(path for path in scan_root.rglob("*.rs") if path.is_file())


def mask_rust_noncode(text: str) -> str:
    """Replace comments and literals with spaces while preserving positions and newlines."""
    out = list(text)
    length = len(text)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if out[position] != "\n":
                out[position] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            blank(index, cursor)
            index = cursor
            continue

        raw_prefix_length = 0
        raw_start = index
        if text.startswith("br", index) or text.startswith("cr", index):
            raw_prefix_length = 2
        elif text.startswith("r", index):
            raw_prefix_length = 1
        if raw_prefix_length:
            cursor = index + raw_prefix_length
            hashes = 0
            while cursor < length and text[cursor] == "#":
                hashes += 1
                cursor += 1
            if cursor < length and text[cursor] == '"':
                terminator = '"' + ("#" * hashes)
                end = text.find(terminator, cursor + 1)
                end = length if end < 0 else end + len(terminator)
                blank(raw_start, end)
                index = end
                continue

        if text[index] == '"' or (
            text[index] in {"b", "c"} and index + 1 < length and text[index + 1] == '"'
        ):
            start = index
            cursor = index + (2 if text[index] in {"b", "c"} else 1)
            escaped = False
            while cursor < length:
                char = text[cursor]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    cursor += 1
                    break
                cursor += 1
            blank(start, cursor)
            index = cursor
            continue
        index += 1
    return "".join(out)


def matching_delimiter(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def source_line(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end < 0:
        end = len(text)
    return text[start:end].strip()


def parse_derives(attributes: str) -> tuple[str, ...]:
    traits: set[str] = set()
    for match in DERIVE_PATTERN.finditer(attributes):
        for trait in match.group("body").split(","):
            normalized = trait.strip().split("::")[-1]
            if normalized:
                traits.add(normalized)
    return tuple(sorted(traits))


def impl_blocks(masked: str, pattern: re.Pattern[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for match in pattern.finditer(masked):
        brace = masked.find("{", match.start(), match.end())
        if brace < 0:
            continue
        end = matching_delimiter(masked, brace, "{", "}")
        if end is None:
            continue
        result.setdefault(match.group("name"), []).append(masked[brace + 1 : end])
    return result


def type_body(masked: str, declaration_end: int) -> tuple[str, int, int] | None:
    cursor = declaration_end
    while cursor < len(masked) and masked[cursor].isspace():
        cursor += 1
    if cursor >= len(masked):
        return None
    if masked[cursor] == "<":
        generic_end = matching_delimiter(masked, cursor, "<", ">")
        if generic_end is None:
            return None
        cursor = generic_end + 1
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
    where_index = masked.find("where", cursor, min(len(masked), cursor + 512))
    candidates = [
        position
        for position in (
            masked.find("{", cursor),
            masked.find("(", cursor),
            masked.find(";", cursor),
        )
        if position >= 0
    ]
    if not candidates:
        return None
    opener = min(candidates)
    if where_index >= 0 and where_index < opener:
        candidates = [
            position
            for position in (
                masked.find("{", where_index),
                masked.find("(", where_index),
                masked.find(";", where_index),
            )
            if position >= 0
        ]
        if not candidates:
            return None
        opener = min(candidates)
    if masked[opener] == ";":
        return "", opener, opener
    closing = "}" if masked[opener] == "{" else ")"
    end = matching_delimiter(masked, opener, masked[opener], closing)
    if end is None:
        return None
    return masked[opener + 1 : end], opener + 1, end


def classify_file(path: Path, root: Path = ROOT) -> list[ConsumerFinding]:
    rel = relative(path, root)
    if rel in EXCLUDED_FILES:
        return []
    source = path.read_text(encoding="utf-8")
    masked = mask_rust_noncode(source)
    signed_impls = impl_blocks(masked, SIGNATURE_IMPL_PATTERN)
    findings: list[ConsumerFinding] = []

    for match in TYPE_PATTERN.finditer(masked):
        parsed = type_body(masked, match.end())
        if parsed is None:
            continue
        body, body_start, _body_end = parsed
        occurrences = tuple(
            RawIdOccurrence(
                symbol=raw_match.group(0),
                line=line_number(source, body_start + raw_match.start()),
                source=source_line(source, body_start + raw_match.start()),
            )
            for raw_match in RAW_ID_PATTERN.finditer(body)
        )
        if not occurrences:
            continue

        name = match.group("name")
        derives = parse_derives(match.group("attrs") or "")
        manual_trait_names = tuple(
            sorted(
                {
                    trait_match.group("trait")
                    for trait_match in MANUAL_SERDE_IMPL_PATTERN.finditer(masked)
                    if trait_match.group("name") == name
                }
            )
        )
        serialized = bool({"Serialize", "Deserialize"}.intersection(derives)) or bool(
            manual_trait_names
        )
        signed_bodies = signed_impls.get(name, [])
        signed = bool(signed_bodies)
        declares_version = bool(VERSION_FIELD_PATTERN.search(body))
        signature_bound = (
            all(re.search(r"\bderivation_version\b", block) for block in signed_bodies)
            if signed and declares_version
            else None
        )

        reasons: list[str] = []
        if serialized and not declares_version:
            reasons.append("serialized_raw_id_without_derivation_version")
        if signed and not declares_version:
            reasons.append("signed_raw_id_without_derivation_version")
        if signed and declares_version and signature_bound is False:
            reasons.append("derivation_version_not_bound_into_signature_preimage")

        if reasons:
            classification = "persisted_or_signed_unversioned"
        elif serialized or signed:
            classification = "version_declared"
        else:
            classification = "ephemeral_or_unclassified"
        findings.append(
            ConsumerFinding(
                path=rel,
                type_name=name,
                type_kind=match.group("kind"),
                line=line_number(source, match.start("kind")),
                derives=derives,
                manual_serde_traits=manual_trait_names,
                serialized=serialized,
                signed=signed,
                raw_id_occurrences=occurrences,
                declares_derivation_version=declares_version,
                derivation_version_bound_to_signature=signature_bound,
                classification=classification,
                blocking_reasons=tuple(reasons),
                blocks_default_flip=bool(reasons),
            )
        )
    return findings


def companion_source(path: Path, module_name: str, *, fallback_to_parent: bool) -> tuple[Path, str]:
    sibling = path.parent / path.stem / f"{module_name}.rs"
    if sibling.is_file():
        return sibling, sibling.read_text(encoding="utf-8")
    if fallback_to_parent:
        return path, path.read_text(encoding="utf-8")
    return sibling, ""


def source_default_state(path: Path, root: Path = ROOT) -> SourceDefaultState:
    top_level_text = path.read_text(encoding="utf-8")
    versioned_path, versioned_text = companion_source(path, "versioned", fallback_to_parent=True)
    wire_path, wire_text = companion_source(path, "wire", fallback_to_parent=False)
    text = top_level_text + "\n" + versioned_text
    default_match = CURRENT_DEFAULT_PATTERN.search(text)
    selected_default = default_match.group(1) if default_match else None
    legacy_marker_visible = selected_default == "LegacyV1"
    historical_schema_default = "Self(deterministic_hash(definition))" in text
    historical_object_default = "Ok(EngineObjectId(deterministic_hash(&preimage)))" in text
    return SourceDefaultState(
        path=relative(path, root),
        selected_default=(
            "legacy_v1"
            if selected_default == "LegacyV1"
            else "sha256_v2"
            if selected_default == "Sha256V2"
            else None
        ),
        legacy_schema_default_visible=legacy_marker_visible or historical_schema_default,
        legacy_object_default_visible=legacy_marker_visible or historical_object_default,
        sha256_v2_default_visible=selected_default == "Sha256V2",
        sha256_v2_schema_api_visible=(
            "pub fn derive_versioned_schema_id" in versioned_text
            and "FrankenEngine.SchemaId.sha256.v2" in versioned_text
        ),
        sha256_v2_object_api_visible=(
            "pub fn derive_versioned_id" in versioned_text
            and "pub fn verify_versioned_id" in versioned_text
            and "FrankenEngine.EngineObjectId.sha256.v2" in versioned_text
        ),
        versioned_source_path=relative(versioned_path, root),
        versioned_source_sha256=hashlib.sha256(versioned_text.encode("utf-8")).hexdigest(),
        wire_source_path=relative(wire_path, root),
        wire_source_sha256=(
            hashlib.sha256(wire_text.encode("utf-8")).hexdigest() if wire_text else ""
        ),
        wire_api_visible=(
            "pub struct PersistedEngineObjectId" in wire_text
            and "pub struct PersistedSchemaId" in wire_text
            and "pub fn encode_binary" in wire_text
            and "pub fn decode_binary" in wire_text
        ),
    )


def build_report(
    root: Path = ROOT,
    contract_path: Path = CONTRACT_PATH,
    scan_roots: Iterable[Path] = SCAN_ROOTS,
    engine_source: Path = ENGINE_SOURCE,
    core_source: Path = CORE_SOURCE,
) -> dict[str, object]:
    contract = load_contract(contract_path)
    findings = [
        finding
        for path in iter_rust_files(scan_roots)
        for finding in classify_file(path, root)
    ]
    blockers = [finding for finding in findings if finding.blocks_default_flip]
    defaults = [
        source_default_state(engine_source, root),
        source_default_state(core_source, root),
    ]
    current_default = contract.get("current_default")
    target_default = contract.get("target_default")
    legacy_default_consistent = all(
        state.legacy_schema_default_visible
        and state.legacy_object_default_visible
        and not state.sha256_v2_default_visible
        for state in defaults
    )
    v2_default_consistent = all(state.sha256_v2_default_visible for state in defaults)
    v2_api_count = sum(
        state.sha256_v2_schema_api_visible and state.sha256_v2_object_api_visible
        for state in defaults
    )
    v2_library_api_consistent = v2_api_count == len(defaults)
    v2_library_api_partial = 0 < v2_api_count < len(defaults)
    versioned_source_parity = len({state.versioned_source_sha256 for state in defaults}) == 1
    wire_api_count = sum(state.wire_api_visible for state in defaults)
    wire_api_consistent = wire_api_count == len(defaults)
    wire_api_partial = 0 < wire_api_count < len(defaults)
    wire_source_parity = (
        wire_api_consistent
        and len({state.wire_source_sha256 for state in defaults}) == 1
    )
    library_source_parity = versioned_source_parity and wire_source_parity

    migration_state = (
        "blocked_on_unversioned_persisted_consumers"
        if blockers
        else "ready_for_explicit_default_flip_review"
    )
    violations: list[str] = []
    if current_default == "legacy_v1" and not legacy_default_consistent:
        violations.append("contract_declares_legacy_v1_but_library_default_drifted")
    if current_default == "sha256_v2" and not v2_default_consistent:
        violations.append("contract_declares_sha256_v2_but_library_default_drifted")
    if blockers and (
        current_default == "sha256_v2" or any(state.sha256_v2_default_visible for state in defaults)
    ):
        violations.append("sha256_v2_default_visible_with_unversioned_persisted_consumers")
    if not v2_library_api_consistent:
        violations.append(
            "sha256_v2_library_api_parity_incomplete"
            if v2_library_api_partial
            else "sha256_v2_library_api_missing"
        )
    if not versioned_source_parity:
        violations.append("sha256_v2_library_source_drift")
    if not wire_api_consistent:
        violations.append(
            "versioned_id_wire_api_parity_incomplete"
            if wire_api_partial
            else "versioned_id_wire_api_missing"
        )
    if wire_api_consistent and not wire_source_parity:
        violations.append("versioned_id_wire_source_drift")
    if current_default not in {"legacy_v1", "sha256_v2"}:
        violations.append("unsupported_current_default")
    if target_default != "sha256_v2":
        violations.append("unexpected_target_default")

    default_flip_allowed = (
        not blockers
        and not violations
        and v2_library_api_consistent
        and library_source_parity
        and wire_api_consistent
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "contract_path": relative(contract_path, root),
        "current_default": current_default,
        "target_default": target_default,
        "migration_state": migration_state,
        "library_api_state": (
            "sha256_v2_available_in_both_crates"
            if v2_library_api_consistent
            else "sha256_v2_partial"
            if v2_library_api_partial
            else "sha256_v2_missing"
        ),
        "versioned_source_parity": versioned_source_parity,
        "wire_api_state": (
            "legacy_compatible_versioned_wire_available_in_both_crates"
            if wire_api_consistent
            else "versioned_wire_partial"
            if wire_api_partial
            else "versioned_wire_missing"
        ),
        "wire_source_parity": wire_source_parity,
        "library_source_parity": library_source_parity,
        "consumer_type_count": len(findings),
        "blocking_consumer_type_count": len(blockers),
        "version_declared_consumer_type_count": sum(
            finding.classification == "version_declared" for finding in findings
        ),
        "ephemeral_or_unclassified_type_count": sum(
            finding.classification == "ephemeral_or_unclassified" for finding in findings
        ),
        "source_defaults": [asdict(state) for state in defaults],
        "blocking_consumers": [asdict(finding) for finding in blockers],
        "all_consumers": [asdict(finding) for finding in findings],
        "violations": violations,
        "decision": "fail_closed" if violations else "allow_current_posture",
        "default_flip_allowed": default_flip_allowed,
        "remediation": (
            "Keep engine/core SHA-256-v2 and persisted-wire sources byte-identical; add a typed derivation_version "
            "field to each serialized or signed type that carries raw EngineObjectId/SchemaId, "
            "bind that field into every signature preimage, or replace raw IDs with versioned wrappers."
        ),
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Guard EngineObjectId defaults using actual serialized/signed raw-ID fields"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        report = build_report()
        if args.output:
            write_report(args.output, report)
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        if report["violations"]:
            return 1
        if args.require_ready and not report["default_flip_allowed"]:
            return 1
        return 0
    except (OSError, ValueError, GuardError) as error:
        print(f"EngineObjectId versioning guard failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
