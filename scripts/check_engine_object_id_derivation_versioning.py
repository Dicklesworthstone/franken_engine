#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
REPORT_SCHEMA = "franken-engine.engine-object-id-consumer-versioning-report.v1"
SYMBOL_PATTERN = re.compile(r"\b(?:EngineObjectId|SchemaId)\b")
DERIVATION_VERSION_PATTERN = re.compile(r"\bderivation_version\b", re.IGNORECASE)
SERDE_PATTERN = re.compile(r"\b(?:Serialize|Deserialize)\b")
PERSISTENCE_HINTS = (
    "attest",
    "checkpoint",
    "evidence",
    "journal",
    "manifest",
    "persist",
    "receipt",
    "recovery",
    "replay",
    "revocation",
    "signaturepreimage",
    "snapshot",
    "transparency",
)
EXCLUDED_FILES = {
    "crates/franken-engine/src/engine_object_id.rs",
    "crates/franken-core/src/engine_object_id.rs",
    "crates/franken-engine/src/bin/franken_engine_object_id_migration.rs",
}


class GuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class ConsumerFinding:
    path: str
    symbols: tuple[str, ...]
    serde_visible: bool
    signature_preimage_visible: bool
    persistence_hints: tuple[str, ...]
    declares_derivation_version: bool
    classification: str
    blocks_default_flip: bool


@dataclass(frozen=True)
class SourceDefaultState:
    path: str
    legacy_schema_default_visible: bool
    legacy_object_default_visible: bool
    sha256_v2_default_visible: bool


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


def classify_consumer(path: Path, root: Path = ROOT) -> ConsumerFinding | None:
    rel = relative(path, root)
    if rel in EXCLUDED_FILES:
        return None
    text = path.read_text(encoding="utf-8")
    symbols = tuple(sorted(set(SYMBOL_PATTERN.findall(text))))
    if not symbols:
        return None
    folded = text.lower()
    hints = tuple(sorted(hint for hint in PERSISTENCE_HINTS if hint in folded))
    serde_visible = bool(SERDE_PATTERN.search(text))
    signature_preimage_visible = "SignaturePreimage" in text
    declares_version = bool(DERIVATION_VERSION_PATTERN.search(text))
    persistence_visible = serde_visible or signature_preimage_visible or bool(hints)
    if declares_version:
        classification = "version_declared"
    elif persistence_visible:
        classification = "persisted_or_signed_unversioned"
    else:
        classification = "ephemeral_or_unclassified"
    return ConsumerFinding(
        path=rel,
        symbols=symbols,
        serde_visible=serde_visible,
        signature_preimage_visible=signature_preimage_visible,
        persistence_hints=hints,
        declares_derivation_version=declares_version,
        classification=classification,
        blocks_default_flip=persistence_visible and not declares_version,
    )


def source_default_state(path: Path, root: Path = ROOT) -> SourceDefaultState:
    text = path.read_text(encoding="utf-8")
    return SourceDefaultState(
        path=relative(path, root),
        legacy_schema_default_visible="Self(deterministic_hash(definition))" in text,
        legacy_object_default_visible="Ok(EngineObjectId(deterministic_hash(&preimage)))" in text,
        sha256_v2_default_visible=(
            "FrankenEngine.SchemaId.sha256.v2" in text
            or "FrankenEngine.EngineObjectId.sha256.v2" in text
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
        if (finding := classify_consumer(path, root)) is not None
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
    v2_default_visible = any(state.sha256_v2_default_visible for state in defaults)
    if blockers:
        migration_state = "blocked_on_unversioned_persisted_consumers"
    else:
        migration_state = "ready_for_explicit_default_flip_review"
    violations: list[str] = []
    if current_default == "legacy_v1" and not legacy_default_consistent:
        violations.append("contract_declares_legacy_v1_but_library_default_drifted")
    if blockers and (current_default == "sha256_v2" or v2_default_visible):
        violations.append("sha256_v2_default_visible_with_unversioned_persisted_consumers")
    if current_default not in {"legacy_v1", "sha256_v2"}:
        violations.append("unsupported_current_default")
    if target_default != "sha256_v2":
        violations.append("unexpected_target_default")
    return {
        "schema_version": REPORT_SCHEMA,
        "contract_path": relative(contract_path, root),
        "current_default": current_default,
        "target_default": target_default,
        "migration_state": migration_state,
        "consumer_count": len(findings),
        "blocking_consumer_count": len(blockers),
        "version_declared_consumer_count": sum(
            finding.declares_derivation_version for finding in findings
        ),
        "ephemeral_or_unclassified_count": sum(
            finding.classification == "ephemeral_or_unclassified" for finding in findings
        ),
        "source_defaults": [asdict(state) for state in defaults],
        "blocking_consumers": [asdict(finding) for finding in blockers],
        "all_consumers": [asdict(finding) for finding in findings],
        "violations": violations,
        "decision": "fail_closed" if violations else "allow_current_posture",
        "default_flip_allowed": not blockers and not violations,
        "remediation": (
            "Add an explicit derivation_version field to every persisted or signed consumer, "
            "or prove and document that the value is ephemeral, before changing the default."
        ),
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Guard the EngineObjectId default until persisted consumers declare derivation versions"
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
