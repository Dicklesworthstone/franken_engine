#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Iterable
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_engine_object_id_derivation_versioning as guard


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_contract(path: Path, current_default: str) -> None:
    write(
        path,
        json.dumps(
            {
                "schema_version": "franken-engine.engine-object-id-derivation-contract.v2",
                "current_default": current_default,
                "target_default": "sha256_v2",
            }
        )
        + "\n",
    )


def wrapper() -> str:
    return "mod versioned;\nmod wire;\npub use versioned::*;\npub use wire::*;\n"


def versioned(default: str, extra: str = "") -> str:
    return f'''
pub struct SchemaId([u8; 32]);
pub struct EngineObjectId([u8; 32]);
pub enum ObjectIdDerivationVersion {{ LegacyV1, Sha256V2 }}
pub const CURRENT_OBJECT_ID_DERIVATION_VERSION: ObjectIdDerivationVersion = ObjectIdDerivationVersion::{default};
const A: &[u8] = b"FrankenEngine.SchemaId.sha256.v2";
const B: &[u8] = b"FrankenEngine.EngineObjectId.sha256.v2";
pub fn derive_versioned_schema_id() {{}}
pub fn derive_versioned_id() {{}}
pub fn verify_versioned_id() {{}}
{extra}
'''


def wire(extra: str = "") -> str:
    return f'''
pub struct PersistedEngineObjectId;
pub struct PersistedSchemaId;
impl PersistedEngineObjectId {{
    pub fn encode_binary(&self) {{}}
    pub fn decode_binary() {{}}
}}
{extra}
'''


def build(root: Path, scan_roots: Iterable[Path] | None = None) -> dict[str, object]:
    return guard.build_report(
        root=root,
        contract_path=root / "docs/engine_object_id_derivation_contract_v2.json",
        scan_roots=(
            (root / "crates/franken-engine/src", root / "crates/franken-core/src")
            if scan_roots is None else scan_roots
        ),
        engine_source=root / "crates/franken-engine/src/engine_object_id.rs",
        core_source=root / "crates/franken-core/src/engine_object_id.rs",
    )


def assert_workflow_reader(root: Path, report: dict[str, object], accepted: bool) -> None:
    workflow = ROOT / ".github/workflows/engine-object-id-versioning-guard.yml"
    match = re.search(
        r"^          python3 - [^\n]+ <<'PY'\n(.*?)^          PY$",
        workflow.read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, "workflow report reader was not found"
    report_path = root / "workflow-report.json"
    guard.write_report(report_path, report)
    completed = subprocess.run(
        [sys.executable, "-", str(report_path)],
        input=textwrap.dedent(match.group(1)),
        text=True,
        capture_output=True,
        check=False,
    )
    assert (completed.returncode == 0) is accepted, (
        completed.returncode, completed.stdout, completed.stderr
    )
    if accepted:
        assert f"blocking_consumers={report['blocking_consumer_type_count']}" in completed.stdout
    else:
        assert "engine_object_id_versioning_guard=pass" not in completed.stdout


def assert_scan_refused(root: Path, scan_roots: Iterable[Path], reason: str) -> None:
    try:
        build(root, scan_roots)
    except guard.GuardError as error:
        assert reason in str(error), error
    else:
        raise AssertionError(f"incomplete source scan was accepted: {reason}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="franken-engine-object-id-guard-") as temporary:
        root = Path(temporary)
        write_contract(root / "docs/engine_object_id_derivation_contract_v2.json", "legacy_v1")
        for crate in ("franken-engine", "franken-core"):
            write(root / f"crates/{crate}/src/engine_object_id.rs", wrapper())
            write(root / f"crates/{crate}/src/engine_object_id/versioned.rs", versioned("LegacyV1"))
            write(root / f"crates/{crate}/src/engine_object_id/wire.rs", wire())

        engine_root = root / "crates/franken-engine/src"
        core_root = root / "crates/franken-core/src"
        missing_root = root / "crates/franken-extension-host/src"
        empty_root = root / "empty-source-tree"
        empty_root.mkdir()
        assert_scan_refused(root, (), "no source roots")
        assert_scan_refused(root, (missing_root,), "not a directory")
        assert_scan_refused(root, (engine_root, core_root, missing_root), "not a directory")
        assert_scan_refused(root, (engine_root / "engine_object_id.rs",), "not a directory")
        assert_scan_refused(root, (engine_root, core_root, empty_root), "no Rust source files")
        with patch.object(guard.os, "scandir", side_effect=PermissionError("denied source tree")):
            assert_scan_refused(root, (engine_root,), "cannot enumerate Rust source tree")

        symbolic_root = root / "symlink-source-tree"
        symbolic_root.mkdir()
        (symbolic_root / "linked").symlink_to(engine_root, target_is_directory=True)
        assert_scan_refused(root, (symbolic_root,), "symlinked source directory")

        write(
            root / "crates/franken-engine/src/comment_only.rs",
            '''
use serde::{Serialize, Deserialize};
// same optimization as EngineObjectId
const NOTE: &str = "SchemaId and EngineObjectId";
#[derive(Serialize, Deserialize)]
struct Other { value: u64 }
''',
        )
        write(
            root / "crates/franken-engine/src/ephemeral.rs",
            '''
use crate::engine_object_id::EngineObjectId;
fn compare(left: EngineObjectId, right: EngineObjectId) -> bool { left == right }
''',
        )
        write(
            root / "crates/franken-engine/src/wire.rs",
            '''
use serde::{Serialize, Deserialize};
use crate::engine_object_id::{EngineObjectId, ObjectIdDerivationVersion};
#[derive(Serialize, Deserialize)]
struct BadWire { object_id: EngineObjectId }
#[derive(Serialize, Deserialize)]
struct GoodWire {
    derivation_version: ObjectIdDerivationVersion,
    object_id: EngineObjectId,
}
''',
        )
        write(
            root / "crates/franken-engine/src/signed.rs",
            '''
use crate::engine_object_id::{EngineObjectId, ObjectIdDerivationVersion};
struct BadSigned { object_id: EngineObjectId }
impl SignaturePreimage for BadSigned {
    fn preimage_bytes(&self) -> Vec<u8> { vec![] }
}
struct MissingBinding {
    derivation_version: ObjectIdDerivationVersion,
    object_id: EngineObjectId,
}
impl SignaturePreimage for MissingBinding {
    fn preimage_bytes(&self) -> Vec<u8> { self.object_id.0.to_vec() }
}
struct GoodSigned {
    derivation_version: ObjectIdDerivationVersion,
    object_id: EngineObjectId,
}
impl SignaturePreimage for GoodSigned {
    fn preimage_bytes(&self) -> Vec<u8> {
        format!("{:?}", self.derivation_version).into_bytes()
    }
}
''',
        )
        write(
            root / "crates/franken-engine/src/manual.rs",
            '''
use serde::{Serialize, Serializer};
use crate::engine_object_id::SchemaId;
struct Manual { schema_id: SchemaId }
impl Serialize for Manual {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { todo!() }
}
''',
        )

        report = build(root)
        assert report["decision"] == "allow_current_posture", report
        assert report["library_source_parity"] is True
        blockers = {
            (item["type_name"], tuple(item["blocking_reasons"]))
            for item in report["blocking_consumers"]
        }
        assert ("BadWire", ("serialized_raw_id_without_derivation_version",)) in blockers
        assert ("BadSigned", ("signed_raw_id_without_derivation_version",)) in blockers
        assert (
            "MissingBinding",
            ("derivation_version_not_bound_into_signature_preimage",),
        ) in blockers
        assert ("Manual", ("serialized_raw_id_without_derivation_version",)) in blockers
        assert not any(
            item["path"].endswith("comment_only.rs")
            for item in report["all_consumers"]
        )
        assert not any(
            item["path"].endswith("ephemeral.rs") and item["blocks_default_flip"]
            for item in report["all_consumers"]
        )
        consumers = {item["type_name"]: item for item in report["all_consumers"]}
        assert consumers["GoodWire"]["classification"] == "version_declared"
        assert consumers["GoodSigned"]["classification"] == "version_declared"
        assert report["default_flip_allowed"] is False
        assert report["blocking_consumer_type_count"] == len(blockers)
        assert report["scanned_source_file_count"] == 11
        assert report["scan_roots"] == [
            "crates/franken-core/src", "crates/franken-engine/src"
        ]
        assert report == build(root, (path for path in (core_root, engine_root)))
        assert report == build(root, (engine_root, core_root, engine_root))
        assert_workflow_reader(root, report, accepted=True)

        write(
            root / "crates/franken-engine/src/wire.rs",
            '''
use serde::{Serialize, Deserialize};
use crate::engine_object_id::{EngineObjectId, ObjectIdDerivationVersion};
#[derive(Serialize, Deserialize)]
struct GoodWire { derivation_version: ObjectIdDerivationVersion, object_id: EngineObjectId }
''',
        )
        write(
            root / "crates/franken-engine/src/signed.rs",
            '''
use crate::engine_object_id::{EngineObjectId, ObjectIdDerivationVersion};
struct GoodSigned { derivation_version: ObjectIdDerivationVersion, object_id: EngineObjectId }
impl SignaturePreimage for GoodSigned {
    fn preimage_bytes(&self) -> Vec<u8> {
        format!("{:?}", self.derivation_version).into_bytes()
    }
}
''',
        )
        write(
            root / "crates/franken-engine/src/manual.rs",
            '''
use crate::engine_object_id::VersionedSchemaId;
struct Manual { schema_id: VersionedSchemaId }
''',
        )
        ready = build(root)
        assert ready["blocking_consumer_type_count"] == 0, ready
        assert ready["default_flip_allowed"] is True, ready
        assert_workflow_reader(root, ready, accepted=False)

        core_versioned = root / "crates/franken-core/src/engine_object_id/versioned.rs"
        write(core_versioned, versioned("LegacyV1", "const DRIFT: u8 = 1;"))
        drift = build(root)
        assert drift["decision"] == "fail_closed"
        assert "sha256_v2_library_source_drift" in drift["violations"]

        write(core_versioned, versioned("LegacyV1"))
        core_wire = root / "crates/franken-core/src/engine_object_id/wire.rs"
        write(core_wire, wire("const DRIFT: u8 = 1;"))
        wire_drift = build(root)
        assert wire_drift["decision"] == "fail_closed"
        assert "versioned_id_wire_source_drift" in wire_drift["violations"]

        core_wire.unlink()
        partial_wire = build(root)
        assert partial_wire["decision"] == "fail_closed"
        assert "versioned_id_wire_api_parity_incomplete" in partial_wire["violations"]

    print("engine-object-id derivation-versioning guard smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
