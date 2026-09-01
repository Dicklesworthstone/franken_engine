#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

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
    return "mod versioned;\npub use versioned::*;\n"


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


def build(root: Path) -> dict[str, object]:
    return guard.build_report(
        root=root,
        contract_path=root / "docs/engine_object_id_derivation_contract_v2.json",
        scan_roots=(root / "crates/franken-engine/src", root / "crates/franken-core/src"),
        engine_source=root / "crates/franken-engine/src/engine_object_id.rs",
        core_source=root / "crates/franken-core/src/engine_object_id.rs",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="franken-engine-object-id-guard-") as temporary:
        root = Path(temporary)
        write_contract(root / "docs/engine_object_id_derivation_contract_v2.json", "legacy_v1")
        for crate in ("franken-engine", "franken-core"):
            write(root / f"crates/{crate}/src/engine_object_id.rs", wrapper())
            write(
                root / f"crates/{crate}/src/engine_object_id/versioned.rs",
                versioned("LegacyV1"),
            )

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

        core_versioned = root / "crates/franken-core/src/engine_object_id/versioned.rs"
        write(core_versioned, versioned("LegacyV1", "const DRIFT: u8 = 1;"))
        drift = build(root)
        assert drift["decision"] == "fail_closed"
        assert "sha256_v2_library_source_drift" in drift["violations"]

    print("engine-object-id derivation-versioning guard smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
