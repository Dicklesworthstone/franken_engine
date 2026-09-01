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
            },
            indent=2,
        )
        + "\n",
    )


def legacy_source() -> str:
    return """
pub struct SchemaId([u8; 32]);
pub struct EngineObjectId([u8; 32]);
fn schema(definition: &[u8]) -> SchemaId { Self(deterministic_hash(definition)) }
fn object(preimage: Vec<u8>) -> Result<EngineObjectId, ()> {
    Ok(EngineObjectId(deterministic_hash(&preimage)))
}
"""


def v2_source() -> str:
    return """
pub struct SchemaId([u8; 32]);
pub struct EngineObjectId([u8; 32]);
const SCHEMA_DOMAIN: &[u8] = b"FrankenEngine.SchemaId.sha256.v2";
const OBJECT_DOMAIN: &[u8] = b"FrankenEngine.EngineObjectId.sha256.v2";
"""


def build(root: Path) -> dict[str, object]:
    contract = root / "docs/engine_object_id_derivation_contract_v2.json"
    engine = root / "crates/franken-engine/src/engine_object_id.rs"
    core = root / "crates/franken-core/src/engine_object_id.rs"
    scan_roots = (
        root / "crates/franken-engine/src",
        root / "crates/franken-core/src",
        root / "crates/franken-extension-host/src",
    )
    return guard.build_report(
        root=root,
        contract_path=contract,
        scan_roots=scan_roots,
        engine_source=engine,
        core_source=core,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="franken-engine-object-id-guard-") as temporary:
        root = Path(temporary)
        contract = root / "docs/engine_object_id_derivation_contract_v2.json"
        engine = root / "crates/franken-engine/src/engine_object_id.rs"
        core = root / "crates/franken-core/src/engine_object_id.rs"
        persisted = root / "crates/franken-engine/src/persisted_evidence.rs"
        ephemeral = root / "crates/franken-engine/src/ephemeral_cache.rs"

        write_contract(contract, "legacy_v1")
        write(engine, legacy_source())
        write(core, legacy_source())
        write(
            persisted,
            """
use serde::{Deserialize, Serialize};
use crate::engine_object_id::EngineObjectId;
#[derive(Serialize, Deserialize)]
struct EvidenceRecord { object_id: EngineObjectId }
""",
        )
        write(
            ephemeral,
            """
use crate::engine_object_id::EngineObjectId;
fn compare(left: EngineObjectId, right: EngineObjectId) -> bool { left == right }
""",
        )

        report = build(root)
        assert report["decision"] == "allow_current_posture"
        assert report["migration_state"] == "blocked_on_unversioned_persisted_consumers"
        assert report["blocking_consumer_count"] == 1
        assert report["default_flip_allowed"] is False
        assert report["violations"] == []
        assert report["blocking_consumers"][0]["path"].endswith("persisted_evidence.rs")

        write_contract(contract, "sha256_v2")
        write(engine, v2_source())
        write(core, v2_source())
        unsafe_flip = build(root)
        assert unsafe_flip["decision"] == "fail_closed"
        assert (
            "sha256_v2_default_visible_with_unversioned_persisted_consumers"
            in unsafe_flip["violations"]
        )
        assert unsafe_flip["default_flip_allowed"] is False

        write(
            persisted,
            """
use serde::{Deserialize, Serialize};
use crate::engine_object_id::EngineObjectId;
#[derive(Serialize, Deserialize)]
struct EvidenceRecord {
    derivation_version: String,
    object_id: EngineObjectId,
}
""",
        )
        ready = build(root)
        assert ready["decision"] == "allow_current_posture"
        assert ready["migration_state"] == "ready_for_explicit_default_flip_review"
        assert ready["blocking_consumer_count"] == 0
        assert ready["default_flip_allowed"] is True

        write_contract(contract, "legacy_v1")
        stale_contract = build(root)
        assert stale_contract["decision"] == "fail_closed"
        assert (
            "contract_declares_legacy_v1_but_library_default_drifted"
            in stale_contract["violations"]
        )

    print("engine-object-id derivation-versioning guard smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
