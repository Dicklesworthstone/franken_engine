#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::ga_exit_evidence_package::{
    BuildProvenance, ClaimMode, EvidenceArtifact, EvidenceDomain,
    GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION, GaExitEvidencePackage, ReproducibilityWitness,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn hash(label: &str) -> ContentHash {
    ContentHash::compute(label.as_bytes())
}

fn build_provenance() -> BuildProvenance {
    BuildProvenance {
        source_commit: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
        source_tree_hash: hash("integration-source-tree"),
        cargo_lock_hash: hash("integration-cargo-lock"),
        rustc_version: "rustc 1.88.0".to_string(),
        target_triple: "x86_64-unknown-linux-gnu".to_string(),
        cargo_profile: "release".to_string(),
        build_flags: vec!["-Clto=fat".to_string(), "-Cdebuginfo=0".to_string()],
        environment: BTreeMap::from([
            ("os".to_string(), "linux".to_string()),
            ("worker".to_string(), "rch-ts2".to_string()),
        ]),
    }
}

fn artifact(id: &str, domain: EvidenceDomain) -> EvidenceArtifact {
    EvidenceArtifact::required(
        id,
        domain,
        format!("franken-engine.{}.v1", domain.as_str()),
        hash(id),
        format!("ga/{id}.json"),
        ClaimMode::ExactShadow,
        format!("frankenctl ga replay {id}"),
    )
}

fn package() -> GaExitEvidencePackage {
    let mut package = GaExitEvidencePackage::new(
        "ga-exit-integration",
        SecurityEpoch::from_raw(904),
        build_provenance(),
    );
    for domain in EvidenceDomain::MANDATORY_FOR_GA.into_iter().rev() {
        package
            .add_evidence_artifact(artifact(domain.as_str(), domain))
            .expect("integration artifact should be valid");
    }
    package
        .add_reproducibility_witness(ReproducibilityWitness {
            witness_id: "external-replay".to_string(),
            schema_version: "franken-engine.external-replay.v1".to_string(),
            content_hash: hash("external-replay"),
            verifier: "third-party".to_string(),
            replay_instructions: vec![
                "frankenctl ga replay --manifest third_party_replay_manifest.json".to_string(),
                "cargo check -p frankenengine-engine".to_string(),
            ],
        })
        .expect("integration witness should be valid");
    package
        .record_schema_version("ga_evidence_index", GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION)
        .expect("schema pin should be valid");
    package
        .record_risk_disposition("RGC-904", "accepted-with-complete-evidence")
        .expect("risk disposition should be valid");
    package
        .add_third_party_replay_command("cargo check -p frankenengine-engine")
        .expect("replay command should be valid");
    package
}

#[test]
fn ga_exit_evidence_package_bytes_are_identical_across_two_runs() {
    let first = package()
        .deterministic_json_bytes()
        .expect("first package serialization should succeed");
    let second = package()
        .deterministic_json_bytes()
        .expect("second package serialization should succeed");
    assert_eq!(first, second);
}
