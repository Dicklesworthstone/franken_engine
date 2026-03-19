//! Enrichment integration tests (batch 2) for the `reproducibility_provenance_pack` module.
//!
//! Covers integrity verification, builder patterns, fingerprint sensitivity,
//! legal assessment edge cases, report generation, and serde round-trips.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::reproducibility_provenance_pack::{
    ArtifactEntry, ArtifactKind, ArtifactManifest, BuildEnvironment, DependencyEntry,
    DependencySnapshot, GitFingerprint, LegalAssessment, LicenseFinding, LicenseRisk,
    PackBuilder, PackIntegrityResult, ReproducibilityReport, ToolchainFingerprint,
    generate_report, SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn test_toolchain() -> ToolchainFingerprint {
    ToolchainFingerprint {
        rustc_version: "1.79.0-nightly".to_string(),
        cargo_version: "1.79.0-nightly".to_string(),
        llvm_version: Some("18.1.0".to_string()),
        linker: "cc".to_string(),
        target_triple: "x86_64-unknown-linux-gnu".to_string(),
        edition: "2024".to_string(),
        profile: "release".to_string(),
        rustflags: vec!["-C linker=cc".to_string()],
    }
}

fn test_git() -> GitFingerprint {
    GitFingerprint {
        commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
        tree_hash: "1234567890abcdef1234567890abcdef12345678".to_string(),
        branch: Some("main".to_string()),
        dirty: false,
        tags: vec!["v0.1.0".to_string()],
    }
}

fn test_env() -> BuildEnvironment {
    BuildEnvironment {
        os_name: "Linux".to_string(),
        os_version: "6.8.0".to_string(),
        arch: "x86_64".to_string(),
        cpu_count: 16,
        memory_mb: 65536,
        container_digest: None,
        ci_system: Some("github-actions".to_string()),
        ci_run_id: Some("12345".to_string()),
        toolchain: test_toolchain(),
        git: test_git(),
        extra: BTreeMap::new(),
    }
}

fn test_artifact(path: &str, kind: ArtifactKind) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_string(),
        kind,
        content_hash: format!("hash_{path}"),
        size_bytes: 1024,
        redacted: false,
    }
}

fn test_dep(name: &str, version: &str) -> DependencyEntry {
    DependencyEntry {
        name: name.to_string(),
        version: version.to_string(),
        source: "crates.io".to_string(),
        checksum: Some(format!("ck_{name}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.reproducibility-provenance.v1");
}

#[test]
fn enrichment_toolchain_hash_deterministic() {
    let tc = test_toolchain();
    let h1 = tc.content_hash();
    let h2 = tc.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_toolchain_hash_differs_on_edition() {
    let mut tc1 = test_toolchain();
    tc1.edition = "2021".to_string();
    let tc2 = test_toolchain(); // edition = "2024"
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_hash_differs_on_target() {
    let mut tc1 = test_toolchain();
    tc1.target_triple = "aarch64-unknown-linux-gnu".to_string();
    let tc2 = test_toolchain();
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_serde_round_trip() {
    let tc = test_toolchain();
    let json = serde_json::to_string(&tc).unwrap();
    let back: ToolchainFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, back);
}

#[test]
fn enrichment_git_hash_deterministic() {
    let git = test_git();
    assert_eq!(git.content_hash(), git.content_hash());
}

#[test]
fn enrichment_git_hash_differs_on_tree_hash() {
    let mut g1 = test_git();
    g1.tree_hash = "0".repeat(40);
    let g2 = test_git();
    assert_ne!(g1.content_hash(), g2.content_hash());
}

#[test]
fn enrichment_git_serde_round_trip() {
    let git = test_git();
    let json = serde_json::to_string(&git).unwrap();
    let back: GitFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(git, back);
}

#[test]
fn enrichment_build_env_hash_deterministic() {
    let env = test_env();
    assert_eq!(env.content_hash(), env.content_hash());
}

#[test]
fn enrichment_build_env_hash_differs_on_memory() {
    let mut e1 = test_env();
    e1.memory_mb = 32768;
    let e2 = test_env();
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_build_env_hash_differs_on_arch() {
    let mut e1 = test_env();
    e1.arch = "aarch64".to_string();
    let e2 = test_env();
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_build_env_serde_round_trip() {
    let env = test_env();
    let json = serde_json::to_string(&env).unwrap();
    let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn enrichment_artifact_kind_display_unique() {
    let displays: BTreeSet<String> = [
        ArtifactKind::Source, ArtifactKind::Binary, ArtifactKind::Config,
        ArtifactKind::TestFixture, ArtifactKind::Evidence, ArtifactKind::LockFile,
        ArtifactKind::Documentation, ArtifactKind::Legal,
    ].iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_artifact_kind_serde_all() {
    for k in [
        ArtifactKind::Source, ArtifactKind::Binary, ArtifactKind::Config,
        ArtifactKind::TestFixture, ArtifactKind::Evidence, ArtifactKind::LockFile,
        ArtifactKind::Documentation, ArtifactKind::Legal,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn enrichment_manifest_sorts_and_computes_totals() {
    let artifacts = vec![
        test_artifact("z.rs", ArtifactKind::Source),
        test_artifact("a.rs", ArtifactKind::Source),
        test_artifact("m.rs", ArtifactKind::Source),
    ];
    let manifest = ArtifactManifest::from_artifacts("pack-sort".to_string(), artifacts);
    assert_eq!(manifest.artifacts[0].path, "a.rs");
    assert_eq!(manifest.artifacts[1].path, "m.rs");
    assert_eq!(manifest.artifacts[2].path, "z.rs");
    assert_eq!(manifest.total_count, 3);
    assert_eq!(manifest.total_size_bytes, 3072);
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_manifest_hash_deterministic() {
    let arts = vec![test_artifact("a.rs", ArtifactKind::Source)];
    let m1 = ArtifactManifest::from_artifacts("p".to_string(), arts.clone());
    let m2 = ArtifactManifest::from_artifacts("p".to_string(), arts);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn enrichment_manifest_hash_differs_on_pack_id() {
    let arts = vec![test_artifact("a.rs", ArtifactKind::Source)];
    let m1 = ArtifactManifest::from_artifacts("pack-A".to_string(), arts.clone());
    let m2 = ArtifactManifest::from_artifacts("pack-B".to_string(), arts);
    assert_ne!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn enrichment_dep_snapshot_sorts_entries() {
    let entries = vec![
        test_dep("z_crate", "1.0"),
        test_dep("a_crate", "2.0"),
    ];
    let snap = DependencySnapshot::from_entries(entries);
    assert_eq!(snap.dependencies[0].name, "a_crate");
    assert_eq!(snap.dependencies[1].name, "z_crate");
    assert_eq!(snap.total_count, 2);
    assert_eq!(snap.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_dep_snapshot_hash_deterministic() {
    let entries = vec![test_dep("serde", "1.0")];
    let s1 = DependencySnapshot::from_entries(entries.clone());
    let s2 = DependencySnapshot::from_entries(entries);
    assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_dep_snapshot_hash_differs_on_source() {
    let mut d1 = test_dep("x", "1.0");
    d1.source = "crates.io".to_string();
    let mut d2 = test_dep("x", "1.0");
    d2.source = "git".to_string();
    let s1 = DependencySnapshot::from_entries(vec![d1]);
    let s2 = DependencySnapshot::from_entries(vec![d2]);
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_license_risk_ordering() {
    assert!(LicenseRisk::None < LicenseRisk::Low);
    assert!(LicenseRisk::Low < LicenseRisk::Medium);
    assert!(LicenseRisk::Medium < LicenseRisk::High);
}

#[test]
fn enrichment_license_risk_serde_all() {
    for r in [LicenseRisk::None, LicenseRisk::Low, LicenseRisk::Medium, LicenseRisk::High] {
        let json = serde_json::to_string(&r).unwrap();
        let back: LicenseRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn enrichment_legal_no_findings_no_review() {
    let assessment = LegalAssessment::from_findings(vec![]);
    assert!(!assessment.has_high_risk);
    assert!(!assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::None);
    assert!(assessment.summary.contains("No license concerns"));
}

#[test]
fn enrichment_legal_high_risk_triggers_review() {
    let findings = vec![LicenseFinding {
        dependency: "gpl".to_string(),
        license_spdx: "GPL-3.0".to_string(),
        risk: LicenseRisk::High,
        notes: String::new(),
    }];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(assessment.has_high_risk);
    assert!(assessment.review_required);
    assert!(assessment.summary.contains("LEGAL REVIEW REQUIRED"));
}

#[test]
fn enrichment_legal_medium_risk_recommended() {
    let findings = vec![LicenseFinding {
        dependency: "lgpl".to_string(),
        license_spdx: "LGPL-2.1".to_string(),
        risk: LicenseRisk::Medium,
        notes: String::new(),
    }];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(!assessment.has_high_risk);
    assert!(assessment.review_required);
    assert!(assessment.summary.contains("recommended"));
}

#[test]
fn enrichment_legal_sorts_findings_by_dependency() {
    let findings = vec![
        LicenseFinding { dependency: "z".into(), license_spdx: "MIT".into(), risk: LicenseRisk::None, notes: String::new() },
        LicenseFinding { dependency: "a".into(), license_spdx: "MIT".into(), risk: LicenseRisk::None, notes: String::new() },
    ];
    let assessment = LegalAssessment::from_findings(findings);
    assert_eq!(assessment.findings[0].dependency, "a");
    assert_eq!(assessment.findings[1].dependency, "z");
}

#[test]
fn enrichment_builder_no_env_returns_none() {
    let builder = PackBuilder::new("FRX-00".to_string(), test_epoch());
    assert!(builder.build().is_none());
}

#[test]
fn enrichment_builder_minimal_pack() {
    let pack = PackBuilder::new("FRX-min".to_string(), test_epoch())
        .environment(test_env())
        .build()
        .unwrap();
    assert!(pack.pack_id.starts_with("pack-"));
    assert_eq!(pack.claim_id, "FRX-min");
    assert_eq!(pack.epoch, test_epoch());
    assert_eq!(pack.artifact_count(), 0);
    assert_eq!(pack.dependency_count(), 0);
    assert!(pack.legal.is_none());
    assert!(!pack.requires_legal_review());
    assert_eq!(pack.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_builder_with_artifacts_deps_legal() {
    let pack = PackBuilder::new("FRX-full".to_string(), test_epoch())
        .environment(test_env())
        .artifact(test_artifact("src/main.rs", ArtifactKind::Source))
        .artifact(test_artifact("Cargo.toml", ArtifactKind::Config))
        .dependency(test_dep("serde", "1.0"))
        .license_finding(LicenseFinding {
            dependency: "gpl_dep".into(),
            license_spdx: "GPL-3.0".into(),
            risk: LicenseRisk::High,
            notes: "copyleft".into(),
        })
        .build()
        .unwrap();
    assert_eq!(pack.artifact_count(), 2);
    assert_eq!(pack.dependency_count(), 1);
    assert!(pack.requires_legal_review());
}

#[test]
fn enrichment_pack_integrity_valid() {
    let pack = PackBuilder::new("FRX-int".to_string(), test_epoch())
        .environment(test_env())
        .artifact(test_artifact("a.rs", ArtifactKind::Source))
        .dependency(test_dep("serde", "1.0"))
        .build()
        .unwrap();
    let result = pack.verify_integrity();
    assert!(result.all_valid);
    assert!(result.pack_hash_valid);
    assert!(result.manifest_count_valid);
    assert!(result.manifest_size_valid);
    assert!(result.artifacts_sorted);
    assert!(result.dependencies_sorted);
}

#[test]
fn enrichment_pack_hash_deterministic() {
    let p1 = PackBuilder::new("FRX-det".to_string(), test_epoch())
        .environment(test_env())
        .build()
        .unwrap();
    let p2 = PackBuilder::new("FRX-det".to_string(), test_epoch())
        .environment(test_env())
        .build()
        .unwrap();
    assert_eq!(p1.pack_hash, p2.pack_hash);
    assert_eq!(p1.pack_id, p2.pack_id);
}

#[test]
fn enrichment_pack_hash_differs_by_claim() {
    let p1 = PackBuilder::new("FRX-a".to_string(), test_epoch())
        .environment(test_env()).build().unwrap();
    let p2 = PackBuilder::new("FRX-b".to_string(), test_epoch())
        .environment(test_env()).build().unwrap();
    assert_ne!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn enrichment_pack_hash_differs_by_epoch() {
    let p1 = PackBuilder::new("FRX-ep".to_string(), SecurityEpoch::from_raw(1))
        .environment(test_env()).build().unwrap();
    let p2 = PackBuilder::new("FRX-ep".to_string(), SecurityEpoch::from_raw(2))
        .environment(test_env()).build().unwrap();
    assert_ne!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn enrichment_pack_integrity_fails_tampered_hash() {
    let mut pack = PackBuilder::new("FRX-tam".to_string(), test_epoch())
        .environment(test_env())
        .artifact(test_artifact("a.rs", ArtifactKind::Source))
        .build()
        .unwrap();
    pack.pack_hash = "deadbeef".to_string();
    let result = pack.verify_integrity();
    assert!(!result.pack_hash_valid);
    assert!(!result.all_valid);
}

#[test]
fn enrichment_pack_integrity_fails_tampered_count() {
    let mut pack = PackBuilder::new("FRX-cnt".to_string(), test_epoch())
        .environment(test_env())
        .artifact(test_artifact("a.rs", ArtifactKind::Source))
        .build()
        .unwrap();
    pack.manifest.total_count = 999;
    let result = pack.verify_integrity();
    assert!(!result.manifest_count_valid);
    assert!(!result.all_valid);
}

#[test]
fn enrichment_pack_serde_round_trip() {
    let pack = PackBuilder::new("FRX-serde".to_string(), test_epoch())
        .environment(test_env())
        .artifact(test_artifact("a.rs", ArtifactKind::Source))
        .dependency(test_dep("serde", "1.0"))
        .build()
        .unwrap();
    let json = serde_json::to_string(&pack).unwrap();
    let back: frankenengine_engine::reproducibility_provenance_pack::ReproducibilityPack =
        serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
}

#[test]
fn enrichment_report_from_valid_pack() {
    let pack = PackBuilder::new("FRX-rpt".to_string(), test_epoch())
        .environment(test_env())
        .artifact(test_artifact("a.rs", ArtifactKind::Source))
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.claim_id, "FRX-rpt");
    assert!(report.integrity.all_valid);
    assert_eq!(report.artifact_count, 1);
    assert!(!report.git_dirty);
    assert!(!report.legal_review_required);
}

#[test]
fn enrichment_report_hash_deterministic() {
    let pack = PackBuilder::new("FRX-rptdet".to_string(), test_epoch())
        .environment(test_env())
        .build()
        .unwrap();
    let r1 = generate_report(&pack);
    let r2 = generate_report(&pack);
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn enrichment_report_shows_legal_risk() {
    let pack = PackBuilder::new("FRX-rptrisk".to_string(), test_epoch())
        .environment(test_env())
        .license_finding(LicenseFinding {
            dependency: "gpl".into(),
            license_spdx: "GPL-3.0".into(),
            risk: LicenseRisk::High,
            notes: String::new(),
        })
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(report.legal_review_required);
    assert_eq!(report.max_license_risk, Some(LicenseRisk::High));
}

#[test]
fn enrichment_report_dirty_git() {
    let mut env = test_env();
    env.git.dirty = true;
    let pack = PackBuilder::new("FRX-dirty".to_string(), test_epoch())
        .environment(env)
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(report.git_dirty);
}

#[test]
fn enrichment_report_serde_round_trip() {
    let pack = PackBuilder::new("FRX-rptserde".to_string(), test_epoch())
        .environment(test_env())
        .build()
        .unwrap();
    let report = generate_report(&pack);
    let json = serde_json::to_string(&report).unwrap();
    let back: ReproducibilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_integrity_result_serde_round_trip() {
    let result = PackIntegrityResult {
        pack_hash_valid: true,
        manifest_count_valid: true,
        manifest_size_valid: true,
        artifacts_sorted: true,
        dependencies_sorted: true,
        all_valid: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: PackIntegrityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_env_with_extra_metadata() {
    let mut env = test_env();
    env.extra.insert("custom_key".to_string(), "custom_val".to_string());
    let pack = PackBuilder::new("FRX-extra".to_string(), test_epoch())
        .environment(env)
        .build()
        .unwrap();
    assert!(pack.verify_integrity().all_valid);
}

#[test]
fn enrichment_artifact_redacted_field_preserved() {
    let entry = ArtifactEntry {
        path: "secrets.txt".to_string(),
        kind: ArtifactKind::Config,
        content_hash: "redacted_hash".to_string(),
        size_bytes: 256,
        redacted: true,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert!(back.redacted);
}

#[test]
fn enrichment_dependency_no_checksum_preserved() {
    let dep = DependencyEntry {
        name: "local".to_string(),
        version: "0.1.0".to_string(),
        source: "path".to_string(),
        checksum: None,
    };
    let json = serde_json::to_string(&dep).unwrap();
    let back: DependencyEntry = serde_json::from_str(&json).unwrap();
    assert!(back.checksum.is_none());
}
