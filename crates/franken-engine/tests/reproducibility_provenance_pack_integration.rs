//! Integration tests for `frankenengine_engine::reproducibility_provenance_pack`.
//!
//! Exercises the reproducibility/provenance pack automation from the public
//! crate boundary: ToolchainFingerprint, GitFingerprint, BuildEnvironment,
//! ArtifactKind, ArtifactEntry, ArtifactManifest, DependencyEntry,
//! DependencySnapshot, LicenseRisk, LicenseFinding, LegalAssessment,
//! ReproducibilityPack, PackBuilder, PackIntegrityResult, generate_report.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;

use frankenengine_engine::reproducibility_provenance_pack::{
    ArtifactEntry, ArtifactKind, ArtifactManifest, BuildEnvironment, DependencyEntry,
    DependencySnapshot, GitFingerprint, LegalAssessment, LicenseFinding, LicenseRisk, PackBuilder,
    ReproducibilityPack, SCHEMA_VERSION, ToolchainFingerprint, generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(10)
}

fn sample_toolchain() -> ToolchainFingerprint {
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

fn sample_git() -> GitFingerprint {
    GitFingerprint {
        commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
        tree_hash: "1234567890abcdef1234567890abcdef12345678".to_string(),
        branch: Some("main".to_string()),
        dirty: false,
        tags: vec!["v0.1.0".to_string()],
    }
}

fn sample_env() -> BuildEnvironment {
    BuildEnvironment {
        os_name: "Linux".to_string(),
        os_version: "6.8.0".to_string(),
        arch: "x86_64".to_string(),
        cpu_count: 16,
        memory_mb: 65536,
        container_digest: None,
        ci_system: Some("github-actions".to_string()),
        ci_run_id: Some("12345".to_string()),
        toolchain: sample_toolchain(),
        git: sample_git(),
        extra: BTreeMap::new(),
    }
}

fn sample_artifact(path: &str, kind: ArtifactKind) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_string(),
        kind,
        content_hash: format!("hash_{path}"),
        size_bytes: 1024,
        redacted: false,
    }
}

fn sample_dep(name: &str, version: &str) -> DependencyEntry {
    DependencyEntry {
        name: name.to_string(),
        version: version.to_string(),
        source: "crates.io".to_string(),
        checksum: Some(format!("ck_{name}")),
    }
}

fn build_simple_pack() -> ReproducibilityPack {
    PackBuilder::new("claim-01".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("src/main.rs", ArtifactKind::Source))
        .artifact(sample_artifact("target/release/app", ArtifactKind::Binary))
        .dependency(sample_dep("serde", "1.0.200"))
        .dependency(sample_dep("sha2", "0.10.8"))
        .build()
        .expect("build pack")
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn schema_version_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

// ── ToolchainFingerprint ────────────────────────────────────────────────

#[test]
fn toolchain_content_hash_deterministic() {
    let tc = sample_toolchain();
    assert_eq!(tc.content_hash(), tc.content_hash());
    assert!(!tc.content_hash().is_empty());
}

#[test]
fn toolchain_content_hash_changes_on_version() {
    let tc1 = sample_toolchain();
    let mut tc2 = sample_toolchain();
    tc2.rustc_version = "1.80.0-nightly".to_string();
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn toolchain_serde_roundtrip() {
    let tc = sample_toolchain();
    let json = serde_json::to_string(&tc).unwrap();
    let back: ToolchainFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tc);
}

// ── GitFingerprint ──────────────────────────────────────────────────────

#[test]
fn git_content_hash_deterministic() {
    let g = sample_git();
    assert_eq!(g.content_hash(), g.content_hash());
}

#[test]
fn git_content_hash_changes_on_sha() {
    let g1 = sample_git();
    let mut g2 = sample_git();
    g2.commit_sha = "0000000000000000000000000000000000000000".to_string();
    assert_ne!(g1.content_hash(), g2.content_hash());
}

#[test]
fn git_dirty_changes_hash() {
    let mut g1 = sample_git();
    g1.dirty = false;
    let mut g2 = sample_git();
    g2.dirty = true;
    assert_ne!(g1.content_hash(), g2.content_hash());
}

#[test]
fn git_serde_roundtrip() {
    let g = sample_git();
    let json = serde_json::to_string(&g).unwrap();
    let back: GitFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, g);
}

// ── BuildEnvironment ────────────────────────────────────────────────────

#[test]
fn env_content_hash_deterministic() {
    let e = sample_env();
    assert_eq!(e.content_hash(), e.content_hash());
}

#[test]
fn env_serde_roundtrip() {
    let e = sample_env();
    let json = serde_json::to_string(&e).unwrap();
    let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ── ArtifactKind ────────────────────────────────────────────────────────

#[test]
fn artifact_kind_display() {
    assert_eq!(ArtifactKind::Source.to_string(), "source");
    assert_eq!(ArtifactKind::Binary.to_string(), "binary");
    assert_eq!(ArtifactKind::Config.to_string(), "config");
    assert_eq!(ArtifactKind::TestFixture.to_string(), "test_fixture");
    assert_eq!(ArtifactKind::Evidence.to_string(), "evidence");
    assert_eq!(ArtifactKind::LockFile.to_string(), "lock_file");
    assert_eq!(ArtifactKind::Documentation.to_string(), "documentation");
    assert_eq!(ArtifactKind::Legal.to_string(), "legal");
}

#[test]
fn artifact_kind_serde_roundtrip() {
    for kind in [
        ArtifactKind::Source,
        ArtifactKind::Binary,
        ArtifactKind::Config,
        ArtifactKind::TestFixture,
        ArtifactKind::Evidence,
        ArtifactKind::LockFile,
        ArtifactKind::Documentation,
        ArtifactKind::Legal,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

// ── ArtifactManifest ────────────────────────────────────────────────────

#[test]
fn artifact_manifest_sorts_by_path() {
    let manifest = ArtifactManifest::from_artifacts(
        "pack-1".to_string(),
        vec![
            sample_artifact("zzz.rs", ArtifactKind::Source),
            sample_artifact("aaa.rs", ArtifactKind::Source),
        ],
    );
    assert_eq!(manifest.artifacts[0].path, "aaa.rs");
    assert_eq!(manifest.artifacts[1].path, "zzz.rs");
}

#[test]
fn artifact_manifest_computes_totals() {
    let manifest = ArtifactManifest::from_artifacts(
        "pack-1".to_string(),
        vec![
            sample_artifact("a.rs", ArtifactKind::Source),
            sample_artifact("b.rs", ArtifactKind::Source),
        ],
    );
    assert_eq!(manifest.total_count, 2);
    assert_eq!(manifest.total_size_bytes, 2048); // 1024 * 2
    assert!(!manifest.manifest_hash.is_empty());
}

#[test]
fn artifact_manifest_serde_roundtrip() {
    let manifest = ArtifactManifest::from_artifacts(
        "pack-1".to_string(),
        vec![sample_artifact("main.rs", ArtifactKind::Source)],
    );
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ArtifactManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ── DependencySnapshot ──────────────────────────────────────────────────

#[test]
fn dep_snapshot_sorts_by_name() {
    let snapshot = DependencySnapshot::from_entries(vec![
        sample_dep("serde", "1.0.200"),
        sample_dep("anyhow", "1.0.86"),
    ]);
    assert_eq!(snapshot.dependencies[0].name, "anyhow");
    assert_eq!(snapshot.dependencies[1].name, "serde");
}

#[test]
fn dep_snapshot_computes_hash() {
    let s1 = DependencySnapshot::from_entries(vec![sample_dep("serde", "1.0.200")]);
    let s2 = DependencySnapshot::from_entries(vec![sample_dep("serde", "1.0.200")]);
    assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
    assert!(!s1.snapshot_hash.is_empty());
}

#[test]
fn dep_snapshot_serde_roundtrip() {
    let snapshot = DependencySnapshot::from_entries(vec![sample_dep("sha2", "0.10.8")]);
    let json = serde_json::to_string(&snapshot).unwrap();
    let back: DependencySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, snapshot);
}

// ── LicenseRisk ─────────────────────────────────────────────────────────

#[test]
fn license_risk_display() {
    assert_eq!(LicenseRisk::None.to_string(), "none");
    assert_eq!(LicenseRisk::Low.to_string(), "low");
    assert_eq!(LicenseRisk::Medium.to_string(), "medium");
    assert_eq!(LicenseRisk::High.to_string(), "high");
}

#[test]
fn license_risk_ordering() {
    assert!(LicenseRisk::None < LicenseRisk::Low);
    assert!(LicenseRisk::Low < LicenseRisk::Medium);
    assert!(LicenseRisk::Medium < LicenseRisk::High);
}

#[test]
fn license_risk_serde_roundtrip() {
    for risk in [
        LicenseRisk::None,
        LicenseRisk::Low,
        LicenseRisk::Medium,
        LicenseRisk::High,
    ] {
        let json = serde_json::to_string(&risk).unwrap();
        let back: LicenseRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(back, risk);
    }
}

// ── LegalAssessment ─────────────────────────────────────────────────────

#[test]
fn legal_assessment_no_findings() {
    let assessment = LegalAssessment::from_findings(vec![]);
    assert!(!assessment.has_high_risk);
    assert!(!assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::None);
    assert!(assessment.summary.contains("No license concerns"));
}

#[test]
fn legal_assessment_high_risk() {
    let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
        dependency: "gpl-lib".to_string(),
        license_spdx: "GPL-3.0".to_string(),
        risk: LicenseRisk::High,
        notes: "Strong copyleft".to_string(),
    }]);
    assert!(assessment.has_high_risk);
    assert!(assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::High);
    assert!(assessment.summary.contains("LEGAL REVIEW REQUIRED"));
}

#[test]
fn legal_assessment_medium_risk() {
    let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
        dependency: "lgpl-lib".to_string(),
        license_spdx: "LGPL-3.0".to_string(),
        risk: LicenseRisk::Medium,
        notes: "Weak copyleft".to_string(),
    }]);
    assert!(!assessment.has_high_risk);
    assert!(assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::Medium);
    assert!(assessment.summary.contains("recommended"));
}

#[test]
fn legal_assessment_sorts_by_dependency() {
    let assessment = LegalAssessment::from_findings(vec![
        LicenseFinding {
            dependency: "zzz-lib".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::None,
            notes: "".to_string(),
        },
        LicenseFinding {
            dependency: "aaa-lib".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::None,
            notes: "".to_string(),
        },
    ]);
    assert_eq!(assessment.findings[0].dependency, "aaa-lib");
    assert_eq!(assessment.findings[1].dependency, "zzz-lib");
}

#[test]
fn legal_assessment_serde_roundtrip() {
    let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
        dependency: "test".to_string(),
        license_spdx: "MIT".to_string(),
        risk: LicenseRisk::None,
        notes: "OK".to_string(),
    }]);
    let json = serde_json::to_string(&assessment).unwrap();
    let back: LegalAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, assessment);
}

// ── PackBuilder ─────────────────────────────────────────────────────────

#[test]
fn pack_builder_without_env_returns_none() {
    let result = PackBuilder::new("claim-01".to_string(), epoch()).build();
    assert!(result.is_none());
}

#[test]
fn pack_builder_produces_valid_pack() {
    let pack = build_simple_pack();
    assert!(pack.pack_id.starts_with("pack-"));
    assert_eq!(pack.schema_version, SCHEMA_VERSION);
    assert_eq!(pack.claim_id, "claim-01");
    assert_eq!(pack.epoch, epoch());
    assert_eq!(pack.artifact_count(), 2);
    assert_eq!(pack.dependency_count(), 2);
    assert!(!pack.pack_hash.is_empty());
}

#[test]
fn pack_builder_with_legal_findings() {
    let pack = PackBuilder::new("claim-02".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("main.rs", ArtifactKind::Source))
        .license_finding(LicenseFinding {
            dependency: "gpl-lib".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    assert!(pack.legal.is_some());
    assert!(pack.requires_legal_review());
}

#[test]
fn pack_builder_no_legal_when_no_findings() {
    let pack = build_simple_pack();
    assert!(pack.legal.is_none());
    assert!(!pack.requires_legal_review());
}

// ── ReproducibilityPack ─────────────────────────────────────────────────

#[test]
fn pack_verify_integrity_passes() {
    let pack = build_simple_pack();
    let result = pack.verify_integrity();
    assert!(result.all_valid);
    assert!(result.pack_hash_valid);
    assert!(result.manifest_count_valid);
    assert!(result.manifest_size_valid);
    assert!(result.artifacts_sorted);
    assert!(result.dependencies_sorted);
}

#[test]
fn pack_deterministic() {
    let p1 = build_simple_pack();
    let p2 = build_simple_pack();
    assert_eq!(p1.pack_id, p2.pack_id);
    assert_eq!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn pack_serde_roundtrip() {
    let pack = build_simple_pack();
    let json = serde_json::to_string(&pack).unwrap();
    let back: ReproducibilityPack = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pack);
}

// ── generate_report ─────────────────────────────────────────────────────

#[test]
fn report_from_valid_pack() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report.pack_id, pack.pack_id);
    assert_eq!(report.claim_id, "claim-01");
    assert_eq!(report.epoch, epoch());
    assert!(report.integrity.all_valid);
    assert_eq!(report.artifact_count, 2);
    assert_eq!(report.dependency_count, 2);
    assert!(!report.legal_review_required);
    assert_eq!(report.max_license_risk, None);
    assert!(!report.git_dirty);
    assert!(!report.report_hash.is_empty());
}

#[test]
fn report_with_legal_risk() {
    let pack = PackBuilder::new("claim-legal".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("main.rs", ArtifactKind::Source))
        .license_finding(LicenseFinding {
            dependency: "gpl-lib".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(report.legal_review_required);
    assert_eq!(report.max_license_risk, Some(LicenseRisk::High));
}

#[test]
fn report_with_dirty_git() {
    let mut env = sample_env();
    env.git.dirty = true;
    let pack = PackBuilder::new("claim-dirty".to_string(), epoch())
        .environment(env)
        .artifact(sample_artifact("main.rs", ArtifactKind::Source))
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(report.git_dirty);
}

#[test]
fn report_deterministic() {
    let pack = build_simple_pack();
    let r1 = generate_report(&pack);
    let r2 = generate_report(&pack);
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn report_serde_roundtrip() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    let json = serde_json::to_string(&report).unwrap();
    let back = serde_json::from_str::<
        frankenengine_engine::reproducibility_provenance_pack::ReproducibilityReport,
    >(&json)
    .unwrap();
    assert_eq!(back, report);
}

// ── Full lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_build_verify_report() {
    // Build a pack with all components.
    let pack = PackBuilder::new("frx-42".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("src/main.rs", ArtifactKind::Source))
        .artifact(sample_artifact("Cargo.toml", ArtifactKind::Config))
        .artifact(sample_artifact("target/release/app", ArtifactKind::Binary))
        .dependency(sample_dep("serde", "1.0.200"))
        .dependency(sample_dep("sha2", "0.10.8"))
        .dependency(sample_dep("hex", "0.4.3"))
        .license_finding(LicenseFinding {
            dependency: "serde".to_string(),
            license_spdx: "MIT OR Apache-2.0".to_string(),
            risk: LicenseRisk::None,
            notes: "".to_string(),
        })
        .license_finding(LicenseFinding {
            dependency: "sha2".to_string(),
            license_spdx: "MIT OR Apache-2.0".to_string(),
            risk: LicenseRisk::None,
            notes: "".to_string(),
        })
        .build()
        .expect("build");

    // Verify integrity.
    let integrity = pack.verify_integrity();
    assert!(integrity.all_valid);

    // Generate report.
    let report = generate_report(&pack);
    assert_eq!(report.artifact_count, 3);
    assert_eq!(report.dependency_count, 3);
    assert!(!report.legal_review_required);
    assert_eq!(report.max_license_risk, Some(LicenseRisk::None));
    assert!(!report.git_dirty);
    assert!(report.integrity.all_valid);
}
