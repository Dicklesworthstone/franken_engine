//! Enrichment integration tests for the `reproducibility_provenance_pack` module.
//!
//! Covers additional edge cases for fingerprints, build environments, manifests,
//! dependency snapshots, legal assessment, pack builder, integrity verification,
//! reports, and serde round-trips.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;

use frankenengine_engine::reproducibility_provenance_pack::{
    ArtifactEntry, ArtifactKind, ArtifactManifest, BuildEnvironment, DependencyEntry,
    DependencySnapshot, GitFingerprint, LegalAssessment, LicenseFinding, LicenseRisk, PackBuilder,
    ReproducibilityPack, ReproducibilityReport, SCHEMA_VERSION, ToolchainFingerprint,
    generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
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

fn make_artifact(path: &str, kind: ArtifactKind, size: u64) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_string(),
        kind,
        content_hash: format!("hash_{path}"),
        size_bytes: size,
        redacted: false,
    }
}

fn make_dep(name: &str, version: &str) -> DependencyEntry {
    DependencyEntry {
        name: name.to_string(),
        version: version.to_string(),
        source: "crates.io".to_string(),
        checksum: Some(format!("ck_{name}")),
    }
}

fn minimal_pack() -> ReproducibilityPack {
    PackBuilder::new("FRX-ENRICH".to_string(), epoch())
        .environment(sample_env())
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// ToolchainFingerprint
// ---------------------------------------------------------------------------

#[test]
fn enrich_toolchain_no_llvm_hash_different() {
    let mut tc = sample_toolchain();
    let h1 = tc.content_hash();
    tc.llvm_version = None;
    let h2 = tc.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_toolchain_different_edition_hash() {
    let mut tc = sample_toolchain();
    let h1 = tc.content_hash();
    tc.edition = "2021".to_string();
    let h2 = tc.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_toolchain_different_profile_hash() {
    let mut tc = sample_toolchain();
    let h1 = tc.content_hash();
    tc.profile = "dev".to_string();
    let h2 = tc.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_toolchain_different_rustflags_hash() {
    let mut tc = sample_toolchain();
    let h1 = tc.content_hash();
    tc.rustflags.push("-C opt-level=3".to_string());
    let h2 = tc.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_toolchain_empty_rustflags_hash() {
    let mut tc = sample_toolchain();
    let h1 = tc.content_hash();
    tc.rustflags = vec![];
    let h2 = tc.content_hash();
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// GitFingerprint
// ---------------------------------------------------------------------------

#[test]
fn enrich_git_no_branch_hash_different() {
    let mut g = sample_git();
    let h1 = g.content_hash();
    g.branch = None;
    let h2 = g.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_git_different_tags_hash() {
    let mut g = sample_git();
    let h1 = g.content_hash();
    g.tags.push("v0.2.0".to_string());
    let h2 = g.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_git_empty_tags_hash() {
    let mut g = sample_git();
    let h1 = g.content_hash();
    g.tags = vec![];
    let h2 = g.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_git_dirty_vs_clean() {
    let mut g1 = sample_git();
    g1.dirty = false;
    let mut g2 = sample_git();
    g2.dirty = true;
    assert_ne!(g1.content_hash(), g2.content_hash());
}

// ---------------------------------------------------------------------------
// BuildEnvironment
// ---------------------------------------------------------------------------

#[test]
fn enrich_env_extra_metadata_changes_hash() {
    let mut e1 = sample_env();
    let h1 = e1.content_hash();
    e1.extra.insert("key".to_string(), "value".to_string());
    let h2 = e1.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_env_different_cpu_count_hash() {
    let mut e1 = sample_env();
    let h1 = e1.content_hash();
    e1.cpu_count = 32;
    let h2 = e1.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_env_different_memory_hash() {
    let mut e1 = sample_env();
    let h1 = e1.content_hash();
    e1.memory_mb = 131072;
    let h2 = e1.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrich_env_container_digest_optional() {
    let mut e = sample_env();
    assert!(e.container_digest.is_none());
    e.container_digest = Some("sha256:abc123".to_string());
    // Just verify it's settable and doesn't panic
    let _ = e.content_hash();
}

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

#[test]
fn enrich_artifact_kind_all_variants_display() {
    let kinds = [
        (ArtifactKind::Source, "source"),
        (ArtifactKind::Binary, "binary"),
        (ArtifactKind::Config, "config"),
        (ArtifactKind::TestFixture, "test_fixture"),
        (ArtifactKind::Evidence, "evidence"),
        (ArtifactKind::LockFile, "lock_file"),
        (ArtifactKind::Documentation, "documentation"),
        (ArtifactKind::Legal, "legal"),
    ];
    for (k, expected) in &kinds {
        assert_eq!(k.to_string(), *expected);
    }
}

#[test]
fn enrich_artifact_kind_serde_all() {
    for k in [
        ArtifactKind::Source,
        ArtifactKind::Binary,
        ArtifactKind::Config,
        ArtifactKind::TestFixture,
        ArtifactKind::Evidence,
        ArtifactKind::LockFile,
        ArtifactKind::Documentation,
        ArtifactKind::Legal,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// ArtifactManifest
// ---------------------------------------------------------------------------

#[test]
fn enrich_manifest_empty_artifacts() {
    let manifest = ArtifactManifest::from_artifacts("pack-empty".to_string(), vec![]);
    assert_eq!(manifest.total_count, 0);
    assert_eq!(manifest.total_size_bytes, 0);
    assert!(manifest.artifacts.is_empty());
}

#[test]
fn enrich_manifest_redacted_artifact() {
    let mut a = make_artifact("secret.key", ArtifactKind::Config, 256);
    a.redacted = true;
    let manifest = ArtifactManifest::from_artifacts("pack-r".to_string(), vec![a]);
    assert!(manifest.artifacts[0].redacted);
}

#[test]
fn enrich_manifest_sort_stability() {
    let artifacts = vec![
        make_artifact("z.rs", ArtifactKind::Source, 100),
        make_artifact("a.rs", ArtifactKind::Source, 200),
        make_artifact("m.rs", ArtifactKind::Source, 300),
    ];
    let m = ArtifactManifest::from_artifacts("pack-sort".to_string(), artifacts);
    assert_eq!(m.artifacts[0].path, "a.rs");
    assert_eq!(m.artifacts[1].path, "m.rs");
    assert_eq!(m.artifacts[2].path, "z.rs");
    assert_eq!(m.total_size_bytes, 600);
}

#[test]
fn enrich_manifest_hash_differs_by_pack_id() {
    let artifacts = vec![make_artifact("a.rs", ArtifactKind::Source, 100)];
    let m1 = ArtifactManifest::from_artifacts("pack-1".to_string(), artifacts.clone());
    let m2 = ArtifactManifest::from_artifacts("pack-2".to_string(), artifacts);
    assert_ne!(m1.manifest_hash, m2.manifest_hash);
}

// ---------------------------------------------------------------------------
// DependencySnapshot
// ---------------------------------------------------------------------------

#[test]
fn enrich_dep_snapshot_empty() {
    let snap = DependencySnapshot::from_entries(vec![]);
    assert_eq!(snap.total_count, 0);
    assert!(snap.dependencies.is_empty());
}

#[test]
fn enrich_dep_snapshot_no_checksum() {
    let entry = DependencyEntry {
        name: "my-dep".to_string(),
        version: "0.1.0".to_string(),
        source: "path".to_string(),
        checksum: None,
    };
    let snap = DependencySnapshot::from_entries(vec![entry]);
    assert_eq!(snap.total_count, 1);
    assert!(snap.dependencies[0].checksum.is_none());
}

#[test]
fn enrich_dep_snapshot_sort_order() {
    let entries = vec![
        make_dep("zlib", "0.1.0"),
        make_dep("alpha", "0.2.0"),
        make_dep("middle", "0.3.0"),
    ];
    let snap = DependencySnapshot::from_entries(entries);
    assert_eq!(snap.dependencies[0].name, "alpha");
    assert_eq!(snap.dependencies[1].name, "middle");
    assert_eq!(snap.dependencies[2].name, "zlib");
}

#[test]
fn enrich_dep_snapshot_hash_differs_by_content() {
    let s1 = DependencySnapshot::from_entries(vec![make_dep("a", "1.0")]);
    let s2 = DependencySnapshot::from_entries(vec![make_dep("a", "2.0")]);
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

// ---------------------------------------------------------------------------
// LicenseRisk
// ---------------------------------------------------------------------------

#[test]
fn enrich_license_risk_ordering_all() {
    assert!(LicenseRisk::None < LicenseRisk::Low);
    assert!(LicenseRisk::Low < LicenseRisk::Medium);
    assert!(LicenseRisk::Medium < LicenseRisk::High);
}

#[test]
fn enrich_license_risk_clone_eq() {
    let r = LicenseRisk::Medium;
    let c = r;
    assert_eq!(r, c);
}

// ---------------------------------------------------------------------------
// LegalAssessment
// ---------------------------------------------------------------------------

#[test]
fn enrich_legal_low_risk_no_review() {
    let findings = vec![LicenseFinding {
        dependency: "bsd-crate".to_string(),
        license_spdx: "BSD-3-Clause".to_string(),
        risk: LicenseRisk::Low,
        notes: "weak copyleft".to_string(),
    }];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(!assessment.has_high_risk);
    assert!(!assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::Low);
}

#[test]
fn enrich_legal_mixed_risks_takes_max() {
    let findings = vec![
        LicenseFinding {
            dependency: "mit-crate".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::None,
            notes: String::new(),
        },
        LicenseFinding {
            dependency: "gpl-crate".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "copyleft".to_string(),
        },
    ];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(assessment.has_high_risk);
    assert!(assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::High);
}

#[test]
fn enrich_legal_multiple_medium_summary() {
    let findings = vec![
        LicenseFinding {
            dependency: "lgpl-a".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: String::new(),
        },
        LicenseFinding {
            dependency: "lgpl-b".to_string(),
            license_spdx: "LGPL-3.0".to_string(),
            risk: LicenseRisk::Medium,
            notes: String::new(),
        },
    ];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(assessment.review_required);
    assert!(!assessment.has_high_risk);
    assert!(assessment.summary.contains("2"));
}

// ---------------------------------------------------------------------------
// PackBuilder
// ---------------------------------------------------------------------------

#[test]
fn enrich_builder_no_env_returns_none() {
    assert!(
        PackBuilder::new("FRX-X".to_string(), epoch())
            .build()
            .is_none()
    );
}

#[test]
fn enrich_builder_pack_id_starts_with_pack() {
    let pack = minimal_pack();
    assert!(pack.pack_id.starts_with("pack-"));
}

#[test]
fn enrich_builder_schema_version_correct() {
    let pack = minimal_pack();
    assert_eq!(pack.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrich_builder_with_many_artifacts() {
    let mut builder = PackBuilder::new("FRX-MANY".to_string(), epoch()).environment(sample_env());
    for i in 0..20 {
        builder = builder.artifact(make_artifact(
            &format!("file_{i:02}.rs"),
            ArtifactKind::Source,
            1024,
        ));
    }
    let pack = builder.build().unwrap();
    assert_eq!(pack.artifact_count(), 20);
}

#[test]
fn enrich_builder_with_many_deps() {
    let mut builder = PackBuilder::new("FRX-DEPS".to_string(), epoch()).environment(sample_env());
    for i in 0..15 {
        builder = builder.dependency(make_dep(&format!("dep_{i:02}"), "1.0.0"));
    }
    let pack = builder.build().unwrap();
    assert_eq!(pack.dependency_count(), 15);
}

#[test]
fn enrich_builder_legal_none_without_findings() {
    let pack = minimal_pack();
    assert!(pack.legal.is_none());
    assert!(!pack.requires_legal_review());
}

#[test]
fn enrich_builder_legal_present_with_findings() {
    let pack = PackBuilder::new("FRX-L".to_string(), epoch())
        .environment(sample_env())
        .license_finding(LicenseFinding {
            dependency: "dep".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::None,
            notes: String::new(),
        })
        .build()
        .unwrap();
    assert!(pack.legal.is_some());
}

// ---------------------------------------------------------------------------
// ReproducibilityPack: integrity
// ---------------------------------------------------------------------------

#[test]
fn enrich_pack_integrity_valid_full() {
    let pack = PackBuilder::new("FRX-INT".to_string(), epoch())
        .environment(sample_env())
        .artifact(make_artifact("a.rs", ArtifactKind::Source, 512))
        .artifact(make_artifact("b.rs", ArtifactKind::Source, 256))
        .dependency(make_dep("serde", "1.0.200"))
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
fn enrich_pack_hash_differs_by_epoch() {
    let p1 = PackBuilder::new("FRX-E".to_string(), SecurityEpoch::from_raw(1))
        .environment(sample_env())
        .build()
        .unwrap();
    let p2 = PackBuilder::new("FRX-E".to_string(), SecurityEpoch::from_raw(2))
        .environment(sample_env())
        .build()
        .unwrap();
    assert_ne!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn enrich_pack_serde_roundtrip_full() {
    let pack = PackBuilder::new("FRX-SERDE".to_string(), epoch())
        .environment(sample_env())
        .artifact(make_artifact("src/lib.rs", ArtifactKind::Source, 4096))
        .dependency(make_dep("sha2", "0.10.9"))
        .license_finding(LicenseFinding {
            dependency: "gpl-dep".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "copyleft".to_string(),
        })
        .build()
        .unwrap();
    let json = serde_json::to_string(&pack).unwrap();
    let back: ReproducibilityPack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
}

// ---------------------------------------------------------------------------
// generate_report
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_fields_correct() {
    let pack = PackBuilder::new("FRX-RPT".to_string(), epoch())
        .environment(sample_env())
        .artifact(make_artifact("x.rs", ArtifactKind::Source, 100))
        .dependency(make_dep("hex", "0.4"))
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.claim_id, "FRX-RPT");
    assert_eq!(report.epoch, epoch());
    assert_eq!(report.artifact_count, 1);
    assert_eq!(report.dependency_count, 1);
    assert!(!report.git_dirty);
    assert!(!report.legal_review_required);
    assert!(report.max_license_risk.is_none());
    assert!(report.integrity.all_valid);
}

#[test]
fn enrich_report_with_legal_review() {
    let pack = PackBuilder::new("FRX-LEGAL".to_string(), epoch())
        .environment(sample_env())
        .license_finding(LicenseFinding {
            dependency: "gpl".to_string(),
            license_spdx: "GPL-3.0".to_string(),
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
fn enrich_report_dirty_git() {
    let mut env = sample_env();
    env.git.dirty = true;
    let pack = PackBuilder::new("FRX-DIRTY".to_string(), epoch())
        .environment(env)
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(report.git_dirty);
}

#[test]
fn enrich_report_hash_deterministic() {
    let pack = minimal_pack();
    let r1 = generate_report(&pack);
    let r2 = generate_report(&pack);
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn enrich_report_serde_roundtrip() {
    let pack = minimal_pack();
    let report = generate_report(&pack);
    let json = serde_json::to_string(&report).unwrap();
    let back: ReproducibilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Schema version constant
// ---------------------------------------------------------------------------

#[test]
fn enrich_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.reproducibility-provenance.v1"
    );
}
