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

// ── Enrichment tests ────────────────────────────────────────────────────

// -- ToolchainFingerprint enrichment --

#[test]
fn enrichment_toolchain_debug_format_contains_fields() {
    let tc = sample_toolchain();
    let dbg = format!("{:?}", tc);
    assert!(dbg.contains("rustc_version"));
    assert!(dbg.contains("cargo_version"));
    assert!(dbg.contains("linker"));
    assert!(dbg.contains("target_triple"));
    assert!(dbg.contains("edition"));
    assert!(dbg.contains("profile"));
    assert!(dbg.contains("rustflags"));
}

#[test]
fn enrichment_toolchain_clone_preserves_all_fields() {
    let tc = sample_toolchain();
    let cloned = tc.clone();
    assert_eq!(cloned.rustc_version, tc.rustc_version);
    assert_eq!(cloned.cargo_version, tc.cargo_version);
    assert_eq!(cloned.llvm_version, tc.llvm_version);
    assert_eq!(cloned.linker, tc.linker);
    assert_eq!(cloned.target_triple, tc.target_triple);
    assert_eq!(cloned.edition, tc.edition);
    assert_eq!(cloned.profile, tc.profile);
    assert_eq!(cloned.rustflags, tc.rustflags);
}

#[test]
fn enrichment_toolchain_hash_hex_length_is_32() {
    let tc = sample_toolchain();
    let h = tc.content_hash();
    // SHA-256 truncated to first 16 bytes, hex-encoded = 32 chars
    assert_eq!(h.len(), 32);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_toolchain_hash_differs_on_target_triple() {
    let tc1 = sample_toolchain();
    let mut tc2 = sample_toolchain();
    tc2.target_triple = "aarch64-apple-darwin".to_string();
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_hash_differs_on_edition() {
    let tc1 = sample_toolchain();
    let mut tc2 = sample_toolchain();
    tc2.edition = "2021".to_string();
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_hash_differs_on_cargo_version() {
    let tc1 = sample_toolchain();
    let mut tc2 = sample_toolchain();
    tc2.cargo_version = "1.80.0-nightly".to_string();
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_empty_rustflags_differs_from_nonempty() {
    let mut tc1 = sample_toolchain();
    tc1.rustflags = vec![];
    let tc2 = sample_toolchain();
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_multiple_rustflags_order_matters() {
    let mut tc1 = sample_toolchain();
    tc1.rustflags = vec!["a".to_string(), "b".to_string()];
    let mut tc2 = sample_toolchain();
    tc2.rustflags = vec!["b".to_string(), "a".to_string()];
    assert_ne!(tc1.content_hash(), tc2.content_hash());
}

#[test]
fn enrichment_toolchain_json_field_names_stable() {
    let tc = sample_toolchain();
    let json = serde_json::to_string(&tc).unwrap();
    for field in &[
        "rustc_version",
        "cargo_version",
        "llvm_version",
        "linker",
        "target_triple",
        "edition",
        "profile",
        "rustflags",
    ] {
        assert!(json.contains(field), "Missing JSON field: {field}");
    }
}

#[test]
fn enrichment_toolchain_llvm_none_serializes_as_null() {
    let mut tc = sample_toolchain();
    tc.llvm_version = None;
    let json = serde_json::to_string(&tc).unwrap();
    assert!(json.contains("null"));
    let back: ToolchainFingerprint = serde_json::from_str(&json).unwrap();
    assert!(back.llvm_version.is_none());
}

// -- GitFingerprint enrichment --

#[test]
fn enrichment_git_debug_format_contains_fields() {
    let g = sample_git();
    let dbg = format!("{:?}", g);
    assert!(dbg.contains("commit_sha"));
    assert!(dbg.contains("tree_hash"));
    assert!(dbg.contains("branch"));
    assert!(dbg.contains("dirty"));
    assert!(dbg.contains("tags"));
}

#[test]
fn enrichment_git_clone_preserves_all_fields() {
    let g = sample_git();
    let cloned = g.clone();
    assert_eq!(cloned.commit_sha, g.commit_sha);
    assert_eq!(cloned.tree_hash, g.tree_hash);
    assert_eq!(cloned.branch, g.branch);
    assert_eq!(cloned.dirty, g.dirty);
    assert_eq!(cloned.tags, g.tags);
}

#[test]
fn enrichment_git_hash_hex_length_is_32() {
    let g = sample_git();
    let h = g.content_hash();
    assert_eq!(h.len(), 32);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_git_hash_differs_on_tree_hash() {
    let g1 = sample_git();
    let mut g2 = sample_git();
    g2.tree_hash = "0".repeat(40);
    assert_ne!(g1.content_hash(), g2.content_hash());
}

#[test]
fn enrichment_git_multiple_tags_changes_hash() {
    let mut g1 = sample_git();
    g1.tags = vec!["v0.1.0".to_string()];
    let mut g2 = sample_git();
    g2.tags = vec!["v0.1.0".to_string(), "v0.2.0".to_string()];
    assert_ne!(g1.content_hash(), g2.content_hash());
}

#[test]
fn enrichment_git_branch_none_serializes_as_null() {
    let mut g = sample_git();
    g.branch = None;
    let json = serde_json::to_string(&g).unwrap();
    assert!(json.contains("null"));
    let back: GitFingerprint = serde_json::from_str(&json).unwrap();
    assert!(back.branch.is_none());
}

#[test]
fn enrichment_git_json_field_names_stable() {
    let g = sample_git();
    let json = serde_json::to_string(&g).unwrap();
    for field in &["commit_sha", "tree_hash", "branch", "dirty", "tags"] {
        assert!(json.contains(field), "Missing JSON field: {field}");
    }
}

#[test]
fn enrichment_git_empty_tags_hash_differs_from_nonempty() {
    let mut g1 = sample_git();
    g1.tags = vec![];
    let g2 = sample_git();
    assert_ne!(g1.content_hash(), g2.content_hash());
}

// -- BuildEnvironment enrichment --

#[test]
fn enrichment_env_debug_format_contains_fields() {
    let e = sample_env();
    let dbg = format!("{:?}", e);
    assert!(dbg.contains("os_name"));
    assert!(dbg.contains("arch"));
    assert!(dbg.contains("cpu_count"));
    assert!(dbg.contains("memory_mb"));
    assert!(dbg.contains("toolchain"));
    assert!(dbg.contains("git"));
}

#[test]
fn enrichment_env_clone_preserves_all_fields() {
    let e = sample_env();
    let cloned = e.clone();
    assert_eq!(cloned.os_name, e.os_name);
    assert_eq!(cloned.os_version, e.os_version);
    assert_eq!(cloned.arch, e.arch);
    assert_eq!(cloned.cpu_count, e.cpu_count);
    assert_eq!(cloned.memory_mb, e.memory_mb);
    assert_eq!(cloned.container_digest, e.container_digest);
    assert_eq!(cloned.ci_system, e.ci_system);
    assert_eq!(cloned.ci_run_id, e.ci_run_id);
    assert_eq!(cloned.toolchain, e.toolchain);
    assert_eq!(cloned.git, e.git);
    assert_eq!(cloned.extra, e.extra);
}

#[test]
fn enrichment_env_hash_hex_length_is_32() {
    let e = sample_env();
    let h = e.content_hash();
    assert_eq!(h.len(), 32);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_env_hash_differs_on_os_version() {
    let e1 = sample_env();
    let mut e2 = sample_env();
    e2.os_version = "7.0.0".to_string();
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_env_hash_differs_on_arch() {
    let e1 = sample_env();
    let mut e2 = sample_env();
    e2.arch = "aarch64".to_string();
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_env_hash_differs_on_memory_mb() {
    let e1 = sample_env();
    let mut e2 = sample_env();
    e2.memory_mb = 32768;
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_env_with_extra_metadata_roundtrip() {
    let mut e = sample_env();
    e.extra.insert("key1".to_string(), "val1".to_string());
    e.extra.insert("key2".to_string(), "val2".to_string());
    let json = serde_json::to_string(&e).unwrap();
    let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extra.len(), 2);
    assert_eq!(back.extra.get("key1").unwrap(), "val1");
}

#[test]
fn enrichment_env_json_field_names_stable() {
    let e = sample_env();
    let json = serde_json::to_string(&e).unwrap();
    for field in &[
        "os_name",
        "os_version",
        "arch",
        "cpu_count",
        "memory_mb",
        "container_digest",
        "ci_system",
        "ci_run_id",
        "toolchain",
        "git",
        "extra",
    ] {
        assert!(json.contains(field), "Missing JSON field: {field}");
    }
}

#[test]
fn enrichment_env_hash_differs_on_toolchain_change() {
    let e1 = sample_env();
    let mut e2 = sample_env();
    e2.toolchain.rustc_version = "1.85.0-nightly".to_string();
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_env_hash_differs_on_git_change() {
    let e1 = sample_env();
    let mut e2 = sample_env();
    e2.git.dirty = true;
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_env_zero_cpu_and_zero_memory() {
    let mut e = sample_env();
    e.cpu_count = 0;
    e.memory_mb = 0;
    let json = serde_json::to_string(&e).unwrap();
    let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cpu_count, 0);
    assert_eq!(back.memory_mb, 0);
}

#[test]
fn enrichment_env_ci_fields_none_roundtrip() {
    let mut e = sample_env();
    e.ci_system = None;
    e.ci_run_id = None;
    let json = serde_json::to_string(&e).unwrap();
    let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
    assert!(back.ci_system.is_none());
    assert!(back.ci_run_id.is_none());
}

// -- ArtifactKind enrichment --

#[test]
fn enrichment_artifact_kind_debug_all_variants() {
    let kinds = [
        ArtifactKind::Source,
        ArtifactKind::Binary,
        ArtifactKind::Config,
        ArtifactKind::TestFixture,
        ArtifactKind::Evidence,
        ArtifactKind::LockFile,
        ArtifactKind::Documentation,
        ArtifactKind::Legal,
    ];
    for k in &kinds {
        let dbg = format!("{:?}", k);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_artifact_kind_clone_eq() {
    let kinds = [
        ArtifactKind::Source,
        ArtifactKind::Binary,
        ArtifactKind::Config,
        ArtifactKind::TestFixture,
        ArtifactKind::Evidence,
        ArtifactKind::LockFile,
        ArtifactKind::Documentation,
        ArtifactKind::Legal,
    ];
    for k in &kinds {
        assert_eq!(*k, k.clone());
    }
}

#[test]
fn enrichment_artifact_kind_serde_snake_case_naming() {
    // ArtifactKind uses #[serde(rename_all = "snake_case")]
    let pairs = [
        (ArtifactKind::Source, "\"source\""),
        (ArtifactKind::Binary, "\"binary\""),
        (ArtifactKind::Config, "\"config\""),
        (ArtifactKind::TestFixture, "\"test_fixture\""),
        (ArtifactKind::Evidence, "\"evidence\""),
        (ArtifactKind::LockFile, "\"lock_file\""),
        (ArtifactKind::Documentation, "\"documentation\""),
        (ArtifactKind::Legal, "\"legal\""),
    ];
    for (kind, expected_json) in &pairs {
        let json = serde_json::to_string(kind).unwrap();
        assert_eq!(&json, expected_json, "ArtifactKind::{:?} serialization", kind);
    }
}

#[test]
fn enrichment_artifact_kind_full_ordering_chain() {
    // Verify the full ordering: Source < Binary < Config < TestFixture < Evidence < LockFile < Documentation < Legal
    let sorted = [
        ArtifactKind::Source,
        ArtifactKind::Binary,
        ArtifactKind::Config,
        ArtifactKind::TestFixture,
        ArtifactKind::Evidence,
        ArtifactKind::LockFile,
        ArtifactKind::Documentation,
        ArtifactKind::Legal,
    ];
    for window in sorted.windows(2) {
        assert!(window[0] < window[1], "{:?} should be less than {:?}", window[0], window[1]);
    }
}

// -- ArtifactEntry enrichment --

#[test]
fn enrichment_artifact_entry_debug_contains_path() {
    let entry = sample_artifact("src/main.rs", ArtifactKind::Source);
    let dbg = format!("{:?}", entry);
    assert!(dbg.contains("src/main.rs"));
}

#[test]
fn enrichment_artifact_entry_clone_equality() {
    let entry = sample_artifact("src/main.rs", ArtifactKind::Source);
    assert_eq!(entry, entry.clone());
}

#[test]
fn enrichment_artifact_entry_zero_size_roundtrip() {
    let entry = ArtifactEntry {
        path: "empty.txt".to_string(),
        kind: ArtifactKind::Config,
        content_hash: "hash_empty".to_string(),
        size_bytes: 0,
        redacted: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.size_bytes, 0);
}

#[test]
fn enrichment_artifact_entry_large_size_roundtrip() {
    let entry = ArtifactEntry {
        path: "big.bin".to_string(),
        kind: ArtifactKind::Binary,
        content_hash: "hash_big".to_string(),
        size_bytes: u64::MAX,
        redacted: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.size_bytes, u64::MAX);
}

#[test]
fn enrichment_artifact_entry_json_field_names() {
    let entry = sample_artifact("test.rs", ArtifactKind::Source);
    let json = serde_json::to_string(&entry).unwrap();
    for field in &["path", "kind", "content_hash", "size_bytes", "redacted"] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

// -- ArtifactManifest enrichment --

#[test]
fn enrichment_manifest_single_artifact() {
    let manifest = ArtifactManifest::from_artifacts(
        "pack-single".to_string(),
        vec![sample_artifact("only.rs", ArtifactKind::Source)],
    );
    assert_eq!(manifest.total_count, 1);
    assert_eq!(manifest.total_size_bytes, 1024);
    assert_eq!(manifest.artifacts.len(), 1);
}

#[test]
fn enrichment_manifest_many_artifacts_total_size() {
    let arts: Vec<ArtifactEntry> = (0..10)
        .map(|i| ArtifactEntry {
            path: format!("file_{i}.rs"),
            kind: ArtifactKind::Source,
            content_hash: format!("hash_{i}"),
            size_bytes: 100 * (i as u64 + 1),
            redacted: false,
        })
        .collect();
    let expected_size: u64 = (1..=10).map(|i| 100 * i).sum();
    let manifest = ArtifactManifest::from_artifacts("pack-many".to_string(), arts);
    assert_eq!(manifest.total_count, 10);
    assert_eq!(manifest.total_size_bytes, expected_size);
}

#[test]
fn enrichment_manifest_preserves_artifact_content_after_sort() {
    let a1 = ArtifactEntry {
        path: "zzz.rs".to_string(),
        kind: ArtifactKind::Binary,
        content_hash: "hash_z".to_string(),
        size_bytes: 2048,
        redacted: true,
    };
    let a2 = ArtifactEntry {
        path: "aaa.rs".to_string(),
        kind: ArtifactKind::Source,
        content_hash: "hash_a".to_string(),
        size_bytes: 512,
        redacted: false,
    };
    let manifest = ArtifactManifest::from_artifacts("pack-sort".to_string(), vec![a1, a2]);
    assert_eq!(manifest.artifacts[0].path, "aaa.rs");
    assert_eq!(manifest.artifacts[0].kind, ArtifactKind::Source);
    assert_eq!(manifest.artifacts[0].size_bytes, 512);
    assert_eq!(manifest.artifacts[1].path, "zzz.rs");
    assert_eq!(manifest.artifacts[1].kind, ArtifactKind::Binary);
    assert_eq!(manifest.artifacts[1].size_bytes, 2048);
}

#[test]
fn enrichment_manifest_hash_differs_on_different_artifacts() {
    let m1 = ArtifactManifest::from_artifacts(
        "pack-x".to_string(),
        vec![sample_artifact("a.rs", ArtifactKind::Source)],
    );
    let m2 = ArtifactManifest::from_artifacts(
        "pack-x".to_string(),
        vec![sample_artifact("b.rs", ArtifactKind::Source)],
    );
    assert_ne!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn enrichment_manifest_clone_equality() {
    let manifest = ArtifactManifest::from_artifacts(
        "pack-clone".to_string(),
        vec![sample_artifact("f.rs", ArtifactKind::Source)],
    );
    assert_eq!(manifest, manifest.clone());
}

#[test]
fn enrichment_manifest_json_field_names() {
    let manifest = ArtifactManifest::from_artifacts(
        "pack-fields".to_string(),
        vec![sample_artifact("f.rs", ArtifactKind::Source)],
    );
    let json = serde_json::to_string(&manifest).unwrap();
    for field in &[
        "schema_version",
        "pack_id",
        "artifacts",
        "total_count",
        "total_size_bytes",
        "manifest_hash",
    ] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

// -- DependencyEntry enrichment --

#[test]
fn enrichment_dep_entry_debug_contains_name() {
    let dep = sample_dep("serde", "1.0.200");
    let dbg = format!("{:?}", dep);
    assert!(dbg.contains("serde"));
}

#[test]
fn enrichment_dep_entry_clone_equality() {
    let dep = sample_dep("serde", "1.0.200");
    assert_eq!(dep, dep.clone());
}

#[test]
fn enrichment_dep_entry_empty_strings_roundtrip() {
    let dep = DependencyEntry {
        name: "".to_string(),
        version: "".to_string(),
        source: "".to_string(),
        checksum: None,
    };
    let json = serde_json::to_string(&dep).unwrap();
    let back: DependencyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "");
    assert_eq!(back.version, "");
}

#[test]
fn enrichment_dep_entry_json_field_names() {
    let dep = sample_dep("sha2", "0.10.8");
    let json = serde_json::to_string(&dep).unwrap();
    for field in &["name", "version", "source", "checksum"] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

// -- DependencySnapshot enrichment --

#[test]
fn enrichment_dep_snapshot_many_entries_sorting() {
    let entries: Vec<DependencyEntry> = ["z-crate", "m-crate", "a-crate", "f-crate"]
        .iter()
        .map(|n| sample_dep(n, "1.0.0"))
        .collect();
    let snap = DependencySnapshot::from_entries(entries);
    let names: Vec<&str> = snap.dependencies.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, vec!["a-crate", "f-crate", "m-crate", "z-crate"]);
}

#[test]
fn enrichment_dep_snapshot_hash_differs_on_name() {
    let s1 = DependencySnapshot::from_entries(vec![sample_dep("alpha", "1.0")]);
    let s2 = DependencySnapshot::from_entries(vec![sample_dep("beta", "1.0")]);
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_dep_snapshot_hash_differs_on_source() {
    let mut d1 = sample_dep("serde", "1.0");
    d1.source = "crates.io".to_string();
    let mut d2 = sample_dep("serde", "1.0");
    d2.source = "git".to_string();
    let s1 = DependencySnapshot::from_entries(vec![d1]);
    let s2 = DependencySnapshot::from_entries(vec![d2]);
    assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
}

#[test]
fn enrichment_dep_snapshot_clone_equality() {
    let snap = DependencySnapshot::from_entries(vec![sample_dep("serde", "1.0")]);
    assert_eq!(snap, snap.clone());
}

#[test]
fn enrichment_dep_snapshot_json_field_names() {
    let snap = DependencySnapshot::from_entries(vec![sample_dep("test", "1.0")]);
    let json = serde_json::to_string(&snap).unwrap();
    for field in &["schema_version", "dependencies", "total_count", "snapshot_hash"] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

// -- LicenseRisk enrichment --

#[test]
fn enrichment_license_risk_debug_all_variants() {
    for risk in [LicenseRisk::None, LicenseRisk::Low, LicenseRisk::Medium, LicenseRisk::High] {
        let dbg = format!("{:?}", risk);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_license_risk_clone_eq() {
    for risk in [LicenseRisk::None, LicenseRisk::Low, LicenseRisk::Medium, LicenseRisk::High] {
        assert_eq!(risk, risk.clone());
    }
}

#[test]
fn enrichment_license_risk_serde_snake_case_naming() {
    let pairs = [
        (LicenseRisk::None, "\"none\""),
        (LicenseRisk::Low, "\"low\""),
        (LicenseRisk::Medium, "\"medium\""),
        (LicenseRisk::High, "\"high\""),
    ];
    for (risk, expected_json) in &pairs {
        let json = serde_json::to_string(risk).unwrap();
        assert_eq!(&json, expected_json);
    }
}

#[test]
fn enrichment_license_risk_self_eq() {
    assert_eq!(LicenseRisk::None, LicenseRisk::None);
    assert_eq!(LicenseRisk::Low, LicenseRisk::Low);
    assert_eq!(LicenseRisk::Medium, LicenseRisk::Medium);
    assert_eq!(LicenseRisk::High, LicenseRisk::High);
}

// -- LicenseFinding enrichment --

#[test]
fn enrichment_license_finding_debug_contains_dependency() {
    let finding = LicenseFinding {
        dependency: "test-dep".to_string(),
        license_spdx: "MIT".to_string(),
        risk: LicenseRisk::None,
        notes: "ok".to_string(),
    };
    let dbg = format!("{:?}", finding);
    assert!(dbg.contains("test-dep"));
}

#[test]
fn enrichment_license_finding_clone_equality() {
    let finding = LicenseFinding {
        dependency: "serde".to_string(),
        license_spdx: "MIT OR Apache-2.0".to_string(),
        risk: LicenseRisk::Low,
        notes: "dual".to_string(),
    };
    assert_eq!(finding, finding.clone());
}

#[test]
fn enrichment_license_finding_empty_notes_roundtrip() {
    let finding = LicenseFinding {
        dependency: "dep".to_string(),
        license_spdx: "MIT".to_string(),
        risk: LicenseRisk::None,
        notes: "".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: LicenseFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.notes, "");
}

#[test]
fn enrichment_license_finding_json_field_names() {
    let finding = LicenseFinding {
        dependency: "dep".to_string(),
        license_spdx: "MIT".to_string(),
        risk: LicenseRisk::None,
        notes: "note".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    for field in &["dependency", "license_spdx", "risk", "notes"] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

// -- LegalAssessment enrichment --

#[test]
fn enrichment_legal_assessment_debug_contains_max_risk() {
    let assessment = LegalAssessment::from_findings(vec![]);
    let dbg = format!("{:?}", assessment);
    assert!(dbg.contains("max_risk"));
    assert!(dbg.contains("has_high_risk"));
}

#[test]
fn enrichment_legal_assessment_clone_equality() {
    let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
        dependency: "dep".to_string(),
        license_spdx: "MIT".to_string(),
        risk: LicenseRisk::None,
        notes: "".to_string(),
    }]);
    assert_eq!(assessment, assessment.clone());
}

#[test]
fn enrichment_legal_assessment_low_risk_no_review() {
    let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
        dependency: "bsd-lib".to_string(),
        license_spdx: "BSD-3-Clause".to_string(),
        risk: LicenseRisk::Low,
        notes: "".to_string(),
    }]);
    assert!(!assessment.has_high_risk);
    assert!(!assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::Low);
}

#[test]
fn enrichment_legal_assessment_none_risk_summary() {
    let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
        dependency: "mit-lib".to_string(),
        license_spdx: "MIT".to_string(),
        risk: LicenseRisk::None,
        notes: "".to_string(),
    }]);
    assert_eq!(assessment.summary, "No license concerns detected");
}

#[test]
fn enrichment_legal_assessment_multiple_high_risk_counts() {
    let findings = vec![
        LicenseFinding {
            dependency: "gpl1".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "".to_string(),
        },
        LicenseFinding {
            dependency: "gpl2".to_string(),
            license_spdx: "GPL-2.0".to_string(),
            risk: LicenseRisk::High,
            notes: "".to_string(),
        },
        LicenseFinding {
            dependency: "lgpl1".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: "".to_string(),
        },
    ];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(assessment.summary.contains("2 high-risk"));
    assert!(assessment.summary.contains("1 medium-risk"));
}

#[test]
fn enrichment_legal_assessment_json_field_names() {
    let assessment = LegalAssessment::from_findings(vec![]);
    let json = serde_json::to_string(&assessment).unwrap();
    for field in &["has_high_risk", "review_required", "findings", "max_risk", "summary"] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

#[test]
fn enrichment_legal_assessment_medium_only_no_high() {
    let findings = vec![
        LicenseFinding {
            dependency: "lgpl1".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: "".to_string(),
        },
    ];
    let assessment = LegalAssessment::from_findings(findings);
    assert!(!assessment.has_high_risk);
    assert!(assessment.review_required);
    assert!(assessment.summary.contains("recommended"));
    assert!(!assessment.summary.contains("LEGAL REVIEW REQUIRED"));
}

// -- PackBuilder enrichment --

#[test]
fn enrichment_builder_debug_format() {
    let builder = PackBuilder::new("claim".to_string(), epoch());
    let dbg = format!("{:?}", builder);
    assert!(dbg.contains("PackBuilder"));
}

#[test]
fn enrichment_builder_clone_builds_same_pack() {
    let builder = PackBuilder::new("claim-clone".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("f.rs", ArtifactKind::Source))
        .dependency(sample_dep("serde", "1.0"));
    let p1 = builder.clone().build().unwrap();
    let p2 = builder.build().unwrap();
    assert_eq!(p1.pack_hash, p2.pack_hash);
    assert_eq!(p1.pack_id, p2.pack_id);
}

#[test]
fn enrichment_builder_chaining_returns_self() {
    // Verify the fluent API works with full chaining
    let pack = PackBuilder::new("chain".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("a.rs", ArtifactKind::Source))
        .artifact(sample_artifact("b.rs", ArtifactKind::Binary))
        .dependency(sample_dep("dep1", "1.0"))
        .dependency(sample_dep("dep2", "2.0"))
        .license_finding(LicenseFinding {
            dependency: "dep1".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::None,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    assert_eq!(pack.artifact_count(), 2);
    assert_eq!(pack.dependency_count(), 2);
    assert!(pack.legal.is_some());
}

#[test]
fn enrichment_builder_no_artifacts_no_deps_valid() {
    let pack = PackBuilder::new("minimal".to_string(), epoch())
        .environment(sample_env())
        .build()
        .unwrap();
    assert_eq!(pack.artifact_count(), 0);
    assert_eq!(pack.dependency_count(), 0);
    assert!(pack.legal.is_none());
    let result = pack.verify_integrity();
    assert!(result.all_valid);
}

// -- ReproducibilityPack enrichment --

#[test]
fn enrichment_pack_debug_contains_claim_id() {
    let pack = build_simple_pack();
    let dbg = format!("{:?}", pack);
    assert!(dbg.contains("claim-01"));
}

#[test]
fn enrichment_pack_clone_equality() {
    let pack = build_simple_pack();
    assert_eq!(pack, pack.clone());
}

#[test]
fn enrichment_pack_hash_is_32_hex_chars() {
    let pack = build_simple_pack();
    assert_eq!(pack.pack_hash.len(), 32);
    assert!(pack.pack_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_pack_id_is_pack_prefix_plus_24_hex() {
    let pack = build_simple_pack();
    assert!(pack.pack_id.starts_with("pack-"));
    let suffix = &pack.pack_id[5..];
    assert_eq!(suffix.len(), 24); // 12 bytes hex = 24 chars
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_pack_different_claim_different_pack_id() {
    let p1 = PackBuilder::new("claim-A".to_string(), epoch())
        .environment(sample_env())
        .build()
        .unwrap();
    let p2 = PackBuilder::new("claim-B".to_string(), epoch())
        .environment(sample_env())
        .build()
        .unwrap();
    assert_ne!(p1.pack_id, p2.pack_id);
}

#[test]
fn enrichment_pack_different_epoch_different_pack_id() {
    let p1 = PackBuilder::new("same".to_string(), SecurityEpoch::from_raw(1))
        .environment(sample_env())
        .build()
        .unwrap();
    let p2 = PackBuilder::new("same".to_string(), SecurityEpoch::from_raw(2))
        .environment(sample_env())
        .build()
        .unwrap();
    assert_ne!(p1.pack_id, p2.pack_id);
}

#[test]
fn enrichment_pack_different_env_different_pack_id() {
    let mut env2 = sample_env();
    env2.os_name = "macOS".to_string();
    let p1 = PackBuilder::new("same".to_string(), epoch())
        .environment(sample_env())
        .build()
        .unwrap();
    let p2 = PackBuilder::new("same".to_string(), epoch())
        .environment(env2)
        .build()
        .unwrap();
    assert_ne!(p1.pack_id, p2.pack_id);
}

#[test]
fn enrichment_pack_requires_legal_review_with_medium_risk() {
    let pack = PackBuilder::new("medium-legal".to_string(), epoch())
        .environment(sample_env())
        .license_finding(LicenseFinding {
            dependency: "lgpl-lib".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    assert!(pack.requires_legal_review());
}

#[test]
fn enrichment_pack_no_review_with_low_risk() {
    let pack = PackBuilder::new("low-legal".to_string(), epoch())
        .environment(sample_env())
        .license_finding(LicenseFinding {
            dependency: "mit-lib".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::Low,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    assert!(!pack.requires_legal_review());
}

// -- PackIntegrityResult enrichment --

#[test]
fn enrichment_integrity_result_debug_format() {
    let result = build_simple_pack().verify_integrity();
    let dbg = format!("{:?}", result);
    assert!(dbg.contains("pack_hash_valid"));
    assert!(dbg.contains("all_valid"));
}

#[test]
fn enrichment_integrity_result_clone_equality() {
    let result = build_simple_pack().verify_integrity();
    assert_eq!(result, result.clone());
}

#[test]
fn enrichment_integrity_tampered_artifacts_order() {
    let mut pack = build_simple_pack();
    // Reverse the sorted artifacts
    pack.manifest.artifacts.reverse();
    let result = pack.verify_integrity();
    // artifacts are now not sorted
    assert!(!result.artifacts_sorted);
    assert!(!result.all_valid);
}

#[test]
fn enrichment_integrity_tampered_deps_order() {
    let mut pack = PackBuilder::new("dep-order".to_string(), epoch())
        .environment(sample_env())
        .dependency(sample_dep("alpha", "1.0"))
        .dependency(sample_dep("beta", "2.0"))
        .build()
        .unwrap();
    // Reverse the sorted dependencies
    pack.dependencies.dependencies.reverse();
    let result = pack.verify_integrity();
    assert!(!result.dependencies_sorted);
    assert!(!result.all_valid);
}

#[test]
fn enrichment_integrity_all_fields_false_when_everything_wrong() {
    let mut pack = build_simple_pack();
    pack.pack_hash = "bad".to_string();
    pack.manifest.total_count = 999;
    pack.manifest.total_size_bytes = 999;
    pack.manifest.artifacts.reverse();
    let result = pack.verify_integrity();
    assert!(!result.pack_hash_valid);
    assert!(!result.manifest_count_valid);
    assert!(!result.manifest_size_valid);
    assert!(!result.all_valid);
}

#[test]
fn enrichment_integrity_json_field_names() {
    let result = build_simple_pack().verify_integrity();
    let json = serde_json::to_string(&result).unwrap();
    for field in &[
        "pack_hash_valid",
        "manifest_count_valid",
        "manifest_size_valid",
        "artifacts_sorted",
        "dependencies_sorted",
        "all_valid",
    ] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

// -- ReproducibilityReport enrichment --

#[test]
fn enrichment_report_debug_contains_claim_id() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    let dbg = format!("{:?}", report);
    assert!(dbg.contains("claim-01"));
}

#[test]
fn enrichment_report_clone_equality() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report, report.clone());
}

#[test]
fn enrichment_report_schema_version_matches_constant() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_report_pack_id_matches_pack() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report.pack_id, pack.pack_id);
}

#[test]
fn enrichment_report_epoch_matches_pack() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report.epoch, pack.epoch);
}

#[test]
fn enrichment_report_pack_hash_matches_pack() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report.pack_hash, pack.pack_hash);
}

#[test]
fn enrichment_report_hash_is_32_hex_chars() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    assert_eq!(report.report_hash.len(), 32);
    assert!(report.report_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_report_json_all_field_names() {
    let pack = build_simple_pack();
    let report = generate_report(&pack);
    let json = serde_json::to_string(&report).unwrap();
    for field in &[
        "schema_version",
        "pack_id",
        "claim_id",
        "epoch",
        "integrity",
        "artifact_count",
        "dependency_count",
        "legal_review_required",
        "max_license_risk",
        "git_dirty",
        "pack_hash",
        "report_hash",
    ] {
        assert!(json.contains(field), "Missing field: {field}");
    }
}

#[test]
fn enrichment_report_with_low_risk_no_legal_review() {
    let pack = PackBuilder::new("low-risk-rpt".to_string(), epoch())
        .environment(sample_env())
        .license_finding(LicenseFinding {
            dependency: "bsd-lib".to_string(),
            license_spdx: "BSD-2-Clause".to_string(),
            risk: LicenseRisk::Low,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(!report.legal_review_required);
    assert_eq!(report.max_license_risk, Some(LicenseRisk::Low));
}

#[test]
fn enrichment_report_with_medium_risk_requires_review() {
    let pack = PackBuilder::new("medium-risk-rpt".to_string(), epoch())
        .environment(sample_env())
        .license_finding(LicenseFinding {
            dependency: "lgpl-lib".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: "".to_string(),
        })
        .build()
        .unwrap();
    let report = generate_report(&pack);
    assert!(report.legal_review_required);
    assert_eq!(report.max_license_risk, Some(LicenseRisk::Medium));
}

// -- Determinism across runs --

#[test]
fn enrichment_determinism_content_hashes_stable_across_calls() {
    let tc = sample_toolchain();
    let g = sample_git();
    let e = sample_env();
    let hashes_tc: Vec<String> = (0..5).map(|_| tc.content_hash()).collect();
    let hashes_g: Vec<String> = (0..5).map(|_| g.content_hash()).collect();
    let hashes_e: Vec<String> = (0..5).map(|_| e.content_hash()).collect();
    for h in &hashes_tc {
        assert_eq!(h, &hashes_tc[0]);
    }
    for h in &hashes_g {
        assert_eq!(h, &hashes_g[0]);
    }
    for h in &hashes_e {
        assert_eq!(h, &hashes_e[0]);
    }
}

#[test]
fn enrichment_determinism_manifest_hash_stable() {
    let arts = vec![
        sample_artifact("a.rs", ArtifactKind::Source),
        sample_artifact("b.rs", ArtifactKind::Binary),
    ];
    let hashes: Vec<String> = (0..5)
        .map(|_| {
            ArtifactManifest::from_artifacts("pid".to_string(), arts.clone()).manifest_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(h, &hashes[0]);
    }
}

#[test]
fn enrichment_determinism_snapshot_hash_stable() {
    let deps = vec![sample_dep("serde", "1.0"), sample_dep("sha2", "0.10")];
    let hashes: Vec<String> = (0..5)
        .map(|_| DependencySnapshot::from_entries(deps.clone()).snapshot_hash)
        .collect();
    for h in &hashes {
        assert_eq!(h, &hashes[0]);
    }
}

#[test]
fn enrichment_determinism_pack_build_stable() {
    let packs: Vec<ReproducibilityPack> = (0..3).map(|_| build_simple_pack()).collect();
    for p in &packs {
        assert_eq!(p.pack_id, packs[0].pack_id);
        assert_eq!(p.pack_hash, packs[0].pack_hash);
    }
}

#[test]
fn enrichment_determinism_report_hash_stable() {
    let pack = build_simple_pack();
    let hashes: Vec<String> = (0..5).map(|_| generate_report(&pack).report_hash).collect();
    for h in &hashes {
        assert_eq!(h, &hashes[0]);
    }
}

// -- Property-based patterns --

#[test]
fn enrichment_property_valid_pack_always_passes_integrity() {
    // Any pack built via PackBuilder should always pass integrity
    for i in 0..5 {
        let pack = PackBuilder::new(format!("claim-{i}"), epoch())
            .environment(sample_env())
            .artifact(sample_artifact(&format!("f{i}.rs"), ArtifactKind::Source))
            .dependency(sample_dep(&format!("dep{i}"), "1.0"))
            .build()
            .unwrap();
        let result = pack.verify_integrity();
        assert!(result.all_valid, "Pack {i} should pass integrity");
    }
}

#[test]
fn enrichment_property_tampered_hash_always_fails() {
    for i in 0..5 {
        let mut pack = PackBuilder::new(format!("tamper-{i}"), epoch())
            .environment(sample_env())
            .artifact(sample_artifact(&format!("f{i}.rs"), ArtifactKind::Source))
            .build()
            .unwrap();
        pack.pack_hash = format!("{:032x}", i);
        let result = pack.verify_integrity();
        assert!(!result.pack_hash_valid, "Tampered pack {i} should fail hash check");
        assert!(!result.all_valid);
    }
}

#[test]
fn enrichment_property_high_risk_implies_review_required() {
    let risks = [LicenseRisk::None, LicenseRisk::Low, LicenseRisk::Medium, LicenseRisk::High];
    for risk in &risks {
        let assessment = LegalAssessment::from_findings(vec![LicenseFinding {
            dependency: "test".to_string(),
            license_spdx: "X".to_string(),
            risk: *risk,
            notes: "".to_string(),
        }]);
        if *risk == LicenseRisk::High {
            assert!(assessment.has_high_risk, "High risk must set has_high_risk");
            assert!(assessment.review_required, "High risk must require review");
        }
        if *risk >= LicenseRisk::Medium {
            assert!(assessment.review_required, "{:?} must require review", risk);
        }
        if *risk < LicenseRisk::Medium {
            assert!(!assessment.review_required, "{:?} must not require review", risk);
        }
    }
}

#[test]
fn enrichment_property_empty_findings_never_high_risk() {
    let assessment = LegalAssessment::from_findings(vec![]);
    assert!(!assessment.has_high_risk);
    assert!(!assessment.review_required);
    assert_eq!(assessment.max_risk, LicenseRisk::None);
}

#[test]
fn enrichment_property_manifest_count_equals_vec_len() {
    for n in 0..6 {
        let arts: Vec<ArtifactEntry> = (0..n)
            .map(|i| sample_artifact(&format!("f{i}.rs"), ArtifactKind::Source))
            .collect();
        let manifest = ArtifactManifest::from_artifacts("pack".to_string(), arts);
        assert_eq!(manifest.total_count, n);
        assert_eq!(manifest.artifacts.len(), n);
    }
}

#[test]
fn enrichment_property_snapshot_count_equals_vec_len() {
    for n in 0..6 {
        let deps: Vec<DependencyEntry> = (0..n)
            .map(|i| sample_dep(&format!("dep{i}"), "1.0"))
            .collect();
        let snap = DependencySnapshot::from_entries(deps);
        assert_eq!(snap.total_count, n);
        assert_eq!(snap.dependencies.len(), n);
    }
}

#[test]
fn enrichment_property_serde_roundtrip_preserves_identity_for_all_types() {
    let pack = PackBuilder::new("round-trip".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("a.rs", ArtifactKind::Source))
        .dependency(sample_dep("serde", "1.0"))
        .license_finding(LicenseFinding {
            dependency: "gpl".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "copyleft".to_string(),
        })
        .build()
        .unwrap();
    let json = serde_json::to_string_pretty(&pack).unwrap();
    let back: ReproducibilityPack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);

    let report = generate_report(&pack);
    let rjson = serde_json::to_string_pretty(&report).unwrap();
    let rback: frankenengine_engine::reproducibility_provenance_pack::ReproducibilityReport =
        serde_json::from_str(&rjson).unwrap();
    assert_eq!(report, rback);
}

// -- Edge cases --

#[test]
fn enrichment_edge_empty_claim_id() {
    let pack = PackBuilder::new("".to_string(), epoch())
        .environment(sample_env())
        .build()
        .unwrap();
    assert_eq!(pack.claim_id, "");
    let result = pack.verify_integrity();
    assert!(result.all_valid);
}

#[test]
fn enrichment_edge_zero_epoch() {
    let pack = PackBuilder::new("zero-ep".to_string(), SecurityEpoch::from_raw(0))
        .environment(sample_env())
        .build()
        .unwrap();
    assert_eq!(pack.epoch, SecurityEpoch::from_raw(0));
    let result = pack.verify_integrity();
    assert!(result.all_valid);
}

#[test]
fn enrichment_edge_max_epoch() {
    let pack = PackBuilder::new("max-ep".to_string(), SecurityEpoch::from_raw(u64::MAX))
        .environment(sample_env())
        .build()
        .unwrap();
    assert_eq!(pack.epoch.as_u64(), u64::MAX);
    let result = pack.verify_integrity();
    assert!(result.all_valid);
}

#[test]
fn enrichment_edge_very_long_path_in_artifact() {
    let long_path = "a/".repeat(500) + "file.rs";
    let entry = ArtifactEntry {
        path: long_path.clone(),
        kind: ArtifactKind::Source,
        content_hash: "hash_long".to_string(),
        size_bytes: 1,
        redacted: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.path, long_path);
}

#[test]
fn enrichment_edge_unicode_in_dependency_name() {
    let dep = DependencyEntry {
        name: "crate-\u{00E9}\u{00FC}\u{00F1}".to_string(),
        version: "1.0.0".to_string(),
        source: "crates.io".to_string(),
        checksum: Some("ck_unicode".to_string()),
    };
    let json = serde_json::to_string(&dep).unwrap();
    let back: DependencyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, dep.name);
}

#[test]
fn enrichment_edge_all_artifact_kinds_in_one_manifest() {
    let kinds = [
        ArtifactKind::Source,
        ArtifactKind::Binary,
        ArtifactKind::Config,
        ArtifactKind::TestFixture,
        ArtifactKind::Evidence,
        ArtifactKind::LockFile,
        ArtifactKind::Documentation,
        ArtifactKind::Legal,
    ];
    let arts: Vec<ArtifactEntry> = kinds
        .iter()
        .enumerate()
        .map(|(i, k)| ArtifactEntry {
            path: format!("file_{i}.dat"),
            kind: *k,
            content_hash: format!("hash_{i}"),
            size_bytes: (i as u64 + 1) * 100,
            redacted: false,
        })
        .collect();
    let manifest = ArtifactManifest::from_artifacts("pack-all-kinds".to_string(), arts);
    assert_eq!(manifest.total_count, 8);
    let expected_size: u64 = (1..=8).map(|i| i * 100).sum();
    assert_eq!(manifest.total_size_bytes, expected_size);
}

#[test]
fn enrichment_edge_duplicate_artifact_paths() {
    // Duplicate paths are allowed (no dedup)
    let arts = vec![
        sample_artifact("dup.rs", ArtifactKind::Source),
        sample_artifact("dup.rs", ArtifactKind::Source),
    ];
    let manifest = ArtifactManifest::from_artifacts("pack-dup".to_string(), arts);
    assert_eq!(manifest.total_count, 2);
    assert_eq!(manifest.artifacts[0].path, manifest.artifacts[1].path);
}

#[test]
fn enrichment_edge_manifest_size_overflow_wraps() {
    // Very large sizes sum correctly
    let arts = vec![
        ArtifactEntry {
            path: "a.bin".to_string(),
            kind: ArtifactKind::Binary,
            content_hash: "h1".to_string(),
            size_bytes: u64::MAX / 2,
            redacted: false,
        },
        ArtifactEntry {
            path: "b.bin".to_string(),
            kind: ArtifactKind::Binary,
            content_hash: "h2".to_string(),
            size_bytes: 1,
            redacted: false,
        },
    ];
    let manifest = ArtifactManifest::from_artifacts("pack-big".to_string(), arts);
    assert_eq!(manifest.total_size_bytes, u64::MAX / 2 + 1);
}

// -- Full lifecycle (extended) --

#[test]
fn enrichment_full_lifecycle_with_all_risk_levels() {
    let pack = PackBuilder::new("frx-all-risks".to_string(), epoch())
        .environment(sample_env())
        .artifact(sample_artifact("main.rs", ArtifactKind::Source))
        .license_finding(LicenseFinding {
            dependency: "mit".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::None,
            notes: "".to_string(),
        })
        .license_finding(LicenseFinding {
            dependency: "bsd".to_string(),
            license_spdx: "BSD-3-Clause".to_string(),
            risk: LicenseRisk::Low,
            notes: "".to_string(),
        })
        .license_finding(LicenseFinding {
            dependency: "lgpl".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: "".to_string(),
        })
        .license_finding(LicenseFinding {
            dependency: "gpl".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "".to_string(),
        })
        .build()
        .unwrap();

    assert!(pack.requires_legal_review());
    let legal = pack.legal.as_ref().unwrap();
    assert!(legal.has_high_risk);
    assert_eq!(legal.max_risk, LicenseRisk::High);
    assert_eq!(legal.findings.len(), 4);
    // Sorted by dependency name
    assert_eq!(legal.findings[0].dependency, "bsd");
    assert_eq!(legal.findings[1].dependency, "gpl");
    assert_eq!(legal.findings[2].dependency, "lgpl");
    assert_eq!(legal.findings[3].dependency, "mit");

    let result = pack.verify_integrity();
    assert!(result.all_valid);

    let report = generate_report(&pack);
    assert!(report.legal_review_required);
    assert_eq!(report.max_license_risk, Some(LicenseRisk::High));
    assert!(report.integrity.all_valid);
}

#[test]
fn enrichment_full_lifecycle_large_pack() {
    let mut builder = PackBuilder::new("frx-large".to_string(), epoch())
        .environment(sample_env());

    for i in 0..50 {
        builder = builder.artifact(ArtifactEntry {
            path: format!("src/module_{i:03}.rs"),
            kind: ArtifactKind::Source,
            content_hash: format!("hash_{i:03}"),
            size_bytes: 1024 + i as u64,
            redacted: false,
        });
    }
    for i in 0..20 {
        builder = builder.dependency(DependencyEntry {
            name: format!("crate_{i:03}"),
            version: format!("{i}.0.0"),
            source: "crates.io".to_string(),
            checksum: Some(format!("ck_{i:03}")),
        });
    }

    let pack = builder.build().unwrap();
    assert_eq!(pack.artifact_count(), 50);
    assert_eq!(pack.dependency_count(), 20);

    let result = pack.verify_integrity();
    assert!(result.all_valid);
    assert!(result.artifacts_sorted);
    assert!(result.dependencies_sorted);

    let report = generate_report(&pack);
    assert_eq!(report.artifact_count, 50);
    assert_eq!(report.dependency_count, 20);

    // Serde roundtrip
    let json = serde_json::to_string(&pack).unwrap();
    let back: ReproducibilityPack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
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
