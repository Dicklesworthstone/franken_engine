//! Reproducibility + Legal + Provenance Artifact Pack Automation.
//!
//! Generates self-contained reproducibility packs for FRX claims, including:
//! - `env.json`: build environment capture (toolchain, OS, CPU),
//! - `manifest.json`: artifact listing with content hashes,
//! - `repro.lock`: deterministic dependency snapshot,
//! - `LEGAL.md` risk assessment when license risk applies,
//! - provenance fingerprints (toolchain, config, git).
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-16.2 (Reproducibility + Legal + Provenance).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for reproducibility pack artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.reproducibility-provenance.v1";

// ---------------------------------------------------------------------------
// ToolchainFingerprint — compiler and toolchain identity
// ---------------------------------------------------------------------------

/// Captures the exact toolchain used for a build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainFingerprint {
    /// Rust compiler version string (e.g., "1.79.0-nightly").
    pub rustc_version: String,
    /// Cargo version string.
    pub cargo_version: String,
    /// LLVM version if available.
    pub llvm_version: Option<String>,
    /// Linker identity (e.g., "cc", "lld", "mold").
    pub linker: String,
    /// Target triple (e.g., "x86_64-unknown-linux-gnu").
    pub target_triple: String,
    /// Rust edition (e.g., "2024").
    pub edition: String,
    /// Profile (e.g., "release", "dev").
    pub profile: String,
    /// Extra RUSTFLAGS applied.
    pub rustflags: Vec<String>,
}

impl ToolchainFingerprint {
    /// Compute a content hash of this fingerprint.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.rustc_version.as_bytes());
        hasher.update(self.cargo_version.as_bytes());
        if let Some(ref llvm) = self.llvm_version {
            hasher.update(llvm.as_bytes());
        }
        hasher.update(self.linker.as_bytes());
        hasher.update(self.target_triple.as_bytes());
        hasher.update(self.edition.as_bytes());
        hasher.update(self.profile.as_bytes());
        for flag in &self.rustflags {
            hasher.update(flag.as_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

// ---------------------------------------------------------------------------
// GitFingerprint — source control identity
// ---------------------------------------------------------------------------

/// Captures the exact git state at build time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitFingerprint {
    /// Commit SHA (full 40-char hex).
    pub commit_sha: String,
    /// Tree hash of the work tree.
    pub tree_hash: String,
    /// Branch name if on a named branch.
    pub branch: Option<String>,
    /// Whether the working tree had uncommitted changes.
    pub dirty: bool,
    /// Tags pointing to this commit.
    pub tags: Vec<String>,
}

impl GitFingerprint {
    /// Compute a content hash of this fingerprint.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.commit_sha.as_bytes());
        hasher.update(self.tree_hash.as_bytes());
        if let Some(ref b) = self.branch {
            hasher.update(b.as_bytes());
        }
        hasher.update(if self.dirty { b"dirty" } else { b"clean" });
        let mut sorted_tags = self.tags.clone();
        sorted_tags.sort();
        for tag in &sorted_tags {
            hasher.update(tag.as_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

// ---------------------------------------------------------------------------
// BuildEnvironment — OS and hardware identity (env.json)
// ---------------------------------------------------------------------------

/// Build environment capture (serialized as env.json in the pack).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildEnvironment {
    /// Operating system name.
    pub os_name: String,
    /// OS version string.
    pub os_version: String,
    /// CPU architecture.
    pub arch: String,
    /// Number of logical CPUs.
    pub cpu_count: u32,
    /// Total memory in megabytes.
    pub memory_mb: u64,
    /// Container image digest, if in a container.
    pub container_digest: Option<String>,
    /// CI system name (e.g., "github-actions"), if applicable.
    pub ci_system: Option<String>,
    /// CI run identifier, if applicable.
    pub ci_run_id: Option<String>,
    /// Toolchain fingerprint.
    pub toolchain: ToolchainFingerprint,
    /// Git fingerprint.
    pub git: GitFingerprint,
    /// Additional key-value metadata.
    pub extra: BTreeMap<String, String>,
}

impl BuildEnvironment {
    /// Compute a content hash of the entire environment.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.os_name.as_bytes());
        hasher.update(self.os_version.as_bytes());
        hasher.update(self.arch.as_bytes());
        hasher.update(self.cpu_count.to_le_bytes());
        hasher.update(self.memory_mb.to_le_bytes());
        hasher.update(self.toolchain.content_hash().as_bytes());
        hasher.update(self.git.content_hash().as_bytes());
        for (k, v) in &self.extra {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

// ---------------------------------------------------------------------------
// ArtifactEntry + ArtifactManifest — file listing (manifest.json)
// ---------------------------------------------------------------------------

/// Classification of an artifact in the pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Source code file.
    Source,
    /// Compiled binary or library.
    Binary,
    /// Configuration file.
    Config,
    /// Test fixture or corpus entry.
    TestFixture,
    /// Evidence or proof artifact.
    Evidence,
    /// Lock file or dependency snapshot.
    LockFile,
    /// Documentation.
    Documentation,
    /// Legal notice or license file.
    Legal,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => f.write_str("source"),
            Self::Binary => f.write_str("binary"),
            Self::Config => f.write_str("config"),
            Self::TestFixture => f.write_str("test_fixture"),
            Self::Evidence => f.write_str("evidence"),
            Self::LockFile => f.write_str("lock_file"),
            Self::Documentation => f.write_str("documentation"),
            Self::Legal => f.write_str("legal"),
        }
    }
}

/// A single artifact in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Relative path within the pack.
    pub path: String,
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// Content hash (SHA-256 hex, first 32 chars).
    pub content_hash: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Whether the artifact was redacted (e.g., secrets removed).
    pub redacted: bool,
}

/// Manifest listing all artifacts in the pack (serialized as manifest.json).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Schema version.
    pub schema_version: String,
    /// Pack identifier (content-addressed).
    pub pack_id: String,
    /// All artifacts sorted by path.
    pub artifacts: Vec<ArtifactEntry>,
    /// Total artifact count.
    pub total_count: usize,
    /// Total size in bytes.
    pub total_size_bytes: u64,
    /// Manifest hash (hash of all artifact hashes in order).
    pub manifest_hash: String,
}

impl ArtifactManifest {
    /// Build a manifest from a list of artifacts, computing aggregate fields.
    pub fn from_artifacts(pack_id: String, mut artifacts: Vec<ArtifactEntry>) -> Self {
        artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        let total_count = artifacts.len();
        let total_size_bytes: u64 = artifacts.iter().map(|a| a.size_bytes).sum();

        let mut hasher = Sha256::new();
        hasher.update(pack_id.as_bytes());
        for a in &artifacts {
            hasher.update(a.content_hash.as_bytes());
        }
        let manifest_hash = hex::encode(&hasher.finalize()[..16]);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            pack_id,
            artifacts,
            total_count,
            total_size_bytes,
            manifest_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// DependencyEntry + DependencySnapshot — (repro.lock)
// ---------------------------------------------------------------------------

/// A single dependency in the lock file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEntry {
    /// Crate/package name.
    pub name: String,
    /// Exact version.
    pub version: String,
    /// Source (e.g., "crates.io", "git", "path").
    pub source: String,
    /// Content hash or checksum of the dependency.
    pub checksum: Option<String>,
}

/// Deterministic dependency snapshot (serialized as repro.lock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySnapshot {
    /// Schema version.
    pub schema_version: String,
    /// All dependencies sorted by name.
    pub dependencies: Vec<DependencyEntry>,
    /// Total dependency count.
    pub total_count: usize,
    /// Snapshot hash (hash of all dependency entries).
    pub snapshot_hash: String,
}

impl DependencySnapshot {
    /// Build a snapshot from dependency entries.
    pub fn from_entries(mut entries: Vec<DependencyEntry>) -> Self {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let total_count = entries.len();

        let mut hasher = Sha256::new();
        for e in &entries {
            hasher.update(e.name.as_bytes());
            hasher.update(e.version.as_bytes());
            hasher.update(e.source.as_bytes());
            if let Some(ref ck) = e.checksum {
                hasher.update(ck.as_bytes());
            }
        }
        let snapshot_hash = hex::encode(&hasher.finalize()[..16]);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            dependencies: entries,
            total_count,
            snapshot_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// LicenseRisk + LegalAssessment — (LEGAL.md content model)
// ---------------------------------------------------------------------------

/// Risk level of a license dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseRisk {
    /// No license concern (MIT, Apache-2.0, BSD).
    None,
    /// Weak copyleft (LGPL, MPL) — requires notice.
    Low,
    /// Strong copyleft (GPL) — may restrict distribution.
    Medium,
    /// Unknown, proprietary, or incompatible license.
    High,
}

impl fmt::Display for LicenseRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
        }
    }
}

/// A license finding for a single dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseFinding {
    /// Dependency name.
    pub dependency: String,
    /// License identifier (SPDX).
    pub license_spdx: String,
    /// Risk classification.
    pub risk: LicenseRisk,
    /// Notes or conditions.
    pub notes: String,
}

/// Legal risk assessment for the entire pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalAssessment {
    /// Whether any high-risk licenses were found.
    pub has_high_risk: bool,
    /// Whether legal review is required before distribution.
    pub review_required: bool,
    /// Individual findings sorted by dependency name.
    pub findings: Vec<LicenseFinding>,
    /// Overall maximum risk level.
    pub max_risk: LicenseRisk,
    /// Summary text (rendered as LEGAL.md body).
    pub summary: String,
}

impl LegalAssessment {
    /// Build an assessment from a list of findings.
    pub fn from_findings(mut findings: Vec<LicenseFinding>) -> Self {
        findings.sort_by(|a, b| a.dependency.cmp(&b.dependency));
        let max_risk = findings
            .iter()
            .map(|f| f.risk)
            .max()
            .unwrap_or(LicenseRisk::None);
        let has_high_risk = max_risk == LicenseRisk::High;
        let review_required = max_risk >= LicenseRisk::Medium;

        let high_count = findings
            .iter()
            .filter(|f| f.risk == LicenseRisk::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.risk == LicenseRisk::Medium)
            .count();

        let summary = if has_high_risk {
            format!(
                "LEGAL REVIEW REQUIRED: {} high-risk and {} medium-risk license(s) detected",
                high_count, medium_count,
            )
        } else if review_required {
            format!(
                "Legal review recommended: {} medium-risk license(s) detected",
                medium_count,
            )
        } else {
            "No license concerns detected".to_string()
        };

        Self {
            has_high_risk,
            review_required,
            findings,
            max_risk,
            summary,
        }
    }
}

// ---------------------------------------------------------------------------
// ReproducibilityPack — the complete pack
// ---------------------------------------------------------------------------

/// Complete reproducibility/provenance pack for an FRX claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityPack {
    /// Content-addressed pack identifier.
    pub pack_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// FRX claim identifier this pack supports.
    pub claim_id: String,
    /// Build environment (env.json).
    pub environment: BuildEnvironment,
    /// Artifact manifest (manifest.json).
    pub manifest: ArtifactManifest,
    /// Dependency snapshot (repro.lock).
    pub dependencies: DependencySnapshot,
    /// Legal assessment (LEGAL.md, present when risk applies).
    pub legal: Option<LegalAssessment>,
    /// Pack-level content hash (hash of all sub-hashes).
    pub pack_hash: String,
}

impl ReproducibilityPack {
    /// Compute the pack-level content hash.
    fn compute_pack_hash(
        env_hash: &str,
        manifest_hash: &str,
        dep_hash: &str,
        claim_id: &str,
        epoch: &SecurityEpoch,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(claim_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(env_hash.as_bytes());
        hasher.update(manifest_hash.as_bytes());
        hasher.update(dep_hash.as_bytes());
        hex::encode(&hasher.finalize()[..16])
    }

    /// Verify that the pack hash matches recomputed values.
    pub fn verify_integrity(&self) -> PackIntegrityResult {
        let expected_pack_hash = Self::compute_pack_hash(
            &self.environment.content_hash(),
            &self.manifest.manifest_hash,
            &self.dependencies.snapshot_hash,
            &self.claim_id,
            &self.epoch,
        );

        let pack_hash_valid = self.pack_hash == expected_pack_hash;

        // Check manifest internal consistency.
        let expected_count = self.manifest.artifacts.len();
        let count_valid = self.manifest.total_count == expected_count;

        let expected_size: u64 = self.manifest.artifacts.iter().map(|a| a.size_bytes).sum();
        let size_valid = self.manifest.total_size_bytes == expected_size;

        // Check artifacts are sorted by path.
        let sorted = self
            .manifest
            .artifacts
            .windows(2)
            .all(|w| w[0].path <= w[1].path);

        // Check dependencies are sorted by name.
        let deps_sorted = self
            .dependencies
            .dependencies
            .windows(2)
            .all(|w| w[0].name <= w[1].name);

        PackIntegrityResult {
            pack_hash_valid,
            manifest_count_valid: count_valid,
            manifest_size_valid: size_valid,
            artifacts_sorted: sorted,
            dependencies_sorted: deps_sorted,
            all_valid: pack_hash_valid && count_valid && size_valid && sorted && deps_sorted,
        }
    }

    /// Whether legal review is required.
    pub fn requires_legal_review(&self) -> bool {
        self.legal
            .as_ref()
            .map(|l| l.review_required)
            .unwrap_or(false)
    }

    /// Total artifact count.
    pub fn artifact_count(&self) -> usize {
        self.manifest.total_count
    }

    /// Total dependency count.
    pub fn dependency_count(&self) -> usize {
        self.dependencies.total_count
    }
}

/// Result of pack integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackIntegrityResult {
    /// Whether the pack-level hash matches.
    pub pack_hash_valid: bool,
    /// Whether the manifest artifact count is consistent.
    pub manifest_count_valid: bool,
    /// Whether the manifest total size is consistent.
    pub manifest_size_valid: bool,
    /// Whether artifacts are sorted by path.
    pub artifacts_sorted: bool,
    /// Whether dependencies are sorted by name.
    pub dependencies_sorted: bool,
    /// All checks passed.
    pub all_valid: bool,
}

// ---------------------------------------------------------------------------
// PackBuilder — fluent builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `ReproducibilityPack`.
#[derive(Debug, Clone)]
pub struct PackBuilder {
    epoch: SecurityEpoch,
    claim_id: String,
    environment: Option<BuildEnvironment>,
    artifacts: Vec<ArtifactEntry>,
    dependencies: Vec<DependencyEntry>,
    license_findings: Vec<LicenseFinding>,
}

impl PackBuilder {
    /// Create a new builder.
    pub fn new(claim_id: String, epoch: SecurityEpoch) -> Self {
        Self {
            epoch,
            claim_id,
            environment: None,
            artifacts: Vec::new(),
            dependencies: Vec::new(),
            license_findings: Vec::new(),
        }
    }

    /// Set the build environment.
    pub fn environment(mut self, env: BuildEnvironment) -> Self {
        self.environment = Some(env);
        self
    }

    /// Add an artifact entry.
    pub fn artifact(mut self, entry: ArtifactEntry) -> Self {
        self.artifacts.push(entry);
        self
    }

    /// Add a dependency entry.
    pub fn dependency(mut self, entry: DependencyEntry) -> Self {
        self.dependencies.push(entry);
        self
    }

    /// Add a license finding.
    pub fn license_finding(mut self, finding: LicenseFinding) -> Self {
        self.license_findings.push(finding);
        self
    }

    /// Build the pack. Returns `None` if environment is not set.
    pub fn build(self) -> Option<ReproducibilityPack> {
        let environment = self.environment?;

        let env_hash = environment.content_hash();

        // Build pack_id from claim + epoch + env hash.
        let mut id_hasher = Sha256::new();
        id_hasher.update(self.claim_id.as_bytes());
        id_hasher.update(self.epoch.as_u64().to_le_bytes());
        id_hasher.update(env_hash.as_bytes());
        let pack_id = format!("pack-{}", hex::encode(&id_hasher.finalize()[..12]));

        let manifest = ArtifactManifest::from_artifacts(pack_id.clone(), self.artifacts);
        let dependencies = DependencySnapshot::from_entries(self.dependencies);

        let legal = if self.license_findings.is_empty() {
            None
        } else {
            Some(LegalAssessment::from_findings(self.license_findings))
        };

        let pack_hash = ReproducibilityPack::compute_pack_hash(
            &env_hash,
            &manifest.manifest_hash,
            &dependencies.snapshot_hash,
            &self.claim_id,
            &self.epoch,
        );

        Some(ReproducibilityPack {
            pack_id,
            schema_version: SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            claim_id: self.claim_id,
            environment,
            manifest,
            dependencies,
            legal,
            pack_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// ReproducibilityReport — CI-readable aggregate report
// ---------------------------------------------------------------------------

/// CI-readable report summarizing the reproducibility pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityReport {
    /// Schema version.
    pub schema_version: String,
    /// Pack identifier.
    pub pack_id: String,
    /// FRX claim identifier.
    pub claim_id: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Pack integrity status.
    pub integrity: PackIntegrityResult,
    /// Artifact count.
    pub artifact_count: usize,
    /// Dependency count.
    pub dependency_count: usize,
    /// Whether legal review is required.
    pub legal_review_required: bool,
    /// Maximum license risk level.
    pub max_license_risk: Option<LicenseRisk>,
    /// Git dirty flag.
    pub git_dirty: bool,
    /// Pack-level content hash.
    pub pack_hash: String,
    /// Content hash for report integrity.
    pub report_hash: String,
}

/// Generate a `ReproducibilityReport` from a pack.
pub fn generate_report(pack: &ReproducibilityPack) -> ReproducibilityReport {
    let integrity = pack.verify_integrity();

    let max_license_risk = pack.legal.as_ref().map(|l| l.max_risk);

    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(pack.pack_id.as_bytes());
    hasher.update(pack.pack_hash.as_bytes());
    hasher.update(
        if integrity.all_valid {
            "valid"
        } else {
            "invalid"
        }
        .as_bytes(),
    );
    let report_hash = hex::encode(&hasher.finalize()[..16]);

    ReproducibilityReport {
        schema_version: SCHEMA_VERSION.to_string(),
        pack_id: pack.pack_id.clone(),
        claim_id: pack.claim_id.clone(),
        epoch: pack.epoch,
        integrity,
        artifact_count: pack.artifact_count(),
        dependency_count: pack.dependency_count(),
        legal_review_required: pack.requires_legal_review(),
        max_license_risk,
        git_dirty: pack.environment.git.dirty,
        pack_hash: pack.pack_hash.clone(),
        report_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(10)
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

    // -- ToolchainFingerprint tests --

    #[test]
    fn toolchain_content_hash_deterministic() {
        let tc = test_toolchain();
        assert_eq!(tc.content_hash(), tc.content_hash());
    }

    #[test]
    fn toolchain_content_hash_differs_on_change() {
        let tc1 = test_toolchain();
        let mut tc2 = test_toolchain();
        tc2.rustc_version = "1.80.0-nightly".to_string();
        assert_ne!(tc1.content_hash(), tc2.content_hash());
    }

    #[test]
    fn toolchain_serde_roundtrip() {
        let tc = test_toolchain();
        let json = serde_json::to_string(&tc).unwrap();
        let back: ToolchainFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, back);
    }

    // -- GitFingerprint tests --

    #[test]
    fn git_content_hash_deterministic() {
        let git = test_git();
        assert_eq!(git.content_hash(), git.content_hash());
    }

    #[test]
    fn git_dirty_changes_hash() {
        let g1 = test_git();
        let mut g2 = test_git();
        g2.dirty = true;
        assert_ne!(g1.content_hash(), g2.content_hash());
    }

    #[test]
    fn git_serde_roundtrip() {
        let git = test_git();
        let json = serde_json::to_string(&git).unwrap();
        let back: GitFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(git, back);
    }

    // -- BuildEnvironment tests --

    #[test]
    fn env_content_hash_deterministic() {
        let env = test_env();
        assert_eq!(env.content_hash(), env.content_hash());
    }

    #[test]
    fn env_serde_roundtrip() {
        let env = test_env();
        let json = serde_json::to_string(&env).unwrap();
        let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    // -- ArtifactKind tests --

    #[test]
    fn artifact_kind_display_all() {
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
        let names: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(names.len(), 8);
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 8);
    }

    #[test]
    fn artifact_kind_serde_roundtrip() {
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

    // -- ArtifactManifest tests --

    #[test]
    fn manifest_sorts_artifacts() {
        let artifacts = vec![
            test_artifact("src/main.rs", ArtifactKind::Source),
            test_artifact("Cargo.toml", ArtifactKind::Config),
            test_artifact("src/lib.rs", ArtifactKind::Source),
        ];
        let manifest = ArtifactManifest::from_artifacts("pack-1".to_string(), artifacts);
        assert_eq!(manifest.artifacts[0].path, "Cargo.toml");
        assert_eq!(manifest.artifacts[1].path, "src/lib.rs");
        assert_eq!(manifest.artifacts[2].path, "src/main.rs");
    }

    #[test]
    fn manifest_computes_totals() {
        let artifacts = vec![
            test_artifact("a.rs", ArtifactKind::Source),
            test_artifact("b.rs", ArtifactKind::Source),
        ];
        let manifest = ArtifactManifest::from_artifacts("pack-2".to_string(), artifacts);
        assert_eq!(manifest.total_count, 2);
        assert_eq!(manifest.total_size_bytes, 2048);
    }

    #[test]
    fn manifest_hash_deterministic() {
        let artifacts = vec![test_artifact("a.rs", ArtifactKind::Source)];
        let m1 = ArtifactManifest::from_artifacts("pack-3".to_string(), artifacts.clone());
        let m2 = ArtifactManifest::from_artifacts("pack-3".to_string(), artifacts);
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let artifacts = vec![test_artifact("a.rs", ArtifactKind::Source)];
        let manifest = ArtifactManifest::from_artifacts("pack-4".to_string(), artifacts);
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ArtifactManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    // -- DependencySnapshot tests --

    #[test]
    fn dep_snapshot_sorts_entries() {
        let entries = vec![
            test_dep("serde", "1.0.200"),
            test_dep("anyhow", "1.0.0"),
            test_dep("sha2", "0.10.9"),
        ];
        let snap = DependencySnapshot::from_entries(entries);
        assert_eq!(snap.dependencies[0].name, "anyhow");
        assert_eq!(snap.dependencies[1].name, "serde");
        assert_eq!(snap.dependencies[2].name, "sha2");
    }

    #[test]
    fn dep_snapshot_hash_deterministic() {
        let entries = vec![test_dep("serde", "1.0.200")];
        let s1 = DependencySnapshot::from_entries(entries.clone());
        let s2 = DependencySnapshot::from_entries(entries);
        assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
    }

    #[test]
    fn dep_snapshot_serde_roundtrip() {
        let entries = vec![test_dep("serde", "1.0.200")];
        let snap = DependencySnapshot::from_entries(entries);
        let json = serde_json::to_string(&snap).unwrap();
        let back: DependencySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // -- LicenseRisk tests --

    #[test]
    fn license_risk_ordering() {
        assert!(LicenseRisk::None < LicenseRisk::Low);
        assert!(LicenseRisk::Low < LicenseRisk::Medium);
        assert!(LicenseRisk::Medium < LicenseRisk::High);
    }

    #[test]
    fn license_risk_display() {
        assert_eq!(LicenseRisk::None.to_string(), "none");
        assert_eq!(LicenseRisk::Low.to_string(), "low");
        assert_eq!(LicenseRisk::Medium.to_string(), "medium");
        assert_eq!(LicenseRisk::High.to_string(), "high");
    }

    #[test]
    fn license_risk_serde_roundtrip() {
        for r in [
            LicenseRisk::None,
            LicenseRisk::Low,
            LicenseRisk::Medium,
            LicenseRisk::High,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: LicenseRisk = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    // -- LegalAssessment tests --

    #[test]
    fn legal_no_findings() {
        let assessment = LegalAssessment::from_findings(vec![]);
        assert!(!assessment.has_high_risk);
        assert!(!assessment.review_required);
        assert_eq!(assessment.max_risk, LicenseRisk::None);
        assert!(assessment.summary.contains("No license concerns"));
    }

    #[test]
    fn legal_high_risk_detected() {
        let findings = vec![LicenseFinding {
            dependency: "gpl-crate".to_string(),
            license_spdx: "GPL-3.0".to_string(),
            risk: LicenseRisk::High,
            notes: "Strong copyleft".to_string(),
        }];
        let assessment = LegalAssessment::from_findings(findings);
        assert!(assessment.has_high_risk);
        assert!(assessment.review_required);
        assert_eq!(assessment.max_risk, LicenseRisk::High);
        assert!(assessment.summary.contains("LEGAL REVIEW REQUIRED"));
    }

    #[test]
    fn legal_medium_risk_review_recommended() {
        let findings = vec![LicenseFinding {
            dependency: "lgpl-crate".to_string(),
            license_spdx: "LGPL-2.1".to_string(),
            risk: LicenseRisk::Medium,
            notes: "Weak copyleft".to_string(),
        }];
        let assessment = LegalAssessment::from_findings(findings);
        assert!(!assessment.has_high_risk);
        assert!(assessment.review_required);
        assert!(assessment.summary.contains("recommended"));
    }

    #[test]
    fn legal_sorts_findings() {
        let findings = vec![
            LicenseFinding {
                dependency: "z-crate".to_string(),
                license_spdx: "MIT".to_string(),
                risk: LicenseRisk::None,
                notes: String::new(),
            },
            LicenseFinding {
                dependency: "a-crate".to_string(),
                license_spdx: "MIT".to_string(),
                risk: LicenseRisk::None,
                notes: String::new(),
            },
        ];
        let assessment = LegalAssessment::from_findings(findings);
        assert_eq!(assessment.findings[0].dependency, "a-crate");
        assert_eq!(assessment.findings[1].dependency, "z-crate");
    }

    #[test]
    fn legal_serde_roundtrip() {
        let findings = vec![LicenseFinding {
            dependency: "serde".to_string(),
            license_spdx: "MIT OR Apache-2.0".to_string(),
            risk: LicenseRisk::None,
            notes: "Dual licensed".to_string(),
        }];
        let assessment = LegalAssessment::from_findings(findings);
        let json = serde_json::to_string(&assessment).unwrap();
        let back: LegalAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(assessment, back);
    }

    // -- PackBuilder tests --

    #[test]
    fn builder_returns_none_without_environment() {
        let builder = PackBuilder::new("FRX-01".to_string(), test_epoch());
        assert!(builder.build().is_none());
    }

    #[test]
    fn builder_minimal_pack() {
        let pack = PackBuilder::new("FRX-01".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();

        assert!(pack.pack_id.starts_with("pack-"));
        assert_eq!(pack.claim_id, "FRX-01");
        assert_eq!(pack.epoch, test_epoch());
        assert_eq!(pack.artifact_count(), 0);
        assert_eq!(pack.dependency_count(), 0);
        assert!(pack.legal.is_none());
        assert!(!pack.requires_legal_review());
    }

    #[test]
    fn builder_with_artifacts_and_deps() {
        let pack = PackBuilder::new("FRX-02".to_string(), test_epoch())
            .environment(test_env())
            .artifact(test_artifact("src/main.rs", ArtifactKind::Source))
            .artifact(test_artifact("Cargo.toml", ArtifactKind::Config))
            .dependency(test_dep("serde", "1.0.200"))
            .dependency(test_dep("sha2", "0.10.9"))
            .build()
            .unwrap();

        assert_eq!(pack.artifact_count(), 2);
        assert_eq!(pack.dependency_count(), 2);
    }

    #[test]
    fn builder_with_legal_findings() {
        let pack = PackBuilder::new("FRX-03".to_string(), test_epoch())
            .environment(test_env())
            .license_finding(LicenseFinding {
                dependency: "gpl-dep".to_string(),
                license_spdx: "GPL-3.0".to_string(),
                risk: LicenseRisk::High,
                notes: "strong copyleft".to_string(),
            })
            .build()
            .unwrap();

        assert!(pack.requires_legal_review());
        assert!(pack.legal.is_some());
        assert!(pack.legal.as_ref().unwrap().has_high_risk);
    }

    // -- ReproducibilityPack tests --

    #[test]
    fn pack_integrity_valid() {
        let pack = PackBuilder::new("FRX-04".to_string(), test_epoch())
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
    fn pack_hash_deterministic() {
        let p1 = PackBuilder::new("FRX-05".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let p2 = PackBuilder::new("FRX-05".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        assert_eq!(p1.pack_hash, p2.pack_hash);
        assert_eq!(p1.pack_id, p2.pack_id);
    }

    #[test]
    fn pack_hash_differs_by_claim() {
        let p1 = PackBuilder::new("FRX-05".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let p2 = PackBuilder::new("FRX-06".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        assert_ne!(p1.pack_hash, p2.pack_hash);
    }

    #[test]
    fn pack_serde_roundtrip() {
        let pack = PackBuilder::new("FRX-07".to_string(), test_epoch())
            .environment(test_env())
            .artifact(test_artifact("a.rs", ArtifactKind::Source))
            .dependency(test_dep("serde", "1.0"))
            .license_finding(LicenseFinding {
                dependency: "dep".to_string(),
                license_spdx: "MIT".to_string(),
                risk: LicenseRisk::None,
                notes: String::new(),
            })
            .build()
            .unwrap();

        let json = serde_json::to_string(&pack).unwrap();
        let back: ReproducibilityPack = serde_json::from_str(&json).unwrap();
        assert_eq!(pack, back);
    }

    // -- ReproducibilityReport tests --

    #[test]
    fn report_from_valid_pack() {
        let pack = PackBuilder::new("FRX-08".to_string(), test_epoch())
            .environment(test_env())
            .artifact(test_artifact("a.rs", ArtifactKind::Source))
            .build()
            .unwrap();

        let report = generate_report(&pack);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.claim_id, "FRX-08");
        assert!(report.integrity.all_valid);
        assert_eq!(report.artifact_count, 1);
        assert!(!report.git_dirty);
        assert!(!report.legal_review_required);
        assert!(!report.report_hash.is_empty());
    }

    #[test]
    fn report_hash_deterministic() {
        let pack = PackBuilder::new("FRX-09".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();

        let r1 = generate_report(&pack);
        let r2 = generate_report(&pack);
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn report_shows_legal_risk() {
        let pack = PackBuilder::new("FRX-10".to_string(), test_epoch())
            .environment(test_env())
            .license_finding(LicenseFinding {
                dependency: "gpl-dep".to_string(),
                license_spdx: "GPL-3.0".to_string(),
                risk: LicenseRisk::High,
                notes: "strong copyleft".to_string(),
            })
            .build()
            .unwrap();

        let report = generate_report(&pack);
        assert!(report.legal_review_required);
        assert_eq!(report.max_license_risk, Some(LicenseRisk::High));
    }

    #[test]
    fn report_serde_roundtrip() {
        let pack = PackBuilder::new("FRX-11".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();

        let report = generate_report(&pack);
        let json = serde_json::to_string(&report).unwrap();
        let back: ReproducibilityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn report_dirty_git() {
        let mut env = test_env();
        env.git.dirty = true;
        let pack = PackBuilder::new("FRX-12".to_string(), test_epoch())
            .environment(env)
            .build()
            .unwrap();

        let report = generate_report(&pack);
        assert!(report.git_dirty);
    }

    // -- PackIntegrityResult tests --

    #[test]
    fn integrity_result_serde_roundtrip() {
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

    // -----------------------------------------------------------------------
    // Enrichment batch 2: edge cases, Display uniqueness, determinism
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_kind_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            ArtifactKind::Source,
            ArtifactKind::Binary,
            ArtifactKind::Config,
            ArtifactKind::TestFixture,
            ArtifactKind::Evidence,
            ArtifactKind::LockFile,
            ArtifactKind::Documentation,
            ArtifactKind::Legal,
        ]
        .iter()
        .map(|k| k.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            8,
            "all ArtifactKind variants must have unique Display"
        );
    }

    #[test]
    fn license_risk_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            LicenseRisk::None,
            LicenseRisk::Low,
            LicenseRisk::Medium,
            LicenseRisk::High,
        ]
        .iter()
        .map(|r| r.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            4,
            "all LicenseRisk variants must have unique Display"
        );
    }

    #[test]
    fn toolchain_fingerprint_serde_roundtrip() {
        let fp = test_env().toolchain;
        let json = serde_json::to_string(&fp).unwrap();
        let back: ToolchainFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, back);
    }

    #[test]
    fn build_environment_serde_roundtrip() {
        let env = test_env();
        let json = serde_json::to_string(&env).unwrap();
        let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn pack_artifact_count_and_dependency_count() {
        let pack = PackBuilder::new("FRX-count".to_string(), test_epoch())
            .environment(test_env())
            .artifact(test_artifact("a.rs", ArtifactKind::Source))
            .artifact(test_artifact("b.rs", ArtifactKind::Source))
            .artifact(test_artifact("c.bin", ArtifactKind::Binary))
            .dependency(test_dep("serde", "1.0"))
            .build()
            .unwrap();
        assert_eq!(pack.artifact_count(), 3);
        assert_eq!(pack.dependency_count(), 1);
    }

    #[test]
    fn pack_without_legal_does_not_require_review() {
        let pack = PackBuilder::new("FRX-nolegal".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        assert!(!pack.requires_legal_review());
        assert!(pack.legal.is_none());
    }

    #[test]
    fn pack_low_risk_findings_no_high_risk() {
        let pack = PackBuilder::new("FRX-low".to_string(), test_epoch())
            .environment(test_env())
            .license_finding(LicenseFinding {
                dependency: "mit-crate".to_string(),
                license_spdx: "MIT".to_string(),
                risk: LicenseRisk::Low,
                notes: "permissive".to_string(),
            })
            .build()
            .unwrap();
        let legal = pack.legal.as_ref().unwrap();
        assert!(!legal.has_high_risk);
        assert_eq!(legal.max_risk, LicenseRisk::Low);
    }

    // -- Enrichment batch 3: clone, individual serde, JSON fields --

    #[test]
    fn toolchain_fingerprint_clone_equality() {
        let fp = test_env().toolchain;
        assert_eq!(fp, fp.clone());
    }

    #[test]
    fn build_environment_clone_equality() {
        let env = test_env();
        assert_eq!(env, env.clone());
    }

    #[test]
    fn license_finding_serde_roundtrip() {
        let finding = LicenseFinding {
            dependency: "serde".to_string(),
            license_spdx: "MIT OR Apache-2.0".to_string(),
            risk: LicenseRisk::None,
            notes: "dual".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: LicenseFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    #[test]
    fn artifact_entry_serde_roundtrip() {
        let entry = test_artifact("main.rs", ArtifactKind::Source);
        let json = serde_json::to_string(&entry).unwrap();
        let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn dependency_entry_serde_roundtrip() {
        let dep = test_dep("serde", "1.0.200");
        let json = serde_json::to_string(&dep).unwrap();
        let back: DependencyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(dep, back);
    }

    #[test]
    fn artifact_kind_serde_all_variants() {
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
            let json = serde_json::to_string(k).unwrap();
            let back: ArtifactKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    #[test]
    fn artifact_kind_ordering() {
        assert!(ArtifactKind::Source < ArtifactKind::Legal);
    }

    #[test]
    fn git_fingerprint_serde_roundtrip() {
        let git = test_env().git;
        let json = serde_json::to_string(&git).unwrap();
        let back: GitFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(git, back);
    }

    #[test]
    fn pack_json_field_presence() {
        let pack = PackBuilder::new("FRX-json".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let json = serde_json::to_string(&pack).unwrap();
        for field in &[
            "pack_id",
            "claim_id",
            "schema_version",
            "epoch",
            "environment",
            "manifest",
            "dependencies",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn report_json_field_presence() {
        let pack = PackBuilder::new("FRX-rpt".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let report = generate_report(&pack);
        let json = serde_json::to_string(&report).unwrap();
        for field in &[
            "schema_version",
            "claim_id",
            "artifact_count",
            "integrity",
            "git_dirty",
            "report_hash",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn legal_multiple_risks_selects_max() {
        let findings = vec![
            LicenseFinding {
                dependency: "a".to_string(),
                license_spdx: "MIT".to_string(),
                risk: LicenseRisk::Low,
                notes: String::new(),
            },
            LicenseFinding {
                dependency: "b".to_string(),
                license_spdx: "GPL-3.0".to_string(),
                risk: LicenseRisk::High,
                notes: String::new(),
            },
            LicenseFinding {
                dependency: "c".to_string(),
                license_spdx: "LGPL-2.1".to_string(),
                risk: LicenseRisk::Medium,
                notes: String::new(),
            },
        ];
        let assessment = LegalAssessment::from_findings(findings);
        assert_eq!(assessment.max_risk, LicenseRisk::High);
        assert!(assessment.has_high_risk);
        assert!(assessment.review_required);
    }

    #[test]
    fn pack_integrity_result_clone_equality() {
        let result = PackIntegrityResult {
            pack_hash_valid: true,
            manifest_count_valid: true,
            manifest_size_valid: true,
            artifacts_sorted: true,
            dependencies_sorted: true,
            all_valid: true,
        };
        assert_eq!(result, result.clone());
    }

    #[test]
    fn reproducibility_report_clone_equality() {
        let pack = PackBuilder::new("FRX-clone".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let report = generate_report(&pack);
        assert_eq!(report, report.clone());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: content-hash sensitivity, edge cases, integrity
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_constant_value() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.reproducibility-provenance.v1"
        );
    }

    #[test]
    fn toolchain_hash_differs_on_llvm_none_vs_some() {
        let mut tc1 = test_toolchain();
        tc1.llvm_version = None;
        let mut tc2 = test_toolchain();
        tc2.llvm_version = Some("18.1.0".to_string());
        assert_ne!(tc1.content_hash(), tc2.content_hash());
    }

    #[test]
    fn toolchain_hash_differs_on_linker() {
        let mut tc1 = test_toolchain();
        tc1.linker = "cc".to_string();
        let mut tc2 = test_toolchain();
        tc2.linker = "mold".to_string();
        assert_ne!(tc1.content_hash(), tc2.content_hash());
    }

    #[test]
    fn toolchain_hash_differs_on_profile() {
        let mut tc1 = test_toolchain();
        tc1.profile = "release".to_string();
        let mut tc2 = test_toolchain();
        tc2.profile = "dev".to_string();
        assert_ne!(tc1.content_hash(), tc2.content_hash());
    }

    #[test]
    fn toolchain_hash_differs_on_rustflags() {
        let mut tc1 = test_toolchain();
        tc1.rustflags = vec![];
        let tc2 = test_toolchain(); // has ["-C linker=cc"]
        assert_ne!(tc1.content_hash(), tc2.content_hash());
    }

    #[test]
    fn git_hash_differs_on_branch_none_vs_some() {
        let mut g1 = test_git();
        g1.branch = None;
        let g2 = test_git(); // branch = Some("main")
        assert_ne!(g1.content_hash(), g2.content_hash());
    }

    #[test]
    fn git_hash_differs_on_tags() {
        let mut g1 = test_git();
        g1.tags = vec![];
        let g2 = test_git(); // tags = ["v0.1.0"]
        assert_ne!(g1.content_hash(), g2.content_hash());
    }

    #[test]
    fn git_hash_differs_on_commit_sha() {
        let mut g1 = test_git();
        g1.commit_sha = "0000000000000000000000000000000000000000".to_string();
        let g2 = test_git();
        assert_ne!(g1.content_hash(), g2.content_hash());
    }

    #[test]
    fn env_hash_differs_on_extra_map() {
        let mut env1 = test_env();
        env1.extra = BTreeMap::new();
        let mut env2 = test_env();
        env2.extra
            .insert("custom_key".to_string(), "custom_value".to_string());
        assert_ne!(env1.content_hash(), env2.content_hash());
    }

    #[test]
    fn env_hash_differs_on_os_name() {
        let mut env1 = test_env();
        env1.os_name = "Linux".to_string();
        let mut env2 = test_env();
        env2.os_name = "macOS".to_string();
        assert_ne!(env1.content_hash(), env2.content_hash());
    }

    #[test]
    fn env_hash_differs_on_cpu_count() {
        let mut env1 = test_env();
        env1.cpu_count = 8;
        let mut env2 = test_env();
        env2.cpu_count = 32;
        assert_ne!(env1.content_hash(), env2.content_hash());
    }

    #[test]
    fn manifest_empty_artifacts() {
        let manifest = ArtifactManifest::from_artifacts("pack-empty".to_string(), vec![]);
        assert_eq!(manifest.total_count, 0);
        assert_eq!(manifest.total_size_bytes, 0);
        assert!(manifest.artifacts.is_empty());
        assert!(!manifest.manifest_hash.is_empty());
    }

    #[test]
    fn manifest_hash_differs_with_different_pack_id() {
        let arts = vec![test_artifact("a.rs", ArtifactKind::Source)];
        let m1 = ArtifactManifest::from_artifacts("pack-A".to_string(), arts.clone());
        let m2 = ArtifactManifest::from_artifacts("pack-B".to_string(), arts);
        assert_ne!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn manifest_schema_version_matches_constant() {
        let manifest = ArtifactManifest::from_artifacts("pack-ver".to_string(), vec![]);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn dep_snapshot_empty_entries() {
        let snap = DependencySnapshot::from_entries(vec![]);
        assert_eq!(snap.total_count, 0);
        assert!(snap.dependencies.is_empty());
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
        assert!(!snap.snapshot_hash.is_empty());
    }

    #[test]
    fn dep_snapshot_hash_differs_on_checksum_none_vs_some() {
        let mut dep1 = test_dep("serde", "1.0");
        dep1.checksum = None;
        let dep2 = test_dep("serde", "1.0"); // checksum = Some("ck_serde")
        let s1 = DependencySnapshot::from_entries(vec![dep1]);
        let s2 = DependencySnapshot::from_entries(vec![dep2]);
        assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
    }

    #[test]
    fn dep_snapshot_hash_differs_on_version() {
        let s1 = DependencySnapshot::from_entries(vec![test_dep("serde", "1.0")]);
        let s2 = DependencySnapshot::from_entries(vec![test_dep("serde", "2.0")]);
        assert_ne!(s1.snapshot_hash, s2.snapshot_hash);
    }

    #[test]
    fn legal_low_risk_does_not_require_review() {
        let findings = vec![LicenseFinding {
            dependency: "permissive".to_string(),
            license_spdx: "MIT".to_string(),
            risk: LicenseRisk::Low,
            notes: String::new(),
        }];
        let assessment = LegalAssessment::from_findings(findings);
        assert!(!assessment.review_required);
        assert!(!assessment.has_high_risk);
        assert_eq!(assessment.max_risk, LicenseRisk::Low);
    }

    #[test]
    fn legal_summary_high_risk_includes_counts() {
        let findings = vec![
            LicenseFinding {
                dependency: "gpl1".to_string(),
                license_spdx: "GPL-3.0".to_string(),
                risk: LicenseRisk::High,
                notes: String::new(),
            },
            LicenseFinding {
                dependency: "lgpl1".to_string(),
                license_spdx: "LGPL-2.1".to_string(),
                risk: LicenseRisk::Medium,
                notes: String::new(),
            },
        ];
        let assessment = LegalAssessment::from_findings(findings);
        assert!(assessment.summary.contains("1 high-risk"));
        assert!(assessment.summary.contains("1 medium-risk"));
    }

    #[test]
    fn legal_summary_medium_only_includes_count() {
        let findings = vec![
            LicenseFinding {
                dependency: "lgpl1".to_string(),
                license_spdx: "LGPL-2.1".to_string(),
                risk: LicenseRisk::Medium,
                notes: String::new(),
            },
            LicenseFinding {
                dependency: "lgpl2".to_string(),
                license_spdx: "MPL-2.0".to_string(),
                risk: LicenseRisk::Medium,
                notes: String::new(),
            },
        ];
        let assessment = LegalAssessment::from_findings(findings);
        assert!(assessment.summary.contains("2 medium-risk"));
        assert!(assessment.summary.contains("recommended"));
    }

    #[test]
    fn pack_hash_differs_by_epoch() {
        let p1 = PackBuilder::new("FRX-ep".to_string(), SecurityEpoch::from_raw(1))
            .environment(test_env())
            .build()
            .unwrap();
        let p2 = PackBuilder::new("FRX-ep".to_string(), SecurityEpoch::from_raw(2))
            .environment(test_env())
            .build()
            .unwrap();
        assert_ne!(p1.pack_hash, p2.pack_hash);
        assert_ne!(p1.pack_id, p2.pack_id);
    }

    #[test]
    fn pack_integrity_fails_on_tampered_hash() {
        let mut pack = PackBuilder::new("FRX-tamper".to_string(), test_epoch())
            .environment(test_env())
            .artifact(test_artifact("a.rs", ArtifactKind::Source))
            .build()
            .unwrap();
        pack.pack_hash = "deadbeefdeadbeef".to_string();
        let result = pack.verify_integrity();
        assert!(!result.pack_hash_valid);
        assert!(!result.all_valid);
    }

    #[test]
    fn pack_integrity_fails_on_tampered_count() {
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
    fn pack_integrity_fails_on_tampered_size() {
        let mut pack = PackBuilder::new("FRX-sz".to_string(), test_epoch())
            .environment(test_env())
            .artifact(test_artifact("a.rs", ArtifactKind::Source))
            .build()
            .unwrap();
        pack.manifest.total_size_bytes = 0;
        let result = pack.verify_integrity();
        assert!(!result.manifest_size_valid);
        assert!(!result.all_valid);
    }

    #[test]
    fn report_no_legal_shows_none_risk() {
        let pack = PackBuilder::new("FRX-norisk".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let report = generate_report(&pack);
        assert!(report.max_license_risk.is_none());
        assert!(!report.legal_review_required);
    }

    #[test]
    fn report_hash_differs_for_different_packs() {
        let p1 = PackBuilder::new("FRX-r1".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let p2 = PackBuilder::new("FRX-r2".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        let r1 = generate_report(&p1);
        let r2 = generate_report(&p2);
        assert_ne!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn artifact_entry_redacted_field_survives_serde() {
        let entry = ArtifactEntry {
            path: "secrets.txt".to_string(),
            kind: ArtifactKind::Config,
            content_hash: "hash_redacted".to_string(),
            size_bytes: 512,
            redacted: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
        assert!(back.redacted);
    }

    #[test]
    fn dependency_entry_without_checksum_serde() {
        let dep = DependencyEntry {
            name: "local-dep".to_string(),
            version: "0.1.0".to_string(),
            source: "path".to_string(),
            checksum: None,
        };
        let json = serde_json::to_string(&dep).unwrap();
        let back: DependencyEntry = serde_json::from_str(&json).unwrap();
        assert!(back.checksum.is_none());
    }

    #[test]
    fn builder_multiple_license_findings_sorted() {
        let pack = PackBuilder::new("FRX-multi".to_string(), test_epoch())
            .environment(test_env())
            .license_finding(LicenseFinding {
                dependency: "z-dep".to_string(),
                license_spdx: "MIT".to_string(),
                risk: LicenseRisk::None,
                notes: String::new(),
            })
            .license_finding(LicenseFinding {
                dependency: "a-dep".to_string(),
                license_spdx: "GPL-3.0".to_string(),
                risk: LicenseRisk::High,
                notes: String::new(),
            })
            .build()
            .unwrap();
        let legal = pack.legal.as_ref().unwrap();
        assert_eq!(legal.findings[0].dependency, "a-dep");
        assert_eq!(legal.findings[1].dependency, "z-dep");
    }

    #[test]
    fn env_with_container_digest_serde_roundtrip() {
        let mut env = test_env();
        env.container_digest = Some("sha256:abc123".to_string());
        let json = serde_json::to_string(&env).unwrap();
        let back: BuildEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.container_digest, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn git_fingerprint_no_branch_no_tags_serde() {
        let git = GitFingerprint {
            commit_sha: "0".repeat(40),
            tree_hash: "1".repeat(40),
            branch: None,
            dirty: true,
            tags: vec![],
        };
        let json = serde_json::to_string(&git).unwrap();
        let back: GitFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(git, back);
        assert!(back.branch.is_none());
        assert!(back.tags.is_empty());
    }

    #[test]
    fn pack_id_format_starts_with_pack_prefix() {
        let pack = PackBuilder::new("FRX-prefix".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        assert!(
            pack.pack_id.starts_with("pack-"),
            "pack_id must start with 'pack-'"
        );
        assert!(
            pack.pack_id.len() > 5,
            "pack_id must have content after prefix"
        );
    }

    #[test]
    fn pack_schema_version_matches_constant() {
        let pack = PackBuilder::new("FRX-sv".to_string(), test_epoch())
            .environment(test_env())
            .build()
            .unwrap();
        assert_eq!(pack.schema_version, SCHEMA_VERSION);
    }
}
