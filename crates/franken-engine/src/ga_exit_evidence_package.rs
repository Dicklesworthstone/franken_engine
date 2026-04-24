//! Deterministic GA exit evidence package for third-party reproducibility handoff.
//!
//! The package aggregates release-gate evidence, schema pins, security epoch,
//! build provenance, and replay instructions into a stable JSON bundle that an
//! external verifier can hash and replay byte-for-byte.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

/// Schema version for GA exit evidence package bundles.
pub const GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION: &str =
    "franken-engine.ga-exit-evidence-package.v1";

/// Release evidence surface represented in the GA package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDomain {
    /// Test262, differential, and compatibility evidence.
    Conformance,
    /// Benchmark and regression evidence.
    Performance,
    /// Capability, IFC, containment, and security audit evidence.
    Security,
    /// Operator telemetry, budget, and attestation evidence.
    Observability,
    /// Risk disposition and release-blocker evidence.
    RiskDisposition,
    /// Third-party replay and byte-for-byte determinism evidence.
    Reproducibility,
    /// Explicit supported and unsupported surface contract.
    SupportSurface,
    /// Compiler, source, and dependency provenance.
    BuildProvenance,
}

impl EvidenceDomain {
    /// Domains that must be represented before GA handoff is valid.
    pub const MANDATORY_FOR_GA: [Self; 7] = [
        Self::Conformance,
        Self::Performance,
        Self::Security,
        Self::Observability,
        Self::RiskDisposition,
        Self::Reproducibility,
        Self::SupportSurface,
    ];

    /// Stable lowercase identifier for manifests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conformance => "conformance",
            Self::Performance => "performance",
            Self::Security => "security",
            Self::Observability => "observability",
            Self::RiskDisposition => "risk_disposition",
            Self::Reproducibility => "reproducibility",
            Self::SupportSurface => "support_surface",
            Self::BuildProvenance => "build_provenance",
        }
    }
}

impl fmt::Display for EvidenceDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Claim mode under which an evidence artifact supports a public claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimMode {
    /// Claim is supported by normal budgeted telemetry.
    BudgetedTelemetry,
    /// Claim is supported only under exact-shadow validation.
    ExactShadow,
    /// Claim is supported under deterministic degraded mode.
    DegradedMode,
    /// Claim requires incident or full-capture mode.
    IncidentCapture,
    /// Claim is explicitly unsupported for GA.
    Unsupported,
}

impl ClaimMode {
    /// Stable lowercase identifier for manifests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetedTelemetry => "budgeted_telemetry",
            Self::ExactShadow => "exact_shadow",
            Self::DegradedMode => "degraded_mode",
            Self::IncidentCapture => "incident_capture",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ClaimMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Release-gate verdict for an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerdict {
    /// Evidence supports the release claim.
    Pass,
    /// Evidence fails the release claim.
    Fail,
    /// Evidence is inconclusive and must block if required.
    Inconclusive,
    /// Evidence is deliberately deferred with risk acceptance.
    Deferred,
}

impl EvidenceVerdict {
    /// Whether this verdict blocks release for a required artifact.
    pub const fn blocks_release(self) -> bool {
        !matches!(self, Self::Pass)
    }
}

/// Source and dependency provenance for the build that produced the evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BuildProvenance {
    /// Source commit used for the package.
    pub source_commit: String,
    /// Hash of the source tree at package assembly.
    pub source_tree_hash: ContentHash,
    /// Hash of Cargo.lock or equivalent dependency lock.
    pub cargo_lock_hash: ContentHash,
    /// Rust compiler version.
    pub rustc_version: String,
    /// Target triple.
    pub target_triple: String,
    /// Cargo profile used for gate evidence.
    pub cargo_profile: String,
    /// Deterministic build flags.
    pub build_flags: Vec<String>,
    /// Stable environment metadata.
    pub environment: BTreeMap<String, String>,
}

impl BuildProvenance {
    /// Return a copy with order-insensitive vectors sorted.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut copy = self.clone();
        copy.build_flags.sort();
        copy
    }
}

/// One required or optional artifact in the GA evidence package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Evidence domain covered by this artifact.
    pub domain: EvidenceDomain,
    /// Schema version of the referenced artifact.
    pub schema_version: String,
    /// Content hash of the referenced artifact bytes.
    pub content_hash: ContentHash,
    /// Immutable source path, URI, or artifact locator.
    pub locator: String,
    /// Whether this artifact is a fail-closed GA blocker.
    pub required: bool,
    /// Gate verdict.
    pub verdict: EvidenceVerdict,
    /// Claim mode in which this evidence is valid.
    pub claim_mode: ClaimMode,
    /// Optional command that replays this artifact.
    pub replay_command: Option<String>,
}

impl EvidenceArtifact {
    /// Build a required passing artifact with a replay command.
    #[must_use]
    pub fn required(
        artifact_id: impl Into<String>,
        domain: EvidenceDomain,
        schema_version: impl Into<String>,
        content_hash: ContentHash,
        locator: impl Into<String>,
        claim_mode: ClaimMode,
        replay_command: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            domain,
            schema_version: schema_version.into(),
            content_hash,
            locator: locator.into(),
            required: true,
            verdict: EvidenceVerdict::Pass,
            claim_mode,
            replay_command: Some(replay_command.into()),
        }
    }
}

/// Byte-identical replay witness for external verification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReproducibilityWitness {
    /// Stable witness identifier.
    pub witness_id: String,
    /// Schema version of the witness artifact.
    pub schema_version: String,
    /// Hash of the witness artifact bytes.
    pub content_hash: ContentHash,
    /// External verifier or tool expected to consume this witness.
    pub verifier: String,
    /// Ordered replay instructions for the witness.
    pub replay_instructions: Vec<String>,
}

impl ReproducibilityWitness {
    /// Return a copy preserving ordered replay instructions.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        self.clone()
    }
}

/// Deterministic GA exit evidence package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GaExitEvidencePackage {
    /// Schema version for this bundle.
    pub schema_version: String,
    /// Stable package identifier.
    pub package_id: String,
    /// Security epoch at which the package was assembled.
    pub security_epoch: SecurityEpoch,
    /// Build provenance.
    pub build_provenance: BuildProvenance,
    /// Release evidence artifacts keyed by stable artifact id.
    pub evidence_artifacts: BTreeMap<String, EvidenceArtifact>,
    /// Reproducibility witnesses keyed by stable witness id.
    pub reproducibility_witnesses: BTreeMap<String, ReproducibilityWitness>,
    /// Frozen schema versions for upstream package components.
    pub schema_versions: BTreeMap<String, String>,
    /// Risk disposition register keyed by stable risk id.
    pub risk_disposition_register: BTreeMap<String, String>,
    /// Commands that an external verifier can run.
    pub third_party_replay_commands: Vec<String>,
    /// Extra deterministic package metadata.
    pub metadata: BTreeMap<String, String>,
}

impl GaExitEvidencePackage {
    /// Create an empty package shell.
    #[must_use]
    pub fn new(
        package_id: impl Into<String>,
        security_epoch: SecurityEpoch,
        build_provenance: BuildProvenance,
    ) -> Self {
        Self {
            schema_version: GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION.to_string(),
            package_id: package_id.into(),
            security_epoch,
            build_provenance,
            evidence_artifacts: BTreeMap::new(),
            reproducibility_witnesses: BTreeMap::new(),
            schema_versions: BTreeMap::new(),
            risk_disposition_register: BTreeMap::new(),
            third_party_replay_commands: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add one evidence artifact.
    pub fn add_evidence_artifact(
        &mut self,
        artifact: EvidenceArtifact,
    ) -> Result<(), GaExitEvidencePackageError> {
        validate_artifact_fields(&artifact)?;
        if self.evidence_artifacts.contains_key(&artifact.artifact_id) {
            return Err(GaExitEvidencePackageError::DuplicateArtifact {
                artifact_id: artifact.artifact_id,
            });
        }
        self.evidence_artifacts
            .insert(artifact.artifact_id.clone(), artifact);
        Ok(())
    }

    /// Add one reproducibility witness.
    pub fn add_reproducibility_witness(
        &mut self,
        witness: ReproducibilityWitness,
    ) -> Result<(), GaExitEvidencePackageError> {
        validate_witness_fields(&witness)?;
        if self
            .reproducibility_witnesses
            .contains_key(&witness.witness_id)
        {
            return Err(GaExitEvidencePackageError::DuplicateWitness {
                witness_id: witness.witness_id,
            });
        }
        self.reproducibility_witnesses
            .insert(witness.witness_id.clone(), witness);
        Ok(())
    }

    /// Record a frozen upstream schema version.
    pub fn record_schema_version(
        &mut self,
        component: impl Into<String>,
        schema_version: impl Into<String>,
    ) -> Result<(), GaExitEvidencePackageError> {
        let component = component.into();
        let schema_version = schema_version.into();
        validate_non_empty("schema component", &component)?;
        validate_non_empty("schema_version", &schema_version)?;
        self.schema_versions.insert(component, schema_version);
        Ok(())
    }

    /// Record a risk disposition entry.
    pub fn record_risk_disposition(
        &mut self,
        risk_id: impl Into<String>,
        disposition: impl Into<String>,
    ) -> Result<(), GaExitEvidencePackageError> {
        let risk_id = risk_id.into();
        let disposition = disposition.into();
        validate_non_empty("risk_id", &risk_id)?;
        validate_non_empty("risk disposition", &disposition)?;
        self.risk_disposition_register.insert(risk_id, disposition);
        Ok(())
    }

    /// Add one external replay command.
    pub fn add_third_party_replay_command(
        &mut self,
        command: impl Into<String>,
    ) -> Result<(), GaExitEvidencePackageError> {
        let command = command.into();
        validate_non_empty("third-party replay command", &command)?;
        self.third_party_replay_commands.push(command);
        Ok(())
    }

    /// Return a canonicalized copy suitable for deterministic serialization.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut copy = self.clone();
        copy.build_provenance = copy.build_provenance.canonicalized();
        copy.third_party_replay_commands.sort();
        copy.reproducibility_witnesses = copy
            .reproducibility_witnesses
            .into_iter()
            .map(|(key, witness)| (key, witness.canonicalized()))
            .collect();
        copy
    }

    /// Validate that the package is complete enough for GA handoff.
    pub fn validate(&self) -> Result<(), GaExitEvidencePackageError> {
        validate_non_empty("schema_version", &self.schema_version)?;
        validate_non_empty("package_id", &self.package_id)?;
        validate_non_empty("source_commit", &self.build_provenance.source_commit)?;
        validate_non_empty("rustc_version", &self.build_provenance.rustc_version)?;
        validate_non_empty("target_triple", &self.build_provenance.target_triple)?;
        validate_non_empty("cargo_profile", &self.build_provenance.cargo_profile)?;

        if self.reproducibility_witnesses.is_empty() {
            return Err(GaExitEvidencePackageError::MissingReproducibilityWitness);
        }
        if self.third_party_replay_commands.is_empty() {
            return Err(GaExitEvidencePackageError::MissingThirdPartyReplayCommand);
        }

        for domain in EvidenceDomain::MANDATORY_FOR_GA {
            if !self
                .evidence_artifacts
                .values()
                .any(|artifact| artifact.domain == domain && artifact.required)
            {
                return Err(GaExitEvidencePackageError::MissingMandatoryDomain { domain });
            }
        }

        for (artifact_key, artifact) in &self.evidence_artifacts {
            validate_artifact_fields(artifact)?;
            if artifact_key != &artifact.artifact_id {
                return Err(GaExitEvidencePackageError::ArtifactKeyMismatch {
                    key: artifact_key.clone(),
                    artifact_id: artifact.artifact_id.clone(),
                });
            }
            if artifact.required && artifact.verdict.blocks_release() {
                return Err(GaExitEvidencePackageError::BlockingEvidence {
                    artifact_id: artifact.artifact_id.clone(),
                    verdict: artifact.verdict,
                });
            }
        }

        for (witness_key, witness) in &self.reproducibility_witnesses {
            validate_witness_fields(witness)?;
            if witness_key != &witness.witness_id {
                return Err(GaExitEvidencePackageError::WitnessKeyMismatch {
                    key: witness_key.clone(),
                    witness_id: witness.witness_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Serialize to deterministic compact JSON bytes.
    pub fn deterministic_json_bytes(&self) -> Result<Vec<u8>, GaExitEvidencePackageError> {
        self.validate()?;
        serde_json::to_vec(&self.canonicalized()).map_err(|err| {
            GaExitEvidencePackageError::Serialization {
                reason: err.to_string(),
            }
        })
    }

    /// Hash the deterministic package bytes.
    pub fn content_hash(&self) -> Result<ContentHash, GaExitEvidencePackageError> {
        self.deterministic_json_bytes()
            .map(|bytes| ContentHash::compute(&bytes))
    }

    /// Return artifact hashes keyed by artifact id.
    #[must_use]
    pub fn artifact_hashes(&self) -> BTreeMap<String, ContentHash> {
        self.evidence_artifacts
            .iter()
            .map(|(id, artifact)| (id.clone(), artifact.content_hash))
            .collect()
    }

    /// Return claim modes keyed by artifact id.
    #[must_use]
    pub fn claim_modes_by_artifact(&self) -> BTreeMap<String, ClaimMode> {
        self.evidence_artifacts
            .iter()
            .map(|(id, artifact)| (id.clone(), artifact.claim_mode))
            .collect()
    }

    /// Emit a compact machine-readable third-party handoff manifest.
    pub fn handoff_manifest(&self) -> Result<BTreeMap<String, String>, GaExitEvidencePackageError> {
        let package_hash = self.content_hash()?.to_hex();
        let mut manifest = BTreeMap::new();
        manifest.insert("schema_version".to_string(), self.schema_version.clone());
        manifest.insert("package_id".to_string(), self.package_id.clone());
        manifest.insert(
            "security_epoch".to_string(),
            self.security_epoch.as_u64().to_string(),
        );
        manifest.insert("package_hash".to_string(), package_hash);
        manifest.insert(
            "source_commit".to_string(),
            self.build_provenance.source_commit.clone(),
        );
        for (artifact_id, artifact) in &self.evidence_artifacts {
            manifest.insert(
                format!("artifact.{artifact_id}.hash"),
                artifact.content_hash.to_hex(),
            );
            manifest.insert(
                format!("artifact.{artifact_id}.schema_version"),
                artifact.schema_version.clone(),
            );
            manifest.insert(
                format!("artifact.{artifact_id}.claim_mode"),
                artifact.claim_mode.to_string(),
            );
        }
        Ok(manifest)
    }
}

/// GA package validation and serialization errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GaExitEvidencePackageError {
    /// Required string field was empty.
    EmptyField { field: &'static str },
    /// Artifact id was duplicated.
    DuplicateArtifact { artifact_id: String },
    /// Witness id was duplicated.
    DuplicateWitness { witness_id: String },
    /// Artifact map key disagreed with the embedded artifact id.
    ArtifactKeyMismatch { key: String, artifact_id: String },
    /// Witness map key disagreed with the embedded witness id.
    WitnessKeyMismatch { key: String, witness_id: String },
    /// Required artifact lacked a replay command.
    MissingArtifactReplayCommand { artifact_id: String },
    /// Witness lacked replay instructions.
    MissingWitnessReplayInstruction { witness_id: String },
    /// No reproducibility witness was present.
    MissingReproducibilityWitness,
    /// No top-level third-party replay command was present.
    MissingThirdPartyReplayCommand,
    /// A mandatory domain was absent.
    MissingMandatoryDomain { domain: EvidenceDomain },
    /// Required evidence blocks release.
    BlockingEvidence {
        artifact_id: String,
        verdict: EvidenceVerdict,
    },
    /// JSON serialization failed.
    Serialization { reason: String },
}

impl fmt::Display for GaExitEvidencePackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "GA evidence package field is empty: {field}"),
            Self::DuplicateArtifact { artifact_id } => {
                write!(f, "duplicate GA evidence artifact: {artifact_id}")
            }
            Self::DuplicateWitness { witness_id } => {
                write!(f, "duplicate GA reproducibility witness: {witness_id}")
            }
            Self::ArtifactKeyMismatch { key, artifact_id } => write!(
                f,
                "GA evidence artifact key mismatch: map key {key} embeds {artifact_id}"
            ),
            Self::WitnessKeyMismatch { key, witness_id } => write!(
                f,
                "GA reproducibility witness key mismatch: map key {key} embeds {witness_id}"
            ),
            Self::MissingArtifactReplayCommand { artifact_id } => write!(
                f,
                "required GA evidence artifact lacks replay command: {artifact_id}"
            ),
            Self::MissingWitnessReplayInstruction { witness_id } => write!(
                f,
                "GA reproducibility witness lacks replay instruction: {witness_id}"
            ),
            Self::MissingReproducibilityWitness => {
                f.write_str("GA evidence package requires a reproducibility witness")
            }
            Self::MissingThirdPartyReplayCommand => {
                f.write_str("GA evidence package requires a third-party replay command")
            }
            Self::MissingMandatoryDomain { domain } => {
                write!(f, "GA evidence package lacks required domain: {domain}")
            }
            Self::BlockingEvidence {
                artifact_id,
                verdict,
            } => write!(
                f,
                "GA evidence artifact blocks release: {artifact_id} ({verdict:?})"
            ),
            Self::Serialization { reason } => {
                write!(f, "GA evidence package serialization failed: {reason}")
            }
        }
    }
}

impl Error for GaExitEvidencePackageError {}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), GaExitEvidencePackageError> {
    if value.trim().is_empty() {
        return Err(GaExitEvidencePackageError::EmptyField { field });
    }
    Ok(())
}

fn validate_artifact_fields(
    artifact: &EvidenceArtifact,
) -> Result<(), GaExitEvidencePackageError> {
    validate_non_empty("artifact_id", &artifact.artifact_id)?;
    validate_non_empty("artifact schema_version", &artifact.schema_version)?;
    validate_non_empty("artifact locator", &artifact.locator)?;
    if artifact
        .required
        && artifact
            .replay_command
            .as_deref()
            .is_none_or(|command| command.trim().is_empty())
    {
        return Err(GaExitEvidencePackageError::MissingArtifactReplayCommand {
            artifact_id: artifact.artifact_id.clone(),
        });
    }
    Ok(())
}

fn validate_witness_fields(
    witness: &ReproducibilityWitness,
) -> Result<(), GaExitEvidencePackageError> {
    validate_non_empty("witness_id", &witness.witness_id)?;
    validate_non_empty("witness schema_version", &witness.schema_version)?;
    validate_non_empty("witness verifier", &witness.verifier)?;
    if witness.replay_instructions.is_empty()
        || witness
            .replay_instructions
            .iter()
            .any(|instruction| instruction.trim().is_empty())
    {
        return Err(
            GaExitEvidencePackageError::MissingWitnessReplayInstruction {
                witness_id: witness.witness_id.clone(),
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(label: &str) -> ContentHash {
        ContentHash::compute(label.as_bytes())
    }

    fn build_provenance() -> BuildProvenance {
        BuildProvenance {
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            source_tree_hash: hash("source-tree"),
            cargo_lock_hash: hash("cargo-lock"),
            rustc_version: "rustc 1.88.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            cargo_profile: "release".to_string(),
            build_flags: vec!["-Cdebuginfo=0".to_string(), "-Clto=fat".to_string()],
            environment: BTreeMap::from([
                ("os".to_string(), "linux".to_string()),
                ("runner".to_string(), "rch-ts2".to_string()),
            ]),
        }
    }

    fn artifact(id: &str, domain: EvidenceDomain) -> EvidenceArtifact {
        EvidenceArtifact::required(
            id,
            domain,
            format!("franken-engine.{}.v1", domain.as_str()),
            hash(id),
            format!("artifacts/{id}.json"),
            ClaimMode::BudgetedTelemetry,
            format!("frankenctl replay {id}"),
        )
    }

    fn witness(id: &str) -> ReproducibilityWitness {
        ReproducibilityWitness {
            witness_id: id.to_string(),
            schema_version: "franken-engine.repro-witness.v1".to_string(),
            content_hash: hash(id),
            verifier: "third-party-verifier".to_string(),
            replay_instructions: vec![
                "cargo check -p frankenengine-engine".to_string(),
                format!("frankenctl verify {id}"),
            ],
        }
    }

    fn complete_package() -> Result<GaExitEvidencePackage, GaExitEvidencePackageError> {
        let mut package = GaExitEvidencePackage::new(
            "ga-exit-2026-04-24",
            SecurityEpoch::from_raw(42),
            build_provenance(),
        );
        for domain in EvidenceDomain::MANDATORY_FOR_GA {
            package.add_evidence_artifact(artifact(domain.as_str(), domain))?;
        }
        package.add_reproducibility_witness(witness("witness-main"))?;
        package
            .record_schema_version("ga_evidence_index", GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION)?;
        package.record_risk_disposition("RISK-001", "accepted-with-controls")?;
        package.add_third_party_replay_command("cargo check -p frankenengine-engine")?;
        Ok(package)
    }

    #[test]
    fn schema_version_is_pinned() {
        assert_eq!(
            GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION,
            "franken-engine.ga-exit-evidence-package.v1"
        );
    }

    #[test]
    fn evidence_domain_strings_are_stable() {
        assert_eq!(EvidenceDomain::Conformance.as_str(), "conformance");
        assert_eq!(EvidenceDomain::RiskDisposition.as_str(), "risk_disposition");
        assert_eq!(
            EvidenceDomain::SupportSurface.to_string(),
            "support_surface"
        );
    }

    #[test]
    fn mandatory_domains_cover_ga_surfaces() {
        assert_eq!(EvidenceDomain::MANDATORY_FOR_GA.len(), 7);
        assert!(EvidenceDomain::MANDATORY_FOR_GA.contains(&EvidenceDomain::Reproducibility));
    }

    #[test]
    fn claim_mode_strings_are_stable() {
        assert_eq!(ClaimMode::ExactShadow.as_str(), "exact_shadow");
        assert_eq!(ClaimMode::IncidentCapture.to_string(), "incident_capture");
    }

    #[test]
    fn verdict_blocks_release_unless_pass() {
        assert!(!EvidenceVerdict::Pass.blocks_release());
        assert!(EvidenceVerdict::Fail.blocks_release());
        assert!(EvidenceVerdict::Inconclusive.blocks_release());
        assert!(EvidenceVerdict::Deferred.blocks_release());
    }

    #[test]
    fn new_package_sets_schema_and_epoch() {
        let package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::from_raw(7), build_provenance());
        assert_eq!(
            package.schema_version,
            GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION
        );
        assert_eq!(package.security_epoch.as_u64(), 7);
    }

    #[test]
    fn build_provenance_canonicalizes_flags() {
        let mut provenance = build_provenance();
        provenance.build_flags = vec!["z".to_string(), "a".to_string()];
        assert_eq!(
            provenance.canonicalized().build_flags,
            vec!["a".to_string(), "z".to_string()]
        );
    }

    #[test]
    fn add_artifact_indexes_by_id() -> Result<(), GaExitEvidencePackageError> {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        package.add_evidence_artifact(artifact("conformance", EvidenceDomain::Conformance))?;
        assert!(package.evidence_artifacts.contains_key("conformance"));
        Ok(())
    }

    #[test]
    fn duplicate_artifact_is_rejected() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        package
            .add_evidence_artifact(artifact("dup", EvidenceDomain::Conformance))
            .expect("first insert should succeed");
        let err = package
            .add_evidence_artifact(artifact("dup", EvidenceDomain::Performance))
            .unwrap_err();
        assert!(matches!(
            err,
            GaExitEvidencePackageError::DuplicateArtifact { .. }
        ));
    }

    #[test]
    fn empty_artifact_id_is_rejected() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        let err = package
            .add_evidence_artifact(artifact("", EvidenceDomain::Conformance))
            .unwrap_err();
        assert!(matches!(err, GaExitEvidencePackageError::EmptyField { .. }));
    }

    #[test]
    fn required_artifact_requires_replay_command() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        let mut item = artifact("conformance", EvidenceDomain::Conformance);
        item.replay_command = None;
        let err = package.add_evidence_artifact(item).unwrap_err();
        assert!(matches!(
            err,
            GaExitEvidencePackageError::MissingArtifactReplayCommand { .. }
        ));
    }

    #[test]
    fn required_artifact_rejects_whitespace_replay_command() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        let mut item = artifact("conformance", EvidenceDomain::Conformance);
        item.replay_command = Some("   ".to_string());
        let err = package.add_evidence_artifact(item).unwrap_err();
        assert!(matches!(
            err,
            GaExitEvidencePackageError::MissingArtifactReplayCommand { .. }
        ));
    }

    #[test]
    fn add_witness_indexes_by_id() -> Result<(), GaExitEvidencePackageError> {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        package.add_reproducibility_witness(witness("w1"))?;
        assert!(package.reproducibility_witnesses.contains_key("w1"));
        Ok(())
    }

    #[test]
    fn duplicate_witness_is_rejected() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        package
            .add_reproducibility_witness(witness("w1"))
            .expect("first insert should succeed");
        let err = package
            .add_reproducibility_witness(witness("w1"))
            .unwrap_err();
        assert!(matches!(
            err,
            GaExitEvidencePackageError::DuplicateWitness { .. }
        ));
    }

    #[test]
    fn empty_witness_instruction_is_rejected() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        let mut item = witness("w1");
        item.replay_instructions = vec![String::new()];
        let err = package.add_reproducibility_witness(item).unwrap_err();
        assert!(matches!(
            err,
            GaExitEvidencePackageError::MissingWitnessReplayInstruction { .. }
        ));
    }

    #[test]
    fn record_schema_version_requires_nonempty_values() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        assert!(package.record_schema_version("", "v1").is_err());
        assert!(package.record_schema_version("component", "").is_err());
    }

    #[test]
    fn risk_disposition_register_is_sorted() -> Result<(), GaExitEvidencePackageError> {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        package.record_risk_disposition("RISK-2", "deferred")?;
        package.record_risk_disposition("RISK-1", "accepted")?;
        let keys: Vec<&String> = package.risk_disposition_register.keys().collect();
        assert_eq!(keys, vec!["RISK-1", "RISK-2"]);
        Ok(())
    }

    #[test]
    fn replay_commands_are_canonicalized() -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        package.add_third_party_replay_command("aaa first")?;
        let canonical = package.canonicalized();
        assert_eq!(
            canonical
                .third_party_replay_commands
                .first()
                .map(String::as_str),
            Some("aaa first")
        );
        Ok(())
    }

    #[test]
    fn witness_replay_instruction_order_is_preserved() {
        let item = ReproducibilityWitness {
            witness_id: "ordered".to_string(),
            schema_version: "franken-engine.repro-witness.v1".to_string(),
            content_hash: hash("ordered"),
            verifier: "third-party-verifier".to_string(),
            replay_instructions: vec!["second".to_string(), "first".to_string()],
        };
        assert_eq!(
            item.canonicalized().replay_instructions,
            vec!["second".to_string(), "first".to_string()]
        );
    }

    #[test]
    fn complete_package_validates() -> Result<(), GaExitEvidencePackageError> {
        complete_package()?.validate()
    }

    #[test]
    fn validation_rejects_empty_package_id() {
        let package = GaExitEvidencePackage::new("", SecurityEpoch::GENESIS, build_provenance());
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::EmptyField { .. })
        ));
    }

    #[test]
    fn validation_rejects_empty_schema_version() {
        let mut package = complete_package().expect("package should build");
        package.schema_version.clear();
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::EmptyField { .. })
        ));
    }

    #[test]
    fn validation_rejects_missing_mandatory_domain() {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        package
            .add_reproducibility_witness(witness("w1"))
            .expect("witness should be valid");
        package
            .add_third_party_replay_command("cargo check -p frankenengine-engine")
            .expect("command should be valid");
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::MissingMandatoryDomain { .. })
        ));
    }

    #[test]
    fn validation_rejects_missing_witness() -> Result<(), GaExitEvidencePackageError> {
        let mut package =
            GaExitEvidencePackage::new("pkg", SecurityEpoch::GENESIS, build_provenance());
        for domain in EvidenceDomain::MANDATORY_FOR_GA {
            package.add_evidence_artifact(artifact(domain.as_str(), domain))?;
        }
        package.add_third_party_replay_command("cargo check -p frankenengine-engine")?;
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::MissingReproducibilityWitness)
        ));
        Ok(())
    }

    #[test]
    fn validation_rejects_blocking_required_artifact() -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        package
            .evidence_artifacts
            .get_mut("security")
            .expect("security artifact exists")
            .verdict = EvidenceVerdict::Inconclusive;
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::BlockingEvidence { .. })
        ));
        Ok(())
    }

    #[test]
    fn validation_rejects_public_artifact_key_mismatch() -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        let mut item = artifact("embedded-id", EvidenceDomain::BuildProvenance);
        item.required = false;
        package
            .evidence_artifacts
            .insert("map-key".to_string(), item);
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::ArtifactKeyMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn validation_rejects_public_witness_key_mismatch() -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        package
            .reproducibility_witnesses
            .insert("map-key".to_string(), witness("embedded-id"));
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::WitnessKeyMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn validation_rejects_public_blank_witness_instruction(
    ) -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        package
            .reproducibility_witnesses
            .get_mut("witness-main")
            .expect("witness exists")
            .replay_instructions
            .push(" ".to_string());
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::MissingWitnessReplayInstruction { .. })
        ));
        Ok(())
    }

    #[test]
    fn validation_rejects_public_blank_artifact_schema() -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        package
            .evidence_artifacts
            .get_mut("security")
            .expect("security artifact exists")
            .schema_version
            .clear();
        assert!(matches!(
            package.validate(),
            Err(GaExitEvidencePackageError::EmptyField { .. })
        ));
        Ok(())
    }

    #[test]
    fn optional_failing_artifact_does_not_block() -> Result<(), GaExitEvidencePackageError> {
        let mut package = complete_package()?;
        let mut optional = artifact("optional-advisory", EvidenceDomain::BuildProvenance);
        optional.required = false;
        optional.verdict = EvidenceVerdict::Fail;
        optional.replay_command = None;
        package.add_evidence_artifact(optional)?;
        package.validate()
    }

    #[test]
    fn deterministic_bytes_are_stable() -> Result<(), GaExitEvidencePackageError> {
        let package = complete_package()?;
        assert_eq!(
            package.deterministic_json_bytes()?,
            package.deterministic_json_bytes()?
        );
        Ok(())
    }

    #[test]
    fn deterministic_bytes_ignore_insertion_order() -> Result<(), GaExitEvidencePackageError> {
        let first = complete_package()?;
        let mut second = GaExitEvidencePackage::new(
            "ga-exit-2026-04-24",
            SecurityEpoch::from_raw(42),
            build_provenance(),
        );
        second.add_third_party_replay_command("cargo check -p frankenengine-engine")?;
        second.record_risk_disposition("RISK-001", "accepted-with-controls")?;
        second
            .record_schema_version("ga_evidence_index", GA_EXIT_EVIDENCE_PACKAGE_SCHEMA_VERSION)?;
        second.add_reproducibility_witness(witness("witness-main"))?;
        for domain in EvidenceDomain::MANDATORY_FOR_GA.into_iter().rev() {
            second.add_evidence_artifact(artifact(domain.as_str(), domain))?;
        }
        assert_eq!(
            first.deterministic_json_bytes()?,
            second.deterministic_json_bytes()?
        );
        Ok(())
    }

    #[test]
    fn content_hash_is_stable() -> Result<(), GaExitEvidencePackageError> {
        let package = complete_package()?;
        assert_eq!(package.content_hash()?, package.content_hash()?);
        Ok(())
    }

    #[test]
    fn content_hash_changes_when_artifact_changes() -> Result<(), GaExitEvidencePackageError> {
        let first = complete_package()?;
        let mut second = complete_package()?;
        second
            .evidence_artifacts
            .get_mut("performance")
            .expect("performance artifact exists")
            .content_hash = hash("changed");
        assert_ne!(first.content_hash()?, second.content_hash()?);
        Ok(())
    }

    #[test]
    fn artifact_hashes_are_reported() -> Result<(), GaExitEvidencePackageError> {
        let package = complete_package()?;
        assert_eq!(
            package.artifact_hashes().get("conformance"),
            Some(&hash("conformance"))
        );
        Ok(())
    }

    #[test]
    fn claim_modes_are_reported() -> Result<(), GaExitEvidencePackageError> {
        let package = complete_package()?;
        assert_eq!(
            package.claim_modes_by_artifact().get("security"),
            Some(&ClaimMode::BudgetedTelemetry)
        );
        Ok(())
    }

    #[test]
    fn handoff_manifest_contains_hashes_and_epoch() -> Result<(), GaExitEvidencePackageError> {
        let package = complete_package()?;
        let manifest = package.handoff_manifest()?;
        assert_eq!(
            manifest.get("security_epoch").map(String::as_str),
            Some("42")
        );
        assert!(manifest.contains_key("package_hash"));
        assert!(manifest.contains_key("artifact.conformance.hash"));
        Ok(())
    }

    #[test]
    fn serde_roundtrip_preserves_package() -> Result<(), Box<dyn Error>> {
        let package = complete_package()?;
        let json = serde_json::to_string(&package)?;
        let restored: GaExitEvidencePackage = serde_json::from_str(&json)?;
        assert_eq!(package, restored);
        Ok(())
    }

    #[test]
    fn display_errors_include_context() {
        let err = GaExitEvidencePackageError::MissingMandatoryDomain {
            domain: EvidenceDomain::Security,
        };
        assert!(err.to_string().contains("security"));
    }
}
