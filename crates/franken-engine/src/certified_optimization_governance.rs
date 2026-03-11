//! Certified optimization governance for tiering, rollback, and workload
//! forensics.
//!
//! Implements [RGC-607C]: integrates certified optimizers into real workloads
//! with explicit rollback, regression, and operator-forensics surfaces so
//! aggressive optimization never outruns debuggability.
//!
//! # Design
//!
//! - `OptimizationTier` defines the optimization aggressiveness ladder.
//! - `OptimizationCertificate` attests that a specific rewrite at a given tier
//!   has passed proof-of-correctness checks.
//! - `RollbackRecord` captures every demotion back to a safer tier.
//! - `ForensicEntry` provides forensic breadcrumbs (source maps, rewrite
//!   chains, proof artifacts, regret traces, operator logs, diff baselines).
//! - `GovernanceState` is the single-epoch aggregate state that evaluates
//!   invariants via `GovernanceVerdict` and produces `GovernanceReport`.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-607C]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.certified-optimization-governance.v1";

/// Component name.
pub const COMPONENT: &str = "certified_optimization_governance";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.7.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-607C";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default maximum speculative promotions without a valid certificate.
pub const DEFAULT_MAX_SPECULATIVE_WITHOUT_CERT: u64 = 2;

/// Default maximum rollbacks per epoch before governance rejects.
pub const DEFAULT_MAX_ROLLBACKS_PER_EPOCH: u64 = 5;

/// Default minimum certificate validity span (epochs).
pub const DEFAULT_MIN_CERT_VALIDITY_EPOCHS: u64 = 10;

/// Default forensic retention (epochs).
pub const DEFAULT_FORENSIC_RETENTION_EPOCHS: u64 = 100;

/// Default maximum concurrently active speculative tiers.
pub const DEFAULT_MAX_ACTIVE_SPECULATIVE: u64 = 8;

// ---------------------------------------------------------------------------
// OptimizationTier
// ---------------------------------------------------------------------------

/// Optimization aggressiveness ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationTier {
    /// Interpreted / no optimization.
    Baseline,
    /// Standard optimization (safe rewrites only).
    Standard,
    /// Aggressive optimization (requires proof certificate).
    Aggressive,
    /// Speculative optimization (may be rolled back at any time).
    Speculative,
}

impl OptimizationTier {
    pub const ALL: &[Self] = &[
        Self::Baseline,
        Self::Standard,
        Self::Aggressive,
        Self::Speculative,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
            Self::Speculative => "speculative",
        }
    }

    /// Whether this tier requires a certificate.
    pub const fn requires_certificate(self) -> bool {
        matches!(self, Self::Aggressive | Self::Speculative)
    }

    /// Numeric rank (higher = more aggressive).
    pub const fn rank(self) -> u32 {
        match self {
            Self::Baseline => 0,
            Self::Standard => 1,
            Self::Aggressive => 2,
            Self::Speculative => 3,
        }
    }
}

impl fmt::Display for OptimizationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CertificateStatus
// ---------------------------------------------------------------------------

/// Status of an optimization certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    /// Certificate is valid and active.
    Valid,
    /// Certificate has expired (past expiry epoch).
    Expired,
    /// Certificate has been explicitly revoked.
    Revoked,
    /// Certificate is pending review.
    Pending,
    /// No certificate present.
    Missing,
}

impl CertificateStatus {
    pub const ALL: &[Self] = &[
        Self::Valid,
        Self::Expired,
        Self::Revoked,
        Self::Pending,
        Self::Missing,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Pending => "pending",
            Self::Missing => "missing",
        }
    }

    /// Whether this status allows optimization to proceed.
    pub const fn allows_optimization(self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger
// ---------------------------------------------------------------------------

/// Why an optimization tier was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTrigger {
    /// Proof of correctness failed.
    ProofFailure,
    /// A regression was detected in metrics.
    RegressionDetected,
    /// An operator explicitly requested rollback.
    OperatorCommand,
    /// The certificate expired mid-execution.
    CertificateExpiry,
    /// A debug session requires baseline behavior.
    DebugRequest,
    /// The optimization exceeded its time budget.
    TimeoutExceeded,
}

impl RollbackTrigger {
    pub const ALL: &[Self] = &[
        Self::ProofFailure,
        Self::RegressionDetected,
        Self::OperatorCommand,
        Self::CertificateExpiry,
        Self::DebugRequest,
        Self::TimeoutExceeded,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofFailure => "proof_failure",
            Self::RegressionDetected => "regression_detected",
            Self::OperatorCommand => "operator_command",
            Self::CertificateExpiry => "certificate_expiry",
            Self::DebugRequest => "debug_request",
            Self::TimeoutExceeded => "timeout_exceeded",
        }
    }
}

impl fmt::Display for RollbackTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ForensicSurface
// ---------------------------------------------------------------------------

/// Forensic evidence surface for debuggability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicSurface {
    /// Source-level mapping from optimized to original code.
    SourceMapping,
    /// Chain of rewrites applied.
    RewriteChain,
    /// Proof artifact (e.g., SMT output).
    ProofArtifact,
    /// Regret trace for decision reversal analysis.
    RegretTrace,
    /// Operator log entry.
    OperatorLog,
    /// Diff against the baseline (unoptimized) output.
    DiffBaseline,
}

impl ForensicSurface {
    pub const ALL: &[Self] = &[
        Self::SourceMapping,
        Self::RewriteChain,
        Self::ProofArtifact,
        Self::RegretTrace,
        Self::OperatorLog,
        Self::DiffBaseline,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceMapping => "source_mapping",
            Self::RewriteChain => "rewrite_chain",
            Self::ProofArtifact => "proof_artifact",
            Self::RegretTrace => "regret_trace",
            Self::OperatorLog => "operator_log",
            Self::DiffBaseline => "diff_baseline",
        }
    }
}

impl fmt::Display for ForensicSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// OptimizationCertificate
// ---------------------------------------------------------------------------

/// Certificate attesting that an optimization at a given tier is correct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationCertificate {
    /// Unique certificate ID.
    pub cert_id: String,
    /// Tier this certificate authorizes.
    pub tier: OptimizationTier,
    /// Function this certificate applies to.
    pub function_id: String,
    /// Number of rewrites applied under this certificate.
    pub rewrite_count: u64,
    /// Hash of the proof artifact.
    pub proof_hash: ContentHash,
    /// Epoch when the certificate was issued.
    pub issued_epoch: SecurityEpoch,
    /// Epoch after which the certificate expires.
    pub expiry_epoch: SecurityEpoch,
    /// Whether the translation receipt is valid.
    pub translation_receipt_valid: bool,
    /// Current status.
    pub status: CertificateStatus,
}

impl OptimizationCertificate {
    /// Compute a content hash for this certificate.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.cert_id.as_bytes());
        h.update(self.tier.as_str().as_bytes());
        h.update(self.function_id.as_bytes());
        h.update(self.rewrite_count.to_le_bytes());
        h.update(self.proof_hash.as_bytes());
        h.update(self.issued_epoch.as_u64().to_le_bytes());
        h.update(self.expiry_epoch.as_u64().to_le_bytes());
        h.update([u8::from(self.translation_receipt_valid)]);
        ContentHash::compute(&h.finalize())
    }

    /// Whether this certificate is valid at the given epoch.
    pub fn is_valid_at(&self, epoch: SecurityEpoch) -> bool {
        self.status == CertificateStatus::Valid
            && epoch.as_u64() >= self.issued_epoch.as_u64()
            && epoch.as_u64() < self.expiry_epoch.as_u64()
    }

    /// Remaining validity in epochs (0 if expired).
    pub fn remaining_epochs(&self, epoch: SecurityEpoch) -> u64 {
        self.expiry_epoch.as_u64().saturating_sub(epoch.as_u64())
    }

    /// Whether the certificate has enough validity remaining.
    pub fn meets_min_validity(&self, epoch: SecurityEpoch, min_epochs: u64) -> bool {
        self.remaining_epochs(epoch) >= min_epochs
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

/// Record of a tier rollback event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Unique record ID.
    pub record_id: String,
    /// Function that was rolled back.
    pub function_id: String,
    /// Why the rollback was triggered.
    pub trigger: RollbackTrigger,
    /// Tier before rollback.
    pub from_tier: OptimizationTier,
    /// Tier after rollback.
    pub to_tier: OptimizationTier,
    /// Epoch when rollback occurred.
    pub epoch: SecurityEpoch,
    /// Human-readable reason.
    pub reason: String,
    /// Steps elapsed before rollback was triggered.
    pub elapsed_steps: u64,
}

impl RollbackRecord {
    /// Compute a content hash for this record.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.record_id.as_bytes());
        h.update(self.function_id.as_bytes());
        h.update(self.trigger.as_str().as_bytes());
        h.update(self.from_tier.as_str().as_bytes());
        h.update(self.to_tier.as_str().as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.reason.as_bytes());
        h.update(self.elapsed_steps.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// ForensicEntry
// ---------------------------------------------------------------------------

/// A forensic breadcrumb for debuggability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicEntry {
    /// Unique entry ID.
    pub entry_id: String,
    /// Which forensic surface this entry belongs to.
    pub surface: ForensicSurface,
    /// Function ID this entry relates to.
    pub function_id: String,
    /// Optimization tier at the time of the entry.
    pub tier: OptimizationTier,
    /// Human-readable description.
    pub description: String,
    /// Hash of the forensic artifact payload.
    pub artifact_hash: ContentHash,
    /// Epoch when the entry was created.
    pub epoch: SecurityEpoch,
}

impl ForensicEntry {
    /// Compute a content hash for this entry.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.entry_id.as_bytes());
        h.update(self.surface.as_str().as_bytes());
        h.update(self.function_id.as_bytes());
        h.update(self.tier.as_str().as_bytes());
        h.update(self.description.as_bytes());
        h.update(self.artifact_hash.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Configuration for certified optimization governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Maximum speculative promotions without a valid certificate.
    pub max_speculative_without_cert: u64,
    /// Maximum rollbacks allowed per epoch.
    pub max_rollbacks_per_epoch: u64,
    /// Whether aggressive tier requires a proof certificate.
    pub require_proof_for_aggressive: bool,
    /// Minimum certificate validity remaining (epochs).
    pub min_cert_validity_epochs: u64,
    /// How long forensic entries are retained (epochs).
    pub forensic_retention_epochs: u64,
    /// Maximum concurrently active speculative tiers.
    pub max_active_speculative: u64,
    /// Minimum epoch for which evidence is trusted.
    pub min_verification_epoch: SecurityEpoch,
}

impl GovernanceConfig {
    /// Default production configuration.
    pub fn default_config() -> Self {
        Self {
            max_speculative_without_cert: DEFAULT_MAX_SPECULATIVE_WITHOUT_CERT,
            max_rollbacks_per_epoch: DEFAULT_MAX_ROLLBACKS_PER_EPOCH,
            require_proof_for_aggressive: true,
            min_cert_validity_epochs: DEFAULT_MIN_CERT_VALIDITY_EPOCHS,
            forensic_retention_epochs: DEFAULT_FORENSIC_RETENTION_EPOCHS,
            max_active_speculative: DEFAULT_MAX_ACTIVE_SPECULATIVE,
            min_verification_epoch: SecurityEpoch::from_raw(0),
        }
    }

    /// Permissive configuration for testing.
    pub fn permissive() -> Self {
        Self {
            max_speculative_without_cert: u64::MAX,
            max_rollbacks_per_epoch: u64::MAX,
            require_proof_for_aggressive: false,
            min_cert_validity_epochs: 0,
            forensic_retention_epochs: u64::MAX,
            max_active_speculative: u64::MAX,
            min_verification_epoch: SecurityEpoch::from_raw(0),
        }
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// GovernanceError
// ---------------------------------------------------------------------------

/// Errors from governance operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceError {
    /// The referenced certificate was not found.
    CertificateNotFound { cert_id: String },
    /// The certificate has expired.
    CertificateExpired { cert_id: String },
    /// The target tier has no valid certificate.
    UncertifiedTier {
        function_id: String,
        tier: OptimizationTier,
    },
    /// Too many rollbacks in this epoch.
    TooManyRollbacks { count: u64, max: u64 },
    /// The configuration is invalid.
    InvalidConfig { reason: String },
    /// Evidence is older than the minimum verification epoch.
    StaleEvidence {
        epoch: SecurityEpoch,
        min: SecurityEpoch,
    },
}

impl GovernanceError {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::CertificateNotFound { .. } => "certificate_not_found",
            Self::CertificateExpired { .. } => "certificate_expired",
            Self::UncertifiedTier { .. } => "uncertified_tier",
            Self::TooManyRollbacks { .. } => "too_many_rollbacks",
            Self::InvalidConfig { .. } => "invalid_config",
            Self::StaleEvidence { .. } => "stale_evidence",
        }
    }
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateNotFound { cert_id } => {
                write!(f, "certificate not found: {cert_id}")
            }
            Self::CertificateExpired { cert_id } => {
                write!(f, "certificate expired: {cert_id}")
            }
            Self::UncertifiedTier { function_id, tier } => {
                write!(f, "no certificate for {function_id} at tier {tier}")
            }
            Self::TooManyRollbacks { count, max } => {
                write!(f, "too many rollbacks: {count} > {max}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
            Self::StaleEvidence { epoch, min } => {
                write!(
                    f,
                    "evidence at epoch {} < min epoch {}",
                    epoch.as_u64(),
                    min.as_u64()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Result of governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All invariants pass.
    Pass {
        active_certs: usize,
        rollback_count: usize,
    },
    /// One or more invariants failed.
    Fail { reasons: Vec<String> },
    /// Evaluation could not determine pass/fail.
    Inconclusive { reasons: Vec<String> },
}

impl GovernanceVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }

    pub fn is_inconclusive(&self) -> bool {
        matches!(self, Self::Inconclusive { .. })
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Pass { .. } => "pass",
            Self::Fail { .. } => "fail",
            Self::Inconclusive { .. } => "inconclusive",
        }
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass {
                active_certs,
                rollback_count,
            } => write!(f, "PASS (certs={active_certs}, rollbacks={rollback_count})"),
            Self::Fail { reasons } => {
                write!(f, "FAIL ({} reason(s))", reasons.len())
            }
            Self::Inconclusive { reasons } => {
                write!(f, "INCONCLUSIVE ({} reason(s))", reasons.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceReport
// ---------------------------------------------------------------------------

/// Report from a governance evaluation cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReport {
    /// Schema version.
    pub schema_version: String,
    /// Epoch of the evaluation.
    pub epoch: SecurityEpoch,
    /// Total certificates registered.
    pub total_certificates: usize,
    /// Certificates currently valid.
    pub valid_certificates: usize,
    /// Total rollback records.
    pub total_rollbacks: usize,
    /// Number of functions at speculative tier.
    pub active_speculative: usize,
    /// Number of forensic entries.
    pub forensic_entry_count: usize,
    /// The governance verdict.
    pub verdict: GovernanceVerdict,
    /// Content hash of the report.
    pub report_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// GovernanceState
// ---------------------------------------------------------------------------

/// Aggregate governance state for a single epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceState {
    /// Registered certificates.
    pub certificates: Vec<OptimizationCertificate>,
    /// Rollback records.
    pub rollbacks: Vec<RollbackRecord>,
    /// Forensic entries.
    pub forensic_entries: Vec<ForensicEntry>,
    /// Current tier for each function.
    pub active_tiers: BTreeMap<String, OptimizationTier>,
    /// Current epoch.
    pub epoch: SecurityEpoch,
}

impl GovernanceState {
    /// Create a fresh governance state at the given epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            certificates: Vec::new(),
            rollbacks: Vec::new(),
            forensic_entries: Vec::new(),
            active_tiers: BTreeMap::new(),
            epoch,
        }
    }

    /// Register an optimization certificate.
    pub fn add_certificate(&mut self, cert: OptimizationCertificate) {
        self.certificates.push(cert);
    }

    /// Revoke a certificate by ID.
    pub fn revoke_certificate(
        &mut self,
        cert_id: &str,
        _reason: &str,
        _epoch: SecurityEpoch,
    ) -> Result<(), GovernanceError> {
        let cert = self.certificates.iter_mut().find(|c| c.cert_id == cert_id);
        match cert {
            Some(c) => {
                c.status = CertificateStatus::Revoked;
                Ok(())
            }
            None => Err(GovernanceError::CertificateNotFound {
                cert_id: cert_id.to_string(),
            }),
        }
    }

    /// Record a rollback event.
    pub fn record_rollback(&mut self, record: RollbackRecord) {
        // Demote the function tier.
        self.active_tiers
            .insert(record.function_id.clone(), record.to_tier);
        self.rollbacks.push(record);
    }

    /// Add a forensic entry.
    pub fn add_forensic_entry(&mut self, entry: ForensicEntry) {
        self.forensic_entries.push(entry);
    }

    /// Promote a function to a higher tier, requiring a valid certificate for
    /// aggressive and speculative tiers.
    pub fn promote_tier(
        &mut self,
        function_id: &str,
        tier: OptimizationTier,
        cert: Option<&OptimizationCertificate>,
    ) -> Result<(), GovernanceError> {
        if tier.requires_certificate() {
            match cert {
                None => {
                    return Err(GovernanceError::UncertifiedTier {
                        function_id: function_id.to_string(),
                        tier,
                    });
                }
                Some(c) => {
                    if !c.is_valid_at(self.epoch) {
                        return Err(GovernanceError::CertificateExpired {
                            cert_id: c.cert_id.clone(),
                        });
                    }
                }
            }
        }
        self.active_tiers.insert(function_id.to_string(), tier);
        Ok(())
    }

    /// Return currently valid certificates at the state's epoch.
    pub fn active_certificates(&self) -> Vec<&OptimizationCertificate> {
        self.certificates
            .iter()
            .filter(|c| c.is_valid_at(self.epoch))
            .collect()
    }

    /// Return rollbacks that occurred in the given epoch.
    pub fn rollbacks_in_epoch(&self, epoch: SecurityEpoch) -> Vec<&RollbackRecord> {
        self.rollbacks.iter().filter(|r| r.epoch == epoch).collect()
    }

    /// Return forensic entries for a specific function.
    pub fn forensics_for_function(&self, function_id: &str) -> Vec<&ForensicEntry> {
        self.forensic_entries
            .iter()
            .filter(|e| e.function_id == function_id)
            .collect()
    }

    /// Count functions currently at speculative tier.
    fn count_active_speculative(&self) -> usize {
        self.active_tiers
            .values()
            .filter(|t| **t == OptimizationTier::Speculative)
            .count()
    }

    /// Count speculative functions without a valid certificate.
    fn count_speculative_without_cert(&self) -> u64 {
        let valid_certs: Vec<&OptimizationCertificate> = self.active_certificates();
        let mut count = 0u64;
        for (fid, tier) in &self.active_tiers {
            if *tier == OptimizationTier::Speculative {
                let has_valid = valid_certs
                    .iter()
                    .any(|c| c.function_id == *fid && c.tier == OptimizationTier::Speculative);
                if !has_valid {
                    count += 1;
                }
            }
        }
        count
    }

    /// Count aggressive functions without a valid certificate.
    fn count_aggressive_without_cert(&self) -> u64 {
        let valid_certs: Vec<&OptimizationCertificate> = self.active_certificates();
        let mut count = 0u64;
        for (fid, tier) in &self.active_tiers {
            if *tier == OptimizationTier::Aggressive {
                let has_valid = valid_certs
                    .iter()
                    .any(|c| c.function_id == *fid && c.tier == OptimizationTier::Aggressive);
                if !has_valid {
                    count += 1;
                }
            }
        }
        count
    }

    /// Evaluate all governance invariants.
    pub fn evaluate(&self, config: &GovernanceConfig) -> GovernanceVerdict {
        let mut reasons = Vec::new();

        // 1. Rollback count in current epoch.
        let epoch_rollbacks = self.rollbacks_in_epoch(self.epoch).len() as u64;
        if epoch_rollbacks > config.max_rollbacks_per_epoch {
            reasons.push(format!(
                "rollbacks in epoch ({epoch_rollbacks}) exceed max ({})",
                config.max_rollbacks_per_epoch
            ));
        }

        // 2. Speculative without cert.
        let spec_no_cert = self.count_speculative_without_cert();
        if spec_no_cert > config.max_speculative_without_cert {
            reasons.push(format!(
                "speculative without cert ({spec_no_cert}) exceeds max ({})",
                config.max_speculative_without_cert
            ));
        }

        // 3. Aggressive without cert when required.
        if config.require_proof_for_aggressive {
            let agg_no_cert = self.count_aggressive_without_cert();
            if agg_no_cert > 0 {
                reasons.push(format!(
                    "{agg_no_cert} aggressive function(s) lack proof certificates"
                ));
            }
        }

        // 4. Active speculative count.
        let active_spec = self.count_active_speculative() as u64;
        if active_spec > config.max_active_speculative {
            reasons.push(format!(
                "active speculative ({active_spec}) exceeds max ({})",
                config.max_active_speculative
            ));
        }

        // 5. Certificate validity: warn about soon-to-expire certs.
        for cert in &self.certificates {
            if cert.is_valid_at(self.epoch)
                && !cert.meets_min_validity(self.epoch, config.min_cert_validity_epochs)
            {
                reasons.push(format!(
                    "certificate {} validity ({} epochs) below min ({})",
                    cert.cert_id,
                    cert.remaining_epochs(self.epoch),
                    config.min_cert_validity_epochs
                ));
            }
        }

        // 6. Stale forensic evidence.
        if self.epoch.as_u64() >= config.min_verification_epoch.as_u64() {
            for entry in &self.forensic_entries {
                if entry.epoch.as_u64() < config.min_verification_epoch.as_u64() {
                    reasons.push(format!(
                        "forensic entry {} predates min verification epoch",
                        entry.entry_id
                    ));
                }
            }
        }

        if reasons.is_empty() {
            let active_certs = self.active_certificates().len();
            let rollback_count = self.rollbacks.len();
            GovernanceVerdict::Pass {
                active_certs,
                rollback_count,
            }
        } else {
            GovernanceVerdict::Fail { reasons }
        }
    }

    /// Produce a governance report.
    pub fn report(&self, config: &GovernanceConfig) -> GovernanceReport {
        let verdict = self.evaluate(config);
        let valid_certificates = self.active_certificates().len();
        let active_speculative = self.count_active_speculative();

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update((self.certificates.len() as u64).to_le_bytes());
        h.update((valid_certificates as u64).to_le_bytes());
        h.update((self.rollbacks.len() as u64).to_le_bytes());
        h.update((active_speculative as u64).to_le_bytes());
        h.update((self.forensic_entries.len() as u64).to_le_bytes());
        h.update(verdict.tag().as_bytes());
        let report_hash = ContentHash::compute(&h.finalize());

        GovernanceReport {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            total_certificates: self.certificates.len(),
            valid_certificates,
            total_rollbacks: self.rollbacks.len(),
            active_speculative,
            forensic_entry_count: self.forensic_entries.len(),
            verdict,
            report_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn make_cert(id: &str, function_id: &str, tier: OptimizationTier) -> OptimizationCertificate {
        OptimizationCertificate {
            cert_id: id.to_string(),
            tier,
            function_id: function_id.to_string(),
            rewrite_count: 5,
            proof_hash: ContentHash::compute(b"proof"),
            issued_epoch: SecurityEpoch::from_raw(90),
            expiry_epoch: SecurityEpoch::from_raw(200),
            translation_receipt_valid: true,
            status: CertificateStatus::Valid,
        }
    }

    fn make_expired_cert(id: &str, function_id: &str) -> OptimizationCertificate {
        OptimizationCertificate {
            cert_id: id.to_string(),
            tier: OptimizationTier::Aggressive,
            function_id: function_id.to_string(),
            rewrite_count: 3,
            proof_hash: ContentHash::compute(b"expired-proof"),
            issued_epoch: SecurityEpoch::from_raw(10),
            expiry_epoch: SecurityEpoch::from_raw(50),
            translation_receipt_valid: true,
            status: CertificateStatus::Valid,
        }
    }

    fn make_rollback(id: &str, function_id: &str, trigger: RollbackTrigger) -> RollbackRecord {
        RollbackRecord {
            record_id: id.to_string(),
            function_id: function_id.to_string(),
            trigger,
            from_tier: OptimizationTier::Speculative,
            to_tier: OptimizationTier::Baseline,
            epoch: epoch(),
            reason: "test rollback".to_string(),
            elapsed_steps: 1000,
        }
    }

    fn make_forensic(id: &str, function_id: &str, surface: ForensicSurface) -> ForensicEntry {
        ForensicEntry {
            entry_id: id.to_string(),
            surface,
            function_id: function_id.to_string(),
            tier: OptimizationTier::Aggressive,
            description: "test forensic entry".to_string(),
            artifact_hash: ContentHash::compute(b"artifact"),
            epoch: epoch(),
        }
    }

    // --- OptimizationTier tests ---

    #[test]
    fn tier_as_str_all_variants() {
        assert_eq!(OptimizationTier::Baseline.as_str(), "baseline");
        assert_eq!(OptimizationTier::Standard.as_str(), "standard");
        assert_eq!(OptimizationTier::Aggressive.as_str(), "aggressive");
        assert_eq!(OptimizationTier::Speculative.as_str(), "speculative");
    }

    #[test]
    fn tier_display() {
        assert_eq!(format!("{}", OptimizationTier::Aggressive), "aggressive");
    }

    #[test]
    fn tier_requires_certificate() {
        assert!(!OptimizationTier::Baseline.requires_certificate());
        assert!(!OptimizationTier::Standard.requires_certificate());
        assert!(OptimizationTier::Aggressive.requires_certificate());
        assert!(OptimizationTier::Speculative.requires_certificate());
    }

    #[test]
    fn tier_rank_ordering() {
        assert!(OptimizationTier::Baseline.rank() < OptimizationTier::Standard.rank());
        assert!(OptimizationTier::Standard.rank() < OptimizationTier::Aggressive.rank());
        assert!(OptimizationTier::Aggressive.rank() < OptimizationTier::Speculative.rank());
    }

    #[test]
    fn tier_all_has_correct_count() {
        assert_eq!(OptimizationTier::ALL.len(), 4);
    }

    #[test]
    fn tier_serde_roundtrip() {
        for tier in OptimizationTier::ALL {
            let json = serde_json::to_string(tier).unwrap();
            let back: OptimizationTier = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, back);
        }
    }

    // --- CertificateStatus tests ---

    #[test]
    fn status_as_str_all_variants() {
        assert_eq!(CertificateStatus::Valid.as_str(), "valid");
        assert_eq!(CertificateStatus::Expired.as_str(), "expired");
        assert_eq!(CertificateStatus::Revoked.as_str(), "revoked");
        assert_eq!(CertificateStatus::Pending.as_str(), "pending");
        assert_eq!(CertificateStatus::Missing.as_str(), "missing");
    }

    #[test]
    fn status_allows_optimization() {
        assert!(CertificateStatus::Valid.allows_optimization());
        assert!(!CertificateStatus::Expired.allows_optimization());
        assert!(!CertificateStatus::Revoked.allows_optimization());
        assert!(!CertificateStatus::Pending.allows_optimization());
        assert!(!CertificateStatus::Missing.allows_optimization());
    }

    #[test]
    fn status_all_has_correct_count() {
        assert_eq!(CertificateStatus::ALL.len(), 5);
    }

    #[test]
    fn status_serde_roundtrip() {
        for s in CertificateStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: CertificateStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- RollbackTrigger tests ---

    #[test]
    fn trigger_as_str_all_variants() {
        assert_eq!(RollbackTrigger::ProofFailure.as_str(), "proof_failure");
        assert_eq!(
            RollbackTrigger::RegressionDetected.as_str(),
            "regression_detected"
        );
        assert_eq!(
            RollbackTrigger::OperatorCommand.as_str(),
            "operator_command"
        );
        assert_eq!(
            RollbackTrigger::CertificateExpiry.as_str(),
            "certificate_expiry"
        );
        assert_eq!(RollbackTrigger::DebugRequest.as_str(), "debug_request");
        assert_eq!(
            RollbackTrigger::TimeoutExceeded.as_str(),
            "timeout_exceeded"
        );
    }

    #[test]
    fn trigger_all_has_correct_count() {
        assert_eq!(RollbackTrigger::ALL.len(), 6);
    }

    #[test]
    fn trigger_serde_roundtrip() {
        for t in RollbackTrigger::ALL {
            let json = serde_json::to_string(t).unwrap();
            let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    // --- ForensicSurface tests ---

    #[test]
    fn forensic_surface_as_str() {
        assert_eq!(ForensicSurface::SourceMapping.as_str(), "source_mapping");
        assert_eq!(ForensicSurface::RewriteChain.as_str(), "rewrite_chain");
        assert_eq!(ForensicSurface::ProofArtifact.as_str(), "proof_artifact");
        assert_eq!(ForensicSurface::RegretTrace.as_str(), "regret_trace");
        assert_eq!(ForensicSurface::OperatorLog.as_str(), "operator_log");
        assert_eq!(ForensicSurface::DiffBaseline.as_str(), "diff_baseline");
    }

    #[test]
    fn forensic_surface_all_has_correct_count() {
        assert_eq!(ForensicSurface::ALL.len(), 6);
    }

    #[test]
    fn forensic_surface_serde_roundtrip() {
        for s in ForensicSurface::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: ForensicSurface = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- OptimizationCertificate tests ---

    #[test]
    fn cert_is_valid_at_epoch() {
        let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        assert!(cert.is_valid_at(SecurityEpoch::from_raw(100)));
        assert!(cert.is_valid_at(SecurityEpoch::from_raw(90)));
        assert!(cert.is_valid_at(SecurityEpoch::from_raw(199)));
        assert!(!cert.is_valid_at(SecurityEpoch::from_raw(200)));
        assert!(!cert.is_valid_at(SecurityEpoch::from_raw(89)));
    }

    #[test]
    fn cert_expired_is_not_valid() {
        let cert = make_expired_cert("c-exp", "fn1");
        assert!(!cert.is_valid_at(epoch()));
    }

    #[test]
    fn cert_remaining_epochs() {
        let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(100)), 100);
        assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(200)), 0);
        assert_eq!(cert.remaining_epochs(SecurityEpoch::from_raw(250)), 0);
    }

    #[test]
    fn cert_meets_min_validity() {
        let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        assert!(cert.meets_min_validity(SecurityEpoch::from_raw(100), 10));
        assert!(cert.meets_min_validity(SecurityEpoch::from_raw(100), 100));
        assert!(!cert.meets_min_validity(SecurityEpoch::from_raw(100), 101));
    }

    #[test]
    fn cert_content_hash_deterministic() {
        let c1 = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        let c2 = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn cert_content_hash_differs_on_id() {
        let c1 = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        let c2 = make_cert("c2", "fn1", OptimizationTier::Aggressive);
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn cert_serde_roundtrip() {
        let cert = make_cert("c-serde", "fn-serde", OptimizationTier::Speculative);
        let json = serde_json::to_string(&cert).unwrap();
        let back: OptimizationCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    // --- RollbackRecord tests ---

    #[test]
    fn rollback_content_hash_deterministic() {
        let r1 = make_rollback("r1", "fn1", RollbackTrigger::ProofFailure);
        let r2 = make_rollback("r1", "fn1", RollbackTrigger::ProofFailure);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn rollback_content_hash_differs_on_trigger() {
        let r1 = make_rollback("r1", "fn1", RollbackTrigger::ProofFailure);
        let r2 = make_rollback("r1", "fn1", RollbackTrigger::DebugRequest);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn rollback_serde_roundtrip() {
        let r = make_rollback("r-serde", "fn1", RollbackTrigger::OperatorCommand);
        let json = serde_json::to_string(&r).unwrap();
        let back: RollbackRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- ForensicEntry tests ---

    #[test]
    fn forensic_content_hash_deterministic() {
        let f1 = make_forensic("f1", "fn1", ForensicSurface::SourceMapping);
        let f2 = make_forensic("f1", "fn1", ForensicSurface::SourceMapping);
        assert_eq!(f1.content_hash(), f2.content_hash());
    }

    #[test]
    fn forensic_content_hash_differs_on_surface() {
        let f1 = make_forensic("f1", "fn1", ForensicSurface::SourceMapping);
        let f2 = make_forensic("f1", "fn1", ForensicSurface::OperatorLog);
        assert_ne!(f1.content_hash(), f2.content_hash());
    }

    #[test]
    fn forensic_serde_roundtrip() {
        let f = make_forensic("f-serde", "fn1", ForensicSurface::RewriteChain);
        let json = serde_json::to_string(&f).unwrap();
        let back: ForensicEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // --- GovernanceConfig tests ---

    #[test]
    fn config_default_matches_constants() {
        let cfg = GovernanceConfig::default_config();
        assert_eq!(
            cfg.max_speculative_without_cert,
            DEFAULT_MAX_SPECULATIVE_WITHOUT_CERT
        );
        assert_eq!(cfg.max_rollbacks_per_epoch, DEFAULT_MAX_ROLLBACKS_PER_EPOCH);
        assert!(cfg.require_proof_for_aggressive);
        assert_eq!(
            cfg.min_cert_validity_epochs,
            DEFAULT_MIN_CERT_VALIDITY_EPOCHS
        );
        assert_eq!(
            cfg.forensic_retention_epochs,
            DEFAULT_FORENSIC_RETENTION_EPOCHS
        );
        assert_eq!(cfg.max_active_speculative, DEFAULT_MAX_ACTIVE_SPECULATIVE);
    }

    #[test]
    fn config_permissive() {
        let cfg = GovernanceConfig::permissive();
        assert_eq!(cfg.max_speculative_without_cert, u64::MAX);
        assert!(!cfg.require_proof_for_aggressive);
    }

    #[test]
    fn config_default_trait() {
        let cfg: GovernanceConfig = Default::default();
        assert_eq!(cfg, GovernanceConfig::default_config());
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = GovernanceConfig::default_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // --- GovernanceState tests ---

    #[test]
    fn state_new_is_empty() {
        let state = GovernanceState::new(epoch());
        assert!(state.certificates.is_empty());
        assert!(state.rollbacks.is_empty());
        assert!(state.forensic_entries.is_empty());
        assert!(state.active_tiers.is_empty());
    }

    #[test]
    fn state_add_certificate() {
        let mut state = GovernanceState::new(epoch());
        state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
        assert_eq!(state.certificates.len(), 1);
    }

    #[test]
    fn state_revoke_certificate_success() {
        let mut state = GovernanceState::new(epoch());
        state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
        assert!(state.revoke_certificate("c1", "test", epoch()).is_ok());
        assert_eq!(state.certificates[0].status, CertificateStatus::Revoked);
    }

    #[test]
    fn state_revoke_certificate_not_found() {
        let mut state = GovernanceState::new(epoch());
        let result = state.revoke_certificate("nonexistent", "test", epoch());
        assert!(result.is_err());
        if let Err(GovernanceError::CertificateNotFound { cert_id }) = result {
            assert_eq!(cert_id, "nonexistent");
        } else {
            panic!("expected CertificateNotFound");
        }
    }

    #[test]
    fn state_record_rollback_updates_tier() {
        let mut state = GovernanceState::new(epoch());
        state
            .active_tiers
            .insert("fn1".to_string(), OptimizationTier::Speculative);
        state.record_rollback(make_rollback("r1", "fn1", RollbackTrigger::ProofFailure));
        assert_eq!(state.active_tiers["fn1"], OptimizationTier::Baseline);
        assert_eq!(state.rollbacks.len(), 1);
    }

    #[test]
    fn state_add_forensic_entry() {
        let mut state = GovernanceState::new(epoch());
        state.add_forensic_entry(make_forensic("f1", "fn1", ForensicSurface::OperatorLog));
        assert_eq!(state.forensic_entries.len(), 1);
    }

    #[test]
    fn state_promote_baseline_no_cert() {
        let mut state = GovernanceState::new(epoch());
        assert!(
            state
                .promote_tier("fn1", OptimizationTier::Baseline, None)
                .is_ok()
        );
        assert_eq!(state.active_tiers["fn1"], OptimizationTier::Baseline);
    }

    #[test]
    fn state_promote_standard_no_cert() {
        let mut state = GovernanceState::new(epoch());
        assert!(
            state
                .promote_tier("fn1", OptimizationTier::Standard, None)
                .is_ok()
        );
    }

    #[test]
    fn state_promote_aggressive_with_valid_cert() {
        let mut state = GovernanceState::new(epoch());
        let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        assert!(
            state
                .promote_tier("fn1", OptimizationTier::Aggressive, Some(&cert))
                .is_ok()
        );
        assert_eq!(state.active_tiers["fn1"], OptimizationTier::Aggressive);
    }

    #[test]
    fn state_promote_aggressive_no_cert_fails() {
        let mut state = GovernanceState::new(epoch());
        let result = state.promote_tier("fn1", OptimizationTier::Aggressive, None);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(GovernanceError::UncertifiedTier { .. })
        ));
    }

    #[test]
    fn state_promote_aggressive_expired_cert_fails() {
        let mut state = GovernanceState::new(epoch());
        let cert = make_expired_cert("c-exp", "fn1");
        let result = state.promote_tier("fn1", OptimizationTier::Aggressive, Some(&cert));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(GovernanceError::CertificateExpired { .. })
        ));
    }

    #[test]
    fn state_active_certificates() {
        let mut state = GovernanceState::new(epoch());
        state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
        state.add_certificate(make_expired_cert("c2", "fn2"));
        let active = state.active_certificates();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].cert_id, "c1");
    }

    #[test]
    fn state_rollbacks_in_epoch() {
        let mut state = GovernanceState::new(epoch());
        state.record_rollback(make_rollback("r1", "fn1", RollbackTrigger::ProofFailure));
        let mut r2 = make_rollback("r2", "fn2", RollbackTrigger::DebugRequest);
        r2.epoch = SecurityEpoch::from_raw(999);
        state.record_rollback(r2);
        assert_eq!(state.rollbacks_in_epoch(epoch()).len(), 1);
        assert_eq!(
            state.rollbacks_in_epoch(SecurityEpoch::from_raw(999)).len(),
            1
        );
    }

    #[test]
    fn state_forensics_for_function() {
        let mut state = GovernanceState::new(epoch());
        state.add_forensic_entry(make_forensic("f1", "fn1", ForensicSurface::SourceMapping));
        state.add_forensic_entry(make_forensic("f2", "fn2", ForensicSurface::OperatorLog));
        state.add_forensic_entry(make_forensic("f3", "fn1", ForensicSurface::RewriteChain));
        assert_eq!(state.forensics_for_function("fn1").len(), 2);
        assert_eq!(state.forensics_for_function("fn2").len(), 1);
        assert_eq!(state.forensics_for_function("fn3").len(), 0);
    }

    // --- GovernanceVerdict tests ---

    #[test]
    fn verdict_pass_properties() {
        let v = GovernanceVerdict::Pass {
            active_certs: 3,
            rollback_count: 1,
        };
        assert!(v.is_pass());
        assert!(!v.is_fail());
        assert!(!v.is_inconclusive());
        assert_eq!(v.tag(), "pass");
    }

    #[test]
    fn verdict_fail_properties() {
        let v = GovernanceVerdict::Fail {
            reasons: vec!["reason".to_string()],
        };
        assert!(!v.is_pass());
        assert!(v.is_fail());
        assert_eq!(v.tag(), "fail");
    }

    #[test]
    fn verdict_inconclusive_properties() {
        let v = GovernanceVerdict::Inconclusive {
            reasons: vec!["uncertain".to_string()],
        };
        assert!(!v.is_pass());
        assert!(v.is_inconclusive());
        assert_eq!(v.tag(), "inconclusive");
    }

    #[test]
    fn verdict_display() {
        let pass = GovernanceVerdict::Pass {
            active_certs: 2,
            rollback_count: 0,
        };
        assert!(format!("{pass}").contains("PASS"));

        let fail = GovernanceVerdict::Fail {
            reasons: vec!["a".into(), "b".into()],
        };
        assert!(format!("{fail}").contains("FAIL"));
        assert!(format!("{fail}").contains("2 reason(s)"));
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = GovernanceVerdict::Pass {
            active_certs: 5,
            rollback_count: 2,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- Evaluation tests ---

    #[test]
    fn evaluate_empty_state_passes() {
        let state = GovernanceState::new(epoch());
        let config = GovernanceConfig::default_config();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_pass());
    }

    #[test]
    fn evaluate_too_many_rollbacks_fails() {
        let mut state = GovernanceState::new(epoch());
        for i in 0..6 {
            state.record_rollback(make_rollback(
                &format!("r{i}"),
                &format!("fn{i}"),
                RollbackTrigger::ProofFailure,
            ));
        }
        let config = GovernanceConfig::default_config();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_fail());
    }

    #[test]
    fn evaluate_speculative_without_cert_fails() {
        let mut state = GovernanceState::new(epoch());
        // 3 speculative without certs, max is 2
        for i in 0..3 {
            state
                .active_tiers
                .insert(format!("fn{i}"), OptimizationTier::Speculative);
        }
        let config = GovernanceConfig::default_config();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_fail());
    }

    #[test]
    fn evaluate_aggressive_without_cert_fails() {
        let mut state = GovernanceState::new(epoch());
        state
            .active_tiers
            .insert("fn1".to_string(), OptimizationTier::Aggressive);
        let config = GovernanceConfig::default_config();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_fail());
    }

    #[test]
    fn evaluate_aggressive_with_valid_cert_passes() {
        let mut state = GovernanceState::new(epoch());
        state
            .active_tiers
            .insert("fn1".to_string(), OptimizationTier::Aggressive);
        state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
        let config = GovernanceConfig::default_config();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_pass());
    }

    #[test]
    fn evaluate_too_many_active_speculative_fails() {
        let mut state = GovernanceState::new(epoch());
        for i in 0..10 {
            state
                .active_tiers
                .insert(format!("fn{i}"), OptimizationTier::Speculative);
            state.add_certificate(make_cert(
                &format!("c{i}"),
                &format!("fn{i}"),
                OptimizationTier::Speculative,
            ));
        }
        let mut config = GovernanceConfig::default_config();
        config.max_speculative_without_cert = 100; // won't trigger
        let verdict = state.evaluate(&config);
        assert!(verdict.is_fail());
    }

    #[test]
    fn evaluate_cert_near_expiry_fails() {
        let mut state = GovernanceState::new(SecurityEpoch::from_raw(195));
        let cert = make_cert("c1", "fn1", OptimizationTier::Aggressive);
        // cert expires at 200, state at 195 => 5 epochs remaining < 10 min
        state.add_certificate(cert);
        state
            .active_tiers
            .insert("fn1".to_string(), OptimizationTier::Aggressive);
        let config = GovernanceConfig::default_config();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_fail());
    }

    #[test]
    fn evaluate_stale_forensic_entry_fails() {
        let mut state = GovernanceState::new(SecurityEpoch::from_raw(200));
        let mut entry = make_forensic("f-old", "fn1", ForensicSurface::SourceMapping);
        entry.epoch = SecurityEpoch::from_raw(5);
        state.add_forensic_entry(entry);
        let mut config = GovernanceConfig::default_config();
        config.min_verification_epoch = SecurityEpoch::from_raw(50);
        let verdict = state.evaluate(&config);
        assert!(verdict.is_fail());
    }

    #[test]
    fn evaluate_permissive_always_passes() {
        let mut state = GovernanceState::new(epoch());
        for i in 0..20 {
            state
                .active_tiers
                .insert(format!("fn{i}"), OptimizationTier::Speculative);
        }
        for i in 0..20 {
            state.record_rollback(make_rollback(
                &format!("r{i}"),
                &format!("fn-rb{i}"),
                RollbackTrigger::ProofFailure,
            ));
        }
        let config = GovernanceConfig::permissive();
        let verdict = state.evaluate(&config);
        assert!(verdict.is_pass());
    }

    // --- Report tests ---

    #[test]
    fn report_empty_state() {
        let state = GovernanceState::new(epoch());
        let config = GovernanceConfig::default_config();
        let report = state.report(&config);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.epoch, epoch());
        assert_eq!(report.total_certificates, 0);
        assert_eq!(report.valid_certificates, 0);
        assert_eq!(report.total_rollbacks, 0);
        assert_eq!(report.active_speculative, 0);
        assert_eq!(report.forensic_entry_count, 0);
        assert!(report.verdict.is_pass());
    }

    #[test]
    fn report_with_data() {
        let mut state = GovernanceState::new(epoch());
        state.add_certificate(make_cert("c1", "fn1", OptimizationTier::Aggressive));
        state.add_certificate(make_expired_cert("c2", "fn2"));
        state.add_forensic_entry(make_forensic("f1", "fn1", ForensicSurface::SourceMapping));
        state
            .active_tiers
            .insert("fn1".to_string(), OptimizationTier::Aggressive);
        let config = GovernanceConfig::default_config();
        let report = state.report(&config);
        assert_eq!(report.total_certificates, 2);
        assert_eq!(report.valid_certificates, 1);
        assert_eq!(report.forensic_entry_count, 1);
        assert!(report.verdict.is_pass());
    }

    #[test]
    fn report_hash_deterministic() {
        let state = GovernanceState::new(epoch());
        let config = GovernanceConfig::default_config();
        let r1 = state.report(&config);
        let r2 = state.report(&config);
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let state = GovernanceState::new(epoch());
        let config = GovernanceConfig::default_config();
        let report = state.report(&config);
        let json = serde_json::to_string(&report).unwrap();
        let back: GovernanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // --- GovernanceError tests ---

    #[test]
    fn error_tag_all_variants() {
        let errors = vec![
            GovernanceError::CertificateNotFound {
                cert_id: "c".into(),
            },
            GovernanceError::CertificateExpired {
                cert_id: "c".into(),
            },
            GovernanceError::UncertifiedTier {
                function_id: "f".into(),
                tier: OptimizationTier::Aggressive,
            },
            GovernanceError::TooManyRollbacks { count: 10, max: 5 },
            GovernanceError::InvalidConfig {
                reason: "bad".into(),
            },
            GovernanceError::StaleEvidence {
                epoch: SecurityEpoch::from_raw(1),
                min: SecurityEpoch::from_raw(10),
            },
        ];
        let expected_tags = [
            "certificate_not_found",
            "certificate_expired",
            "uncertified_tier",
            "too_many_rollbacks",
            "invalid_config",
            "stale_evidence",
        ];
        for (e, tag) in errors.iter().zip(expected_tags.iter()) {
            assert_eq!(e.tag(), *tag);
        }
    }

    #[test]
    fn error_display() {
        let e = GovernanceError::TooManyRollbacks { count: 10, max: 5 };
        assert!(format!("{e}").contains("10"));
        assert!(format!("{e}").contains("5"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let e = GovernanceError::UncertifiedTier {
            function_id: "fn1".into(),
            tier: OptimizationTier::Speculative,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Constants ---

    #[test]
    fn constants_are_consistent() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.certified-optimization-governance.v1"
        );
        assert_eq!(COMPONENT, "certified_optimization_governance");
        assert_eq!(BEAD_ID, "bd-1lsy.7.7.3");
        assert_eq!(POLICY_ID, "RGC-607C");
        assert_eq!(MILLIONTHS, 1_000_000);
    }
}
