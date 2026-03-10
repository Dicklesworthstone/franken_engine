//! Descent certificate gate for support claims and shipped-path evidence.
//!
//! Implements [RGC-808C]: gates support claims, documentation assertions,
//! and shipped-path parity evidence on obstruction-free descent certificates
//! so public claims reflect global coherence rather than local optimism.
//!
//! # Design
//!
//! A "descent certificate" attests that a support surface (a region of the
//! program/workload space) can be continuously improved without encountering
//! obstructions that would invalidate existing claims. The gate checks:
//!
//! - Each support claim has an associated descent certificate.
//! - The certificate covers the claimed surface without gaps.
//! - No active obstructions exist within the claimed region.
//! - Shipped-path parity is maintained when evidence says so.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-808C]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.descent-certificate-gate.v1";

/// Component name.
pub const COMPONENT: &str = "descent_certificate_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.9.8.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-808C";

/// Minimum coverage required for a descent certificate (millionths).
/// 95% = 950_000.
pub const MIN_DESCENT_COVERAGE: u64 = 950_000;

/// Maximum allowed obstruction count before a claim is rejected.
pub const MAX_OBSTRUCTIONS_ALLOWED: usize = 0;

/// Minimum confidence for a descent certificate (millionths).
pub const MIN_DESCENT_CONFIDENCE: u64 = 850_000;

// ---------------------------------------------------------------------------
// SupportSurface
// ---------------------------------------------------------------------------

/// A region of program/workload space over which a claim is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportSurface {
    /// Latency performance surface.
    Latency,
    /// Throughput performance surface.
    Throughput,
    /// Memory usage surface.
    Memory,
    /// Correctness surface.
    Correctness,
    /// Compatibility surface (cross-platform/cross-version).
    Compatibility,
    /// Documentation accuracy surface.
    Documentation,
    /// Shipped binary parity surface.
    ShippedPath,
}

impl SupportSurface {
    pub const ALL: &[Self] = &[
        Self::Latency,
        Self::Throughput,
        Self::Memory,
        Self::Correctness,
        Self::Compatibility,
        Self::Documentation,
        Self::ShippedPath,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Throughput => "throughput",
            Self::Memory => "memory",
            Self::Correctness => "correctness",
            Self::Compatibility => "compatibility",
            Self::Documentation => "documentation",
            Self::ShippedPath => "shipped_path",
        }
    }
}

impl fmt::Display for SupportSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ObstructionKind
// ---------------------------------------------------------------------------

/// Type of obstruction that blocks descent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObstructionKind {
    /// Local minimum: no improving moves available.
    LocalMinimum,
    /// Saddle point: improvement requires traversing worse states.
    SaddlePoint,
    /// Discontinuity: abrupt change in the surface.
    Discontinuity,
    /// Infeasibility: the region is not reachable under constraints.
    Infeasibility,
    /// Interference: concurrent changes conflict.
    Interference,
}

impl ObstructionKind {
    pub const ALL: &[Self] = &[
        Self::LocalMinimum,
        Self::SaddlePoint,
        Self::Discontinuity,
        Self::Infeasibility,
        Self::Interference,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalMinimum => "local_minimum",
            Self::SaddlePoint => "saddle_point",
            Self::Discontinuity => "discontinuity",
            Self::Infeasibility => "infeasibility",
            Self::Interference => "interference",
        }
    }
}

impl fmt::Display for ObstructionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Obstruction
// ---------------------------------------------------------------------------

/// A specific obstruction in a support surface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Obstruction {
    /// Kind of obstruction.
    pub kind: ObstructionKind,
    /// Surface where the obstruction exists.
    pub surface: SupportSurface,
    /// Region identifier within the surface.
    pub region: String,
    /// Severity (millionths, higher = worse).
    pub severity_millionths: u64,
    /// Description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// DescentCertificate
// ---------------------------------------------------------------------------

/// Certificate attesting obstruction-free descent over a support surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescentCertificate {
    /// Certificate ID.
    pub certificate_id: String,
    /// Surface this certificate covers.
    pub surface: SupportSurface,
    /// Coverage of the surface (millionths, 0–1_000_000).
    pub coverage_millionths: u64,
    /// Confidence in the certificate (millionths).
    pub confidence_millionths: u64,
    /// Active obstructions found within the covered region.
    pub obstructions: Vec<Obstruction>,
    /// Regions explicitly excluded from the certificate.
    pub excluded_regions: BTreeSet<String>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl DescentCertificate {
    /// Create a new certificate with computed hash.
    pub fn new(
        certificate_id: impl Into<String>,
        surface: SupportSurface,
        coverage_millionths: u64,
        confidence_millionths: u64,
        obstructions: Vec<Obstruction>,
        excluded_regions: BTreeSet<String>,
    ) -> Self {
        let certificate_id = certificate_id.into();
        let mut h = Sha256::new();
        h.update(certificate_id.as_bytes());
        h.update(surface.as_str().as_bytes());
        h.update(coverage_millionths.to_le_bytes());
        h.update(confidence_millionths.to_le_bytes());
        h.update((obstructions.len() as u64).to_le_bytes());
        for r in &excluded_regions {
            h.update(r.as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            certificate_id,
            surface,
            coverage_millionths,
            confidence_millionths,
            obstructions,
            excluded_regions,
            content_hash,
        }
    }

    /// Whether this certificate is obstruction-free.
    pub fn is_obstruction_free(&self) -> bool {
        self.obstructions.is_empty()
    }

    /// Whether coverage meets the minimum threshold.
    pub fn meets_coverage_threshold(&self, threshold: u64) -> bool {
        self.coverage_millionths >= threshold
    }

    /// Whether confidence meets a threshold.
    pub fn meets_confidence_threshold(&self, threshold: u64) -> bool {
        self.confidence_millionths >= threshold
    }
}

// ---------------------------------------------------------------------------
// SupportClaim
// ---------------------------------------------------------------------------

/// A claim about supported behavior on a surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportClaim {
    /// Unique claim ID.
    pub claim_id: String,
    /// Surface this claim is about.
    pub surface: SupportSurface,
    /// Region(s) covered by the claim.
    pub regions: BTreeSet<String>,
    /// Description of what is claimed.
    pub description: String,
    /// Whether this is a shipped-path claim (requires parity evidence).
    pub is_shipped_path: bool,
}

// ---------------------------------------------------------------------------
// GateRejection
// ---------------------------------------------------------------------------

/// Why a support claim was rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateRejection {
    /// No descent certificate available.
    NoCertificate,
    /// Certificate surface does not match claim surface.
    SurfaceMismatch {
        claim_surface: SupportSurface,
        cert_surface: SupportSurface,
    },
    /// Certificate coverage below threshold.
    InsufficientCoverage {
        coverage_millionths: u64,
        threshold_millionths: u64,
    },
    /// Certificate confidence below threshold.
    InsufficientConfidence {
        confidence_millionths: u64,
        threshold_millionths: u64,
    },
    /// Active obstructions found.
    ActiveObstructions { count: usize },
    /// Claimed regions not covered (excluded from certificate).
    UncoveredRegions { regions: BTreeSet<String> },
    /// Shipped-path claim but no parity evidence.
    NoParityEvidence,
}

impl GateRejection {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoCertificate => "no_certificate",
            Self::SurfaceMismatch { .. } => "surface_mismatch",
            Self::InsufficientCoverage { .. } => "insufficient_coverage",
            Self::InsufficientConfidence { .. } => "insufficient_confidence",
            Self::ActiveObstructions { .. } => "active_obstructions",
            Self::UncoveredRegions { .. } => "uncovered_regions",
            Self::NoParityEvidence => "no_parity_evidence",
        }
    }
}

impl fmt::Display for GateRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificate => write!(f, "no descent certificate"),
            Self::SurfaceMismatch {
                claim_surface,
                cert_surface,
            } => write!(f, "surface mismatch: {claim_surface} vs {cert_surface}"),
            Self::InsufficientCoverage {
                coverage_millionths,
                threshold_millionths,
            } => write!(
                f,
                "coverage {coverage_millionths} < threshold {threshold_millionths}"
            ),
            Self::InsufficientConfidence {
                confidence_millionths,
                threshold_millionths,
            } => write!(
                f,
                "confidence {confidence_millionths} < threshold {threshold_millionths}"
            ),
            Self::ActiveObstructions { count } => {
                write!(f, "{count} active obstruction(s)")
            }
            Self::UncoveredRegions { regions } => {
                write!(f, "uncovered regions: {}", regions.len())
            }
            Self::NoParityEvidence => write!(f, "shipped-path claim lacks parity evidence"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict for a support claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Claim is supported by descent evidence.
    Supported {
        claim_id: String,
        certificate_id: String,
    },
    /// Claim is rejected.
    Rejected {
        claim_id: String,
        reasons: Vec<GateRejection>,
    },
    /// No certificate found for this claim.
    NoCertificate { claim_id: String },
}

impl GateVerdict {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    pub fn claim_id(&self) -> &str {
        match self {
            Self::Supported { claim_id, .. }
            | Self::Rejected { claim_id, .. }
            | Self::NoCertificate { claim_id } => claim_id,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Supported { .. } => "supported",
            Self::Rejected { .. } => "rejected",
            Self::NoCertificate { .. } => "no_certificate",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supported {
                claim_id,
                certificate_id,
            } => write!(f, "SUPPORTED {claim_id} by {certificate_id}"),
            Self::Rejected {
                claim_id, reasons, ..
            } => write!(f, "REJECTED {claim_id}: {} reason(s)", reasons.len()),
            Self::NoCertificate { claim_id } => write!(f, "NO_CERTIFICATE {claim_id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// DescentGate
// ---------------------------------------------------------------------------

/// Configuration for descent certificate gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescentGateConfig {
    /// Minimum coverage required (millionths).
    pub min_coverage: u64,
    /// Minimum confidence required (millionths).
    pub min_confidence: u64,
    /// Maximum obstructions allowed.
    pub max_obstructions: usize,
    /// Whether shipped-path claims require parity evidence.
    pub require_parity_for_shipped: bool,
}

impl DescentGateConfig {
    pub fn default_config() -> Self {
        Self {
            min_coverage: MIN_DESCENT_COVERAGE,
            min_confidence: MIN_DESCENT_CONFIDENCE,
            max_obstructions: MAX_OBSTRUCTIONS_ALLOWED,
            require_parity_for_shipped: true,
        }
    }

    pub fn permissive() -> Self {
        Self {
            min_coverage: 0,
            min_confidence: 0,
            max_obstructions: usize::MAX,
            require_parity_for_shipped: false,
        }
    }
}

impl Default for DescentGateConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Gate that evaluates support claims against descent certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescentGate {
    pub config: DescentGateConfig,
    pub schema_version: String,
}

impl DescentGate {
    pub fn with_defaults() -> Self {
        Self {
            config: DescentGateConfig::default(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    pub fn with_config(config: DescentGateConfig) -> Self {
        Self {
            config,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Evaluate a claim against a certificate.
    /// `has_parity_evidence` indicates whether shipped-path parity is available.
    pub fn evaluate(
        &self,
        claim: &SupportClaim,
        certificate: Option<&DescentCertificate>,
        has_parity_evidence: bool,
    ) -> GateVerdict {
        let Some(cert) = certificate else {
            return GateVerdict::NoCertificate {
                claim_id: claim.claim_id.clone(),
            };
        };

        let mut reasons = Vec::new();

        // 1. Surface match.
        if cert.surface != claim.surface {
            reasons.push(GateRejection::SurfaceMismatch {
                claim_surface: claim.surface,
                cert_surface: cert.surface,
            });
        }

        // 2. Coverage threshold.
        if cert.coverage_millionths < self.config.min_coverage {
            reasons.push(GateRejection::InsufficientCoverage {
                coverage_millionths: cert.coverage_millionths,
                threshold_millionths: self.config.min_coverage,
            });
        }

        // 3. Confidence threshold.
        if cert.confidence_millionths < self.config.min_confidence {
            reasons.push(GateRejection::InsufficientConfidence {
                confidence_millionths: cert.confidence_millionths,
                threshold_millionths: self.config.min_confidence,
            });
        }

        // 4. Obstruction count.
        if cert.obstructions.len() > self.config.max_obstructions {
            reasons.push(GateRejection::ActiveObstructions {
                count: cert.obstructions.len(),
            });
        }

        // 5. Region coverage (check if claimed regions are excluded).
        let uncovered: BTreeSet<String> = claim
            .regions
            .intersection(&cert.excluded_regions)
            .cloned()
            .collect();
        if !uncovered.is_empty() {
            reasons.push(GateRejection::UncoveredRegions { regions: uncovered });
        }

        // 6. Shipped-path parity.
        if claim.is_shipped_path && self.config.require_parity_for_shipped && !has_parity_evidence {
            reasons.push(GateRejection::NoParityEvidence);
        }

        if reasons.is_empty() {
            GateVerdict::Supported {
                claim_id: claim.claim_id.clone(),
                certificate_id: cert.certificate_id.clone(),
            }
        } else {
            GateVerdict::Rejected {
                claim_id: claim.claim_id.clone(),
                reasons,
            }
        }
    }

    /// Evaluate a batch of claims.
    pub fn evaluate_batch(
        &self,
        claims: &[SupportClaim],
        certificates: &BTreeMap<String, DescentCertificate>,
        parity_claim_ids: &BTreeSet<String>,
    ) -> Vec<GateVerdict> {
        claims
            .iter()
            .map(|c| {
                let cert = certificates.get(&c.claim_id);
                let has_parity = parity_claim_ids.contains(&c.claim_id);
                self.evaluate(c, cert, has_parity)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

/// Report from a descent gate evaluation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub verdicts: Vec<GateVerdict>,
    pub supported_count: usize,
    pub rejected_count: usize,
    pub no_certificate_count: usize,
    pub content_hash: ContentHash,
}

impl GateReport {
    pub fn new(epoch: SecurityEpoch, verdicts: Vec<GateVerdict>) -> Self {
        let supported_count = verdicts.iter().filter(|v| v.is_supported()).count();
        let rejected_count = verdicts.iter().filter(|v| v.is_rejected()).count();
        let no_certificate_count = verdicts
            .iter()
            .filter(|v| matches!(v, GateVerdict::NoCertificate { .. }))
            .count();

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update((verdicts.len() as u64).to_le_bytes());
        h.update((supported_count as u64).to_le_bytes());
        h.update((rejected_count as u64).to_le_bytes());
        for v in &verdicts {
            h.update(v.claim_id().as_bytes());
            h.update(v.tag().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            verdicts,
            supported_count,
            rejected_count,
            no_certificate_count,
            content_hash,
        }
    }

    pub fn total_count(&self) -> usize {
        self.verdicts.len()
    }

    pub fn support_rate(&self) -> u64 {
        (self.supported_count as u64)
            .saturating_mul(1_000_000)
            .checked_div(self.verdicts.len() as u64)
            .unwrap_or(0)
    }

    pub fn all_supported(&self) -> bool {
        !self.verdicts.is_empty() && self.supported_count == self.verdicts.len()
    }

    pub fn has_rejections(&self) -> bool {
        self.rejected_count > 0
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(900)
    }

    fn clean_cert(surface: SupportSurface) -> DescentCertificate {
        DescentCertificate::new(
            "cert-1",
            surface,
            980_000,
            900_000,
            Vec::new(),
            BTreeSet::new(),
        )
    }

    fn obstructed_cert(surface: SupportSurface) -> DescentCertificate {
        DescentCertificate::new(
            "cert-obs",
            surface,
            980_000,
            900_000,
            vec![Obstruction {
                kind: ObstructionKind::LocalMinimum,
                surface,
                region: "hot-loop".into(),
                severity_millionths: 200_000,
                description: "stuck at local minimum".into(),
            }],
            BTreeSet::new(),
        )
    }

    fn latency_claim() -> SupportClaim {
        SupportClaim {
            claim_id: "lat-1".into(),
            surface: SupportSurface::Latency,
            regions: BTreeSet::from(["region-a".to_string()]),
            description: "p99 latency < 10ms".into(),
            is_shipped_path: false,
        }
    }

    fn shipped_claim() -> SupportClaim {
        SupportClaim {
            claim_id: "ship-1".into(),
            surface: SupportSurface::ShippedPath,
            regions: BTreeSet::from(["binary-x86".to_string()]),
            description: "shipped binary parity".into(),
            is_shipped_path: true,
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "descent_certificate_gate");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn threshold_invariants() {
        let mdc = MIN_DESCENT_COVERAGE;
        let mdc2 = MIN_DESCENT_CONFIDENCE;
        let moa = MAX_OBSTRUCTIONS_ALLOWED;
        assert!(mdc > 0);
        assert!(mdc <= 1_000_000);
        assert!(mdc2 > 0);
        assert_eq!(moa, 0);
    }

    // --- SupportSurface ---

    #[test]
    fn surface_all_length() {
        assert_eq!(SupportSurface::ALL.len(), 7);
    }

    #[test]
    fn surface_names_unique() {
        let names: BTreeSet<&str> = SupportSurface::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), SupportSurface::ALL.len());
    }

    #[test]
    fn surface_display_matches_as_str() {
        for s in SupportSurface::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn surface_serde_all() {
        for s in SupportSurface::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: SupportSurface = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- ObstructionKind ---

    #[test]
    fn obstruction_kind_all_length() {
        assert_eq!(ObstructionKind::ALL.len(), 5);
    }

    #[test]
    fn obstruction_kind_names_unique() {
        let names: BTreeSet<&str> = ObstructionKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), ObstructionKind::ALL.len());
    }

    #[test]
    fn obstruction_kind_display() {
        for k in ObstructionKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn obstruction_kind_serde() {
        for k in ObstructionKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: ObstructionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- DescentCertificate ---

    #[test]
    fn cert_clean() {
        let c = clean_cert(SupportSurface::Latency);
        assert!(c.is_obstruction_free());
        assert!(c.meets_coverage_threshold(950_000));
        assert!(c.meets_confidence_threshold(850_000));
    }

    #[test]
    fn cert_obstructed() {
        let c = obstructed_cert(SupportSurface::Latency);
        assert!(!c.is_obstruction_free());
    }

    #[test]
    fn cert_below_coverage() {
        let c = DescentCertificate::new(
            "cert-low",
            SupportSurface::Latency,
            500_000,
            900_000,
            Vec::new(),
            BTreeSet::new(),
        );
        assert!(!c.meets_coverage_threshold(950_000));
    }

    #[test]
    fn cert_hash_deterministic() {
        let c1 = clean_cert(SupportSurface::Latency);
        let c2 = clean_cert(SupportSurface::Latency);
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn cert_serde() {
        let c = clean_cert(SupportSurface::Throughput);
        let json = serde_json::to_string(&c).unwrap();
        let back: DescentCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- GateRejection ---

    #[test]
    fn rejection_tags_unique() {
        let rejections = [
            GateRejection::NoCertificate,
            GateRejection::SurfaceMismatch {
                claim_surface: SupportSurface::Latency,
                cert_surface: SupportSurface::Memory,
            },
            GateRejection::InsufficientCoverage {
                coverage_millionths: 0,
                threshold_millionths: 0,
            },
            GateRejection::InsufficientConfidence {
                confidence_millionths: 0,
                threshold_millionths: 0,
            },
            GateRejection::ActiveObstructions { count: 1 },
            GateRejection::UncoveredRegions {
                regions: BTreeSet::new(),
            },
            GateRejection::NoParityEvidence,
        ];
        let tags: BTreeSet<&str> = rejections.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 7);
    }

    #[test]
    fn rejection_display() {
        let r = GateRejection::InsufficientCoverage {
            coverage_millionths: 800_000,
            threshold_millionths: 950_000,
        };
        let s = r.to_string();
        assert!(s.contains("800000"));
    }

    #[test]
    fn rejection_serde() {
        let r = GateRejection::ActiveObstructions { count: 3 };
        let json = serde_json::to_string(&r).unwrap();
        let back: GateRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- GateVerdict ---

    #[test]
    fn verdict_supported() {
        let v = GateVerdict::Supported {
            claim_id: "x".into(),
            certificate_id: "c1".into(),
        };
        assert!(v.is_supported());
        assert!(!v.is_rejected());
        assert_eq!(v.tag(), "supported");
    }

    #[test]
    fn verdict_rejected() {
        let v = GateVerdict::Rejected {
            claim_id: "x".into(),
            reasons: vec![GateRejection::NoCertificate],
        };
        assert!(v.is_rejected());
        assert!(!v.is_supported());
    }

    #[test]
    fn verdict_display() {
        let v = GateVerdict::Supported {
            claim_id: "test".into(),
            certificate_id: "cert-1".into(),
        };
        assert!(v.to_string().contains("SUPPORTED"));
    }

    #[test]
    fn verdict_serde() {
        let v = GateVerdict::Rejected {
            claim_id: "x".into(),
            reasons: vec![GateRejection::NoCertificate],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- DescentGate ---

    #[test]
    fn gate_supports_clean_cert() {
        let gate = DescentGate::with_defaults();
        let v = gate.evaluate(
            &latency_claim(),
            Some(&clean_cert(SupportSurface::Latency)),
            false,
        );
        assert!(v.is_supported());
    }

    #[test]
    fn gate_rejects_no_cert() {
        let gate = DescentGate::with_defaults();
        let v = gate.evaluate(&latency_claim(), None, false);
        assert!(matches!(v, GateVerdict::NoCertificate { .. }));
    }

    #[test]
    fn gate_rejects_obstructed() {
        let gate = DescentGate::with_defaults();
        let v = gate.evaluate(
            &latency_claim(),
            Some(&obstructed_cert(SupportSurface::Latency)),
            false,
        );
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_surface_mismatch() {
        let gate = DescentGate::with_defaults();
        let v = gate.evaluate(
            &latency_claim(),
            Some(&clean_cert(SupportSurface::Memory)),
            false,
        );
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_low_coverage() {
        let gate = DescentGate::with_defaults();
        let cert = DescentCertificate::new(
            "cert-low",
            SupportSurface::Latency,
            800_000,
            900_000,
            Vec::new(),
            BTreeSet::new(),
        );
        let v = gate.evaluate(&latency_claim(), Some(&cert), false);
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_shipped_no_parity() {
        let gate = DescentGate::with_defaults();
        let cert = clean_cert(SupportSurface::ShippedPath);
        let v = gate.evaluate(&shipped_claim(), Some(&cert), false);
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_supports_shipped_with_parity() {
        let gate = DescentGate::with_defaults();
        let cert = clean_cert(SupportSurface::ShippedPath);
        let v = gate.evaluate(&shipped_claim(), Some(&cert), true);
        assert!(v.is_supported());
    }

    // --- GateReport ---

    #[test]
    fn report_empty() {
        let r = GateReport::new(epoch(), Vec::new());
        assert_eq!(r.total_count(), 0);
        assert!(!r.all_supported());
    }

    #[test]
    fn report_all_supported() {
        let verdicts = vec![GateVerdict::Supported {
            claim_id: "a".into(),
            certificate_id: "c1".into(),
        }];
        let r = GateReport::new(epoch(), verdicts);
        assert!(r.all_supported());
        assert_eq!(r.support_rate(), 1_000_000);
    }

    #[test]
    fn report_hash_deterministic() {
        let v = vec![GateVerdict::Supported {
            claim_id: "a".into(),
            certificate_id: "c1".into(),
        }];
        let r1 = GateReport::new(epoch(), v.clone());
        let r2 = GateReport::new(epoch(), v);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_serde() {
        let verdicts = vec![
            GateVerdict::Supported {
                claim_id: "a".into(),
                certificate_id: "c1".into(),
            },
            GateVerdict::Rejected {
                claim_id: "b".into(),
                reasons: vec![GateRejection::NoCertificate],
            },
        ];
        let r = GateReport::new(epoch(), verdicts);
        let json = serde_json::to_string(&r).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
