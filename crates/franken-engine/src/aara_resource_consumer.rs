#![forbid(unsafe_code)]

//! AARA resource certificate consumer for scheduler, GC, module, and specialization budgets.
//!
//! Implements [RGC-625B]: wires resource certificates into specialization admission,
//! scheduler budgets, GC pacing, module work budgets, and hostcall exhaustion
//! semantics, with explicit user-visible reason codes and support-ready receipts.
//!
//! The consumer reads `ResourceCertificate` artifacts from the certificate plane
//! (RGC-625A) and translates bounds + effect summaries into actionable budget
//! decisions for each subsystem.
//!
//! # Design
//!
//! 1. Each subsystem (scheduler, GC, module loader, specializer, hostcall gate)
//!    registers its budget requirements.
//! 2. The consumer evaluates certificates against registered requirements and
//!    produces per-subsystem budget decisions with structured reason codes.
//! 3. Decisions are auditable via receipts and aggregated into a consumption report.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Bead: bd-1lsy.7.25.2
//! Policy: RGC-625B

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aara_resource_certificate::{
    CertificateVerdict, EffectKind, ResourceCertificate, ResourceDimension,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for serialised resource consumption artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.aara_resource_consumer.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.25.2";

/// Logical component name within the engine.
pub const COMPONENT: &str = "aara_resource_consumer";

/// Policy identifier governing this module's behaviour.
pub const POLICY_ID: &str = "RGC-625B";

/// Fixed-point scaling constant: 1.0 = 1_000_000.
const MILLIONTHS: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn content_hash_from_parts(parts: &[&[u8]]) -> ContentHash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    ContentHash(out)
}

// ---------------------------------------------------------------------------
// Subsystem — which runtime subsystem consumes the budget
// ---------------------------------------------------------------------------

/// Runtime subsystem that consumes resource budgets from certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    /// Scheduler — controls task scheduling, queue depths, and time slices.
    Scheduler,
    /// GC — controls garbage collection pacing and heap limits.
    GarbageCollector,
    /// Module loader — controls module import budgets and dynamic import gates.
    ModuleLoader,
    /// Specializer — controls optimization/compilation admission.
    Specializer,
    /// Hostcall gate — controls external call budgets.
    HostcallGate,
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheduler => write!(f, "scheduler"),
            Self::GarbageCollector => write!(f, "gc"),
            Self::ModuleLoader => write!(f, "module_loader"),
            Self::Specializer => write!(f, "specializer"),
            Self::HostcallGate => write!(f, "hostcall_gate"),
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetDecision — per-subsystem outcome
// ---------------------------------------------------------------------------

/// Budget decision for a subsystem after consuming a resource certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDecision {
    /// Full budget granted — certificate fully covers the subsystem's needs.
    FullBudget,
    /// Reduced budget — certificate covers partially, subsystem must operate
    /// in degraded mode.
    ReducedBudget,
    /// Budget denied — certificate is insufficient or absent for this subsystem.
    Denied,
    /// Abstain — the certificate doesn't cover dimensions relevant to this subsystem.
    Abstain,
}

impl BudgetDecision {
    /// Returns true if any budget was granted.
    pub fn is_granted(self) -> bool {
        matches!(self, Self::FullBudget | Self::ReducedBudget)
    }
}

impl fmt::Display for BudgetDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullBudget => write!(f, "full_budget"),
            Self::ReducedBudget => write!(f, "reduced_budget"),
            Self::Denied => write!(f, "denied"),
            Self::Abstain => write!(f, "abstain"),
        }
    }
}

// ---------------------------------------------------------------------------
// DenialReason — why a budget was denied or reduced
// ---------------------------------------------------------------------------

/// Structured reason for a budget denial or reduction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// Required resource dimension not covered by certificate.
    MissingDimension { dimension: ResourceDimension },
    /// Bound too low for subsystem minimum requirement.
    BoundTooLow {
        dimension: ResourceDimension,
        bound_millionths: i64,
        required_millionths: i64,
    },
    /// Certificate verdict is not certified.
    CertificateNotCertified { verdict: CertificateVerdict },
    /// Effect summary indicates forbidden side effects.
    ForbiddenEffect { effect: EffectKind },
    /// Confidence on bound is too low.
    LowBoundConfidence {
        dimension: ResourceDimension,
        confidence_millionths: i64,
        required_millionths: i64,
    },
    /// Certificate has critical assumptions the subsystem cannot satisfy.
    CriticalAssumptions,
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDimension { dimension } => {
                write!(f, "missing dimension: {dimension}")
            }
            Self::BoundTooLow {
                dimension,
                bound_millionths,
                required_millionths,
            } => write!(
                f,
                "bound too low on {dimension}: {bound_millionths} < {required_millionths}"
            ),
            Self::CertificateNotCertified { verdict } => {
                write!(f, "certificate not certified: {verdict}")
            }
            Self::ForbiddenEffect { effect } => {
                write!(f, "forbidden effect: {effect}")
            }
            Self::LowBoundConfidence {
                dimension,
                confidence_millionths,
                required_millionths,
            } => write!(
                f,
                "low confidence on {dimension}: {confidence_millionths} < {required_millionths}"
            ),
            Self::CriticalAssumptions => write!(f, "critical assumptions present"),
        }
    }
}

// ---------------------------------------------------------------------------
// SubsystemRequirement — what a subsystem needs
// ---------------------------------------------------------------------------

/// Requirements for a subsystem to grant a budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemRequirement {
    /// Which subsystem this requirement covers.
    pub subsystem: Subsystem,
    /// Required resource dimensions and minimum bounds (millionths).
    pub min_bounds: BTreeMap<ResourceDimension, i64>,
    /// Effects that are forbidden for this subsystem.
    pub forbidden_effects: BTreeSet<EffectKind>,
    /// Minimum bound confidence (millionths) for each dimension.
    pub min_confidence_millionths: i64,
    /// Whether critical assumptions block the budget.
    pub reject_critical_assumptions: bool,
}

impl SubsystemRequirement {
    /// Creates a scheduler requirement.
    pub fn scheduler() -> Self {
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::Time, 100_000); // 0.1 time unit minimum
        min_bounds.insert(ResourceDimension::StackDepth, 50_000); // 0.05 stack depth

        Self {
            subsystem: Subsystem::Scheduler,
            min_bounds,
            forbidden_effects: BTreeSet::new(),
            min_confidence_millionths: 600_000, // 60%
            reject_critical_assumptions: false,
        }
    }

    /// Creates a GC requirement.
    pub fn garbage_collector() -> Self {
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::HeapMemory, 100_000);
        min_bounds.insert(ResourceDimension::GcPressure, 50_000);

        Self {
            subsystem: Subsystem::GarbageCollector,
            min_bounds,
            forbidden_effects: BTreeSet::new(),
            min_confidence_millionths: 700_000,
            reject_critical_assumptions: false,
        }
    }

    /// Creates a module loader requirement.
    pub fn module_loader() -> Self {
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::ModuleLoadCount, 50_000);
        min_bounds.insert(ResourceDimension::IoOperationCount, 50_000);

        Self {
            subsystem: Subsystem::ModuleLoader,
            min_bounds,
            forbidden_effects: BTreeSet::new(),
            min_confidence_millionths: 600_000,
            reject_critical_assumptions: false,
        }
    }

    /// Creates a specializer requirement.
    pub fn specializer() -> Self {
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::Time, 200_000);
        min_bounds.insert(ResourceDimension::HeapMemory, 200_000);

        let mut forbidden = BTreeSet::new();
        forbidden.insert(EffectKind::DynamicCodeGen);

        Self {
            subsystem: Subsystem::Specializer,
            min_bounds,
            forbidden_effects: forbidden,
            min_confidence_millionths: 800_000, // Strict for optimization
            reject_critical_assumptions: true,
        }
    }

    /// Creates a hostcall gate requirement.
    pub fn hostcall_gate() -> Self {
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::HostcallCount, 50_000);

        Self {
            subsystem: Subsystem::HostcallGate,
            min_bounds,
            forbidden_effects: BTreeSet::new(),
            min_confidence_millionths: 600_000,
            reject_critical_assumptions: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ConsumptionReceipt — auditable decision record
// ---------------------------------------------------------------------------

/// Auditable receipt for a subsystem budget decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumptionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Certificate identifier that was consumed.
    pub certificate_id: String,
    /// Subsystem that consumed the certificate.
    pub subsystem: Subsystem,
    /// Budget decision.
    pub decision: BudgetDecision,
    /// Denial reasons (empty if granted).
    pub denial_reasons: Vec<DenialReason>,
    /// Allocated budget per dimension (millionths). Empty if denied.
    pub allocated_budgets: BTreeMap<ResourceDimension, i64>,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Receipt hash.
    pub receipt_hash: ContentHash,
}

impl ConsumptionReceipt {
    fn compute_hash(
        receipt_id: &str,
        certificate_id: &str,
        subsystem: &Subsystem,
        decision: &BudgetDecision,
        epoch: &SecurityEpoch,
    ) -> ContentHash {
        let data = format!(
            "consumption:{}:{}:{}:{}:{}",
            receipt_id,
            certificate_id,
            subsystem,
            decision,
            epoch.as_u64(),
        );
        content_hash_from_parts(&[data.as_bytes()])
    }
}

// ---------------------------------------------------------------------------
// ResourceConsumer — main consumer engine
// ---------------------------------------------------------------------------

/// The resource certificate consumer. Evaluates certificates against subsystem
/// requirements and produces auditable budget decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConsumer {
    /// Registered subsystem requirements.
    pub requirements: Vec<SubsystemRequirement>,
    /// Consumption receipts.
    pub receipts: Vec<ConsumptionReceipt>,
    /// Receipt counter.
    receipt_counter: u64,
    /// Current epoch.
    pub epoch: SecurityEpoch,
}

impl ResourceConsumer {
    /// Creates a new consumer with default subsystem requirements.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self {
            requirements: vec![
                SubsystemRequirement::scheduler(),
                SubsystemRequirement::garbage_collector(),
                SubsystemRequirement::module_loader(),
                SubsystemRequirement::specializer(),
                SubsystemRequirement::hostcall_gate(),
            ],
            receipts: Vec::new(),
            receipt_counter: 0,
            epoch,
        }
    }

    /// Creates a consumer with custom requirements.
    pub fn new(requirements: Vec<SubsystemRequirement>, epoch: SecurityEpoch) -> Self {
        Self {
            requirements,
            receipts: Vec::new(),
            receipt_counter: 0,
            epoch,
        }
    }

    /// Consumes a certificate, producing budget decisions for all registered subsystems.
    pub fn consume(&mut self, cert: &ResourceCertificate) -> Vec<BudgetDecision> {
        let mut decisions = Vec::new();

        for req in &self.requirements {
            let (decision, denial_reasons, allocated) = self.evaluate_subsystem(cert, req);

            self.receipt_counter += 1;
            let receipt_id = format!("rc-rcpt-{}", self.receipt_counter);
            let receipt_hash = ConsumptionReceipt::compute_hash(
                &receipt_id,
                &cert.certificate_id,
                &req.subsystem,
                &decision,
                &self.epoch,
            );

            self.receipts.push(ConsumptionReceipt {
                receipt_id,
                certificate_id: cert.certificate_id.clone(),
                subsystem: req.subsystem,
                decision,
                denial_reasons,
                allocated_budgets: allocated,
                epoch: self.epoch,
                receipt_hash,
            });

            decisions.push(decision);
        }

        decisions
    }

    /// Evaluates a certificate against a single subsystem requirement.
    fn evaluate_subsystem(
        &self,
        cert: &ResourceCertificate,
        req: &SubsystemRequirement,
    ) -> (
        BudgetDecision,
        Vec<DenialReason>,
        BTreeMap<ResourceDimension, i64>,
    ) {
        let mut denial_reasons = Vec::new();
        let mut allocated = BTreeMap::new();
        let mut has_all_dimensions = true;
        let mut any_reduced = false;

        // 1. Check certificate verdict.
        if cert.verdict != CertificateVerdict::Certified {
            denial_reasons.push(DenialReason::CertificateNotCertified {
                verdict: cert.verdict,
            });
            return (BudgetDecision::Denied, denial_reasons, allocated);
        }

        // 2. Check critical assumptions.
        if req.reject_critical_assumptions && cert.has_critical_assumptions() {
            denial_reasons.push(DenialReason::CriticalAssumptions);
        }

        // 3. Check forbidden effects.
        for effect in &req.forbidden_effects {
            if cert
                .effect_summary
                .entries
                .iter()
                .any(|e| e.kind == *effect)
            {
                denial_reasons.push(DenialReason::ForbiddenEffect { effect: *effect });
            }
        }

        // 4. Check required dimensions and bounds.
        for (dim, min_required) in &req.min_bounds {
            if let Some(bound) = cert.bound_for(*dim) {
                // Check bound value
                if bound.upper_bound_millionths < *min_required {
                    denial_reasons.push(DenialReason::BoundTooLow {
                        dimension: *dim,
                        bound_millionths: bound.upper_bound_millionths,
                        required_millionths: *min_required,
                    });
                    any_reduced = true;
                } else {
                    allocated.insert(*dim, bound.upper_bound_millionths);
                }

                // Check confidence
                if bound.confidence_millionths < req.min_confidence_millionths {
                    denial_reasons.push(DenialReason::LowBoundConfidence {
                        dimension: *dim,
                        confidence_millionths: bound.confidence_millionths,
                        required_millionths: req.min_confidence_millionths,
                    });
                    any_reduced = true;
                }
            } else {
                denial_reasons.push(DenialReason::MissingDimension { dimension: *dim });
                has_all_dimensions = false;
            }
        }

        // 5. Determine decision.
        let decision = if !has_all_dimensions {
            // Missing required dimensions → abstain (not deny, since cert
            // just doesn't cover this subsystem).
            BudgetDecision::Abstain
        } else if denial_reasons.is_empty() {
            BudgetDecision::FullBudget
        } else if any_reduced
            && !denial_reasons.iter().any(|r| {
                matches!(
                    r,
                    DenialReason::ForbiddenEffect { .. } | DenialReason::CriticalAssumptions
                )
            })
        {
            BudgetDecision::ReducedBudget
        } else {
            BudgetDecision::Denied
        };

        (decision, denial_reasons, allocated)
    }

    /// Returns all receipts.
    pub fn receipts(&self) -> &[ConsumptionReceipt] {
        &self.receipts
    }

    /// Returns receipts for a specific subsystem.
    pub fn receipts_for(&self, subsystem: Subsystem) -> Vec<&ConsumptionReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.subsystem == subsystem)
            .collect()
    }

    /// Returns the most recent receipt for a subsystem.
    pub fn last_receipt_for(&self, subsystem: Subsystem) -> Option<&ConsumptionReceipt> {
        self.receipts
            .iter()
            .rev()
            .find(|r| r.subsystem == subsystem)
    }

    /// Generates a consumption summary.
    pub fn summary(&self) -> ConsumptionSummary {
        let total = self.receipts.len() as u64;
        let full_budget_count = self
            .receipts
            .iter()
            .filter(|r| r.decision == BudgetDecision::FullBudget)
            .count() as u64;
        let reduced_count = self
            .receipts
            .iter()
            .filter(|r| r.decision == BudgetDecision::ReducedBudget)
            .count() as u64;
        let denied_count = self
            .receipts
            .iter()
            .filter(|r| r.decision == BudgetDecision::Denied)
            .count() as u64;
        let abstain_count = self
            .receipts
            .iter()
            .filter(|r| r.decision == BudgetDecision::Abstain)
            .count() as u64;

        let mut denial_reason_counts = BTreeMap::new();
        for receipt in &self.receipts {
            for reason in &receipt.denial_reasons {
                let key = format!("{reason}");
                *denial_reason_counts.entry(key).or_insert(0u64) += 1;
            }
        }

        let mut subsystem_decisions = BTreeMap::new();
        for receipt in &self.receipts {
            subsystem_decisions
                .entry(receipt.subsystem)
                .or_insert_with(Vec::new)
                .push(receipt.decision);
        }

        let grant_rate = if total > 0 {
            (full_budget_count.saturating_add(reduced_count) as i64).saturating_mul(MILLIONTHS)
                / total as i64
        } else {
            0
        };

        let summary_hash = content_hash_from_parts(&[format!(
            "summary:{}:{}:{}:{}:{}",
            total, full_budget_count, reduced_count, denied_count, abstain_count,
        )
        .as_bytes()]);

        ConsumptionSummary {
            total_decisions: total,
            full_budget_count,
            reduced_count,
            denied_count,
            abstain_count,
            denial_reason_counts,
            grant_rate_millionths: grant_rate,
            epoch: self.epoch,
            summary_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ConsumptionSummary
// ---------------------------------------------------------------------------

/// Summary statistics for resource certificate consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumptionSummary {
    /// Total budget decisions made.
    pub total_decisions: u64,
    /// Full budget grants.
    pub full_budget_count: u64,
    /// Reduced budget grants.
    pub reduced_count: u64,
    /// Budget denials.
    pub denied_count: u64,
    /// Abstentions (irrelevant dimensions).
    pub abstain_count: u64,
    /// Denial reason counts.
    pub denial_reason_counts: BTreeMap<String, u64>,
    /// Grant rate (full + reduced) in millionths.
    pub grant_rate_millionths: i64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Summary hash.
    pub summary_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ConsumptionManifest
// ---------------------------------------------------------------------------

/// Complete manifest for a resource consumption session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumptionManifest {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Component name.
    pub component: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Summary.
    pub summary: ConsumptionSummary,
    /// All receipts.
    pub receipts: Vec<ConsumptionReceipt>,
    /// Manifest hash.
    pub manifest_hash: ContentHash,
}

impl ConsumptionManifest {
    /// Builds a manifest from a consumer.
    pub fn from_consumer(consumer: &ResourceConsumer) -> Self {
        let summary = consumer.summary();
        let receipts = consumer.receipts().to_vec();

        let manifest_data = format!(
            "manifest:{}:{}:{}:{}",
            SCHEMA_VERSION,
            summary.total_decisions,
            summary.full_budget_count,
            summary.denied_count,
        );
        let manifest_hash = content_hash_from_parts(&[manifest_data.as_bytes()]);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            summary,
            receipts,
            manifest_hash,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aara_resource_certificate::{
        AbstentionPoint, AbstentionReason, AssumptionKind, CertificateAssumption, CertificateInput,
        EffectEntry, EffectSummary, ResourceBound,
    };

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_bounds() -> Vec<ResourceBound> {
        ResourceDimension::ALL
            .iter()
            .map(|dim| ResourceBound {
                dimension: *dim,
                upper_bound_millionths: 500_000,
                is_tight: true,
                confidence_millionths: 900_000,
            })
            .collect()
    }

    fn make_effect_summary(entries: Vec<EffectEntry>) -> EffectSummary {
        EffectSummary::build("test-region", entries, vec![])
    }

    fn good_certificate() -> ResourceCertificate {
        let bounds = make_bounds();
        let effect_summary = make_effect_summary(vec![EffectEntry {
            kind: EffectKind::Allocation,
            program_point: "main:1".to_string(),
            worst_case_count_millionths: 10_000_000,
            is_exact: true,
        }]);
        let input = CertificateInput {
            certificate_id: "test-cert-001".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary,
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    fn low_bound_certificate() -> ResourceCertificate {
        let mut bounds = make_bounds();
        // Set time bound very low
        if let Some(b) = bounds
            .iter_mut()
            .find(|b| b.dimension == ResourceDimension::Time)
        {
            b.upper_bound_millionths = 10_000;
        }
        let input = CertificateInput {
            certificate_id: "test-low-bound".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    fn uncertified_certificate() -> ResourceCertificate {
        // Create a certificate with abstention points so verdict is Abstained
        let input = CertificateInput {
            certificate_id: "test-uncertified".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds: vec![],
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![AbstentionPoint {
                program_point: "unknown:0".to_string(),
                reason: AbstentionReason::DynamicDispatch,
                detail: "test abstention".to_string(),
            }],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    fn dynamic_code_gen_certificate() -> ResourceCertificate {
        let bounds = make_bounds();
        let effect_summary = make_effect_summary(vec![EffectEntry {
            kind: EffectKind::DynamicCodeGen,
            program_point: "eval_block:1".to_string(),
            worst_case_count_millionths: 1_000_000,
            is_exact: false,
        }]);
        let input = CertificateInput {
            certificate_id: "test-dyncodegen".to_string(),
            region_id: "eval_block".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary,
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    fn low_confidence_certificate() -> ResourceCertificate {
        let bounds: Vec<ResourceBound> = ResourceDimension::ALL
            .iter()
            .map(|dim| ResourceBound {
                dimension: *dim,
                upper_bound_millionths: 500_000,
                is_tight: false,
                confidence_millionths: 300_000,
            })
            .collect();
        let input = CertificateInput {
            certificate_id: "test-low-conf".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    fn partial_dimension_certificate() -> ResourceCertificate {
        // Only cover Time and HeapMemory
        let bounds: Vec<ResourceBound> = [ResourceDimension::Time, ResourceDimension::HeapMemory]
            .iter()
            .map(|dim| ResourceBound {
                dimension: *dim,
                upper_bound_millionths: 500_000,
                is_tight: true,
                confidence_millionths: 900_000,
            })
            .collect();
        let input = CertificateInput {
            certificate_id: "test-partial".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    // -----------------------------------------------------------------------
    // Subsystem and BudgetDecision tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_subsystem_display() {
        assert_eq!(Subsystem::Scheduler.to_string(), "scheduler");
        assert_eq!(Subsystem::GarbageCollector.to_string(), "gc");
        assert_eq!(Subsystem::ModuleLoader.to_string(), "module_loader");
        assert_eq!(Subsystem::Specializer.to_string(), "specializer");
        assert_eq!(Subsystem::HostcallGate.to_string(), "hostcall_gate");
    }

    #[test]
    fn test_budget_decision_is_granted() {
        assert!(BudgetDecision::FullBudget.is_granted());
        assert!(BudgetDecision::ReducedBudget.is_granted());
        assert!(!BudgetDecision::Denied.is_granted());
        assert!(!BudgetDecision::Abstain.is_granted());
    }

    #[test]
    fn test_budget_decision_display() {
        assert_eq!(BudgetDecision::FullBudget.to_string(), "full_budget");
        assert_eq!(BudgetDecision::Denied.to_string(), "denied");
    }

    // -----------------------------------------------------------------------
    // SubsystemRequirement tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scheduler_requirement() {
        let req = SubsystemRequirement::scheduler();
        assert_eq!(req.subsystem, Subsystem::Scheduler);
        assert!(req.min_bounds.contains_key(&ResourceDimension::Time));
        assert!(!req.reject_critical_assumptions);
    }

    #[test]
    fn test_gc_requirement() {
        let req = SubsystemRequirement::garbage_collector();
        assert_eq!(req.subsystem, Subsystem::GarbageCollector);
        assert!(req.min_bounds.contains_key(&ResourceDimension::HeapMemory));
    }

    #[test]
    fn test_specializer_forbids_dynamic_code_gen() {
        let req = SubsystemRequirement::specializer();
        assert!(req.forbidden_effects.contains(&EffectKind::DynamicCodeGen));
        assert!(req.reject_critical_assumptions);
    }

    #[test]
    fn test_hostcall_gate_requirement() {
        let req = SubsystemRequirement::hostcall_gate();
        assert!(
            req.min_bounds
                .contains_key(&ResourceDimension::HostcallCount)
        );
    }

    // -----------------------------------------------------------------------
    // Consumer — good certificate tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_consume_good_cert_all_subsystems() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        let decisions = consumer.consume(&cert);
        assert_eq!(decisions.len(), 5); // 5 default subsystems
        // At least scheduler and GC should get full budget
        assert!(decisions.contains(&BudgetDecision::FullBudget));
    }

    #[test]
    fn test_consume_good_cert_scheduler_gets_budget() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::FullBudget);
        assert!(receipt.denial_reasons.is_empty());
        assert!(!receipt.allocated_budgets.is_empty());
    }

    #[test]
    fn test_consume_good_cert_gc_gets_budget() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let receipt = consumer
            .last_receipt_for(Subsystem::GarbageCollector)
            .unwrap();
        assert_eq!(receipt.decision, BudgetDecision::FullBudget);
    }

    #[test]
    fn test_consume_good_cert_hostcall_gets_budget() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::HostcallGate).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::FullBudget);
    }

    // -----------------------------------------------------------------------
    // Consumer — uncertified certificate tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_uncertified_cert_denied_all_subsystems() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = uncertified_certificate();
        let decisions = consumer.consume(&cert);
        for d in &decisions {
            assert_eq!(*d, BudgetDecision::Denied);
        }
    }

    #[test]
    fn test_uncertified_cert_has_denial_reason() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = uncertified_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert!(
            receipt
                .denial_reasons
                .iter()
                .any(|r| matches!(r, DenialReason::CertificateNotCertified { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Consumer — low bound tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_low_bound_reduces_scheduler_budget() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = low_bound_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        // Time bound = 10k < required 100k → should be reduced or denied
        assert!(!receipt.denial_reasons.is_empty());
    }

    // -----------------------------------------------------------------------
    // Consumer — forbidden effect tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dynamic_code_gen_blocks_specializer() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = dynamic_code_gen_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::Denied);
        assert!(receipt.denial_reasons.iter().any(|r| matches!(
            r,
            DenialReason::ForbiddenEffect {
                effect: EffectKind::DynamicCodeGen
            }
        )));
    }

    #[test]
    fn test_dynamic_code_gen_does_not_block_scheduler() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = dynamic_code_gen_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::FullBudget);
    }

    // -----------------------------------------------------------------------
    // Consumer — low confidence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_low_confidence_affects_decisions() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = low_confidence_certificate();
        consumer.consume(&cert);
        // Cert has 300k confidence which is below MIN_CERTIFICATE_CONFIDENCE (900k),
        // so the certificate verdict is Provisional (not Certified) and the consumer
        // rejects it as CertificateNotCertified before checking per-dimension confidence.
        let receipt = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
        assert!(
            receipt
                .denial_reasons
                .iter()
                .any(|r| matches!(r, DenialReason::CertificateNotCertified { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Consumer — partial dimensions tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_partial_dimensions_causes_abstain() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = partial_dimension_certificate();
        consumer.consume(&cert);
        // Module loader requires ModuleLoadCount and IoOperationCount — not covered
        let receipt = consumer.last_receipt_for(Subsystem::ModuleLoader).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::Abstain);
    }

    #[test]
    fn test_partial_dimensions_scheduler_may_still_get_budget() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = partial_dimension_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        // Scheduler needs Time (covered) and StackDepth (not covered) → abstain
        assert_eq!(receipt.decision, BudgetDecision::Abstain);
    }

    // -----------------------------------------------------------------------
    // Consumer — custom requirements
    // -----------------------------------------------------------------------

    #[test]
    fn test_custom_single_requirement() {
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::Time, 100_000);
        let req = SubsystemRequirement {
            subsystem: Subsystem::Scheduler,
            min_bounds,
            forbidden_effects: BTreeSet::new(),
            min_confidence_millionths: 500_000,
            reject_critical_assumptions: false,
        };
        let mut consumer = ResourceConsumer::new(vec![req], epoch());
        let cert = good_certificate();
        let decisions = consumer.consume(&cert);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0], BudgetDecision::FullBudget);
    }

    // -----------------------------------------------------------------------
    // Receipt tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_counter_increments() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        assert_eq!(consumer.receipts().len(), 5);
        assert_eq!(consumer.receipts()[0].receipt_id, "rc-rcpt-1");
        assert_eq!(consumer.receipts()[4].receipt_id, "rc-rcpt-5");
    }

    #[test]
    fn test_receipts_for_subsystem() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        consumer.consume(&cert);
        let sched_receipts = consumer.receipts_for(Subsystem::Scheduler);
        assert_eq!(sched_receipts.len(), 2);
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let h1 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::FullBudget,
            &epoch(),
        );
        let h2 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::FullBudget,
            &epoch(),
        );
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // Summary tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_summary() {
        let consumer = ResourceConsumer::with_defaults(epoch());
        let summary = consumer.summary();
        assert_eq!(summary.total_decisions, 0);
        assert_eq!(summary.grant_rate_millionths, 0);
    }

    #[test]
    fn test_summary_after_consumption() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let summary = consumer.summary();
        assert_eq!(summary.total_decisions, 5);
        assert!(summary.full_budget_count > 0);
    }

    #[test]
    fn test_summary_grant_rate() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let good = good_certificate();
        let bad = uncertified_certificate();
        consumer.consume(&good);
        consumer.consume(&bad);
        let summary = consumer.summary();
        assert_eq!(summary.total_decisions, 10);
        // Good cert: some granted. Bad cert: all denied.
        assert!(summary.grant_rate_millionths > 0);
        assert!(summary.grant_rate_millionths < MILLIONTHS);
    }

    // -----------------------------------------------------------------------
    // Manifest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest_from_consumer() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let manifest = ConsumptionManifest::from_consumer(&consumer);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.bead_id, BEAD_ID);
        assert_eq!(manifest.receipts.len(), 5);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let mut c1 = ResourceConsumer::with_defaults(epoch());
        let mut c2 = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        c1.consume(&cert);
        c2.consume(&cert);
        let m1 = ConsumptionManifest::from_consumer(&c1);
        let m2 = ConsumptionManifest::from_consumer(&c2);
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_subsystem_serde_roundtrip() {
        for s in [
            Subsystem::Scheduler,
            Subsystem::GarbageCollector,
            Subsystem::ModuleLoader,
            Subsystem::Specializer,
            Subsystem::HostcallGate,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: Subsystem = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn test_budget_decision_serde_roundtrip() {
        for d in [
            BudgetDecision::FullBudget,
            BudgetDecision::ReducedBudget,
            BudgetDecision::Denied,
            BudgetDecision::Abstain,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: BudgetDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn test_denial_reason_display() {
        let reasons = vec![
            DenialReason::MissingDimension {
                dimension: ResourceDimension::Time,
            },
            DenialReason::BoundTooLow {
                dimension: ResourceDimension::HeapMemory,
                bound_millionths: 10_000,
                required_millionths: 100_000,
            },
            DenialReason::CertificateNotCertified {
                verdict: CertificateVerdict::Abstained,
            },
            DenialReason::ForbiddenEffect {
                effect: EffectKind::DynamicCodeGen,
            },
            DenialReason::CriticalAssumptions,
        ];
        for r in &reasons {
            let s = format!("{r}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_manifest_serde_roundtrip() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let manifest = ConsumptionManifest::from_consumer(&consumer);
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ConsumptionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest.schema_version, back.schema_version);
        assert_eq!(manifest.manifest_hash, back.manifest_hash);
    }

    // -----------------------------------------------------------------------
    // Additional tests — edge cases, error paths, boundary conditions
    // -----------------------------------------------------------------------

    /// Helper to create a certificate with critical assumptions.
    fn critical_assumption_certificate() -> ResourceCertificate {
        let bounds = make_bounds();
        let input = CertificateInput {
            certificate_id: "test-critical-assumptions".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![CertificateAssumption {
                key: "bounded-iter".to_string(),
                kind: AssumptionKind::BoundedIteration,
                description: "loop bound depends on input".to_string(),
                is_critical: true,
            }],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    /// Helper to make a certificate with exact boundary values for a single
    /// subsystem's minimum requirements.
    fn boundary_scheduler_certificate() -> ResourceCertificate {
        let bounds: Vec<ResourceBound> = ResourceDimension::ALL
            .iter()
            .map(|dim| {
                let upper = match dim {
                    // Exactly at scheduler minimum (100_000)
                    ResourceDimension::Time => 100_000,
                    // Exactly at scheduler minimum (50_000)
                    ResourceDimension::StackDepth => 50_000,
                    _ => 500_000,
                };
                ResourceBound {
                    dimension: *dim,
                    upper_bound_millionths: upper,
                    is_tight: true,
                    confidence_millionths: 900_000,
                }
            })
            .collect();
        let input = CertificateInput {
            certificate_id: "test-boundary-sched".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        ResourceCertificate::new(input)
    }

    #[test]
    fn test_critical_assumptions_deny_specializer_only() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = critical_assumption_certificate();
        consumer.consume(&cert);
        // Specializer has reject_critical_assumptions = true, so denied.
        let spec_receipt = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
        assert_eq!(spec_receipt.decision, BudgetDecision::Denied);
        assert!(
            spec_receipt
                .denial_reasons
                .iter()
                .any(|r| matches!(r, DenialReason::CriticalAssumptions))
        );
        // Scheduler does NOT reject critical assumptions.
        let sched_receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert_eq!(sched_receipt.decision, BudgetDecision::FullBudget);
    }

    #[test]
    fn test_critical_assumptions_gc_module_hostcall_unaffected() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = critical_assumption_certificate();
        consumer.consume(&cert);
        for subsys in [
            Subsystem::GarbageCollector,
            Subsystem::ModuleLoader,
            Subsystem::HostcallGate,
        ] {
            let receipt = consumer.last_receipt_for(subsys).unwrap();
            assert!(
                receipt.decision.is_granted(),
                "{subsys} should still be granted with critical assumptions"
            );
        }
    }

    #[test]
    fn test_zero_bound_certificate_causes_bound_too_low() {
        // All bounds at zero — should produce BoundTooLow for any subsystem
        // that has a non-zero minimum requirement.
        let bounds: Vec<ResourceBound> = ResourceDimension::ALL
            .iter()
            .map(|dim| ResourceBound {
                dimension: *dim,
                upper_bound_millionths: 0,
                is_tight: true,
                confidence_millionths: 900_000,
            })
            .collect();
        let input = CertificateInput {
            certificate_id: "test-zero-bounds".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        let cert = ResourceCertificate::new(input);
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        consumer.consume(&cert);
        let sched = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert!(
            sched
                .denial_reasons
                .iter()
                .any(|r| matches!(r, DenialReason::BoundTooLow { .. }))
        );
    }

    #[test]
    fn test_boundary_exact_minimum_scheduler_passes() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = boundary_scheduler_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        // Bounds are exactly equal to required — should be FullBudget (>= not >).
        assert_eq!(receipt.decision, BudgetDecision::FullBudget);
    }

    #[test]
    fn test_boundary_one_below_minimum_scheduler_reduced() {
        let bounds: Vec<ResourceBound> = ResourceDimension::ALL
            .iter()
            .map(|dim| {
                let upper = match dim {
                    ResourceDimension::Time => 99_999, // one below 100_000
                    _ => 500_000,
                };
                ResourceBound {
                    dimension: *dim,
                    upper_bound_millionths: upper,
                    is_tight: true,
                    confidence_millionths: 900_000,
                }
            })
            .collect();
        let input = CertificateInput {
            certificate_id: "test-one-below".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        let cert = ResourceCertificate::new(input);
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        // Time bound is one below minimum → reduced (bound too low but
        // no forbidden effect or critical assumption).
        assert_eq!(receipt.decision, BudgetDecision::ReducedBudget);
    }

    #[test]
    fn test_consumer_with_no_requirements_produces_no_decisions() {
        let mut consumer = ResourceConsumer::new(vec![], epoch());
        let cert = good_certificate();
        let decisions = consumer.consume(&cert);
        assert!(decisions.is_empty());
        assert!(consumer.receipts().is_empty());
    }

    #[test]
    fn test_empty_consumer_receipts_for_returns_empty() {
        let consumer = ResourceConsumer::with_defaults(epoch());
        assert!(consumer.receipts_for(Subsystem::Scheduler).is_empty());
    }

    #[test]
    fn test_last_receipt_for_none_before_consumption() {
        let consumer = ResourceConsumer::with_defaults(epoch());
        assert!(consumer.last_receipt_for(Subsystem::Scheduler).is_none());
    }

    #[test]
    fn test_multiple_consumptions_receipt_counter_continues() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        consumer.consume(&cert);
        // 5 subsystems * 2 consumptions = 10 receipts
        assert_eq!(consumer.receipts().len(), 10);
        assert_eq!(consumer.receipts()[9].receipt_id, "rc-rcpt-10");
    }

    #[test]
    fn test_last_receipt_for_returns_most_recent() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let good = good_certificate();
        let bad = uncertified_certificate();
        consumer.consume(&good);
        consumer.consume(&bad);
        // last_receipt_for should return the second consumption's receipt
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert_eq!(receipt.certificate_id, "test-uncertified");
        assert_eq!(receipt.decision, BudgetDecision::Denied);
    }

    #[test]
    fn test_receipt_hash_differs_for_different_inputs() {
        let h1 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::FullBudget,
            &epoch(),
        );
        let h2 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::GarbageCollector,
            &BudgetDecision::FullBudget,
            &epoch(),
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_receipt_hash_differs_on_decision() {
        let h1 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::FullBudget,
            &epoch(),
        );
        let h2 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::Denied,
            &epoch(),
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_receipt_hash_differs_on_epoch() {
        let e1 = SecurityEpoch::from_raw(1);
        let e2 = SecurityEpoch::from_raw(2);
        let h1 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::FullBudget,
            &e1,
        );
        let h2 = ConsumptionReceipt::compute_hash(
            "r1",
            "c1",
            &Subsystem::Scheduler,
            &BudgetDecision::FullBudget,
            &e2,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_summary_all_denied() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = uncertified_certificate();
        consumer.consume(&cert);
        let summary = consumer.summary();
        assert_eq!(summary.total_decisions, 5);
        assert_eq!(summary.denied_count, 5);
        assert_eq!(summary.full_budget_count, 0);
        assert_eq!(summary.reduced_count, 0);
        assert_eq!(summary.abstain_count, 0);
        assert_eq!(summary.grant_rate_millionths, 0);
    }

    #[test]
    fn test_summary_denial_reason_counts_populated() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = uncertified_certificate();
        consumer.consume(&cert);
        let summary = consumer.summary();
        // All 5 subsystems get CertificateNotCertified denial
        assert!(!summary.denial_reason_counts.is_empty());
        let total_denial_reasons: u64 = summary.denial_reason_counts.values().sum();
        assert!(total_denial_reasons >= 5);
    }

    #[test]
    fn test_summary_hash_deterministic() {
        let mut c1 = ResourceConsumer::with_defaults(epoch());
        let mut c2 = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        c1.consume(&cert);
        c2.consume(&cert);
        let s1 = c1.summary();
        let s2 = c2.summary();
        assert_eq!(s1.summary_hash, s2.summary_hash);
    }

    #[test]
    fn test_summary_hash_differs_for_different_decisions() {
        let mut c1 = ResourceConsumer::with_defaults(epoch());
        let mut c2 = ResourceConsumer::with_defaults(epoch());
        c1.consume(&good_certificate());
        c2.consume(&uncertified_certificate());
        let s1 = c1.summary();
        let s2 = c2.summary();
        assert_ne!(s1.summary_hash, s2.summary_hash);
    }

    #[test]
    fn test_manifest_empty_consumer() {
        let consumer = ResourceConsumer::with_defaults(epoch());
        let manifest = ConsumptionManifest::from_consumer(&consumer);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.component, COMPONENT);
        assert_eq!(manifest.policy_id, POLICY_ID);
        assert!(manifest.receipts.is_empty());
        assert_eq!(manifest.summary.total_decisions, 0);
    }

    #[test]
    fn test_manifest_full_serde_roundtrip_with_denials() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        consumer.consume(&good_certificate());
        consumer.consume(&uncertified_certificate());
        consumer.consume(&dynamic_code_gen_certificate());
        let manifest = ConsumptionManifest::from_consumer(&consumer);
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let back: ConsumptionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn test_denial_reason_serde_roundtrip_all_variants() {
        let reasons = vec![
            DenialReason::MissingDimension {
                dimension: ResourceDimension::Time,
            },
            DenialReason::BoundTooLow {
                dimension: ResourceDimension::HeapMemory,
                bound_millionths: 10_000,
                required_millionths: 200_000,
            },
            DenialReason::CertificateNotCertified {
                verdict: CertificateVerdict::Provisional,
            },
            DenialReason::ForbiddenEffect {
                effect: EffectKind::DynamicCodeGen,
            },
            DenialReason::LowBoundConfidence {
                dimension: ResourceDimension::GcPressure,
                confidence_millionths: 400_000,
                required_millionths: 700_000,
            },
            DenialReason::CriticalAssumptions,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: DenialReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    #[test]
    fn test_denial_reason_low_confidence_display_format() {
        let reason = DenialReason::LowBoundConfidence {
            dimension: ResourceDimension::StackDepth,
            confidence_millionths: 300_000,
            required_millionths: 800_000,
        };
        let s = format!("{reason}");
        assert!(s.contains("low confidence"));
        assert!(s.contains("stack_depth"));
        assert!(s.contains("300000"));
        assert!(s.contains("800000"));
    }

    #[test]
    fn test_budget_decision_reduced_display() {
        assert_eq!(BudgetDecision::ReducedBudget.to_string(), "reduced_budget");
        assert_eq!(BudgetDecision::Abstain.to_string(), "abstain");
    }

    #[test]
    fn test_subsystem_ordering_is_deterministic() {
        // BTreeMap/BTreeSet usage relies on Ord being deterministic.
        let mut subsystems = vec![
            Subsystem::HostcallGate,
            Subsystem::Scheduler,
            Subsystem::GarbageCollector,
            Subsystem::Specializer,
            Subsystem::ModuleLoader,
        ];
        subsystems.sort();
        // Verify consistent ordering across runs.
        let mut subsystems2 = subsystems.clone();
        subsystems2.sort();
        assert_eq!(subsystems, subsystems2);
    }

    #[test]
    fn test_consumer_serde_roundtrip() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        consumer.consume(&good_certificate());
        let json = serde_json::to_string(&consumer).unwrap();
        let back: ResourceConsumer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.receipts().len(), consumer.receipts().len());
        assert_eq!(back.epoch, consumer.epoch);
    }

    #[test]
    fn test_consumption_receipt_serde_roundtrip() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        consumer.consume(&good_certificate());
        for receipt in consumer.receipts() {
            let json = serde_json::to_string(receipt).unwrap();
            let back: ConsumptionReceipt = serde_json::from_str(&json).unwrap();
            assert_eq!(*receipt, back);
        }
    }

    #[test]
    fn test_subsystem_requirement_serde_roundtrip() {
        let req = SubsystemRequirement::specializer();
        let json = serde_json::to_string(&req).unwrap();
        let back: SubsystemRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn test_content_hash_from_parts_determinism() {
        let h1 = content_hash_from_parts(&[b"hello", b"world"]);
        let h2 = content_hash_from_parts(&[b"hello", b"world"]);
        assert_eq!(h1, h2);
        // Different input must differ.
        let h3 = content_hash_from_parts(&[b"hello", b"worl!"]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_content_hash_from_parts_empty() {
        let h1 = content_hash_from_parts(&[]);
        let h2 = content_hash_from_parts(&[]);
        assert_eq!(h1, h2);
        // Empty-slice hash differs from non-empty.
        let h3 = content_hash_from_parts(&[b"x"]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_violated_certificate_denied() {
        // Negative bound triggers Violated verdict.
        let bounds = vec![ResourceBound {
            dimension: ResourceDimension::Time,
            upper_bound_millionths: -1,
            is_tight: true,
            confidence_millionths: 1_000_000,
        }];
        let input = CertificateInput {
            certificate_id: "test-violated".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        let cert = ResourceCertificate::new(input);
        assert_eq!(cert.verdict, CertificateVerdict::Violated);
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let decisions = consumer.consume(&cert);
        for d in &decisions {
            assert_eq!(*d, BudgetDecision::Denied);
        }
    }

    #[test]
    fn test_provisional_certificate_denied() {
        // Empty bounds → Provisional verdict.
        let input = CertificateInput {
            certificate_id: "test-provisional".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds: vec![],
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        let cert = ResourceCertificate::new(input);
        assert_eq!(cert.verdict, CertificateVerdict::Provisional);
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let decisions = consumer.consume(&cert);
        for d in &decisions {
            assert_eq!(*d, BudgetDecision::Denied);
        }
    }

    #[test]
    fn test_multiple_forbidden_effects_all_reported() {
        // Certificate with DynamicCodeGen AND Hostcall effects.
        let bounds = make_bounds();
        let effect_summary = make_effect_summary(vec![
            EffectEntry {
                kind: EffectKind::DynamicCodeGen,
                program_point: "eval:1".to_string(),
                worst_case_count_millionths: 1_000_000,
                is_exact: false,
            },
            EffectEntry {
                kind: EffectKind::Hostcall,
                program_point: "call:2".to_string(),
                worst_case_count_millionths: 500_000,
                is_exact: true,
            },
        ]);
        let input = CertificateInput {
            certificate_id: "test-multi-effects".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary,
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        let cert = ResourceCertificate::new(input);

        // Build custom requirement that forbids both effects.
        let mut forbidden = BTreeSet::new();
        forbidden.insert(EffectKind::DynamicCodeGen);
        forbidden.insert(EffectKind::Hostcall);
        let req = SubsystemRequirement {
            subsystem: Subsystem::Specializer,
            min_bounds: BTreeMap::new(),
            forbidden_effects: forbidden,
            min_confidence_millionths: 0,
            reject_critical_assumptions: false,
        };
        let mut consumer = ResourceConsumer::new(vec![req], epoch());
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::Denied);
        let forbidden_count = receipt
            .denial_reasons
            .iter()
            .filter(|r| matches!(r, DenialReason::ForbiddenEffect { .. }))
            .count();
        assert_eq!(forbidden_count, 2);
    }

    #[test]
    fn test_allocated_budgets_populated_on_full_grant() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::FullBudget);
        // Scheduler needs Time and StackDepth → both should be allocated.
        assert!(
            receipt
                .allocated_budgets
                .contains_key(&ResourceDimension::Time)
        );
        assert!(
            receipt
                .allocated_budgets
                .contains_key(&ResourceDimension::StackDepth)
        );
        // Values should match the certificate bounds (500_000 from make_bounds).
        assert_eq!(receipt.allocated_budgets[&ResourceDimension::Time], 500_000);
    }

    #[test]
    fn test_allocated_budgets_empty_on_denial() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = uncertified_certificate();
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Scheduler).unwrap();
        assert_eq!(receipt.decision, BudgetDecision::Denied);
        // On an early CertificateNotCertified return, allocated is empty.
        assert!(receipt.allocated_budgets.is_empty());
    }

    #[test]
    fn test_summary_subsystem_decisions_grouped() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        consumer.consume(&good_certificate());
        consumer.consume(&uncertified_certificate());
        let summary = consumer.summary();
        // Should have decisions from both consumptions.
        assert_eq!(summary.total_decisions, 10);
        // Granted from good + denied from uncertified. Grant rate between 0 and 1.
        assert!(summary.grant_rate_millionths > 0);
        assert!(summary.grant_rate_millionths < MILLIONTHS);
    }

    #[test]
    fn test_module_loader_requirement_dimensions() {
        let req = SubsystemRequirement::module_loader();
        assert_eq!(req.subsystem, Subsystem::ModuleLoader);
        assert!(
            req.min_bounds
                .contains_key(&ResourceDimension::ModuleLoadCount)
        );
        assert!(
            req.min_bounds
                .contains_key(&ResourceDimension::IoOperationCount)
        );
        assert_eq!(req.min_confidence_millionths, 600_000);
        assert!(!req.reject_critical_assumptions);
    }

    #[test]
    fn test_specializer_high_confidence_threshold() {
        // Certificate with enough bound but confidence at 799_999 (one below 800_000).
        let bounds: Vec<ResourceBound> = ResourceDimension::ALL
            .iter()
            .map(|dim| ResourceBound {
                dimension: *dim,
                upper_bound_millionths: 500_000,
                is_tight: true,
                // Exactly one below the specializer's confidence threshold.
                // But must still meet certificate-level confidence (900_000).
                confidence_millionths: 900_000,
            })
            .collect();
        let input = CertificateInput {
            certificate_id: "test-spec-conf-edge".to_string(),
            region_id: "main".to_string(),
            epoch: epoch(),
            bounds,
            effect_summary: make_effect_summary(vec![]),
            assumptions: vec![],
            abstention_points: vec![],
            potentials: vec![],
        };
        let cert = ResourceCertificate::new(input);
        assert_eq!(cert.verdict, CertificateVerdict::Certified);

        // Custom specializer with confidence threshold at 900_001
        let mut min_bounds = BTreeMap::new();
        min_bounds.insert(ResourceDimension::Time, 100_000);
        let req = SubsystemRequirement {
            subsystem: Subsystem::Specializer,
            min_bounds,
            forbidden_effects: BTreeSet::new(),
            min_confidence_millionths: 900_001,
            reject_critical_assumptions: false,
        };
        let mut consumer = ResourceConsumer::new(vec![req], epoch());
        consumer.consume(&cert);
        let receipt = consumer.last_receipt_for(Subsystem::Specializer).unwrap();
        // Confidence 900_000 < required 900_001 → reduced budget.
        assert_eq!(receipt.decision, BudgetDecision::ReducedBudget);
        assert!(
            receipt
                .denial_reasons
                .iter()
                .any(|r| matches!(r, DenialReason::LowBoundConfidence { .. }))
        );
    }

    #[test]
    fn test_receipt_certificate_id_matches() {
        let mut consumer = ResourceConsumer::with_defaults(epoch());
        let cert = good_certificate();
        consumer.consume(&cert);
        for receipt in consumer.receipts() {
            assert_eq!(receipt.certificate_id, "test-cert-001");
        }
    }

    #[test]
    fn test_receipt_epoch_matches_consumer_epoch() {
        let e = SecurityEpoch::from_raw(999);
        let mut consumer = ResourceConsumer::with_defaults(e);
        let cert = good_certificate();
        consumer.consume(&cert);
        for receipt in consumer.receipts() {
            assert_eq!(receipt.epoch.as_u64(), 999);
        }
    }

    #[test]
    fn test_constants_are_correct() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.aara_resource_consumer.v1");
        assert_eq!(BEAD_ID, "bd-1lsy.7.25.2");
        assert_eq!(COMPONENT, "aara_resource_consumer");
        assert_eq!(POLICY_ID, "RGC-625B");
    }
}
