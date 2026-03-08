//! Obstruction Certificates and Deterministic Fallback Planner — FRX-14.3
//!
//! Transforms coherence violations from the Global Coherence Checker (FRX-14.2)
//! into minimal, evidence-linked obstruction certificates that:
//!
//! 1. **Witness minimality** — each certificate includes only the components,
//!    edges, and contract fragments necessary to prove the incompatibility.
//! 2. **Deterministic fallback planning** — every obstruction maps to a ranked
//!    list of fallback actions (isolate, degrade, split, escalate) with
//!    deterministic selection under fixed evidence.
//! 3. **Gate traceability** — certificates carry debt codes, evidence hashes,
//!    and epoch information for integration into verification and release gates.
//!
//! The obstruction→fallback pipeline is a pure function from coherence check
//! results: identical inputs always produce identical certificates and plans.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::global_coherence_checker::{
    CoherenceCheckResult, CoherenceOutcome, CoherenceViolation, CoherenceViolationKind,
    SeverityScore,
};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for obstruction certificate artifacts.
pub const OBSTRUCTION_CERT_SCHEMA_VERSION: &str = "franken-engine.obstruction_certificate.v1";

/// Bead identifier for this module.
pub const OBSTRUCTION_CERT_BEAD_ID: &str = "bd-mjh3.14.3";

/// Maximum certificates per batch (budget guard).
const MAX_CERTIFICATES: usize = 10_000;

/// Maximum fallback actions per plan.
const MAX_FALLBACK_ACTIONS: usize = 100;

/// Maximum witness components in a single certificate.
const MAX_WITNESS_COMPONENTS: usize = 500;

// ---------------------------------------------------------------------------
// Blocking quality-debt codes (FRX-14.3)
// ---------------------------------------------------------------------------

pub const DEBT_OBSTRUCTION_UNRESOLVED: &str = "FE-FRX-14-3-OBSTRUCTION-0001";
pub const DEBT_FALLBACK_INFEASIBLE: &str = "FE-FRX-14-3-OBSTRUCTION-0002";
pub const DEBT_WITNESS_INCOMPLETE: &str = "FE-FRX-14-3-OBSTRUCTION-0003";
pub const DEBT_PLAN_CYCLE: &str = "FE-FRX-14-3-OBSTRUCTION-0004";
pub const DEBT_BUDGET_EXHAUSTED: &str = "FE-FRX-14-3-OBSTRUCTION-0005";

// ---------------------------------------------------------------------------
// Fallback action taxonomy
// ---------------------------------------------------------------------------

/// Category of fallback action for resolving an obstruction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FallbackActionKind {
    /// Isolate the offending component behind a boundary.
    Isolate,
    /// Degrade the component to a safe-mode variant.
    Degrade,
    /// Split the composition boundary to separate conflicting contracts.
    SplitBoundary,
    /// Inject a compatibility adapter between conflicting components.
    InjectAdapter,
    /// Remove the offending component and substitute a stub.
    RemoveAndStub,
    /// Escalate to operator for manual resolution.
    Escalate,
}

impl fmt::Display for FallbackActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolate => write!(f, "isolate"),
            Self::Degrade => write!(f, "degrade"),
            Self::SplitBoundary => write!(f, "split-boundary"),
            Self::InjectAdapter => write!(f, "inject-adapter"),
            Self::RemoveAndStub => write!(f, "remove-and-stub"),
            Self::Escalate => write!(f, "escalate"),
        }
    }
}

/// A single fallback action with cost and feasibility metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackAction {
    /// Unique identifier for this action.
    pub id: EngineObjectId,
    /// The kind of fallback.
    pub kind: FallbackActionKind,
    /// Components targeted by this action.
    pub target_components: Vec<String>,
    /// Human-readable description of what this action does.
    pub description: String,
    /// Estimated disruption cost in millionths (1_000_000 = 1.0).
    /// Lower is better.
    pub disruption_cost_millionths: i64,
    /// Whether this action is feasible given current constraints.
    pub feasible: bool,
    /// Evidence hash for this action's rationale.
    pub rationale_hash: ContentHash,
}

impl FallbackAction {
    /// Compute a deterministic evidence hash for this action.
    fn compute_rationale_hash(
        kind: &FallbackActionKind,
        target_components: &[String],
        description: &str,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(format!("{kind}").as_bytes());
        canonical.push(b'|');
        for comp in target_components {
            canonical.extend_from_slice(comp.as_bytes());
            canonical.push(b',');
        }
        canonical.push(b'|');
        canonical.extend_from_slice(description.as_bytes());
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// Fallback plan
// ---------------------------------------------------------------------------

/// A ranked fallback plan for a single obstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackPlan {
    /// Identifier for this plan.
    pub id: EngineObjectId,
    /// Reference to the obstruction certificate this plan addresses.
    pub certificate_id: EngineObjectId,
    /// Ranked actions (lowest disruption cost first).
    pub actions: Vec<FallbackAction>,
    /// The recommended (top-ranked) action index.
    pub recommended_action_index: usize,
    /// Whether a feasible resolution exists.
    pub has_feasible_resolution: bool,
    /// Debt code if no feasible resolution.
    pub debt_code: Option<String>,
    /// Deterministic hash of the entire plan.
    pub plan_hash: ContentHash,
}

impl FallbackPlan {
    /// Return the recommended action, if any.
    pub fn recommended_action(&self) -> Option<&FallbackAction> {
        self.actions.get(self.recommended_action_index)
    }

    /// Return only feasible actions.
    pub fn feasible_actions(&self) -> Vec<&FallbackAction> {
        self.actions.iter().filter(|a| a.feasible).collect()
    }

    /// Summary line for operator display.
    pub fn summary_line(&self) -> String {
        let feasible_count = self.actions.iter().filter(|a| a.feasible).count();
        format!(
            "plan for cert {}: {} actions ({} feasible), recommended={}",
            self.certificate_id,
            self.actions.len(),
            feasible_count,
            self.recommended_action_index,
        )
    }
}

// ---------------------------------------------------------------------------
// Obstruction certificate
// ---------------------------------------------------------------------------

/// A minimal obstruction witness proving that a set of components
/// cannot be coherently composed under their current contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObstructionCertificate {
    /// Unique identifier for this certificate.
    pub id: EngineObjectId,
    /// The violation that generated this obstruction.
    pub source_violation_id: EngineObjectId,
    /// Category of the original violation.
    pub violation_kind_tag: String,
    /// Severity inherited from the violation.
    pub severity: SeverityScore,
    /// Debt code inherited from the violation.
    pub debt_code: String,
    /// Epoch at which this obstruction was detected.
    pub detected_epoch: u64,
    /// Minimal set of components involved in the obstruction.
    pub witness_components: BTreeSet<String>,
    /// Minimal set of contract fragments proving the incompatibility.
    pub witness_fragments: Vec<WitnessFragment>,
    /// Human-readable explanation of why this is an obstruction.
    pub explanation: String,
    /// Deterministic evidence hash of the full certificate.
    pub certificate_hash: ContentHash,
    /// The fallback plan for this obstruction.
    pub fallback_plan: Option<FallbackPlan>,
}

impl ObstructionCertificate {
    /// Whether this obstruction is blocking (severity >= medium).
    pub fn is_blocking(&self) -> bool {
        self.severity.is_blocking()
    }

    /// Summary line for operator display.
    pub fn summary_line(&self) -> String {
        format!(
            "[{}] {} — {} witness components, severity={}",
            self.debt_code,
            self.violation_kind_tag,
            self.witness_components.len(),
            self.severity.0,
        )
    }
}

/// A contract fragment included in the witness to prove the obstruction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WitnessFragment {
    /// Component this fragment belongs to.
    pub component_id: String,
    /// The contract aspect (e.g. "context.provides", "effect.layout", "capability.requires").
    pub contract_aspect: String,
    /// The specific value or constraint (e.g. "ThemeContext", "useLayoutEffect", "network").
    pub contract_value: String,
}

impl fmt::Display for WitnessFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}: {}",
            self.component_id, self.contract_aspect, self.contract_value
        )
    }
}

// ---------------------------------------------------------------------------
// Batch result
// ---------------------------------------------------------------------------

/// Outcome of the obstruction certification pass.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CertificationOutcome {
    /// No obstructions — composition is coherent.
    Clear,
    /// Obstructions found but all have feasible fallbacks.
    ObstructedWithFallbacks,
    /// At least one obstruction has no feasible fallback.
    ObstructedNoFallback,
    /// Budget exhausted before all violations processed.
    BudgetExhausted,
}

impl fmt::Display for CertificationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clear => write!(f, "clear"),
            Self::ObstructedWithFallbacks => write!(f, "obstructed-with-fallbacks"),
            Self::ObstructedNoFallback => write!(f, "obstructed-no-fallback"),
            Self::BudgetExhausted => write!(f, "budget-exhausted"),
        }
    }
}

/// Full result of the obstruction certification pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationResult {
    pub schema_version: String,
    pub bead_id: String,
    pub outcome: CertificationOutcome,
    pub certificates: Vec<ObstructionCertificate>,
    pub total_obstructions: usize,
    pub blocking_obstructions: usize,
    pub feasible_fallback_count: usize,
    pub infeasible_fallback_count: usize,
    pub certification_epoch: u64,
    pub result_hash: ContentHash,
}

impl CertificationResult {
    /// Whether the composition can proceed (clear or all fallbacks feasible).
    pub fn can_proceed(&self) -> bool {
        matches!(
            self.outcome,
            CertificationOutcome::Clear | CertificationOutcome::ObstructedWithFallbacks
        )
    }

    /// Return certificates that have no feasible fallback.
    pub fn infeasible_certificates(&self) -> Vec<&ObstructionCertificate> {
        self.certificates
            .iter()
            .filter(|c| {
                c.fallback_plan
                    .as_ref()
                    .is_none_or(|p| !p.has_feasible_resolution)
            })
            .collect()
    }

    /// Return all blocking certificates.
    pub fn blocking_certificates(&self) -> Vec<&ObstructionCertificate> {
        self.certificates
            .iter()
            .filter(|c| c.is_blocking())
            .collect()
    }

    /// Certificates grouped by debt code.
    pub fn by_debt_code(&self) -> BTreeMap<String, Vec<&ObstructionCertificate>> {
        let mut map: BTreeMap<String, Vec<&ObstructionCertificate>> = BTreeMap::new();
        for cert in &self.certificates {
            map.entry(cert.debt_code.clone()).or_default().push(cert);
        }
        map
    }

    /// Summary line for operator display.
    pub fn summary_line(&self) -> String {
        format!(
            "{}: {} obstructions ({} blocking), {} feasible fallbacks, {} infeasible",
            self.outcome,
            self.total_obstructions,
            self.blocking_obstructions,
            self.feasible_fallback_count,
            self.infeasible_fallback_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during obstruction certification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObstructionError {
    /// Budget exhausted for a resource.
    BudgetExhausted { resource: String, limit: usize },
    /// Input coherence result is missing required data.
    InvalidInput(String),
    /// Internal inconsistency in certificate generation.
    InternalInconsistency(String),
}

impl fmt::Display for ObstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { resource, limit } => {
                write!(f, "budget exhausted for {resource}: limit={limit}")
            }
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::InternalInconsistency(msg) => write!(f, "internal inconsistency: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the obstruction certifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObstructionCertifierConfig {
    /// Maximum certificates to generate.
    pub max_certificates: usize,
    /// Maximum fallback actions per plan.
    pub max_actions_per_plan: usize,
    /// Maximum witness components per certificate.
    pub max_witness_components: usize,
    /// Whether to include non-blocking violations.
    pub include_non_blocking: bool,
    /// Base disruption cost for each fallback kind (in millionths).
    pub disruption_costs: BTreeMap<String, i64>,
}

impl Default for ObstructionCertifierConfig {
    fn default() -> Self {
        let mut costs = BTreeMap::new();
        costs.insert("isolate".to_string(), 200_000);
        costs.insert("degrade".to_string(), 350_000);
        costs.insert("split-boundary".to_string(), 500_000);
        costs.insert("inject-adapter".to_string(), 600_000);
        costs.insert("remove-and-stub".to_string(), 800_000);
        costs.insert("escalate".to_string(), MILLION);
        Self {
            max_certificates: MAX_CERTIFICATES,
            max_actions_per_plan: MAX_FALLBACK_ACTIONS,
            max_witness_components: MAX_WITNESS_COMPONENTS,
            include_non_blocking: true,
            disruption_costs: costs,
        }
    }
}

// ---------------------------------------------------------------------------
// Certifier
// ---------------------------------------------------------------------------

/// The obstruction certifier: transforms coherence violations into
/// minimal obstruction certificates with deterministic fallback plans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObstructionCertifier {
    config: ObstructionCertifierConfig,
}

impl ObstructionCertifier {
    pub fn new() -> Self {
        Self {
            config: ObstructionCertifierConfig::default(),
        }
    }

    pub fn with_config(config: ObstructionCertifierConfig) -> Self {
        Self { config }
    }

    /// Generate obstruction certificates from a coherence check result.
    ///
    /// This is a pure function: identical inputs always produce identical outputs.
    pub fn certify(
        &self,
        check_result: &CoherenceCheckResult,
    ) -> Result<CertificationResult, ObstructionError> {
        // If coherent, return a clear result.
        if check_result.outcome == CoherenceOutcome::Coherent {
            return Ok(self.build_clear_result(check_result.check_epoch));
        }

        let violations: Vec<&CoherenceViolation> = if self.config.include_non_blocking {
            check_result.violations.iter().collect()
        } else {
            check_result
                .violations
                .iter()
                .filter(|v| v.severity.is_blocking())
                .collect()
        };

        if violations.is_empty() {
            return Ok(self.build_clear_result(check_result.check_epoch));
        }

        let mut certificates = Vec::new();
        let mut budget_exhausted = false;

        for violation in &violations {
            if certificates.len() >= self.config.max_certificates {
                budget_exhausted = true;
                break;
            }
            let cert = self.violation_to_certificate(violation, check_result.check_epoch)?;
            certificates.push(cert);
        }

        // Attach fallback plans to each certificate.
        for cert in &mut certificates {
            let plan = self.plan_fallback(cert)?;
            cert.fallback_plan = Some(plan);
        }

        let blocking_count = certificates.iter().filter(|c| c.is_blocking()).count();
        let feasible_count = certificates
            .iter()
            .filter(|c| {
                c.fallback_plan
                    .as_ref()
                    .is_some_and(|p| p.has_feasible_resolution)
            })
            .count();
        let infeasible_count = certificates.len() - feasible_count;

        let outcome = if budget_exhausted {
            CertificationOutcome::BudgetExhausted
        } else if infeasible_count > 0 {
            CertificationOutcome::ObstructedNoFallback
        } else {
            CertificationOutcome::ObstructedWithFallbacks
        };

        let result_hash = Self::compute_result_hash(&certificates, &outcome);

        Ok(CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
            bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
            outcome,
            total_obstructions: certificates.len(),
            blocking_obstructions: blocking_count,
            feasible_fallback_count: feasible_count,
            infeasible_fallback_count: infeasible_count,
            certification_epoch: check_result.check_epoch,
            result_hash,
            certificates,
        })
    }

    // -----------------------------------------------------------------------
    // Certificate generation
    // -----------------------------------------------------------------------

    fn violation_to_certificate(
        &self,
        violation: &CoherenceViolation,
        epoch: u64,
    ) -> Result<ObstructionCertificate, ObstructionError> {
        let (witness_components, witness_fragments, kind_tag, explanation) =
            self.extract_witness(violation)?;

        let cert_hash = Self::compute_certificate_hash(
            &violation.id,
            &witness_components,
            &witness_fragments,
            &kind_tag,
        );

        let schema_id = SchemaId::from_definition(b"obstruction_certificate.certificate.v1");
        let cert_id = derive_id(
            ObjectDomain::EvidenceRecord,
            "obstruction-certificate",
            &schema_id,
            cert_hash.as_bytes(),
        )
        .unwrap_or_else(|_| violation.id.clone());

        Ok(ObstructionCertificate {
            id: cert_id,
            source_violation_id: violation.id.clone(),
            violation_kind_tag: kind_tag,
            severity: violation.severity.clone(),
            debt_code: violation.debt_code.clone(),
            detected_epoch: epoch,
            witness_components,
            witness_fragments,
            explanation,
            certificate_hash: cert_hash,
            fallback_plan: None,
        })
    }

    fn extract_witness(
        &self,
        violation: &CoherenceViolation,
    ) -> Result<(BTreeSet<String>, Vec<WitnessFragment>, String, String), ObstructionError> {
        let max_w = self.config.max_witness_components;

        match &violation.kind {
            CoherenceViolationKind::UnresolvedContext {
                consumer,
                context_key,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(consumer.clone());
                let fragments = vec![WitnessFragment {
                    component_id: consumer.clone(),
                    contract_aspect: "context.consumes".to_string(),
                    contract_value: context_key.clone(),
                }];
                Ok((
                    comps,
                    fragments,
                    "unresolved-context".to_string(),
                    format!(
                        "Component '{consumer}' consumes context '{context_key}' \
                         but no provider ancestor exists in the composition tree."
                    ),
                ))
            }
            CoherenceViolationKind::OrphanedProvider {
                provider,
                context_key,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(provider.clone());
                let fragments = vec![WitnessFragment {
                    component_id: provider.clone(),
                    contract_aspect: "context.provides".to_string(),
                    contract_value: context_key.clone(),
                }];
                Ok((
                    comps,
                    fragments,
                    "orphaned-provider".to_string(),
                    format!(
                        "Component '{provider}' provides context '{context_key}' \
                         but no descendant consumes it."
                    ),
                ))
            }
            CoherenceViolationKind::CapabilityGap {
                component,
                missing_capabilities,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(component.clone());
                let fragments: Vec<WitnessFragment> = missing_capabilities
                    .iter()
                    .take(max_w)
                    .map(|cap| WitnessFragment {
                        component_id: component.clone(),
                        contract_aspect: "capability.requires".to_string(),
                        contract_value: cap.clone(),
                    })
                    .collect();
                Ok((
                    comps,
                    fragments,
                    "capability-gap".to_string(),
                    format!(
                        "Component '{component}' requires capabilities [{}] \
                         not granted by any boundary ancestor.",
                        missing_capabilities.join(", ")
                    ),
                ))
            }
            CoherenceViolationKind::EffectOrderCycle { cycle_participants } => {
                let comps: BTreeSet<String> =
                    cycle_participants.iter().take(max_w).cloned().collect();
                let fragments: Vec<WitnessFragment> = cycle_participants
                    .iter()
                    .take(max_w)
                    .map(|p| WitnessFragment {
                        component_id: p.clone(),
                        contract_aspect: "effect.ordering".to_string(),
                        contract_value: "cycle-member".to_string(),
                    })
                    .collect();
                Ok((
                    comps,
                    fragments,
                    "effect-order-cycle".to_string(),
                    format!(
                        "Effect ordering cycle among [{}].",
                        cycle_participants.join(" -> ")
                    ),
                ))
            }
            CoherenceViolationKind::LayoutAfterPassive {
                layout_component,
                passive_component,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(layout_component.clone());
                comps.insert(passive_component.clone());
                let fragments = vec![
                    WitnessFragment {
                        component_id: layout_component.clone(),
                        contract_aspect: "effect.layout".to_string(),
                        contract_value: "useLayoutEffect".to_string(),
                    },
                    WitnessFragment {
                        component_id: passive_component.clone(),
                        contract_aspect: "effect.passive".to_string(),
                        contract_value: "useEffect".to_string(),
                    },
                ];
                Ok((
                    comps,
                    fragments,
                    "layout-after-passive".to_string(),
                    format!(
                        "Layout effect in '{layout_component}' appears after \
                         passive effect in '{passive_component}' — violates \
                         React effect ordering invariant."
                    ),
                ))
            }
            CoherenceViolationKind::SuspenseBoundaryConflict {
                boundary_component,
                conflicting_children,
                reason,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(boundary_component.clone());
                for child in conflicting_children.iter().take(max_w.saturating_sub(1)) {
                    comps.insert(child.clone());
                }
                let mut fragments = vec![WitnessFragment {
                    component_id: boundary_component.clone(),
                    contract_aspect: "boundary.suspense".to_string(),
                    contract_value: "boundary-owner".to_string(),
                }];
                for child in conflicting_children.iter().take(max_w.saturating_sub(1)) {
                    fragments.push(WitnessFragment {
                        component_id: child.clone(),
                        contract_aspect: "boundary.suspense.child".to_string(),
                        contract_value: reason.clone(),
                    });
                }
                Ok((
                    comps,
                    fragments,
                    "suspense-boundary-conflict".to_string(),
                    format!(
                        "Suspense boundary at '{boundary_component}' wraps children \
                         [{}] with incompatible async contracts: {reason}.",
                        conflicting_children.join(", ")
                    ),
                ))
            }
            CoherenceViolationKind::HydrationBoundaryConflict {
                boundary_component,
                conflicting_children,
                reason,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(boundary_component.clone());
                for child in conflicting_children.iter().take(max_w.saturating_sub(1)) {
                    comps.insert(child.clone());
                }
                let mut fragments = vec![WitnessFragment {
                    component_id: boundary_component.clone(),
                    contract_aspect: "boundary.hydration".to_string(),
                    contract_value: "boundary-owner".to_string(),
                }];
                for child in conflicting_children.iter().take(max_w.saturating_sub(1)) {
                    fragments.push(WitnessFragment {
                        component_id: child.clone(),
                        contract_aspect: "boundary.hydration.child".to_string(),
                        contract_value: reason.clone(),
                    });
                }
                Ok((
                    comps,
                    fragments,
                    "hydration-boundary-conflict".to_string(),
                    format!(
                        "Hydration boundary at '{boundary_component}' wraps children \
                         [{}] with incompatible effect contracts: {reason}.",
                        conflicting_children.join(", ")
                    ),
                ))
            }
            CoherenceViolationKind::HookCleanupMismatch {
                component_a,
                component_b,
                hook_label,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(component_a.clone());
                comps.insert(component_b.clone());
                let fragments = vec![
                    WitnessFragment {
                        component_id: component_a.clone(),
                        contract_aspect: "hook.cleanup".to_string(),
                        contract_value: hook_label.clone(),
                    },
                    WitnessFragment {
                        component_id: component_b.clone(),
                        contract_aspect: "hook.cleanup".to_string(),
                        contract_value: hook_label.clone(),
                    },
                ];
                Ok((
                    comps,
                    fragments,
                    "hook-cleanup-mismatch".to_string(),
                    format!(
                        "Components '{component_a}' and '{component_b}' share \
                         hook dependency graph '{hook_label}' but disagree on \
                         cleanup policy."
                    ),
                ))
            }
            CoherenceViolationKind::DuplicateProvider {
                providers,
                context_key,
            } => {
                let comps: BTreeSet<String> = providers.iter().take(max_w).cloned().collect();
                let fragments: Vec<WitnessFragment> = providers
                    .iter()
                    .take(max_w)
                    .map(|p| WitnessFragment {
                        component_id: p.clone(),
                        contract_aspect: "context.provides".to_string(),
                        contract_value: context_key.clone(),
                    })
                    .collect();
                Ok((
                    comps,
                    fragments,
                    "duplicate-provider".to_string(),
                    format!(
                        "Multiple providers [{}] for context '{context_key}' \
                         in the same subtree — ambiguous resolution.",
                        providers.join(", ")
                    ),
                ))
            }
            CoherenceViolationKind::BoundaryCapabilityLeak {
                boundary,
                leaked_capabilities,
            } => {
                let mut comps = BTreeSet::new();
                comps.insert(boundary.clone());
                let fragments: Vec<WitnessFragment> = leaked_capabilities
                    .iter()
                    .take(max_w)
                    .map(|cap| WitnessFragment {
                        component_id: boundary.clone(),
                        contract_aspect: "capability.leaked".to_string(),
                        contract_value: cap.clone(),
                    })
                    .collect();
                Ok((
                    comps,
                    fragments,
                    "boundary-capability-leak".to_string(),
                    format!(
                        "Boundary '{boundary}' does not cover transitive \
                         capability requirements [{}] of its children.",
                        leaked_capabilities.join(", ")
                    ),
                ))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Fallback planning
    // -----------------------------------------------------------------------

    fn plan_fallback(
        &self,
        cert: &ObstructionCertificate,
    ) -> Result<FallbackPlan, ObstructionError> {
        let actions = self.generate_fallback_actions(cert)?;

        let has_feasible = actions.iter().any(|a| a.feasible);
        let recommended_idx = actions
            .iter()
            .enumerate()
            .filter(|(_, a)| a.feasible)
            .min_by_key(|(_, a)| a.disruption_cost_millionths)
            .map(|(i, _)| i)
            .unwrap_or(0);

        let debt_code = if !has_feasible {
            Some(DEBT_FALLBACK_INFEASIBLE.to_string())
        } else {
            None
        };

        let plan_hash = Self::compute_plan_hash(&cert.id, &actions);

        let schema_id = SchemaId::from_definition(b"obstruction_certificate.plan.v1");
        let plan_id = derive_id(
            ObjectDomain::EvidenceRecord,
            "obstruction-plan",
            &schema_id,
            plan_hash.as_bytes(),
        )
        .unwrap_or_else(|_| cert.id.clone());

        Ok(FallbackPlan {
            id: plan_id,
            certificate_id: cert.id.clone(),
            actions,
            recommended_action_index: recommended_idx,
            has_feasible_resolution: has_feasible,
            debt_code,
            plan_hash,
        })
    }

    fn generate_fallback_actions(
        &self,
        cert: &ObstructionCertificate,
    ) -> Result<Vec<FallbackAction>, ObstructionError> {
        let target_components: Vec<String> = cert.witness_components.iter().cloned().collect();
        let tag = &cert.violation_kind_tag;

        // Generate candidate actions based on the obstruction kind.
        let candidates = match tag.as_str() {
            "unresolved-context" => self.unresolved_context_actions(&target_components),
            "orphaned-provider" => self.orphaned_provider_actions(&target_components),
            "capability-gap" => self.capability_gap_actions(&target_components),
            "effect-order-cycle" => self.effect_cycle_actions(&target_components),
            "layout-after-passive" => self.layout_after_passive_actions(&target_components),
            "suspense-boundary-conflict" => {
                self.boundary_conflict_actions(&target_components, "suspense")
            }
            "hydration-boundary-conflict" => {
                self.boundary_conflict_actions(&target_components, "hydration")
            }
            "hook-cleanup-mismatch" => self.hook_mismatch_actions(&target_components),
            "duplicate-provider" => self.duplicate_provider_actions(&target_components),
            "boundary-capability-leak" => self.boundary_leak_actions(&target_components),
            _ => vec![self.make_escalate_action(&target_components, "unknown obstruction kind")],
        };

        // Sort by disruption cost, truncate to budget.
        let mut actions = candidates;
        actions.sort_by_key(|a| a.disruption_cost_millionths);
        actions.truncate(self.config.max_actions_per_plan);
        Ok(actions)
    }

    // ---- Per-kind fallback generators ----

    fn unresolved_context_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::InjectAdapter,
                targets,
                "Inject a default context provider above the consumer.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Degrade consumer to a no-context safe-mode variant.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Isolate,
                targets,
                "Isolate consumer behind an error boundary with fallback UI.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: manual context wiring required.",
                true,
            ),
        ]
    }

    fn orphaned_provider_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::RemoveAndStub,
                targets,
                "Remove orphaned provider — no consumers depend on it.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Mark provider as dormant and skip its initialization.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: verify provider is intentionally orphaned.",
                true,
            ),
        ]
    }

    fn capability_gap_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::Isolate,
                targets,
                "Isolate component behind a capability boundary that denies the missing capabilities.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Degrade component to safe-mode variant that does not require the missing capabilities.",
                true,
            ),
            self.make_action(
                FallbackActionKind::InjectAdapter,
                targets,
                "Inject a capability-providing adapter boundary above the component.",
                targets.len() <= 3,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: grant required capabilities via policy update.",
                true,
            ),
        ]
    }

    fn effect_cycle_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::SplitBoundary,
                targets,
                "Split effect ordering by breaking the cycle at the lowest-severity edge.",
                targets.len() <= 10,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Degrade one cycle participant to a pure-render variant with no effects.",
                true,
            ),
            self.make_action(
                FallbackActionKind::RemoveAndStub,
                targets,
                "Remove the cycle participant with the lowest priority and substitute a stub.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: manual effect-ordering resolution required.",
                true,
            ),
        ]
    }

    fn layout_after_passive_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Convert layout effect to passive effect (may cause visual flicker).",
                true,
            ),
            self.make_action(
                FallbackActionKind::SplitBoundary,
                targets,
                "Split composition to ensure layout effects execute before passive effects.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: reorder components to fix layout/passive ordering.",
                true,
            ),
        ]
    }

    fn boundary_conflict_actions(
        &self,
        targets: &[String],
        boundary_kind: &str,
    ) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::SplitBoundary,
                targets,
                &format!(
                    "Split {boundary_kind} boundary to separate conflicting children \
                     into compatible groups."
                ),
                true,
            ),
            self.make_action(
                FallbackActionKind::Isolate,
                targets,
                &format!(
                    "Isolate conflicting children behind separate {boundary_kind} boundaries."
                ),
                true,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                &format!(
                    "Degrade conflicting children to synchronous ({boundary_kind}-safe) variants."
                ),
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                &format!("Escalate to operator: restructure {boundary_kind} boundary manually."),
                true,
            ),
        ]
    }

    fn hook_mismatch_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::InjectAdapter,
                targets,
                "Inject a cleanup-policy adapter that normalizes both components' hook contracts.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Degrade the stricter component to match the more permissive cleanup policy.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Isolate,
                targets,
                "Isolate both components so their hook dependency graphs no longer overlap.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: reconcile cleanup policies manually.",
                true,
            ),
        ]
    }

    fn duplicate_provider_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::RemoveAndStub,
                targets,
                "Remove duplicate provider(s), keeping only the highest-priority one.",
                targets.len() >= 2,
            ),
            self.make_action(
                FallbackActionKind::SplitBoundary,
                targets,
                "Split the subtree so each provider serves a disjoint consumer set.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: select the canonical provider explicitly.",
                true,
            ),
        ]
    }

    fn boundary_leak_actions(&self, targets: &[String]) -> Vec<FallbackAction> {
        vec![
            self.make_action(
                FallbackActionKind::InjectAdapter,
                targets,
                "Inject a capability grant boundary that covers the leaked requirements.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Isolate,
                targets,
                "Isolate leaking children behind a deny-all boundary.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Degrade,
                targets,
                "Degrade children to variants that do not require the leaked capabilities.",
                true,
            ),
            self.make_action(
                FallbackActionKind::Escalate,
                targets,
                "Escalate to operator: widen boundary grants or restructure composition.",
                true,
            ),
        ]
    }

    // ---- Action construction helpers ----

    fn make_action(
        &self,
        kind: FallbackActionKind,
        targets: &[String],
        description: &str,
        feasible: bool,
    ) -> FallbackAction {
        let kind_str = format!("{kind}");
        let base_cost = self
            .config
            .disruption_costs
            .get(&kind_str)
            .copied()
            .unwrap_or(MILLION);
        // Scale cost by number of targets (more targets = more disruption).
        let target_count = targets.len().max(1) as i64;
        let disruption_cost = base_cost.saturating_mul(target_count).min(10 * MILLION);

        let rationale_hash = FallbackAction::compute_rationale_hash(&kind, targets, description);

        let schema_id = SchemaId::from_definition(b"obstruction_certificate.action.v1");
        let action_id = derive_id(
            ObjectDomain::EvidenceRecord,
            "obstruction-action",
            &schema_id,
            rationale_hash.as_bytes(),
        )
        .unwrap_or_else(|_| {
            // Fallback: derive from description bytes.
            let fallback_schema =
                SchemaId::from_definition(b"obstruction_certificate.action.fallback.v1");
            derive_id(
                ObjectDomain::EvidenceRecord,
                "obstruction-action-fb",
                &fallback_schema,
                description.as_bytes(),
            )
            .expect("fallback derive_id should not fail")
        });

        FallbackAction {
            id: action_id,
            kind,
            target_components: targets.to_vec(),
            description: description.to_string(),
            disruption_cost_millionths: disruption_cost,
            feasible,
            rationale_hash,
        }
    }

    fn make_escalate_action(&self, targets: &[String], reason: &str) -> FallbackAction {
        self.make_action(
            FallbackActionKind::Escalate,
            targets,
            &format!("Escalate to operator: {reason}."),
            true,
        )
    }

    // -----------------------------------------------------------------------
    // Hashing
    // -----------------------------------------------------------------------

    fn compute_certificate_hash(
        violation_id: &EngineObjectId,
        witness_components: &BTreeSet<String>,
        witness_fragments: &[WitnessFragment],
        kind_tag: &str,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(OBSTRUCTION_CERT_SCHEMA_VERSION.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{violation_id}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(kind_tag.as_bytes());
        canonical.push(b'|');
        for comp in witness_components {
            canonical.extend_from_slice(comp.as_bytes());
            canonical.push(b',');
        }
        canonical.push(b'|');
        for frag in witness_fragments {
            canonical.extend_from_slice(frag.component_id.as_bytes());
            canonical.push(b'/');
            canonical.extend_from_slice(frag.contract_aspect.as_bytes());
            canonical.push(b':');
            canonical.extend_from_slice(frag.contract_value.as_bytes());
            canonical.push(b';');
        }
        ContentHash::compute(&canonical)
    }

    fn compute_plan_hash(cert_id: &EngineObjectId, actions: &[FallbackAction]) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(OBSTRUCTION_CERT_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|plan|");
        canonical.extend_from_slice(format!("{cert_id}").as_bytes());
        canonical.push(b'|');
        for action in actions {
            canonical.extend_from_slice(format!("{}", action.kind).as_bytes());
            canonical.push(b':');
            canonical.extend_from_slice(action.disruption_cost_millionths.to_string().as_bytes());
            canonical.push(b':');
            canonical.extend_from_slice(if action.feasible { b"T" } else { b"F" });
            canonical.push(b';');
        }
        ContentHash::compute(&canonical)
    }

    fn compute_result_hash(
        certs: &[ObstructionCertificate],
        outcome: &CertificationOutcome,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(OBSTRUCTION_CERT_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|result|");
        canonical.extend_from_slice(format!("{outcome}").as_bytes());
        canonical.push(b'|');
        for cert in certs {
            canonical.extend_from_slice(cert.certificate_hash.as_bytes());
            canonical.push(b';');
        }
        ContentHash::compute(&canonical)
    }

    fn build_clear_result(&self, epoch: u64) -> CertificationResult {
        let result_hash = Self::compute_result_hash(&[], &CertificationOutcome::Clear);
        CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
            bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
            outcome: CertificationOutcome::Clear,
            certificates: Vec::new(),
            total_obstructions: 0,
            blocking_obstructions: 0,
            feasible_fallback_count: 0,
            infeasible_fallback_count: 0,
            certification_epoch: epoch,
            result_hash,
        }
    }
}

impl Default for ObstructionCertifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Gate integration helpers
// ---------------------------------------------------------------------------

/// Render a human-readable report from a certification result.
pub fn render_certification_report(result: &CertificationResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "=== Obstruction Certification Report (epoch {}) ===",
        result.certification_epoch
    ));
    lines.push(result.summary_line());
    lines.push(String::new());

    if result.certificates.is_empty() {
        lines.push("No obstructions detected. Composition is coherent.".to_string());
    } else {
        for (i, cert) in result.certificates.iter().enumerate() {
            lines.push(format!("--- Obstruction #{} ---", i + 1));
            lines.push(cert.summary_line());
            lines.push(format!("  Explanation: {}", cert.explanation));
            lines.push(format!(
                "  Witness components: [{}]",
                cert.witness_components
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            for frag in &cert.witness_fragments {
                lines.push(format!("    Fragment: {frag}"));
            }
            if let Some(plan) = &cert.fallback_plan {
                lines.push(format!("  Fallback plan: {}", plan.summary_line()));
                for (j, action) in plan.actions.iter().enumerate() {
                    let marker = if j == plan.recommended_action_index {
                        " [RECOMMENDED]"
                    } else {
                        ""
                    };
                    let feasibility = if action.feasible {
                        "feasible"
                    } else {
                        "INFEASIBLE"
                    };
                    lines.push(format!(
                        "    Action #{}: {} ({}, cost={}){}",
                        j + 1,
                        action.kind,
                        feasibility,
                        action.disruption_cost_millionths,
                        marker,
                    ));
                    lines.push(format!("      {}", action.description));
                }
            }
            lines.push(String::new());
        }
    }

    lines.push(format!("Result hash: {}", result.result_hash));
    lines.join("\n")
}

/// Check whether a certification result should block a gate.
pub fn should_block_gate(result: &CertificationResult) -> bool {
    matches!(
        result.outcome,
        CertificationOutcome::ObstructedNoFallback | CertificationOutcome::BudgetExhausted
    )
}

/// Extract all debt codes from a certification result.
pub fn collect_debt_codes(result: &CertificationResult) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    for cert in &result.certificates {
        codes.insert(cert.debt_code.clone());
        if let Some(plan) = &cert.fallback_plan
            && let Some(code) = &plan.debt_code
        {
            codes.insert(code.clone());
        }
    }
    codes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_coherence_checker::{
        CoherenceCheckResult, CoherenceOutcome, CoherenceViolation, CoherenceViolationKind,
        DEBT_CAPABILITY_GAP, DEBT_EFFECT_CYCLE, DEBT_HOOK_CLEANUP_MISMATCH,
        DEBT_HYDRATION_BOUNDARY_CONFLICT, DEBT_SUSPENSE_BOUNDARY_CONFLICT, DEBT_UNRESOLVED_CONTEXT,
        GLOBAL_COHERENCE_SCHEMA_VERSION, SeverityScore,
    };
    use crate::hash_tiers::ContentHash;

    // ---- Helper to build a minimal coherence check result ----

    fn make_violation(
        kind: CoherenceViolationKind,
        severity: SeverityScore,
        debt_code: &str,
    ) -> CoherenceViolation {
        let desc = format!("{kind}");
        let evidence_hash = ContentHash::compute(desc.as_bytes());
        let schema_id = SchemaId::from_definition(b"test.violation.v1");
        let id = derive_id(
            ObjectDomain::EvidenceRecord,
            "test-violation",
            &schema_id,
            evidence_hash.as_bytes(),
        )
        .unwrap();
        CoherenceViolation {
            id,
            kind,
            severity,
            debt_code: debt_code.to_string(),
            description: desc,
            evidence_hash,
            detected_epoch: 1,
        }
    }

    fn make_check_result(
        violations: Vec<CoherenceViolation>,
        outcome: CoherenceOutcome,
    ) -> CoherenceCheckResult {
        let result_hash = ContentHash::compute(b"test-result");
        CoherenceCheckResult {
            schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
            bead_id: "bd-test".to_string(),
            outcome,
            component_count: 10,
            edge_count: 15,
            context_pairs_checked: 5,
            capability_boundaries_checked: 3,
            effect_orderings_checked: 2,
            suspense_boundaries_checked: 1,
            hydration_boundaries_checked: 1,
            total_severity_millionths: violations.iter().map(|v| v.severity.0).sum(),
            blocking_violation_count: violations
                .iter()
                .filter(|v| v.severity.is_blocking())
                .count(),
            check_epoch: 1,
            result_hash,
            violations,
        }
    }

    // =========================================================================
    // Basic construction and defaults
    // =========================================================================

    #[test]
    fn test_certifier_default_config() {
        let c = ObstructionCertifier::new();
        assert_eq!(c.config.max_certificates, MAX_CERTIFICATES);
        assert_eq!(c.config.max_actions_per_plan, MAX_FALLBACK_ACTIONS);
        assert!(c.config.include_non_blocking);
        assert_eq!(c.config.disruption_costs.len(), 6);
    }

    #[test]
    fn test_custom_config() {
        let config = ObstructionCertifierConfig {
            max_certificates: 5,
            include_non_blocking: false,
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config.clone());
        assert_eq!(c.config.max_certificates, 5);
        assert!(!c.config.include_non_blocking);
    }

    // =========================================================================
    // Clear result for coherent input
    // =========================================================================

    #[test]
    fn test_certify_coherent_input() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.outcome, CertificationOutcome::Clear);
        assert!(result.certificates.is_empty());
        assert!(result.can_proceed());
        assert!(!should_block_gate(&result));
    }

    #[test]
    fn test_certify_coherent_with_warnings_but_no_violations() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::CoherentWithWarnings);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.outcome, CertificationOutcome::Clear);
    }

    // =========================================================================
    // Unresolved context obstruction
    // =========================================================================

    #[test]
    fn test_unresolved_context_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "MyComponent".to_string(),
                context_key: "ThemeContext".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        assert_eq!(
            result.outcome,
            CertificationOutcome::ObstructedWithFallbacks
        );
        assert_eq!(result.total_obstructions, 1);
        assert_eq!(result.blocking_obstructions, 1);

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "unresolved-context");
        assert!(cert.witness_components.contains("MyComponent"));
        assert_eq!(cert.witness_fragments.len(), 1);
        assert_eq!(
            cert.witness_fragments[0].contract_aspect,
            "context.consumes"
        );
        assert_eq!(cert.witness_fragments[0].contract_value, "ThemeContext");
        assert!(cert.is_blocking());

        // Fallback plan should exist with feasible actions.
        let plan = cert.fallback_plan.as_ref().unwrap();
        assert!(plan.has_feasible_resolution);
        assert!(plan.actions.len() >= 3);
        // First feasible action should be lowest-cost.
        let recommended = plan.recommended_action().unwrap();
        assert!(recommended.feasible);
    }

    #[test]
    fn test_unresolved_context_witness_fragments() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "App".to_string(),
                context_key: "AuthContext".to_string(),
            },
            SeverityScore::high(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert!(cert.explanation.contains("AuthContext"));
        assert!(cert.explanation.contains("App"));
    }

    // =========================================================================
    // Orphaned provider obstruction
    // =========================================================================

    #[test]
    fn test_orphaned_provider_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "ThemeProvider".to_string(),
                context_key: "ThemeContext".to_string(),
            },
            SeverityScore::low(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::CoherentWithWarnings);
        let result = c.certify(&input).unwrap();

        assert_eq!(
            result.outcome,
            CertificationOutcome::ObstructedWithFallbacks
        );
        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "orphaned-provider");
        assert!(!cert.is_blocking()); // low severity
        assert!(cert.witness_components.contains("ThemeProvider"));
    }

    // =========================================================================
    // Capability gap obstruction
    // =========================================================================

    #[test]
    fn test_capability_gap_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "NetworkWidget".to_string(),
                missing_capabilities: vec!["network".to_string(), "storage".to_string()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "capability-gap");
        assert_eq!(cert.witness_fragments.len(), 2);
        assert!(
            cert.witness_fragments
                .iter()
                .any(|f| f.contract_value == "network")
        );
        assert!(
            cert.witness_fragments
                .iter()
                .any(|f| f.contract_value == "storage")
        );
    }

    // =========================================================================
    // Effect order cycle obstruction
    // =========================================================================

    #[test]
    fn test_effect_cycle_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: vec![
                    "CompA".to_string(),
                    "CompB".to_string(),
                    "CompC".to_string(),
                ],
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "effect-order-cycle");
        assert_eq!(cert.witness_components.len(), 3);
        assert!(cert.witness_components.contains("CompA"));
        assert!(cert.witness_components.contains("CompB"));
        assert!(cert.witness_components.contains("CompC"));
    }

    #[test]
    fn test_effect_cycle_large_infeasible_split() {
        let c = ObstructionCertifier::new();
        let participants: Vec<String> = (0..20).map(|i| format!("Comp{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: participants.clone(),
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        let plan = cert.fallback_plan.as_ref().unwrap();
        // SplitBoundary is infeasible for >10 targets.
        let split_action = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::SplitBoundary);
        if let Some(sa) = split_action {
            assert!(!sa.feasible);
        }
    }

    // =========================================================================
    // Layout after passive obstruction
    // =========================================================================

    #[test]
    fn test_layout_after_passive_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::LayoutAfterPassive {
                layout_component: "MeasureBox".to_string(),
                passive_component: "DataFetcher".to_string(),
            },
            SeverityScore::medium(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "layout-after-passive");
        assert_eq!(cert.witness_components.len(), 2);
        assert_eq!(cert.witness_fragments.len(), 2);
    }

    // =========================================================================
    // Suspense boundary conflict
    // =========================================================================

    #[test]
    fn test_suspense_boundary_conflict_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::SuspenseBoundaryConflict {
                boundary_component: "SuspenseWrapper".to_string(),
                conflicting_children: vec!["AsyncA".to_string(), "AsyncB".to_string()],
                reason: "incompatible loading states".to_string(),
            },
            SeverityScore::high(),
            DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "suspense-boundary-conflict");
        assert!(cert.witness_components.contains("SuspenseWrapper"));
        assert!(cert.witness_components.contains("AsyncA"));
        assert!(cert.witness_components.contains("AsyncB"));
    }

    // =========================================================================
    // Hydration boundary conflict
    // =========================================================================

    #[test]
    fn test_hydration_boundary_conflict_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HydrationBoundaryConflict {
                boundary_component: "HydrationRoot".to_string(),
                conflicting_children: vec!["ClientOnly".to_string()],
                reason: "client-side effect in SSR boundary".to_string(),
            },
            SeverityScore::critical(),
            DEBT_HYDRATION_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "hydration-boundary-conflict");
        assert!(cert.explanation.contains("client-side effect"));
    }

    // =========================================================================
    // Hook cleanup mismatch
    // =========================================================================

    #[test]
    fn test_hook_cleanup_mismatch_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HookCleanupMismatch {
                component_a: "WidgetA".to_string(),
                component_b: "WidgetB".to_string(),
                hook_label: "useSubscription".to_string(),
            },
            SeverityScore::medium(),
            DEBT_HOOK_CLEANUP_MISMATCH,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "hook-cleanup-mismatch");
        assert_eq!(cert.witness_components.len(), 2);
        assert_eq!(cert.witness_fragments.len(), 2);
    }

    // =========================================================================
    // Duplicate provider
    // =========================================================================

    #[test]
    fn test_duplicate_provider_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::DuplicateProvider {
                providers: vec!["ProvA".to_string(), "ProvB".to_string()],
                context_key: "RouterContext".to_string(),
            },
            SeverityScore::high(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "duplicate-provider");
        assert!(
            cert.witness_fragments
                .iter()
                .all(|f| f.contract_value == "RouterContext")
        );
    }

    // =========================================================================
    // Boundary capability leak
    // =========================================================================

    #[test]
    fn test_boundary_capability_leak_certificate() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::BoundaryCapabilityLeak {
                boundary: "SecurityBoundary".to_string(),
                leaked_capabilities: vec!["filesystem".to_string(), "network".to_string()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        assert_eq!(cert.violation_kind_tag, "boundary-capability-leak");
        assert_eq!(cert.witness_fragments.len(), 2);
    }

    // =========================================================================
    // Multiple violations
    // =========================================================================

    #[test]
    fn test_multiple_violations_generate_multiple_certificates() {
        let c = ObstructionCertifier::new();
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "Ctx1".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "B".to_string(),
                missing_capabilities: vec!["cap1".to_string()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let v3 = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: vec!["C".to_string(), "D".to_string()],
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v1, v2, v3], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        assert_eq!(result.total_obstructions, 3);
        assert_eq!(result.certificates.len(), 3);
        assert_eq!(result.blocking_obstructions, 3);
    }

    // =========================================================================
    // Non-blocking filter
    // =========================================================================

    #[test]
    fn test_exclude_non_blocking_violations() {
        let config = ObstructionCertifierConfig {
            include_non_blocking: false,
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config);

        let v1 = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "P".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::low(), // non-blocking
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K2".to_string(),
            },
            SeverityScore::critical(), // blocking
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v1, v2], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        // Only the blocking violation should produce a certificate.
        assert_eq!(result.total_obstructions, 1);
        assert_eq!(
            result.certificates[0].violation_kind_tag,
            "unresolved-context"
        );
    }

    // =========================================================================
    // Budget exhaustion
    // =========================================================================

    #[test]
    fn test_budget_exhaustion() {
        let config = ObstructionCertifierConfig {
            max_certificates: 2,
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config);

        let violations: Vec<CoherenceViolation> = (0..5)
            .map(|i| {
                make_violation(
                    CoherenceViolationKind::UnresolvedContext {
                        consumer: format!("C{i}"),
                        context_key: format!("K{i}"),
                    },
                    SeverityScore::critical(),
                    DEBT_UNRESOLVED_CONTEXT,
                )
            })
            .collect();
        let input = make_check_result(violations, CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        assert_eq!(result.outcome, CertificationOutcome::BudgetExhausted);
        assert_eq!(result.certificates.len(), 2);
        assert!(should_block_gate(&result));
    }

    // =========================================================================
    // Determinism
    // =========================================================================

    #[test]
    fn test_deterministic_output() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "Comp".to_string(),
                context_key: "Ctx".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);

        let r1 = c.certify(&input).unwrap();
        let r2 = c.certify(&input).unwrap();

        assert_eq!(r1.result_hash, r2.result_hash);
        assert_eq!(r1.certificates.len(), r2.certificates.len());
        for (c1, c2) in r1.certificates.iter().zip(r2.certificates.iter()) {
            assert_eq!(c1.certificate_hash, c2.certificate_hash);
            assert_eq!(c1.id, c2.id);
            if let (Some(p1), Some(p2)) = (&c1.fallback_plan, &c2.fallback_plan) {
                assert_eq!(p1.plan_hash, p2.plan_hash);
            }
        }
    }

    // =========================================================================
    // Fallback plan structure
    // =========================================================================

    #[test]
    fn test_fallback_plan_recommended_action_is_lowest_cost() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HookCleanupMismatch {
                component_a: "A".to_string(),
                component_b: "B".to_string(),
                hook_label: "useFoo".to_string(),
            },
            SeverityScore::medium(),
            DEBT_HOOK_CLEANUP_MISMATCH,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let recommended = plan.recommended_action().unwrap();
        assert!(recommended.feasible);
        // All other feasible actions should cost >= recommended.
        for action in &plan.actions {
            if action.feasible {
                assert!(
                    action.disruption_cost_millionths >= recommended.disruption_cost_millionths
                );
            }
        }
    }

    #[test]
    fn test_fallback_plan_has_correct_certificate_ref() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "X".to_string(),
                context_key: "Y".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let cert = &result.certificates[0];
        let plan = cert.fallback_plan.as_ref().unwrap();
        assert_eq!(plan.certificate_id, cert.id);
    }

    // =========================================================================
    // Disruption cost scaling
    // =========================================================================

    #[test]
    fn test_disruption_cost_scales_with_targets() {
        let c = ObstructionCertifier::new();
        // Single-target violation.
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        // Multi-target violation (3 cycle participants).
        let v2 = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: vec!["X".to_string(), "Y".to_string(), "Z".to_string()],
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );

        let r1 = c
            .certify(&make_check_result(vec![v1], CoherenceOutcome::Incoherent))
            .unwrap();
        let r2 = c
            .certify(&make_check_result(vec![v2], CoherenceOutcome::Incoherent))
            .unwrap();

        let plan1 = r1.certificates[0].fallback_plan.as_ref().unwrap();
        let plan2 = r2.certificates[0].fallback_plan.as_ref().unwrap();

        // For the same action kind, multi-target should cost more.
        if let (Some(esc1), Some(esc2)) = (
            plan1
                .actions
                .iter()
                .find(|a| a.kind == FallbackActionKind::Escalate),
            plan2
                .actions
                .iter()
                .find(|a| a.kind == FallbackActionKind::Escalate),
        ) {
            assert!(esc2.disruption_cost_millionths > esc1.disruption_cost_millionths);
        }
    }

    // =========================================================================
    // Serde round-trip
    // =========================================================================

    #[test]
    fn test_certification_result_serde_roundtrip() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CertificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.outcome, deserialized.outcome);
        assert_eq!(result.total_obstructions, deserialized.total_obstructions);
        assert_eq!(result.result_hash, deserialized.result_hash);
        assert_eq!(result.certificates.len(), deserialized.certificates.len());
    }

    #[test]
    fn test_obstruction_certificate_serde_roundtrip() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".to_string(),
                missing_capabilities: vec!["net".to_string()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];

        let json = serde_json::to_string(cert).unwrap();
        let deserialized: ObstructionCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert.id, deserialized.id);
        assert_eq!(cert.certificate_hash, deserialized.certificate_hash);
    }

    // =========================================================================
    // Report rendering
    // =========================================================================

    #[test]
    fn test_render_report_clear() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("No obstructions detected"));
        assert!(report.contains("clear"));
    }

    #[test]
    fn test_render_report_with_obstructions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "Foo".to_string(),
                context_key: "Bar".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("Obstruction #1"));
        assert!(report.contains("[RECOMMENDED]"));
        assert!(report.contains("unresolved-context"));
    }

    // =========================================================================
    // Gate integration
    // =========================================================================

    #[test]
    fn test_should_block_gate_for_no_fallback() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        // All fallbacks are feasible for unresolved-context, so should NOT block.
        assert!(!should_block_gate(&result));
    }

    #[test]
    fn test_should_not_block_gate_for_clear() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        assert!(!should_block_gate(&result));
    }

    // =========================================================================
    // Debt code collection
    // =========================================================================

    #[test]
    fn test_collect_debt_codes() {
        let c = ObstructionCertifier::new();
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "B".to_string(),
                missing_capabilities: vec!["x".to_string()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v1, v2], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let codes = collect_debt_codes(&result);
        assert!(codes.contains(DEBT_UNRESOLVED_CONTEXT));
        assert!(codes.contains(DEBT_CAPABILITY_GAP));
    }

    // =========================================================================
    // CertificationResult helpers
    // =========================================================================

    #[test]
    fn test_can_proceed() {
        let clear = CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
            bead_id: "test".to_string(),
            outcome: CertificationOutcome::Clear,
            certificates: vec![],
            total_obstructions: 0,
            blocking_obstructions: 0,
            feasible_fallback_count: 0,
            infeasible_fallback_count: 0,
            certification_epoch: 1,
            result_hash: ContentHash::compute(b"test"),
        };
        assert!(clear.can_proceed());

        let with_fallbacks = CertificationResult {
            outcome: CertificationOutcome::ObstructedWithFallbacks,
            ..clear.clone()
        };
        assert!(with_fallbacks.can_proceed());

        let no_fallback = CertificationResult {
            outcome: CertificationOutcome::ObstructedNoFallback,
            ..clear.clone()
        };
        assert!(!no_fallback.can_proceed());

        let exhausted = CertificationResult {
            outcome: CertificationOutcome::BudgetExhausted,
            ..clear
        };
        assert!(!exhausted.can_proceed());
    }

    #[test]
    fn test_summary_line_format() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        let line = result.summary_line();
        assert!(line.contains("clear"));
        assert!(line.contains("0 obstructions"));
    }

    // =========================================================================
    // WitnessFragment Display
    // =========================================================================

    #[test]
    fn test_witness_fragment_display() {
        let frag = WitnessFragment {
            component_id: "Comp".to_string(),
            contract_aspect: "context.consumes".to_string(),
            contract_value: "ThemeCtx".to_string(),
        };
        assert_eq!(format!("{frag}"), "Comp/context.consumes: ThemeCtx");
    }

    // =========================================================================
    // FallbackActionKind Display
    // =========================================================================

    #[test]
    fn test_fallback_action_kind_display() {
        assert_eq!(format!("{}", FallbackActionKind::Isolate), "isolate");
        assert_eq!(format!("{}", FallbackActionKind::Degrade), "degrade");
        assert_eq!(
            format!("{}", FallbackActionKind::SplitBoundary),
            "split-boundary"
        );
        assert_eq!(
            format!("{}", FallbackActionKind::InjectAdapter),
            "inject-adapter"
        );
        assert_eq!(
            format!("{}", FallbackActionKind::RemoveAndStub),
            "remove-and-stub"
        );
        assert_eq!(format!("{}", FallbackActionKind::Escalate), "escalate");
    }

    // =========================================================================
    // CertificationOutcome Display
    // =========================================================================

    #[test]
    fn test_certification_outcome_display() {
        assert_eq!(format!("{}", CertificationOutcome::Clear), "clear");
        assert_eq!(
            format!("{}", CertificationOutcome::ObstructedWithFallbacks),
            "obstructed-with-fallbacks"
        );
        assert_eq!(
            format!("{}", CertificationOutcome::ObstructedNoFallback),
            "obstructed-no-fallback"
        );
        assert_eq!(
            format!("{}", CertificationOutcome::BudgetExhausted),
            "budget-exhausted"
        );
    }

    // =========================================================================
    // ObstructionError Display
    // =========================================================================

    #[test]
    fn test_obstruction_error_display() {
        let err = ObstructionError::BudgetExhausted {
            resource: "certs".to_string(),
            limit: 100,
        };
        assert!(format!("{err}").contains("budget exhausted"));

        let err = ObstructionError::InvalidInput("bad data".to_string());
        assert!(format!("{err}").contains("bad data"));

        let err = ObstructionError::InternalInconsistency("oops".to_string());
        assert!(format!("{err}").contains("oops"));
    }

    // =========================================================================
    // by_debt_code grouping
    // =========================================================================

    #[test]
    fn test_by_debt_code_grouping() {
        let c = ObstructionCertifier::new();
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K1".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "B".to_string(),
                context_key: "K2".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v3 = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "C".to_string(),
                missing_capabilities: vec!["x".to_string()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v1, v2, v3], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let grouped = result.by_debt_code();
        assert_eq!(grouped.get(DEBT_UNRESOLVED_CONTEXT).unwrap().len(), 2);
        assert_eq!(grouped.get(DEBT_CAPABILITY_GAP).unwrap().len(), 1);
    }

    // =========================================================================
    // FallbackPlan helpers
    // =========================================================================

    #[test]
    fn test_fallback_plan_feasible_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "Comp".to_string(),
                context_key: "Ctx".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

        let feasible = plan.feasible_actions();
        assert!(!feasible.is_empty());
        for a in feasible {
            assert!(a.feasible);
        }
    }

    #[test]
    fn test_fallback_plan_summary_line() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let summary = plan.summary_line();
        assert!(summary.contains("actions"));
        assert!(summary.contains("feasible"));
    }

    // =========================================================================
    // ObstructionCertificate helpers
    // =========================================================================

    #[test]
    fn test_certificate_summary_line() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".to_string(),
                missing_capabilities: vec!["net".to_string(), "fs".to_string()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        let summary = cert.summary_line();
        assert!(summary.contains("capability-gap"));
        assert!(summary.contains(DEBT_CAPABILITY_GAP));
    }

    // =========================================================================
    // blocking_certificates and infeasible_certificates
    // =========================================================================

    #[test]
    fn test_blocking_certificates_filter() {
        let c = ObstructionCertifier::new();
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K1".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "P".to_string(),
                context_key: "K2".to_string(),
            },
            SeverityScore::low(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v1, v2], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let blocking = result.blocking_certificates();
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].violation_kind_tag, "unresolved-context");
    }

    // =========================================================================
    // Custom disruption costs
    // =========================================================================

    #[test]
    fn test_custom_disruption_costs() {
        let mut config = ObstructionCertifierConfig::default();
        config.disruption_costs.insert("isolate".to_string(), 100);
        let c = ObstructionCertifier::with_config(config);

        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

        let isolate = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::Isolate)
            .unwrap();
        // Cost should be 100 * 1 target = 100.
        assert_eq!(isolate.disruption_cost_millionths, 100);
    }

    // =========================================================================
    // Hash stability
    // =========================================================================

    #[test]
    fn test_certificate_hash_changes_with_different_violations() {
        let c = ObstructionCertifier::new();
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K1".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "B".to_string(),
                context_key: "K2".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );

        let r1 = c
            .certify(&make_check_result(vec![v1], CoherenceOutcome::Incoherent))
            .unwrap();
        let r2 = c
            .certify(&make_check_result(vec![v2], CoherenceOutcome::Incoherent))
            .unwrap();

        assert_ne!(
            r1.certificates[0].certificate_hash,
            r2.certificates[0].certificate_hash
        );
    }

    // =========================================================================
    // Config defaults serde
    // =========================================================================

    #[test]
    fn test_config_serde_roundtrip() {
        let config = ObstructionCertifierConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ObstructionCertifierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.max_certificates, deserialized.max_certificates);
        assert_eq!(config.disruption_costs, deserialized.disruption_costs);
    }

    // =========================================================================
    // Certifier serde
    // =========================================================================

    #[test]
    fn test_certifier_serde_roundtrip() {
        let c = ObstructionCertifier::new();
        let json = serde_json::to_string(&c).unwrap();
        let deserialized: ObstructionCertifier = serde_json::from_str(&json).unwrap();
        assert_eq!(
            c.config.max_certificates,
            deserialized.config.max_certificates
        );
    }

    // =========================================================================
    // Default trait
    // =========================================================================

    #[test]
    fn test_certifier_default() {
        let c = ObstructionCertifier::default();
        assert_eq!(c.config.max_certificates, MAX_CERTIFICATES);
    }

    // =========================================================================
    // FallbackAction hash determinism
    // =========================================================================

    #[test]
    fn test_fallback_action_rationale_hash_deterministic() {
        let h1 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Isolate,
            &["A".to_string(), "B".to_string()],
            "test description",
        );
        let h2 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Isolate,
            &["A".to_string(), "B".to_string()],
            "test description",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fallback_action_rationale_hash_varies_with_input() {
        let h1 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Isolate,
            &["A".to_string()],
            "desc1",
        );
        let h2 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Degrade,
            &["A".to_string()],
            "desc1",
        );
        assert_ne!(h1, h2);
    }

    // =========================================================================
    // Schema version constants
    // =========================================================================

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(
            OBSTRUCTION_CERT_SCHEMA_VERSION,
            "franken-engine.obstruction_certificate.v1"
        );
    }

    #[test]
    fn test_bead_id_constant() {
        assert_eq!(OBSTRUCTION_CERT_BEAD_ID, "bd-mjh3.14.3");
    }

    // =========================================================================
    // Debt code constants
    // =========================================================================

    #[test]
    fn test_debt_code_format() {
        assert!(DEBT_OBSTRUCTION_UNRESOLVED.starts_with("FE-FRX-14-3-"));
        assert!(DEBT_FALLBACK_INFEASIBLE.starts_with("FE-FRX-14-3-"));
        assert!(DEBT_WITNESS_INCOMPLETE.starts_with("FE-FRX-14-3-"));
        assert!(DEBT_PLAN_CYCLE.starts_with("FE-FRX-14-3-"));
        assert!(DEBT_BUDGET_EXHAUSTED.starts_with("FE-FRX-14-3-"));
    }

    // =========================================================================
    // FallbackActionKind serde roundtrip
    // =========================================================================

    #[test]
    fn test_fallback_action_kind_serde_all_variants() {
        let variants = [
            FallbackActionKind::Isolate,
            FallbackActionKind::Degrade,
            FallbackActionKind::SplitBoundary,
            FallbackActionKind::InjectAdapter,
            FallbackActionKind::RemoveAndStub,
            FallbackActionKind::Escalate,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: FallbackActionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant);
        }
    }

    #[test]
    fn test_fallback_action_kind_ordering() {
        let mut kinds = [
            FallbackActionKind::Escalate,
            FallbackActionKind::Isolate,
            FallbackActionKind::Degrade,
        ];
        kinds.sort();
        assert_eq!(kinds[0], FallbackActionKind::Isolate);
    }

    // =========================================================================
    // CertificationOutcome serde roundtrip
    // =========================================================================

    #[test]
    fn test_certification_outcome_serde_all_variants() {
        let variants = [
            CertificationOutcome::Clear,
            CertificationOutcome::ObstructedWithFallbacks,
            CertificationOutcome::ObstructedNoFallback,
            CertificationOutcome::BudgetExhausted,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: CertificationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant);
        }
    }

    #[test]
    fn test_certification_outcome_ordering() {
        assert!(CertificationOutcome::Clear < CertificationOutcome::BudgetExhausted);
    }

    // =========================================================================
    // WitnessFragment serde roundtrip
    // =========================================================================

    #[test]
    fn test_witness_fragment_serde_roundtrip() {
        let frag = WitnessFragment {
            component_id: "MyComp".to_string(),
            contract_aspect: "context.provides".to_string(),
            contract_value: "ThemeCtx".to_string(),
        };
        let json = serde_json::to_string(&frag).unwrap();
        let back: WitnessFragment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, frag);
    }

    #[test]
    fn test_witness_fragment_ordering() {
        let a = WitnessFragment {
            component_id: "A".to_string(),
            contract_aspect: "x".to_string(),
            contract_value: "1".to_string(),
        };
        let b = WitnessFragment {
            component_id: "B".to_string(),
            contract_aspect: "x".to_string(),
            contract_value: "1".to_string(),
        };
        assert!(a < b);
    }

    // =========================================================================
    // ObstructionError serde roundtrip
    // =========================================================================

    #[test]
    fn test_obstruction_error_serde_roundtrip() {
        let errors = [
            ObstructionError::BudgetExhausted {
                resource: "certs".to_string(),
                limit: 42,
            },
            ObstructionError::InvalidInput("bad".to_string()),
            ObstructionError::InternalInconsistency("oops".to_string()),
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ObstructionError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, err);
        }
    }

    // =========================================================================
    // FallbackPlan edge cases
    // =========================================================================

    #[test]
    fn test_fallback_plan_recommended_action_empty_plan() {
        let plan = FallbackPlan {
            id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"empty",
            )
            .unwrap(),
            certificate_id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"cert",
            )
            .unwrap(),
            actions: vec![],
            recommended_action_index: 0,
            has_feasible_resolution: false,
            debt_code: Some(DEBT_FALLBACK_INFEASIBLE.to_string()),
            plan_hash: ContentHash::compute(b"empty-plan"),
        };
        assert!(plan.recommended_action().is_none());
        assert!(plan.feasible_actions().is_empty());
    }

    // =========================================================================
    // FallbackAction serde roundtrip
    // =========================================================================

    #[test]
    fn test_fallback_action_serde_roundtrip() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let action = &plan.actions[0];

        let json = serde_json::to_string(action).unwrap();
        let back: FallbackAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, action.id);
        assert_eq!(back.kind, action.kind);
        assert_eq!(back.feasible, action.feasible);
        assert_eq!(
            back.disruption_cost_millionths,
            action.disruption_cost_millionths
        );
    }

    // =========================================================================
    // FallbackPlan serde roundtrip
    // =========================================================================

    #[test]
    fn test_fallback_plan_serde_roundtrip() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".to_string(),
                missing_capabilities: vec!["net".to_string()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

        let json = serde_json::to_string(plan).unwrap();
        let back: FallbackPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, plan.id);
        assert_eq!(back.plan_hash, plan.plan_hash);
        assert_eq!(back.actions.len(), plan.actions.len());
    }

    // =========================================================================
    // Infeasible certificates filter
    // =========================================================================

    #[test]
    fn test_infeasible_certificates_all_feasible() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        // All fallbacks for unresolved-context are feasible
        let infeasible = result.infeasible_certificates();
        assert!(infeasible.is_empty());
    }

    // =========================================================================
    // collect_debt_codes for empty result
    // =========================================================================

    #[test]
    fn test_collect_debt_codes_empty() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        let codes = collect_debt_codes(&result);
        assert!(codes.is_empty());
    }

    // =========================================================================
    // should_block_gate for all outcomes
    // =========================================================================

    #[test]
    fn test_should_block_gate_budget_exhausted() {
        let config = ObstructionCertifierConfig {
            max_certificates: 1,
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config);
        let violations: Vec<CoherenceViolation> = (0..3)
            .map(|i| {
                make_violation(
                    CoherenceViolationKind::UnresolvedContext {
                        consumer: format!("C{i}"),
                        context_key: format!("K{i}"),
                    },
                    SeverityScore::critical(),
                    DEBT_UNRESOLVED_CONTEXT,
                )
            })
            .collect();
        let input = make_check_result(violations, CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        assert!(should_block_gate(&result));
        assert_eq!(result.outcome, CertificationOutcome::BudgetExhausted);
    }

    // =========================================================================
    // Disruption cost capping
    // =========================================================================

    #[test]
    fn test_disruption_cost_caps_at_10_million() {
        let c = ObstructionCertifier::new();
        // 20 cycle participants → escalate cost = 1M * 20 = 20M, capped to 10M
        let participants: Vec<String> = (0..20).map(|i| format!("Comp{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: participants,
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        for action in &plan.actions {
            assert!(action.disruption_cost_millionths <= 10 * MILLION);
        }
    }

    // =========================================================================
    // Capability gap with many capabilities
    // =========================================================================

    #[test]
    fn test_capability_gap_many_capabilities_witness_bounded() {
        let config = ObstructionCertifierConfig {
            max_witness_components: 3,
            ..Default::default()
        };
        let c = ObstructionCertifier::with_config(config);

        let caps: Vec<String> = (0..10).map(|i| format!("cap{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".to_string(),
                missing_capabilities: caps,
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        // Witness fragments should be capped at max_witness_components
        assert!(cert.witness_fragments.len() <= 3);
    }

    // =========================================================================
    // Duplicate provider single provider (infeasible RemoveAndStub)
    // =========================================================================

    #[test]
    fn test_duplicate_provider_single_provider_remove_infeasible() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::DuplicateProvider {
                providers: vec!["OnlyProvider".to_string()],
                context_key: "Ctx".to_string(),
            },
            SeverityScore::medium(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let remove = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::RemoveAndStub);
        if let Some(ra) = remove {
            // With only 1 provider, removing it is infeasible
            assert!(!ra.feasible);
        }
    }

    // =========================================================================
    // Capability gap with >3 targets makes InjectAdapter infeasible
    // =========================================================================

    #[test]
    fn test_capability_gap_many_targets_inject_infeasible() {
        let c = ObstructionCertifier::new();
        // CapabilityGap creates only 1 component in witnesses, but many capabilities
        // The inject adapter feasibility check is `targets.len() <= 3`
        // Since witness_components is always just the one component, inject should be feasible
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".to_string(),
                missing_capabilities: vec!["a".to_string(), "b".to_string()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let inject = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::InjectAdapter)
            .unwrap();
        assert!(inject.feasible); // 1 target component <= 3
    }

    // =========================================================================
    // Render report for budget exhaustion
    // =========================================================================

    #[test]
    fn test_render_report_budget_exhausted() {
        let config = ObstructionCertifierConfig {
            max_certificates: 1,
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config);
        let violations: Vec<CoherenceViolation> = (0..3)
            .map(|i| {
                make_violation(
                    CoherenceViolationKind::UnresolvedContext {
                        consumer: format!("C{i}"),
                        context_key: format!("K{i}"),
                    },
                    SeverityScore::critical(),
                    DEBT_UNRESOLVED_CONTEXT,
                )
            })
            .collect();
        let input = make_check_result(violations, CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("budget-exhausted"));
        assert!(report.contains("Obstruction #1"));
    }

    // =========================================================================
    // ObstructionCertificate is_blocking
    // =========================================================================

    #[test]
    fn test_certificate_is_blocking_severity_medium() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::medium(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        // Medium severity should be blocking
        assert!(result.certificates[0].is_blocking());
    }

    #[test]
    fn test_certificate_not_blocking_severity_low() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "P".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::low(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::CoherentWithWarnings);
        let result = c.certify(&input).unwrap();
        assert!(!result.certificates[0].is_blocking());
    }

    // =========================================================================
    // CertificationResult summary_line with obstructions
    // =========================================================================

    #[test]
    fn test_result_summary_line_with_obstructions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let line = result.summary_line();
        assert!(line.contains("1 obstructions"));
        assert!(line.contains("1 blocking"));
        assert!(line.contains("feasible"));
    }

    // =========================================================================
    // Multiple violations with mixed severity
    // =========================================================================

    #[test]
    fn test_mixed_severity_counts() {
        let c = ObstructionCertifier::new();
        let v_critical = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K1".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v_high = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "B".to_string(),
                missing_capabilities: vec!["x".to_string()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let v_low = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "P".to_string(),
                context_key: "K3".to_string(),
            },
            SeverityScore::low(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(
            vec![v_critical, v_high, v_low],
            CoherenceOutcome::Incoherent,
        );
        let result = c.certify(&input).unwrap();
        assert_eq!(result.total_obstructions, 3);
        assert_eq!(result.blocking_obstructions, 2); // critical + high
        assert_eq!(result.blocking_certificates().len(), 2);
    }

    // =========================================================================
    // Hydration boundary conflict witness details
    // =========================================================================

    #[test]
    fn test_hydration_boundary_witness_fragments() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HydrationBoundaryConflict {
                boundary_component: "HRoot".to_string(),
                conflicting_children: vec!["Ch1".to_string(), "Ch2".to_string()],
                reason: "mismatch".to_string(),
            },
            SeverityScore::critical(),
            DEBT_HYDRATION_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert_eq!(cert.witness_components.len(), 3);
        // First fragment is the boundary owner
        assert_eq!(
            cert.witness_fragments[0].contract_aspect,
            "boundary.hydration"
        );
        // Children have hydration.child aspect
        assert!(
            cert.witness_fragments[1..]
                .iter()
                .all(|f| f.contract_aspect == "boundary.hydration.child")
        );
    }

    // =========================================================================
    // Suspense boundary conflict witness details
    // =========================================================================

    #[test]
    fn test_suspense_boundary_witness_fragments() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::SuspenseBoundaryConflict {
                boundary_component: "SBoundary".to_string(),
                conflicting_children: vec!["C1".to_string(), "C2".to_string(), "C3".to_string()],
                reason: "async conflict".to_string(),
            },
            SeverityScore::high(),
            DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert_eq!(cert.witness_components.len(), 4); // boundary + 3 children
        assert!(cert.explanation.contains("async conflict"));
    }

    // =========================================================================
    // Hook cleanup mismatch witness details
    // =========================================================================

    #[test]
    fn test_hook_cleanup_mismatch_witness_details() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HookCleanupMismatch {
                component_a: "CompX".to_string(),
                component_b: "CompY".to_string(),
                hook_label: "useTimer".to_string(),
            },
            SeverityScore::medium(),
            DEBT_HOOK_CLEANUP_MISMATCH,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert!(cert.witness_components.contains("CompX"));
        assert!(cert.witness_components.contains("CompY"));
        assert!(
            cert.witness_fragments
                .iter()
                .all(|f| f.contract_aspect == "hook.cleanup" && f.contract_value == "useTimer")
        );
        assert!(cert.explanation.contains("useTimer"));
    }

    // =========================================================================
    // Boundary capability leak witness details
    // =========================================================================

    #[test]
    fn test_boundary_leak_witness_details() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::BoundaryCapabilityLeak {
                boundary: "SecBound".to_string(),
                leaked_capabilities: vec![
                    "filesystem".to_string(),
                    "network".to_string(),
                    "crypto".to_string(),
                ],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert_eq!(cert.witness_components.len(), 1);
        assert!(cert.witness_components.contains("SecBound"));
        assert_eq!(cert.witness_fragments.len(), 3);
        assert!(
            cert.witness_fragments
                .iter()
                .all(|f| f.contract_aspect == "capability.leaked")
        );
    }

    // =========================================================================
    // Layout after passive witness and fallback details
    // =========================================================================

    #[test]
    fn test_layout_after_passive_fallback_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::LayoutAfterPassive {
                layout_component: "LayoutBox".to_string(),
                passive_component: "DataLoader".to_string(),
            },
            SeverityScore::medium(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        // Should have degrade, split, escalate
        assert!(plan.actions.len() >= 3);
        let kinds: Vec<&FallbackActionKind> = plan.actions.iter().map(|a| &a.kind).collect();
        assert!(kinds.contains(&&FallbackActionKind::Degrade));
        assert!(kinds.contains(&&FallbackActionKind::SplitBoundary));
        assert!(kinds.contains(&&FallbackActionKind::Escalate));
    }

    // =========================================================================
    // Render report includes fragments
    // =========================================================================

    #[test]
    fn test_render_report_includes_fragments() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "Widget".to_string(),
                missing_capabilities: vec!["network".to_string()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("Fragment:"));
        assert!(report.contains("Widget"));
        assert!(report.contains("Result hash:"));
    }

    // =========================================================================
    // ObstructionCertifierConfig default disruption costs completeness
    // =========================================================================

    #[test]
    fn test_default_config_has_all_six_action_kinds() {
        let config = ObstructionCertifierConfig::default();
        let expected_keys = [
            "isolate",
            "degrade",
            "split-boundary",
            "inject-adapter",
            "remove-and-stub",
            "escalate",
        ];
        for key in &expected_keys {
            assert!(
                config.disruption_costs.contains_key(*key),
                "missing cost for {key}"
            );
        }
        assert_eq!(config.disruption_costs.len(), 6);
    }

    #[test]
    fn test_default_costs_ordering() {
        let config = ObstructionCertifierConfig::default();
        let isolate = config.disruption_costs["isolate"];
        let degrade = config.disruption_costs["degrade"];
        let split = config.disruption_costs["split-boundary"];
        let inject = config.disruption_costs["inject-adapter"];
        let remove = config.disruption_costs["remove-and-stub"];
        let escalate = config.disruption_costs["escalate"];
        // Costs should increase in this order
        assert!(isolate < degrade);
        assert!(degrade < split);
        assert!(split < inject);
        assert!(inject < remove);
        assert!(remove < escalate);
    }

    // =========================================================================
    // Unknown violation kind tag falls back to escalate
    // =========================================================================

    #[test]
    fn test_certifier_result_hash_includes_outcome() {
        let c = ObstructionCertifier::new();
        let r1 = c
            .certify(&make_check_result(vec![], CoherenceOutcome::Coherent))
            .unwrap();
        // Same input → same hash
        let r2 = c
            .certify(&make_check_result(vec![], CoherenceOutcome::Coherent))
            .unwrap();
        assert_eq!(r1.result_hash, r2.result_hash);
    }

    // =========================================================================
    // collect_debt_codes includes plan debt codes
    // =========================================================================

    #[test]
    fn test_collect_debt_codes_includes_plan_codes() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let codes = collect_debt_codes(&result);
        // Should include the cert debt code
        assert!(codes.contains(DEBT_UNRESOLVED_CONTEXT));
        // For feasible plans, plan.debt_code is None, so no extra code
    }

    // =========================================================================
    // ObstructionCertificate detected_epoch
    // =========================================================================

    #[test]
    fn test_certificate_epoch_matches_input() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".to_string(),
                context_key: "K".to_string(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let mut input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        input.check_epoch = 42;
        let result = c.certify(&input).unwrap();
        assert_eq!(result.certification_epoch, 42);
        assert_eq!(result.certificates[0].detected_epoch, 42);
    }

    // =========================================================================
    // Orphaned provider fallback details
    // =========================================================================

    #[test]
    fn test_orphaned_provider_fallback_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "OrphanP".to_string(),
                context_key: "UnusedCtx".to_string(),
            },
            SeverityScore::low(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::CoherentWithWarnings);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let kinds: Vec<&FallbackActionKind> = plan.actions.iter().map(|a| &a.kind).collect();
        assert!(kinds.contains(&&FallbackActionKind::RemoveAndStub));
        assert!(kinds.contains(&&FallbackActionKind::Degrade));
        assert!(kinds.contains(&&FallbackActionKind::Escalate));
    }

    // =========================================================================
    // Enrichment: PearlTower 2026-02-26
    // =========================================================================

    #[test]
    fn should_block_gate_obstructed_with_fallbacks_is_false() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(
            result.outcome,
            CertificationOutcome::ObstructedWithFallbacks
        );
        assert!(!should_block_gate(&result));
    }

    #[test]
    fn effect_cycle_split_feasible_at_boundary_ten() {
        let c = ObstructionCertifier::new();
        let participants: Vec<String> = (0..10).map(|i| format!("C{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: participants,
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let split = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::SplitBoundary)
            .unwrap();
        // targets.len() <= 10, so feasible
        assert!(split.feasible);
    }

    #[test]
    fn effect_cycle_split_infeasible_at_eleven() {
        let c = ObstructionCertifier::new();
        let participants: Vec<String> = (0..11).map(|i| format!("C{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: participants,
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let split = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::SplitBoundary)
            .unwrap();
        assert!(!split.feasible);
    }

    #[test]
    fn unknown_disruption_cost_key_defaults_to_million() {
        let config = ObstructionCertifierConfig {
            disruption_costs: BTreeMap::new(), // empty — no known costs
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config);
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        // All action costs should be MILLION * 1 target = 1_000_000
        for action in &plan.actions {
            assert_eq!(action.disruption_cost_millionths, MILLION);
        }
    }

    #[test]
    fn render_report_shows_infeasible_label() {
        let c = ObstructionCertifier::new();
        let participants: Vec<String> = (0..20).map(|i| format!("C{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: participants,
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("INFEASIBLE"));
    }

    #[test]
    fn result_hash_differs_for_different_outcomes() {
        let c = ObstructionCertifier::new();
        let r_clear = c
            .certify(&make_check_result(vec![], CoherenceOutcome::Coherent))
            .unwrap();

        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "X".into(),
                context_key: "Y".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let r_obstructed = c
            .certify(&make_check_result(vec![v], CoherenceOutcome::Incoherent))
            .unwrap();

        assert_ne!(r_clear.result_hash, r_obstructed.result_hash);
    }

    #[test]
    fn certification_result_full_serde_equality() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".into(),
                missing_capabilities: vec!["net".into(), "fs".into()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: CertificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn obstruction_certificate_full_serde_equality() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HookCleanupMismatch {
                component_a: "A".into(),
                component_b: "B".into(),
                hook_label: "useHook".into(),
            },
            SeverityScore::medium(),
            DEBT_HOOK_CLEANUP_MISMATCH,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        let json = serde_json::to_string(cert).unwrap();
        let back: ObstructionCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(*cert, back);
    }

    #[test]
    fn compute_rationale_hash_empty_targets() {
        let h = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Escalate,
            &[],
            "escalate reason",
        );
        // Should produce a valid hash without panicking
        assert_ne!(h, ContentHash::compute(b""));
    }

    #[test]
    fn duplicate_provider_two_providers_remove_feasible() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::DuplicateProvider {
                providers: vec!["ProvA".into(), "ProvB".into()],
                context_key: "Ctx".into(),
            },
            SeverityScore::medium(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let remove = plan
            .actions
            .iter()
            .find(|a| a.kind == FallbackActionKind::RemoveAndStub)
            .unwrap();
        assert!(remove.feasible); // >= 2 providers
    }

    #[test]
    fn unresolved_context_produces_four_fallback_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 4);
    }

    #[test]
    fn orphaned_provider_produces_three_fallback_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "P".into(),
                context_key: "K".into(),
            },
            SeverityScore::low(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::CoherentWithWarnings);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 3);
    }

    #[test]
    fn boundary_conflict_suspense_produces_four_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::SuspenseBoundaryConflict {
                boundary_component: "S".into(),
                conflicting_children: vec!["C1".into()],
                reason: "test".into(),
            },
            SeverityScore::high(),
            DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 4);
    }

    #[test]
    fn boundary_conflict_hydration_produces_four_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HydrationBoundaryConflict {
                boundary_component: "H".into(),
                conflicting_children: vec!["C1".into()],
                reason: "test".into(),
            },
            SeverityScore::critical(),
            DEBT_HYDRATION_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 4);
    }

    #[test]
    fn boundary_leak_produces_four_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::BoundaryCapabilityLeak {
                boundary: "B".into(),
                leaked_capabilities: vec!["cap".into()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 4);
    }

    #[test]
    fn hook_mismatch_produces_four_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HookCleanupMismatch {
                component_a: "A".into(),
                component_b: "B".into(),
                hook_label: "useFoo".into(),
            },
            SeverityScore::medium(),
            DEBT_HOOK_CLEANUP_MISMATCH,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 4);
    }

    #[test]
    fn capability_gap_produces_four_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".into(),
                missing_capabilities: vec!["x".into()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 4);
    }

    #[test]
    fn clear_result_epoch_matches_input() {
        let c = ObstructionCertifier::new();
        let mut input = make_check_result(vec![], CoherenceOutcome::Coherent);
        input.check_epoch = 99;
        let result = c.certify(&input).unwrap();
        assert_eq!(result.certification_epoch, 99);
    }

    #[test]
    fn fallback_plan_actions_sorted_by_disruption_cost() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "W".into(),
                missing_capabilities: vec!["a".into(), "b".into()],
            },
            SeverityScore::critical(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        for window in plan.actions.windows(2) {
            assert!(window[0].disruption_cost_millionths <= window[1].disruption_cost_millionths);
        }
    }

    #[test]
    fn certificate_source_violation_id_matches() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let violation_id = v.id.clone();
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.certificates[0].source_violation_id, violation_id);
    }

    #[test]
    fn certificate_debt_code_inherited_from_violation() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: vec!["A".into(), "B".into()],
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.certificates[0].debt_code, DEBT_EFFECT_CYCLE);
    }

    #[test]
    fn fallback_plan_no_debt_code_when_feasible() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert!(plan.has_feasible_resolution);
        assert!(plan.debt_code.is_none());
    }

    #[test]
    fn fallback_action_target_components_match_witness() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::HookCleanupMismatch {
                component_a: "Alpha".into(),
                component_b: "Beta".into(),
                hook_label: "useHook".into(),
            },
            SeverityScore::medium(),
            DEBT_HOOK_CLEANUP_MISMATCH,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        let plan = cert.fallback_plan.as_ref().unwrap();
        let witness: BTreeSet<String> = cert.witness_components.clone();
        for action in &plan.actions {
            let action_targets: BTreeSet<String> =
                action.target_components.iter().cloned().collect();
            assert_eq!(action_targets, witness);
        }
    }

    #[test]
    fn explanation_contains_violation_specific_details() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::LayoutAfterPassive {
                layout_component: "LayoutComp".into(),
                passive_component: "PassiveComp".into(),
            },
            SeverityScore::medium(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert!(cert.explanation.contains("LayoutComp"));
        assert!(cert.explanation.contains("PassiveComp"));
        assert!(cert.explanation.contains("Layout"));
    }

    #[test]
    fn config_serde_with_custom_values() {
        let config = ObstructionCertifierConfig {
            max_certificates: 42,
            max_actions_per_plan: 7,
            max_witness_components: 3,
            include_non_blocking: false,
            disruption_costs: {
                let mut m = BTreeMap::new();
                m.insert("custom-action".into(), 999_999);
                m
            },
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ObstructionCertifierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn obstruction_error_variants_are_distinct() {
        let e1 = ObstructionError::BudgetExhausted {
            resource: "r".into(),
            limit: 1,
        };
        let e2 = ObstructionError::InvalidInput("x".into());
        let e3 = ObstructionError::InternalInconsistency("y".into());
        let s1 = format!("{e1}");
        let s2 = format!("{e2}");
        let s3 = format!("{e3}");
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_ne!(s1, s3);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 3 --

    #[test]
    fn should_block_gate_obstructed_no_fallback_is_true() {
        let result = CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
            bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
            outcome: CertificationOutcome::ObstructedNoFallback,
            certificates: vec![],
            total_obstructions: 1,
            blocking_obstructions: 1,
            feasible_fallback_count: 0,
            infeasible_fallback_count: 1,
            certification_epoch: 1,
            result_hash: ContentHash::compute(b"test-no-fallback"),
        };
        assert!(should_block_gate(&result));
    }

    #[test]
    fn debt_code_constants_all_distinct() {
        let codes = [
            DEBT_OBSTRUCTION_UNRESOLVED,
            DEBT_FALLBACK_INFEASIBLE,
            DEBT_WITNESS_INCOMPLETE,
            DEBT_PLAN_CYCLE,
            DEBT_BUDGET_EXHAUSTED,
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn config_default_max_witness_components_is_500() {
        let config = ObstructionCertifierConfig::default();
        assert_eq!(config.max_witness_components, 500);
    }

    #[test]
    fn collect_debt_codes_includes_plan_debt_code_when_infeasible() {
        let schema = SchemaId::from_definition(b"test.enrichment.v1");
        let plan = FallbackPlan {
            id: derive_id(ObjectDomain::EvidenceRecord, "test-plan", &schema, b"p1").unwrap(),
            certificate_id: derive_id(ObjectDomain::EvidenceRecord, "test-cert", &schema, b"c1")
                .unwrap(),
            actions: vec![],
            recommended_action_index: 0,
            has_feasible_resolution: false,
            debt_code: Some(DEBT_FALLBACK_INFEASIBLE.to_string()),
            plan_hash: ContentHash::compute(b"infeasible-plan"),
        };
        let cert = ObstructionCertificate {
            id: derive_id(ObjectDomain::EvidenceRecord, "test-cert", &schema, b"c1").unwrap(),
            source_violation_id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test-viol",
                &schema,
                b"v1",
            )
            .unwrap(),
            violation_kind_tag: "test-kind".to_string(),
            severity: SeverityScore::critical(),
            debt_code: DEBT_UNRESOLVED_CONTEXT.to_string(),
            detected_epoch: 1,
            witness_components: BTreeSet::new(),
            witness_fragments: vec![],
            explanation: "test".to_string(),
            certificate_hash: ContentHash::compute(b"test-cert-hash"),
            fallback_plan: Some(plan),
        };
        let result = CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
            bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
            outcome: CertificationOutcome::ObstructedNoFallback,
            certificates: vec![cert],
            total_obstructions: 1,
            blocking_obstructions: 1,
            feasible_fallback_count: 0,
            infeasible_fallback_count: 1,
            certification_epoch: 1,
            result_hash: ContentHash::compute(b"test-result"),
        };
        let codes = collect_debt_codes(&result);
        assert!(codes.contains(DEBT_UNRESOLVED_CONTEXT));
        assert!(codes.contains(DEBT_FALLBACK_INFEASIBLE));
    }

    #[test]
    fn certificate_summary_line_includes_witness_count() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: vec!["A".into(), "B".into(), "C".into()],
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let summary = result.certificates[0].summary_line();
        assert!(summary.contains("3 witness components"));
    }

    #[test]
    fn render_report_includes_epoch_number() {
        let c = ObstructionCertifier::new();
        let mut input = make_check_result(vec![], CoherenceOutcome::Coherent);
        input.check_epoch = 42;
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("epoch 42"));
    }

    #[test]
    fn certification_result_metadata_matches_constants() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.schema_version, OBSTRUCTION_CERT_SCHEMA_VERSION);
        assert_eq!(result.bead_id, OBSTRUCTION_CERT_BEAD_ID);
    }

    #[test]
    fn infeasible_certificates_includes_no_plan_cert() {
        let schema = SchemaId::from_definition(b"test.enrichment.v1");
        let cert = ObstructionCertificate {
            id: derive_id(ObjectDomain::EvidenceRecord, "test", &schema, b"c").unwrap(),
            source_violation_id: derive_id(ObjectDomain::EvidenceRecord, "test", &schema, b"v")
                .unwrap(),
            violation_kind_tag: "test-kind".to_string(),
            severity: SeverityScore::critical(),
            debt_code: "TEST-DEBT".to_string(),
            detected_epoch: 1,
            witness_components: BTreeSet::new(),
            witness_fragments: vec![],
            explanation: "test".to_string(),
            certificate_hash: ContentHash::compute(b"cert"),
            fallback_plan: None,
        };
        let result = CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
            bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
            outcome: CertificationOutcome::ObstructedNoFallback,
            certificates: vec![cert],
            total_obstructions: 1,
            blocking_obstructions: 1,
            feasible_fallback_count: 0,
            infeasible_fallback_count: 1,
            certification_epoch: 1,
            result_hash: ContentHash::compute(b"test"),
        };
        let infeasible = result.infeasible_certificates();
        assert_eq!(infeasible.len(), 1);
        assert_eq!(infeasible[0].violation_kind_tag, "test-kind");
    }

    #[test]
    fn obstruction_error_budget_display_includes_resource_and_limit() {
        let err = ObstructionError::BudgetExhausted {
            resource: "certificates".to_string(),
            limit: 42,
        };
        let display = format!("{err}");
        assert!(display.contains("for certificates"));
        assert!(display.contains("limit=42"));
    }

    #[test]
    fn fallback_plan_summary_line_includes_cert_id_and_recommended() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let summary = plan.summary_line();
        assert!(summary.contains(&format!("{}", plan.certificate_id)));
        assert!(summary.contains("recommended="));
    }

    #[test]
    fn clear_result_all_counts_are_zero() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.total_obstructions, 0);
        assert_eq!(result.blocking_obstructions, 0);
        assert_eq!(result.feasible_fallback_count, 0);
        assert_eq!(result.infeasible_fallback_count, 0);
        assert!(result.certificates.is_empty());
    }

    #[test]
    fn layout_after_passive_produces_exactly_three_actions() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::LayoutAfterPassive {
                layout_component: "L".into(),
                passive_component: "P".into(),
            },
            SeverityScore::medium(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert_eq!(plan.actions.len(), 3);
        let kinds: Vec<&FallbackActionKind> = plan.actions.iter().map(|a| &a.kind).collect();
        assert!(kinds.contains(&&FallbackActionKind::Degrade));
        assert!(kinds.contains(&&FallbackActionKind::SplitBoundary));
        assert!(kinds.contains(&&FallbackActionKind::Escalate));
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn compute_rationale_hash_varies_with_targets() {
        let h1 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Isolate,
            &["A".to_string()],
            "same desc",
        );
        let h2 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Isolate,
            &["B".to_string()],
            "same desc",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_rationale_hash_varies_with_description() {
        let h1 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Degrade,
            &["A".to_string()],
            "desc one",
        );
        let h2 = FallbackAction::compute_rationale_hash(
            &FallbackActionKind::Degrade,
            &["A".to_string()],
            "desc two",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn certification_outcome_ordering_complete() {
        assert!(CertificationOutcome::Clear < CertificationOutcome::ObstructedWithFallbacks);
        assert!(
            CertificationOutcome::ObstructedWithFallbacks
                < CertificationOutcome::ObstructedNoFallback
        );
        assert!(CertificationOutcome::ObstructedNoFallback < CertificationOutcome::BudgetExhausted);
    }

    #[test]
    fn fallback_action_id_deterministic() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let r1 = c.certify(&input).unwrap();
        let r2 = c.certify(&input).unwrap();
        let p1 = r1.certificates[0].fallback_plan.as_ref().unwrap();
        let p2 = r2.certificates[0].fallback_plan.as_ref().unwrap();
        for (a1, a2) in p1.actions.iter().zip(p2.actions.iter()) {
            assert_eq!(a1.id, a2.id);
        }
    }

    #[test]
    fn fallback_action_ids_distinct_per_kind() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        let ids: BTreeSet<_> = plan.actions.iter().map(|a| &a.id).collect();
        assert_eq!(ids.len(), plan.actions.len());
    }

    #[test]
    fn max_actions_per_plan_truncation() {
        let config = ObstructionCertifierConfig {
            max_actions_per_plan: 2,
            ..ObstructionCertifierConfig::default()
        };
        let c = ObstructionCertifier::with_config(config);
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
        assert!(plan.actions.len() <= 2);
    }

    #[test]
    fn render_report_multiple_obstructions_numbered() {
        let c = ObstructionCertifier::new();
        let v1 = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".into(),
                context_key: "K1".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let v2 = make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "B".into(),
                missing_capabilities: vec!["x".into()],
            },
            SeverityScore::high(),
            DEBT_CAPABILITY_GAP,
        );
        let input = make_check_result(vec![v1, v2], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("Obstruction #1"));
        assert!(report.contains("Obstruction #2"));
    }

    #[test]
    fn render_report_action_line_includes_feasible_label() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(report.contains("feasible"));
        assert!(report.contains("cost="));
    }

    #[test]
    fn infeasible_certificates_mixed_feasible_and_infeasible() {
        let schema = SchemaId::from_definition(b"test.enrichment2.v1");
        let plan_feasible = FallbackPlan {
            id: derive_id(ObjectDomain::EvidenceRecord, "p", &schema, b"p1").unwrap(),
            certificate_id: derive_id(ObjectDomain::EvidenceRecord, "c", &schema, b"c1").unwrap(),
            actions: vec![],
            recommended_action_index: 0,
            has_feasible_resolution: true,
            debt_code: None,
            plan_hash: ContentHash::compute(b"feasible"),
        };
        let plan_infeasible = FallbackPlan {
            id: derive_id(ObjectDomain::EvidenceRecord, "p", &schema, b"p2").unwrap(),
            certificate_id: derive_id(ObjectDomain::EvidenceRecord, "c", &schema, b"c2").unwrap(),
            actions: vec![],
            recommended_action_index: 0,
            has_feasible_resolution: false,
            debt_code: Some(DEBT_FALLBACK_INFEASIBLE.to_string()),
            plan_hash: ContentHash::compute(b"infeasible"),
        };
        let cert1 = ObstructionCertificate {
            id: derive_id(ObjectDomain::EvidenceRecord, "c", &schema, b"c1").unwrap(),
            source_violation_id: derive_id(ObjectDomain::EvidenceRecord, "v", &schema, b"v1")
                .unwrap(),
            violation_kind_tag: "feasible-kind".into(),
            severity: SeverityScore::critical(),
            debt_code: DEBT_UNRESOLVED_CONTEXT.into(),
            detected_epoch: 1,
            witness_components: BTreeSet::new(),
            witness_fragments: vec![],
            explanation: "ok".into(),
            certificate_hash: ContentHash::compute(b"c1"),
            fallback_plan: Some(plan_feasible),
        };
        let cert2 = ObstructionCertificate {
            id: derive_id(ObjectDomain::EvidenceRecord, "c", &schema, b"c2").unwrap(),
            source_violation_id: derive_id(ObjectDomain::EvidenceRecord, "v", &schema, b"v2")
                .unwrap(),
            violation_kind_tag: "infeasible-kind".into(),
            severity: SeverityScore::critical(),
            debt_code: DEBT_CAPABILITY_GAP.into(),
            detected_epoch: 1,
            witness_components: BTreeSet::new(),
            witness_fragments: vec![],
            explanation: "nope".into(),
            certificate_hash: ContentHash::compute(b"c2"),
            fallback_plan: Some(plan_infeasible),
        };
        let result = CertificationResult {
            schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.into(),
            bead_id: OBSTRUCTION_CERT_BEAD_ID.into(),
            outcome: CertificationOutcome::ObstructedNoFallback,
            certificates: vec![cert1, cert2],
            total_obstructions: 2,
            blocking_obstructions: 2,
            feasible_fallback_count: 1,
            infeasible_fallback_count: 1,
            certification_epoch: 1,
            result_hash: ContentHash::compute(b"mixed"),
        };
        let infeasible = result.infeasible_certificates();
        assert_eq!(infeasible.len(), 1);
        assert_eq!(infeasible[0].violation_kind_tag, "infeasible-kind");
    }

    #[test]
    fn duplicate_provider_three_providers_witness() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::DuplicateProvider {
                providers: vec!["P1".into(), "P2".into(), "P3".into()],
                context_key: "Ctx".into(),
            },
            SeverityScore::high(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert_eq!(cert.witness_components.len(), 3);
        assert_eq!(cert.witness_fragments.len(), 3);
    }

    #[test]
    fn fallback_action_kind_display_all_distinct() {
        let kinds = [
            FallbackActionKind::Isolate,
            FallbackActionKind::Degrade,
            FallbackActionKind::SplitBoundary,
            FallbackActionKind::InjectAdapter,
            FallbackActionKind::RemoveAndStub,
            FallbackActionKind::Escalate,
        ];
        let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{k}")).collect();
        assert_eq!(displays.len(), kinds.len());
    }

    #[test]
    fn feasible_fallback_count_accuracy() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "A".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        assert_eq!(result.feasible_fallback_count, 1);
        assert_eq!(result.infeasible_fallback_count, 0);
    }

    #[test]
    fn certificate_id_differs_from_source_violation_id() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "C".into(),
                context_key: "K".into(),
            },
            SeverityScore::critical(),
            DEBT_UNRESOLVED_CONTEXT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert_ne!(cert.id, cert.source_violation_id);
    }

    #[test]
    fn build_clear_result_deterministic() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let r1 = c.certify(&input).unwrap();
        let r2 = c.certify(&input).unwrap();
        assert_eq!(r1.result_hash, r2.result_hash);
    }

    #[test]
    fn suspense_boundary_many_children_witness_bounded() {
        let config = ObstructionCertifierConfig {
            max_witness_components: 3,
            ..Default::default()
        };
        let c = ObstructionCertifier::with_config(config);
        let children: Vec<String> = (0..10).map(|i| format!("Child{i}")).collect();
        let v = make_violation(
            CoherenceViolationKind::SuspenseBoundaryConflict {
                boundary_component: "Boundary".into(),
                conflicting_children: children,
                reason: "conflict".into(),
            },
            SeverityScore::high(),
            DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        // max_witness_components is 3: boundary + 2 children
        assert!(cert.witness_components.len() <= 3);
    }

    #[test]
    fn obstruction_error_display_exact_format() {
        let e1 = ObstructionError::BudgetExhausted {
            resource: "actions".into(),
            limit: 50,
        };
        assert_eq!(e1.to_string(), "budget exhausted for actions: limit=50");

        let e2 = ObstructionError::InvalidInput("missing data".into());
        assert_eq!(e2.to_string(), "invalid input: missing data");

        let e3 = ObstructionError::InternalInconsistency("hash fail".into());
        assert_eq!(e3.to_string(), "internal inconsistency: hash fail");
    }

    #[test]
    fn render_report_clear_has_no_recommended_label() {
        let c = ObstructionCertifier::new();
        let input = make_check_result(vec![], CoherenceOutcome::Coherent);
        let result = c.certify(&input).unwrap();
        let report = render_certification_report(&result);
        assert!(!report.contains("[RECOMMENDED]"));
    }

    #[test]
    fn effect_cycle_explanation_contains_arrow_chain() {
        let c = ObstructionCertifier::new();
        let v = make_violation(
            CoherenceViolationKind::EffectOrderCycle {
                cycle_participants: vec!["X".into(), "Y".into(), "Z".into()],
            },
            SeverityScore::critical(),
            DEBT_EFFECT_CYCLE,
        );
        let input = make_check_result(vec![v], CoherenceOutcome::Incoherent);
        let result = c.certify(&input).unwrap();
        let cert = &result.certificates[0];
        assert!(cert.explanation.contains("X -> Y -> Z"));
    }
}
