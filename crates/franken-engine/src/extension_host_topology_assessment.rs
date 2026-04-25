#![forbid(unsafe_code)]
//! Extension-host control-plane topology promotion assessment.
//!
//! Bead: bd-3nr.1.6 [10.13X.F]. This is an assessment contract, not the
//! topology migration itself.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

pub const COMPONENT: &str = "extension_host_topology_assessment";
pub const BEAD_ID: &str = "bd-3nr.1.6";
pub const POLICY_ID: &str = "policy-extension-host-topology-assessment-v1";
pub const SCHEMA_VERSION: &str = "franken-engine.extension-host-topology-assessment.v1";

pub const FIXED_POINT_SCALE_MILLIONTHS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyPromotionDecision {
    NoPromotion,
    TargetedPromotion,
    BroaderPromotion,
}

impl TopologyPromotionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoPromotion => "no_promotion",
            Self::TargetedPromotion => "targeted_promotion",
            Self::BroaderPromotion => "broader_promotion",
        }
    }
}

impl fmt::Display for TopologyPromotionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologySeamId {
    ExtensionLifecycleManager,
    ExecutionOrchestrator,
    DelegateCellFactory,
    FrankenlabReleaseGate,
    ControlPlanePolicyDiagnostics,
    LabRuntime,
}

impl TopologySeamId {
    pub const ALL: [Self; 6] = [
        Self::ExtensionLifecycleManager,
        Self::ExecutionOrchestrator,
        Self::DelegateCellFactory,
        Self::FrankenlabReleaseGate,
        Self::ControlPlanePolicyDiagnostics,
        Self::LabRuntime,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExtensionLifecycleManager => "extension_lifecycle_manager",
            Self::ExecutionOrchestrator => "execution_orchestrator",
            Self::DelegateCellFactory => "delegate_cell_factory",
            Self::FrankenlabReleaseGate => "frankenlab_release_gate",
            Self::ControlPlanePolicyDiagnostics => "control_plane_policy_diagnostics",
            Self::LabRuntime => "lab_runtime",
        }
    }
}

impl fmt::Display for TopologySeamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionTrigger {
    LongLivedNamedWorker,
    ManualRestartPolicy,
    SingleOwnerState,
    AdHocRequestReply,
    ShutdownRecoveryComplexity,
    DiagnosticPolicyComplexity,
}

impl PromotionTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongLivedNamedWorker => "long_lived_named_worker",
            Self::ManualRestartPolicy => "manual_restart_policy",
            Self::SingleOwnerState => "single_owner_state",
            Self::AdHocRequestReply => "ad_hoc_request_reply",
            Self::ShutdownRecoveryComplexity => "shutdown_recovery_complexity",
            Self::DiagnosticPolicyComplexity => "diagnostic_policy_complexity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerDisposition {
    NotPresent,
    PresentManaged,
    PromotionCandidate,
    BlockedByPrerequisite,
}

impl TriggerDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotPresent => "not_present",
            Self::PresentManaged => "present_managed",
            Self::PromotionCandidate => "promotion_candidate",
            Self::BlockedByPrerequisite => "blocked_by_prerequisite",
        }
    }

    pub fn is_candidate(self) -> bool {
        matches!(self, Self::PromotionCandidate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerAssessment {
    pub trigger: PromotionTrigger,
    pub disposition: TriggerDisposition,
    pub evidence: String,
    pub expected_benefit_micros: u64,
    pub migration_risk_micros: u64,
    pub rollback_cost_micros: u64,
    pub diagnostic_simplification_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamAssessment {
    pub seam_id: TopologySeamId,
    pub source_files: Vec<String>,
    pub decision: TopologyPromotionDecision,
    pub rationale: String,
    pub trigger_assessments: Vec<TriggerAssessment>,
    pub required_upstream_primitives: Vec<String>,
    pub expected_benefits: Vec<String>,
    pub migration_risks: Vec<String>,
    pub rollback_plan: String,
    pub operator_diagnostic_benefit: String,
    pub implementation_order: Vec<String>,
}

impl SeamAssessment {
    pub fn candidate_trigger_count(&self) -> usize {
        self.trigger_assessments
            .iter()
            .filter(|assessment| assessment.disposition.is_candidate())
            .count()
    }

    pub fn total_expected_benefit_micros(&self) -> u64 {
        self.trigger_assessments
            .iter()
            .map(|assessment| assessment.expected_benefit_micros)
            .sum()
    }

    pub fn max_migration_risk_micros(&self) -> u64 {
        self.trigger_assessments
            .iter()
            .map(|assessment| assessment.migration_risk_micros)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyPromotionSummary {
    pub total_seams: usize,
    pub no_promotion_count: usize,
    pub targeted_promotion_count: usize,
    pub broader_promotion_count: usize,
    pub promotion_candidate_trigger_count: usize,
    pub total_expected_benefit_micros: u64,
    pub max_migration_risk_micros: u64,
    pub decision_counts: BTreeMap<String, usize>,
}

impl TopologyPromotionSummary {
    pub fn from_seams(seams: &[SeamAssessment]) -> Self {
        let mut decision_counts = BTreeMap::new();
        for decision in [
            TopologyPromotionDecision::NoPromotion,
            TopologyPromotionDecision::TargetedPromotion,
            TopologyPromotionDecision::BroaderPromotion,
        ] {
            decision_counts.insert(decision.as_str().to_string(), 0);
        }

        let mut no_promotion_count = 0;
        let mut targeted_promotion_count = 0;
        let mut broader_promotion_count = 0;
        let mut promotion_candidate_trigger_count = 0;
        let mut total_expected_benefit_micros: u64 = 0;
        let mut max_migration_risk_micros = 0;

        for seam in seams {
            *decision_counts
                .entry(seam.decision.as_str().to_string())
                .or_insert(0) += 1;
            match seam.decision {
                TopologyPromotionDecision::NoPromotion => no_promotion_count += 1,
                TopologyPromotionDecision::TargetedPromotion => targeted_promotion_count += 1,
                TopologyPromotionDecision::BroaderPromotion => broader_promotion_count += 1,
            }
            promotion_candidate_trigger_count += seam.candidate_trigger_count();
            total_expected_benefit_micros =
                total_expected_benefit_micros.saturating_add(seam.total_expected_benefit_micros());
            max_migration_risk_micros =
                max_migration_risk_micros.max(seam.max_migration_risk_micros());
        }

        Self {
            total_seams: seams.len(),
            no_promotion_count,
            targeted_promotion_count,
            broader_promotion_count,
            promotion_candidate_trigger_count,
            total_expected_benefit_micros,
            max_migration_risk_micros,
            decision_counts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyPromotionAssessment {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub policy_id: String,
    pub decision: TopologyPromotionDecision,
    pub rationale: String,
    pub fail_closed: bool,
    pub required_prerequisites: Vec<String>,
    pub generated_from: Vec<String>,
    pub seams: Vec<SeamAssessment>,
    pub summary: TopologyPromotionSummary,
    pub required_artifacts: Vec<String>,
    pub verification_commands: Vec<String>,
    pub content_hash: String,
}

impl TopologyPromotionAssessment {
    pub fn targeted_seams(&self) -> Vec<&SeamAssessment> {
        self.seams
            .iter()
            .filter(|seam| seam.decision == TopologyPromotionDecision::TargetedPromotion)
            .collect()
    }

    pub fn has_broader_promotion(&self) -> bool {
        self.seams
            .iter()
            .any(|seam| seam.decision == TopologyPromotionDecision::BroaderPromotion)
    }

    pub fn compute_content_hash(&self) -> String {
        // Create a temporary structure for hashing without the content_hash field
        // to avoid recursive dependencies
        #[derive(Serialize)]
        struct HashableAssessment<'a> {
            schema_version: &'a str,
            bead_id: &'a str,
            component: &'a str,
            policy_id: &'a str,
            decision: &'a TopologyPromotionDecision,
            rationale: &'a str,
            fail_closed: bool,
            required_prerequisites: &'a Vec<String>,
            generated_from: &'a Vec<String>,
            seams: &'a Vec<SeamAssessment>,
            summary: &'a TopologyPromotionSummary,
            required_artifacts: &'a Vec<String>,
            verification_commands: &'a Vec<String>,
        }

        let hashable = HashableAssessment {
            schema_version: &self.schema_version,
            bead_id: &self.bead_id,
            component: &self.component,
            policy_id: &self.policy_id,
            decision: &self.decision,
            rationale: &self.rationale,
            fail_closed: self.fail_closed,
            required_prerequisites: &self.required_prerequisites,
            generated_from: &self.generated_from,
            seams: &self.seams,
            summary: &self.summary,
            required_artifacts: &self.required_artifacts,
            verification_commands: &self.verification_commands,
        };

        // Use canonical JSON serialization to avoid boundary collisions
        let canonical_bytes = match serde_json::to_vec(&hashable) {
            Ok(bytes) => bytes,
            Err(_) => return "fallback_hash_serialization_failed".to_string(),
        };

        ContentHash::compute(&canonical_bytes).to_hex()
    }
}

pub fn build_topology_promotion_assessment() -> TopologyPromotionAssessment {
    let seams = vec![
        extension_lifecycle_manager_seam(),
        execution_orchestrator_seam(),
        delegate_cell_factory_seam(),
        frankenlab_release_gate_seam(),
        control_plane_policy_diagnostics_seam(),
        lab_runtime_seam(),
    ];
    let summary = TopologyPromotionSummary::from_seams(&seams);
    let decision = if summary.broader_promotion_count > 0 {
        TopologyPromotionDecision::BroaderPromotion
    } else if summary.targeted_promotion_count > 0 {
        TopologyPromotionDecision::TargetedPromotion
    } else {
        TopologyPromotionDecision::NoPromotion
    };

    let mut assessment = TopologyPromotionAssessment {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        decision,
        rationale: "Targeted promotion is warranted only at the extension lifecycle manager seam; broader AppSpec/actor promotion would add topology before the remaining seams show restart or request-reply pressure.".to_string(),
        fail_closed: false,
        required_prerequisites: vec![
            "bd-3nr.1.1.1 control-plane mock seam inventory closed".to_string(),
            "bd-3nr.1.1.2 local-vs-upstream frankenlab gap matrix closed".to_string(),
            "bd-3nr.1.3.2 outcome/capability narrowing contract closed".to_string(),
            "bd-3nr.1.3.3 operator diagnostic mapping contract closed".to_string(),
        ],
        generated_from: vec![
            "crates/franken-engine/src/extension_lifecycle_manager.rs".to_string(),
            "crates/franken-engine/src/execution_orchestrator.rs".to_string(),
            "crates/franken-extension-host/src/lib.rs".to_string(),
            "crates/franken-engine/src/frankenlab_release_gate.rs".to_string(),
            "crates/franken-engine/src/control_plane_policy_diagnostics.rs".to_string(),
            "crates/franken-engine/src/lab_runtime.rs".to_string(),
        ],
        seams,
        summary,
        required_artifacts: vec![
            "topology_promotion_assessment.json".to_string(),
            "run_manifest.json".to_string(),
            "events.jsonl".to_string(),
            "commands.txt".to_string(),
            "trace_ids.json".to_string(),
            "step_logs/step_001_generate.log".to_string(),
            "summary.md".to_string(),
            "env.json".to_string(),
            "repro.lock".to_string(),
        ],
        verification_commands: vec![
            "rch exec -- cargo check -p frankenengine-engine --lib --bin franken_extension_host_topology_assessment".to_string(),
            "rch exec 'env RUSTFLAGS=\"-C linker=cc\" cargo test -p frankenengine-engine --test extension_host_topology_assessment_cli'".to_string(),
            "rch exec -- cargo clippy -p frankenengine-engine --lib --bin franken_extension_host_topology_assessment --test extension_host_topology_assessment_cli -- -D warnings".to_string(),
        ],
        content_hash: String::new(),
    };
    assessment.content_hash = assessment.compute_content_hash();
    assessment
}

pub fn render_operator_rationale(assessment: &TopologyPromotionAssessment) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# Extension-host topology promotion assessment").expect("write summary");
    writeln!(&mut out).expect("write summary");
    writeln!(&mut out, "- Bead: `{}`", assessment.bead_id).expect("write summary");
    writeln!(&mut out, "- Decision: `{}`", assessment.decision).expect("write summary");
    writeln!(&mut out, "- Content hash: `{}`", assessment.content_hash).expect("write summary");
    writeln!(&mut out).expect("write summary");
    writeln!(&mut out, "{}", assessment.rationale).expect("write summary");
    writeln!(&mut out).expect("write summary");
    writeln!(&mut out, "## Seam decisions").expect("write summary");
    for seam in &assessment.seams {
        writeln!(&mut out, "- `{}`: `{}`", seam.seam_id, seam.decision).expect("write summary");
        writeln!(&mut out, "  - {}", seam.rationale).expect("write summary");
        writeln!(
            &mut out,
            "  - Operator diagnostic benefit: {}",
            seam.operator_diagnostic_benefit
        )
        .expect("write summary");
    }
    out
}

fn trigger(
    trigger: PromotionTrigger,
    disposition: TriggerDisposition,
    evidence: &str,
    expected_benefit_micros: u64,
    migration_risk_micros: u64,
    rollback_cost_micros: u64,
    diagnostic_simplification_micros: u64,
) -> TriggerAssessment {
    TriggerAssessment {
        trigger,
        disposition,
        evidence: evidence.to_string(),
        expected_benefit_micros,
        migration_risk_micros,
        rollback_cost_micros,
        diagnostic_simplification_micros,
    }
}

fn extension_lifecycle_manager_seam() -> SeamAssessment {
    SeamAssessment {
        seam_id: TopologySeamId::ExtensionLifecycleManager,
        source_files: vec!["crates/franken-engine/src/extension_lifecycle_manager.rs".to_string()],
        decision: TopologyPromotionDecision::TargetedPromotion,
        rationale: "This seam already owns named extension records, state transitions, cooperative shutdown, and recovery/quarantine outcomes. A narrow supervised-service boundary would clarify ownership without moving parser or VM hot paths.".to_string(),
        trigger_assessments: vec![
            trigger(PromotionTrigger::LongLivedNamedWorker, TriggerDisposition::PromotionCandidate, "Extension records persist across load/start/suspend/resume/terminate transitions.", 760_000, 260_000, 220_000, 640_000),
            trigger(PromotionTrigger::ManualRestartPolicy, TriggerDisposition::PresentManaged, "The current state machine has failure transitions and quarantine, but no automatic restart loop is currently required.", 300_000, 230_000, 120_000, 260_000),
            trigger(PromotionTrigger::SingleOwnerState, TriggerDisposition::PromotionCandidate, "A deterministic BTreeMap of extension records is naturally single-owner state.", 720_000, 240_000, 180_000, 560_000),
            trigger(PromotionTrigger::ShutdownRecoveryComplexity, TriggerDisposition::PromotionCandidate, "Cooperative shutdown has grace expiry, force/quarantine branches, and structured lifecycle events.", 800_000, 300_000, 220_000, 700_000),
        ],
        required_upstream_primitives: vec![
            "franken-kernel Cx propagation for lifecycle calls".to_string(),
            "supervision::SupervisorTree restart-budget semantics".to_string(),
            "frankenlab lifecycle oracle replay for shutdown/quarantine scenarios".to_string(),
        ],
        expected_benefits: vec![
            "single-owner lifecycle state instead of implicit manager-as-service topology".to_string(),
            "restart/quarantine policy encoded as supervision evidence".to_string(),
            "operator diagnostics can point at lifecycle worker state and last transition".to_string(),
        ],
        migration_risks: vec![
            "must not introduce async/runtime dependencies into VM execution".to_string(),
            "must preserve deterministic BTreeMap ordering in replay artifacts".to_string(),
            "must keep existing lifecycle transition guards as the source of truth".to_string(),
        ],
        rollback_plan: "Keep ExtensionLifecycleManager as the public API and gate the supervised adapter behind an internal constructor; rollback removes the adapter and preserves the existing state machine.".to_string(),
        operator_diagnostic_benefit: "targeted promotion gives operators a named lifecycle service, restart budget, last-transition evidence, and replay pointer for shutdown/quarantine incidents".to_string(),
        implementation_order: vec![
            "add an internal lifecycle-supervision adapter around ExtensionLifecycleManager".to_string(),
            "emit supervision events with trace_id, component, event, outcome, error_code, seed, scenario_id".to_string(),
            "prove parity against existing lifecycle-manager tests and frankenlab lifecycle scenarios".to_string(),
            "only then expose the adapter to release-gate/operator bundle code".to_string(),
        ],
    }
}

fn execution_orchestrator_seam() -> SeamAssessment {
    no_promotion_seam(
        TopologySeamId::ExecutionOrchestrator,
        vec!["crates/franken-engine/src/execution_orchestrator.rs"],
        "The orchestrator is a deterministic composition boundary for policy, evidence, and execution-cell calls; it does not currently show restart-loop or mailbox semantics that would justify actor promotion.",
        vec![
            trigger(
                PromotionTrigger::AdHocRequestReply,
                TriggerDisposition::NotPresent,
                "Calls remain direct function composition with structured return values.",
                120_000,
                360_000,
                250_000,
                100_000,
            ),
            trigger(
                PromotionTrigger::DiagnosticPolicyComplexity,
                TriggerDisposition::PresentManaged,
                "Policy diagnostics are already delegated to explicit diagnostic contracts.",
                180_000,
                320_000,
                220_000,
                220_000,
            ),
        ],
    )
}

fn delegate_cell_factory_seam() -> SeamAssessment {
    no_promotion_seam(
        TopologySeamId::DelegateCellFactory,
        vec!["crates/franken-extension-host/src/lib.rs"],
        "DelegateCellFactory is a construction/policy path, not a long-lived worker. Promotion would obscure the existing manifest/policy validation path without a clear operator benefit.",
        vec![
            trigger(
                PromotionTrigger::LongLivedNamedWorker,
                TriggerDisposition::NotPresent,
                "The factory creates cells; it is not itself a supervised process.",
                90_000,
                300_000,
                180_000,
                80_000,
            ),
            trigger(
                PromotionTrigger::SingleOwnerState,
                TriggerDisposition::PresentManaged,
                "Ownership belongs to created cells and manifests, not factory-local mutable state.",
                120_000,
                260_000,
                160_000,
                100_000,
            ),
        ],
    )
}

fn frankenlab_release_gate_seam() -> SeamAssessment {
    no_promotion_seam(
        TopologySeamId::FrankenlabReleaseGate,
        vec!["crates/franken-engine/src/frankenlab_release_gate.rs"],
        "The release gate is a batch evaluator with fail-closed artifacts. It benefits more from oracle coverage than from a long-lived supervision topology.",
        vec![
            trigger(
                PromotionTrigger::ManualRestartPolicy,
                TriggerDisposition::NotPresent,
                "Gate failures block release; they are not restarted as services.",
                100_000,
                280_000,
                150_000,
                140_000,
            ),
            trigger(
                PromotionTrigger::DiagnosticPolicyComplexity,
                TriggerDisposition::PresentManaged,
                "Gate reports already encode fail/pass/infrastructure/timeout verdicts.",
                240_000,
                260_000,
                150_000,
                300_000,
            ),
        ],
    )
}

fn control_plane_policy_diagnostics_seam() -> SeamAssessment {
    no_promotion_seam(
        TopologySeamId::ControlPlanePolicyDiagnostics,
        vec!["crates/franken-engine/src/control_plane_policy_diagnostics.rs"],
        "The diagnostics surface is a pure contract/emitter. Turning it into an actor would add lifecycle state where deterministic artifact generation is the simpler invariant.",
        vec![
            trigger(
                PromotionTrigger::DiagnosticPolicyComplexity,
                TriggerDisposition::PresentManaged,
                "The mapping contract already preserves rich semantics until the intended user/operator edge.",
                260_000,
                220_000,
                140_000,
                420_000,
            ),
            trigger(
                PromotionTrigger::AdHocRequestReply,
                TriggerDisposition::NotPresent,
                "No mailbox/request protocol exists; outputs are deterministic reports.",
                80_000,
                240_000,
                120_000,
                90_000,
            ),
        ],
    )
}

fn lab_runtime_seam() -> SeamAssessment {
    no_promotion_seam(
        TopologySeamId::LabRuntime,
        vec!["crates/franken-engine/src/lab_runtime.rs"],
        "The lab runtime intentionally simulates scheduling under deterministic virtual time. Promoting it into production supervision would blur test harness and product topology boundaries.",
        vec![
            trigger(
                PromotionTrigger::LongLivedNamedWorker,
                TriggerDisposition::BlockedByPrerequisite,
                "Lab tasks are deterministic test entities, not production workers.",
                220_000,
                400_000,
                260_000,
                180_000,
            ),
            trigger(
                PromotionTrigger::ShutdownRecoveryComplexity,
                TriggerDisposition::PresentManaged,
                "Fault and cancellation injection are harness features covered by frankenlab migration beads.",
                260_000,
                360_000,
                220_000,
                240_000,
            ),
        ],
    )
}

fn no_promotion_seam(
    seam_id: TopologySeamId,
    source_files: Vec<&str>,
    rationale: &str,
    trigger_assessments: Vec<TriggerAssessment>,
) -> SeamAssessment {
    SeamAssessment {
        seam_id,
        source_files: source_files.into_iter().map(str::to_string).collect(),
        decision: TopologyPromotionDecision::NoPromotion,
        rationale: rationale.to_string(),
        trigger_assessments,
        required_upstream_primitives: Vec::new(),
        expected_benefits: vec!["preserve current direct topology and artifact determinism".to_string()],
        migration_risks: vec![
            "promotion would add lifecycle semantics without enough trigger evidence".to_string(),
        ],
        rollback_plan: "No migration; keep the existing direct surface and reassess only if future beads add persistent worker or restart-loop pressure.".to_string(),
        operator_diagnostic_benefit: "no topology change; operators continue using the existing report/replay artifacts".to_string(),
        implementation_order: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_targets_only_lifecycle_manager() {
        let assessment = build_topology_promotion_assessment();
        assert_eq!(
            assessment.decision,
            TopologyPromotionDecision::TargetedPromotion
        );
        assert!(!assessment.has_broader_promotion());
        let targeted = assessment.targeted_seams();
        assert_eq!(targeted.len(), 1);
        assert_eq!(
            targeted[0].seam_id,
            TopologySeamId::ExtensionLifecycleManager
        );
        assert!(!targeted[0].required_upstream_primitives.is_empty());
        assert!(!targeted[0].implementation_order.is_empty());
    }

    #[test]
    fn summary_counts_are_self_consistent() {
        let assessment = build_topology_promotion_assessment();
        assert_eq!(assessment.summary.total_seams, TopologySeamId::ALL.len());
        assert_eq!(
            assessment.summary.no_promotion_count
                + assessment.summary.targeted_promotion_count
                + assessment.summary.broader_promotion_count,
            assessment.summary.total_seams
        );
        assert_eq!(
            assessment.summary.decision_counts
                [TopologyPromotionDecision::TargetedPromotion.as_str()],
            1
        );
        assert!(assessment.summary.promotion_candidate_trigger_count >= 3);
    }

    #[test]
    fn content_hash_is_stable_and_rationale_names_no_broad_promotion() {
        let first = build_topology_promotion_assessment();
        let second = build_topology_promotion_assessment();
        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(first.content_hash.len(), 64);
        let summary = render_operator_rationale(&first);
        assert!(summary.contains("targeted_promotion"));
        assert!(summary.contains("extension_lifecycle_manager"));
        assert!(summary.contains("broader AppSpec/actor promotion"));
    }

    #[test]
    fn all_trigger_assessments_use_fixed_point_millionths() {
        let assessment = build_topology_promotion_assessment();
        for seam in assessment.seams {
            for trigger in seam.trigger_assessments {
                assert!(trigger.expected_benefit_micros <= FIXED_POINT_SCALE_MILLIONTHS);
                assert!(trigger.migration_risk_micros <= FIXED_POINT_SCALE_MILLIONTHS);
                assert!(trigger.rollback_cost_micros <= FIXED_POINT_SCALE_MILLIONTHS);
                assert!(trigger.diagnostic_simplification_micros <= FIXED_POINT_SCALE_MILLIONTHS);
            }
        }
    }
}
