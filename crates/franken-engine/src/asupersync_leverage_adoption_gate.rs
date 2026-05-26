#![forbid(unsafe_code)]
//! Final Asupersync leverage adoption gate.
//!
//! Bead: bd-3nr.1.7 [10.13X.G]. This aggregates the correction-wave evidence
//! into a deterministic operator stop/go contract.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::extension_host_topology_assessment::{
    TopologyPromotionAssessment, TopologyPromotionDecision, build_topology_promotion_assessment,
};

pub const COMPONENT: &str = "asupersync_leverage_adoption_gate";
pub const BEAD_ID: &str = "bd-3nr.1.7";
pub const POLICY_ID: &str = "policy-asupersync-leverage-adoption-gate-v1";
pub const SCHEMA_VERSION: &str = "franken-engine.asupersync-leverage-adoption-gate.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionGateVerdict {
    Stop,
    GoTargeted,
    GoBroader,
}

impl AdoptionGateVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::GoTargeted => "go_targeted",
            Self::GoBroader => "go_broader",
        }
    }
}

impl fmt::Display for AdoptionGateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateArtifactStatus {
    Satisfied,
    Outstanding,
}

impl GateArtifactStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Outstanding => "outstanding",
        }
    }

    pub const fn is_satisfied(self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandatoryChildArtifact {
    pub bead_id: String,
    pub title: String,
    pub artifact_id: String,
    pub artifact_path_hint: String,
    pub status: GateArtifactStatus,
    pub stop_go_code: String,
    pub user_impact: String,
    pub operator_impact: String,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticContractEntry {
    pub diagnostic_id: String,
    pub source_bead_id: String,
    pub audience: String,
    pub artifact_id: String,
    pub stable_fields: Vec<String>,
    pub replay_signal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptionGateSummary {
    pub mandatory_child_count: usize,
    pub satisfied_child_count: usize,
    pub outstanding_child_count: usize,
    pub diagnostic_contract_count: usize,
    pub decision_counts: BTreeMap<String, usize>,
}

impl AdoptionGateSummary {
    pub fn from_parts(
        mandatory_child_artifacts: &[MandatoryChildArtifact],
        diagnostic_contract_index: &[DiagnosticContractEntry],
        topology_decision: TopologyPromotionDecision,
    ) -> Self {
        let mut decision_counts = BTreeMap::new();
        for key in ["no_promotion", "targeted_promotion", "broader_promotion"] {
            decision_counts.insert(key.to_string(), 0);
        }
        *decision_counts
            .entry(topology_decision.as_str().to_string())
            .or_insert(0) += 1;

        let satisfied_child_count = mandatory_child_artifacts
            .iter()
            .filter(|artifact| artifact.status.is_satisfied())
            .count();
        let mandatory_child_count = mandatory_child_artifacts.len();
        Self {
            mandatory_child_count,
            satisfied_child_count,
            outstanding_child_count: mandatory_child_count.saturating_sub(satisfied_child_count),
            diagnostic_contract_count: diagnostic_contract_index.len(),
            decision_counts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsupersyncLeverageAdoptionGate {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub policy_id: String,
    pub verdict: AdoptionGateVerdict,
    pub stop_go_code: String,
    pub topology_decision: TopologyPromotionDecision,
    pub topology_assessment_hash: String,
    pub topology_assessment_artifact: String,
    pub summary: AdoptionGateSummary,
    pub mandatory_child_artifacts: Vec<MandatoryChildArtifact>,
    pub diagnostic_contract_index: Vec<DiagnosticContractEntry>,
    pub outstanding_risk_ids: Vec<String>,
    pub user_impact: String,
    pub operator_impact: String,
    pub next_action: String,
    pub required_artifacts: Vec<String>,
    pub verification_commands: Vec<String>,
    pub content_hash: String,
}

impl AsupersyncLeverageAdoptionGate {
    pub fn is_go(&self) -> bool {
        matches!(
            self.verdict,
            AdoptionGateVerdict::GoTargeted | AdoptionGateVerdict::GoBroader
        )
    }

    pub fn has_outstanding_child_artifacts(&self) -> bool {
        self.summary.outstanding_child_count > 0 || !self.outstanding_risk_ids.is_empty()
    }
}

pub fn build_asupersync_leverage_adoption_gate() -> Result<AsupersyncLeverageAdoptionGate, String> {
    let topology = build_topology_promotion_assessment();
    build_asupersync_leverage_adoption_gate_from_topology(topology)
}

pub fn build_asupersync_leverage_adoption_gate_from_topology(
    topology: TopologyPromotionAssessment,
) -> Result<AsupersyncLeverageAdoptionGate, String> {
    let mandatory_child_artifacts = mandatory_child_artifacts(&topology);
    let diagnostic_contract_index = diagnostic_contract_index();
    let outstanding_risk_ids = mandatory_child_artifacts
        .iter()
        .filter(|artifact| !artifact.status.is_satisfied())
        .map(|artifact| artifact.stop_go_code.clone())
        .collect::<Vec<_>>();
    let verdict = if !outstanding_risk_ids.is_empty() {
        AdoptionGateVerdict::Stop
    } else if topology.has_broader_promotion() {
        AdoptionGateVerdict::GoBroader
    } else if topology.decision == TopologyPromotionDecision::TargetedPromotion {
        AdoptionGateVerdict::GoTargeted
    } else {
        AdoptionGateVerdict::Stop
    };
    let stop_go_code = match verdict {
        AdoptionGateVerdict::Stop => "asupersync_leverage.stop.open_gap",
        AdoptionGateVerdict::GoTargeted => "asupersync_leverage.go.targeted_lifecycle_supervision",
        AdoptionGateVerdict::GoBroader => "asupersync_leverage.go.broader_supervision_surface",
    }
    .to_string();
    let summary = AdoptionGateSummary::from_parts(
        &mandatory_child_artifacts,
        &diagnostic_contract_index,
        topology.decision,
    );
    let next_action = match verdict {
        AdoptionGateVerdict::Stop => "Generate or repair outstanding child artifacts before publishing adoption guidance.".to_string(),
        AdoptionGateVerdict::GoTargeted => "Proceed with the extension lifecycle manager supervision adapter first; keep other seams on the direct-manager topology.".to_string(),
        AdoptionGateVerdict::GoBroader => "Sequence broader topology promotion behind a dedicated migration plan and rollback rehearsal.".to_string(),
    };
    let user_impact = "Users get corrected control-plane semantics, explicit unsupported-surface diagnostics, and no silent broad topology migration.".to_string();
    let operator_impact = "Operators get one stop/go contract that links inventories, semantic contracts, diagnostics, release-gate blockers, compatibility proof, overhead proof, and topology guidance.".to_string();
    let required_artifacts = vec![
        "asupersync_leverage_adoption_gate.json".to_string(),
        "decision_record.json".to_string(),
        "diagnostic_contract_index.json".to_string(),
        "run_manifest.json".to_string(),
        "events.jsonl".to_string(),
        "commands.txt".to_string(),
        "trace_ids.json".to_string(),
        "step_logs/".to_string(),
        "summary.md".to_string(),
        "env.json".to_string(),
        "repro.lock".to_string(),
    ];
    let verification_commands = vec![
        "rch exec -- cargo check -p frankenengine-engine --lib --bin franken_asupersync_leverage_adoption_gate --test asupersync_leverage_adoption_gate_cli".to_string(),
        "rch exec 'env RUSTFLAGS=\"-C linker=cc\" cargo test -p frankenengine-engine --test asupersync_leverage_adoption_gate_cli'".to_string(),
        "rch exec -- cargo clippy -p frankenengine-engine --lib --bin franken_asupersync_leverage_adoption_gate --test asupersync_leverage_adoption_gate_cli -- -D warnings".to_string(),
    ];

    let mut gate = AsupersyncLeverageAdoptionGate {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        verdict,
        stop_go_code,
        topology_decision: topology.decision,
        topology_assessment_hash: topology.content_hash,
        topology_assessment_artifact: "topology_promotion_assessment.json".to_string(),
        summary,
        mandatory_child_artifacts,
        diagnostic_contract_index,
        outstanding_risk_ids,
        user_impact,
        operator_impact,
        next_action,
        required_artifacts,
        verification_commands,
        content_hash: String::new(),
    };
    gate.content_hash = content_hash_for_gate(&gate)?;
    Ok(gate)
}

pub fn render_operator_summary(gate: &AsupersyncLeverageAdoptionGate) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# Asupersync Leverage Adoption Gate");
    let _ = writeln!(output);
    let _ = writeln!(output, "- bead: `{}`", gate.bead_id);
    let _ = writeln!(output, "- verdict: `{}`", gate.verdict);
    let _ = writeln!(output, "- stop_go_code: `{}`", gate.stop_go_code);
    let _ = writeln!(output, "- topology_decision: `{}`", gate.topology_decision);
    let _ = writeln!(output, "- content_hash: `{}`", gate.content_hash);
    let _ = writeln!(output);
    let _ = writeln!(output, "## User Impact");
    let _ = writeln!(output, "{}", gate.user_impact);
    let _ = writeln!(output);
    let _ = writeln!(output, "## Operator Impact");
    let _ = writeln!(output, "{}", gate.operator_impact);
    let _ = writeln!(output);
    let _ = writeln!(output, "## Next Action");
    let _ = writeln!(output, "{}", gate.next_action);
    let _ = writeln!(output);
    let _ = writeln!(output, "## Mandatory Child Artifacts");
    for artifact in &gate.mandatory_child_artifacts {
        let _ = writeln!(
            output,
            "- `{}` `{}` `{}`: {}",
            artifact.bead_id,
            artifact.artifact_id,
            artifact.status.as_str(),
            artifact.next_action
        );
    }
    let _ = writeln!(output);
    let _ = writeln!(output, "## Diagnostic Contracts");
    for diagnostic in &gate.diagnostic_contract_index {
        let _ = writeln!(
            output,
            "- `{}` audience={} artifact={} fields={}",
            diagnostic.diagnostic_id,
            diagnostic.audience,
            diagnostic.artifact_id,
            diagnostic.stable_fields.join(",")
        );
    }
    output
}

fn mandatory_child_artifacts(
    topology: &TopologyPromotionAssessment,
) -> Vec<MandatoryChildArtifact> {
    vec![
        validate_child_artifact(
            "bd-3nr.1.2.2",
            "control-plane mock guardrail",
            "mock_seam_guardrail_report",
            "mock_seam_guardrail_report.json",
            "Rejects new production control_plane::mocks usage before adoption.",
        ),
        validate_child_artifact(
            "bd-3nr.1.3.1",
            "budget propagation contract",
            "budget_contract_report",
            "budget_contract_report.json",
            "Keeps child and cleanup budgets explicit at boundary crossings.",
        ),
        validate_child_artifact(
            "bd-3nr.1.3.2",
            "outcome and capability narrowing contract",
            "outcome_capability_narrowing_report",
            "outcome_capability_narrowing_report.json",
            "Preserves four-valued outcomes and deterministic capability narrowing.",
        ),
        validate_child_artifact(
            "bd-3nr.1.3.3",
            "operator diagnostic mapping",
            "control_plane_policy_diagnostics",
            "control_plane_policy_diagnostics.json",
            "Maps policy outcomes to user and operator remediation.",
        ),
        validate_child_artifact(
            "bd-3nr.1.4.3",
            "oracle release gate promotion",
            "oracle_release_gate_promotion",
            "oracle_release_gate_promotion.json",
            "Promotes frankenlab/oracle release blockers into operator triage bundles.",
        ),
        validate_child_artifact(
            "bd-3nr.1.5.1",
            "cross-repo contract matrix",
            "asupersync_contract_matrix",
            "asupersync_contract_compat_matrix.json",
            "Pins franken-kernel, franken-decision, franken-evidence, and frankenlab surface contracts.",
        ),
        validate_child_artifact(
            "bd-3nr.1.5.2",
            "real-context overhead proof",
            "control_plane_benchmark_split_gate",
            "control_plane_benchmark_split_gate.json",
            "Proves bounded overhead without mock shortcuts.",
        ),
        validate_topology_artifact(topology),
    ]
}

/// Validates a child artifact by checking if the artifact file exists and contains valid JSON.
/// Regression fix for bd-2yez8: fail closed on missing/invalid artifacts instead of hardcoding Satisfied.
fn validate_child_artifact(
    bead_id: &str,
    title: &str,
    artifact_id: &str,
    artifact_path_hint: &str,
    impact: &str,
) -> MandatoryChildArtifact {
    use std::env;
    use std::fs;
    use std::path::Path;

    // Check for artifact in typical locations: artifacts/asupersync_leverage_adoption_gate/{timestamp}/
    let status = if let Ok(current_dir) = env::current_dir() {
        let artifact_root = current_dir
            .join("artifacts")
            .join("asupersync_leverage_adoption_gate");
        let manifest_paths = [
            // Direct path in current directory
            current_dir.join(artifact_path_hint),
            // Path in artifacts directory
            artifact_root.join(artifact_path_hint),
        ];

        // Check if any of the expected paths exist and contain valid JSON
        let found_valid = manifest_paths.iter().any(|path| {
            Path::new(path).exists()
                && fs::read_to_string(path)
                    .map(|content| serde_json::from_str::<serde_json::Value>(&content).is_ok())
                    .unwrap_or(false)
        });

        if found_valid {
            GateArtifactStatus::Satisfied
        } else {
            GateArtifactStatus::Outstanding
        }
    } else {
        // Fail closed if we can't determine current directory
        GateArtifactStatus::Outstanding
    };

    let stop_go_code = match status {
        GateArtifactStatus::Satisfied => format!("{artifact_id}.satisfied"),
        GateArtifactStatus::Outstanding => format!("{artifact_id}.missing_or_invalid"),
    };

    MandatoryChildArtifact {
        bead_id: bead_id.to_string(),
        title: title.to_string(),
        artifact_id: artifact_id.to_string(),
        artifact_path_hint: artifact_path_hint.to_string(),
        status,
        stop_go_code,
        user_impact: impact.to_string(),
        operator_impact: format!("{artifact_id} is linked in the final adoption record."),
        next_action: match status {
            GateArtifactStatus::Satisfied => {
                "Keep artifact linked in run_manifest.json and decision_record.json.".to_string()
            }
            GateArtifactStatus::Outstanding => {
                format!("Generate {artifact_path_hint} before re-running adoption gate.")
            }
        },
    }
}

/// Validates the topology artifact specifically.
/// The topology artifact is provided as input so it should always be satisfied.
fn validate_topology_artifact(topology: &TopologyPromotionAssessment) -> MandatoryChildArtifact {
    MandatoryChildArtifact {
        bead_id: "bd-3nr.1.6".to_string(),
        title: "extension-host topology assessment".to_string(),
        artifact_id: "topology_promotion_assessment".to_string(),
        artifact_path_hint: "topology_promotion_assessment.json".to_string(),
        status: GateArtifactStatus::Satisfied, // Always satisfied since provided as input
        stop_go_code: format!("topology_decision.{}", topology.decision.as_str()),
        user_impact: "Avoids a broad topology migration while preserving the targeted lifecycle-manager improvement path.".to_string(),
        operator_impact: "Names the only current promotion seam and records direct-manager seams that should remain unchanged.".to_string(),
        next_action: "Use this decision as the topology input to the adoption gate.".to_string(),
    }
}

fn diagnostic_contract_index() -> Vec<DiagnosticContractEntry> {
    let stable_fields = vec![
        "trace_id".to_string(),
        "component".to_string(),
        "event".to_string(),
        "outcome".to_string(),
        "error_code".to_string(),
        "seed".to_string(),
        "scenario_id".to_string(),
        "decision_id".to_string(),
        "policy_id".to_string(),
    ];
    vec![
        DiagnosticContractEntry {
            diagnostic_id: "policy_mapping".to_string(),
            source_bead_id: "bd-3nr.1.3.3".to_string(),
            audience: "user_and_operator".to_string(),
            artifact_id: "control_plane_policy_diagnostics".to_string(),
            stable_fields: stable_fields.clone(),
            replay_signal: "policy mapping identifier plus remediation contract".to_string(),
        },
        DiagnosticContractEntry {
            diagnostic_id: "release_blocker".to_string(),
            source_bead_id: "bd-3nr.1.4.3".to_string(),
            audience: "operator".to_string(),
            artifact_id: "oracle_release_gate_promotion".to_string(),
            stable_fields: stable_fields.clone(),
            replay_signal: "blocker code and oracle verdict".to_string(),
        },
        DiagnosticContractEntry {
            diagnostic_id: "topology_decision".to_string(),
            source_bead_id: "bd-3nr.1.6".to_string(),
            audience: "operator".to_string(),
            artifact_id: "topology_promotion_assessment".to_string(),
            stable_fields,
            replay_signal: "targeted promotion decision and topology content hash".to_string(),
        },
    ]
}

fn content_hash_for_gate(gate: &AsupersyncLeverageAdoptionGate) -> Result<String, String> {
    let mut canonical = gate.clone();
    canonical.content_hash.clear();
    let encoded = serde_json::to_vec(&canonical)
        .map_err(|e| format!("Failed to serialize adoption gate for hashing: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child_artifact(
        artifact_id: &str,
        status: GateArtifactStatus,
        stop_go_code: &str,
    ) -> MandatoryChildArtifact {
        MandatoryChildArtifact {
            bead_id: format!("bd-test-{artifact_id}"),
            title: format!("{artifact_id} test artifact"),
            artifact_id: artifact_id.to_string(),
            artifact_path_hint: format!("{artifact_id}.json"),
            status,
            stop_go_code: stop_go_code.to_string(),
            user_impact: format!("{artifact_id} user impact"),
            operator_impact: format!("{artifact_id} operator impact"),
            next_action: format!("{artifact_id} next action"),
        }
    }

    #[test]
    fn gate_fails_closed_over_missing_children() {
        // After bd-2yez8 fix: gate should fail closed when child artifacts are missing
        let gate = build_asupersync_leverage_adoption_gate()
            .expect("operation should succeed for valid inputs");
        assert_eq!(gate.verdict, AdoptionGateVerdict::Stop);
        assert!(!gate.is_go());
        assert!(gate.has_outstanding_child_artifacts());
        assert_eq!(gate.summary.mandatory_child_count, 8);
        assert!(gate.summary.satisfied_child_count < gate.summary.mandatory_child_count);
        assert!(gate.summary.outstanding_child_count > 0);
        assert!(!gate.outstanding_risk_ids.is_empty());
        assert_eq!(
            gate.topology_decision,
            TopologyPromotionDecision::TargetedPromotion
        );
        assert_eq!(
            gate.summary.decision_counts.get("targeted_promotion"),
            Some(&1)
        );
    }

    #[test]
    fn content_hash_and_summary_are_stable() {
        let first = build_asupersync_leverage_adoption_gate()
            .expect("operation should succeed for valid inputs");
        let second = build_asupersync_leverage_adoption_gate()
            .expect("operation should succeed for valid inputs");
        assert_eq!(first.content_hash, second.content_hash);
        assert!(first.content_hash.starts_with("sha256:"));
        let summary = render_operator_summary(&first);
        assert!(summary.contains("targeted_promotion"));
        assert!(summary.contains("topology_promotion_assessment"));
        assert!(summary.contains("control_plane_policy_diagnostics"));
    }

    #[test]
    fn artifact_status_strings_and_satisfaction_flags_are_pinned() {
        assert_eq!(GateArtifactStatus::Satisfied.as_str(), "satisfied");
        assert_eq!(GateArtifactStatus::Outstanding.as_str(), "outstanding");
        assert!(GateArtifactStatus::Satisfied.is_satisfied());
        assert!(!GateArtifactStatus::Outstanding.is_satisfied());
    }

    #[test]
    fn verdict_display_and_serde_names_are_stable() {
        for (verdict, expected) in [
            (AdoptionGateVerdict::Stop, "stop"),
            (AdoptionGateVerdict::GoTargeted, "go_targeted"),
            (AdoptionGateVerdict::GoBroader, "go_broader"),
        ] {
            assert_eq!(verdict.as_str(), expected);
            assert_eq!(verdict.to_string(), expected);
            assert_eq!(
                serde_json::to_string(&verdict).expect("verdict should serialize"),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<AdoptionGateVerdict>(&format!("\"{expected}\""))
                    .expect("verdict should deserialize"),
                verdict
            );
        }
    }

    #[test]
    fn summary_counts_satisfied_outstanding_and_all_decision_buckets() {
        let artifacts = [
            child_artifact(
                "ready_a",
                GateArtifactStatus::Satisfied,
                "ready_a.satisfied",
            ),
            child_artifact(
                "ready_b",
                GateArtifactStatus::Satisfied,
                "ready_b.satisfied",
            ),
            child_artifact(
                "missing",
                GateArtifactStatus::Outstanding,
                "missing.missing_or_invalid",
            ),
        ];
        let diagnostics = [
            DiagnosticContractEntry {
                diagnostic_id: "policy_mapping".to_string(),
                source_bead_id: "bd-test-diagnostic".to_string(),
                audience: "operator".to_string(),
                artifact_id: "policy_mapping".to_string(),
                stable_fields: vec!["trace_id".to_string(), "decision_id".to_string()],
                replay_signal: "deterministic replay signal".to_string(),
            },
            DiagnosticContractEntry {
                diagnostic_id: "release_blocker".to_string(),
                source_bead_id: "bd-test-release".to_string(),
                audience: "user_and_operator".to_string(),
                artifact_id: "release_blocker".to_string(),
                stable_fields: vec!["policy_id".to_string()],
                replay_signal: "release blocker code".to_string(),
            },
        ];

        let summary = AdoptionGateSummary::from_parts(
            &artifacts,
            &diagnostics,
            TopologyPromotionDecision::BroaderPromotion,
        );

        assert_eq!(summary.mandatory_child_count, 3);
        assert_eq!(summary.satisfied_child_count, 2);
        assert_eq!(summary.outstanding_child_count, 1);
        assert_eq!(summary.diagnostic_contract_count, 2);
        assert_eq!(summary.decision_counts["no_promotion"], 0);
        assert_eq!(summary.decision_counts["targeted_promotion"], 0);
        assert_eq!(summary.decision_counts["broader_promotion"], 1);
    }

    #[test]
    fn missing_or_invalid_child_artifact_fails_closed_with_actionable_code() {
        let artifact = validate_child_artifact(
            "bd-test-missing",
            "missing child",
            "definitely_absent_child_artifact_for_bd_juf8o",
            "definitely_absent_child_artifact_for_bd_juf8o.json",
            "missing child should block adoption",
        );

        assert_eq!(artifact.status, GateArtifactStatus::Outstanding);
        assert_eq!(
            artifact.stop_go_code,
            "definitely_absent_child_artifact_for_bd_juf8o.missing_or_invalid"
        );
        assert_eq!(
            artifact.next_action,
            "Generate definitely_absent_child_artifact_for_bd_juf8o.json before re-running adoption gate."
        );
        assert_eq!(artifact.user_impact, "missing child should block adoption");
    }

    #[test]
    fn topology_artifact_status_is_satisfied_and_records_decision_code() {
        let mut topology = build_topology_promotion_assessment();
        topology.decision = TopologyPromotionDecision::NoPromotion;

        let artifact = validate_topology_artifact(&topology);

        assert_eq!(artifact.status, GateArtifactStatus::Satisfied);
        assert_eq!(artifact.stop_go_code, "topology_decision.no_promotion");
        assert_eq!(artifact.artifact_id, "topology_promotion_assessment");
        assert!(
            artifact
                .operator_impact
                .contains("direct-manager seams that should remain unchanged")
        );
    }

    #[test]
    fn outstanding_child_artifacts_override_broader_topology_promotion() {
        let mut topology = build_topology_promotion_assessment();
        topology.decision = TopologyPromotionDecision::BroaderPromotion;
        topology
            .seams
            .first_mut()
            .expect("default topology has at least one seam")
            .decision = TopologyPromotionDecision::BroaderPromotion;

        let gate = build_asupersync_leverage_adoption_gate_from_topology(topology)
            .expect("adoption gate should build from broader topology");

        assert_eq!(
            gate.topology_decision,
            TopologyPromotionDecision::BroaderPromotion
        );
        assert_eq!(gate.verdict, AdoptionGateVerdict::Stop);
        assert_eq!(gate.stop_go_code, "asupersync_leverage.stop.open_gap");
        assert!(!gate.is_go());
        assert!(gate.has_outstanding_child_artifacts());
        assert!(
            gate.outstanding_risk_ids
                .iter()
                .all(|risk| risk.ends_with(".missing_or_invalid"))
        );
    }

    #[test]
    fn diagnostic_contract_index_pins_required_stable_fields_for_every_audience() {
        let diagnostics = diagnostic_contract_index();
        assert_eq!(diagnostics.len(), 3);

        for diagnostic in diagnostics {
            assert!(matches!(
                diagnostic.audience.as_str(),
                "operator" | "user_and_operator"
            ));
            for required in [
                "trace_id",
                "component",
                "event",
                "outcome",
                "error_code",
                "seed",
                "scenario_id",
                "decision_id",
                "policy_id",
            ] {
                assert!(
                    diagnostic
                        .stable_fields
                        .iter()
                        .any(|field| field == required),
                    "{} missing stable field {required}",
                    diagnostic.diagnostic_id
                );
            }
            assert!(!diagnostic.replay_signal.trim().is_empty());
        }
    }

    #[test]
    fn content_hash_ignores_existing_hash_field_but_changes_with_contract_content() {
        let mut gate = build_asupersync_leverage_adoption_gate()
            .expect("adoption gate should build for hash regression");
        let original = content_hash_for_gate(&gate).expect("hash should compute");

        gate.content_hash = "sha256:preexisting-placeholder".to_string();
        assert_eq!(
            content_hash_for_gate(&gate).expect("hash should ignore content_hash field"),
            original
        );

        gate.next_action
            .push_str(" Extra deterministic operator action.");
        assert_ne!(
            content_hash_for_gate(&gate).expect("hash should include contract content"),
            original
        );
    }

    #[test]
    fn rendered_summary_lists_every_child_artifact_and_diagnostic_contract() {
        let gate = build_asupersync_leverage_adoption_gate()
            .expect("adoption gate should build for summary coverage");
        let summary = render_operator_summary(&gate);

        for artifact in &gate.mandatory_child_artifacts {
            assert!(
                summary.contains(&artifact.bead_id),
                "summary missing child bead {}",
                artifact.bead_id
            );
            assert!(
                summary.contains(&artifact.artifact_id),
                "summary missing artifact {}",
                artifact.artifact_id
            );
            assert!(
                summary.contains(artifact.status.as_str()),
                "summary missing status {}",
                artifact.status.as_str()
            );
        }

        for diagnostic in &gate.diagnostic_contract_index {
            assert!(
                summary.contains(&diagnostic.diagnostic_id),
                "summary missing diagnostic {}",
                diagnostic.diagnostic_id
            );
            assert!(
                summary.contains(&diagnostic.artifact_id),
                "summary missing diagnostic artifact {}",
                diagnostic.artifact_id
            );
        }
    }
}
