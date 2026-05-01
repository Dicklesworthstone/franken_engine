#![forbid(unsafe_code)]

//! Production impossible-by-default feature catalog gate.
//!
//! The gate turns candidate feature claims into a parent metric artifact for
//! `disruptive_floor_metric_gate`. It fails closed unless at least three
//! user-facing features are observed with fresh, live proof artifacts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::disruptive_floor_metric_gate::{
    DEFAULT_MAX_FRESHNESS_DAYS, DisruptiveMetricId, MetricArtifact,
};
use crate::proof_artifact::{
    PROOF_MANIFEST_SCHEMA_VERSION, RedactionPolicy, redact_text, sha256_hex, validate_sha256,
};

pub const SCHEMA_VERSION: &str = "franken-engine.production-feature-catalog-gate.v1";
pub const COMPONENT: &str = "production_feature_catalog_gate";
pub const BEAD_ID: &str = "bd-1qr4f";
pub const REQUIRED_OBSERVED_FEATURES: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionFeatureState {
    Observed,
    Provisional, // Claims implementation but lacks proper evidence
    Target,
    Hypothesis,
}

impl ProductionFeatureState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Provisional => "provisional",
            Self::Target => "target",
            Self::Hypothesis => "hypothesis",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureProofKind {
    LiveProofArtifact,
    StaticFixture,
    UnverifiedDocClaim,
    InternalOnlyModule,
}

impl FeatureProofKind {
    pub const fn is_live(self) -> bool {
        matches!(self, Self::LiveProofArtifact)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureArtifactHandle {
    pub path: String,
    pub sha256: String,
    pub role: String,
    pub proof_kind: FeatureProofKind,
    pub verification_command: String,
    pub user_facing_workflow: String,
    pub proof_manifest_id: String,
    pub redaction_status: String,
    // Evidence requirements for production features
    pub evidence_bead_id: Option<String>, // Closed bead ID that implemented this feature
    pub evidence_commit_hash: Option<String>, // Commit hash with implementation
    pub evidence_test_name: Option<String>, // Test name proving functionality
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionFeatureCatalogEntry {
    pub feature_id: String,
    pub user_facing_name: String,
    pub impossible_by_default_rationale: String,
    pub state: ProductionFeatureState,
    pub artifact_handles: Vec<FeatureArtifactHandle>,
    pub freshness_days: u64,
    pub owning_bead: String,
    pub downgrade_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionFeatureCatalogInput {
    pub schema_version: String,
    pub code_revision: String,
    pub max_freshness_days: u64,
    pub features: Vec<ProductionFeatureCatalogEntry>,
}

impl ProductionFeatureCatalogInput {
    pub fn representative_fixture(code_revision: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            code_revision: code_revision.into(),
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            features: representative_features(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionFeatureCatalogDecision {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionFeatureCatalogEvent {
    pub feature_id: String,
    pub feature_state: ProductionFeatureState,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub verification_command: String,
    pub node_bun_rationale: String,
    pub freshness_days: u64,
    pub proof_manifest_id: String,
    pub command_id: String,
    pub code_revision: String,
    pub duration_ms: u64,
    pub redaction_status: String,
    pub decision: String,
    pub downgrade_text: String,
    pub reason: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionFeatureCatalogReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub decision: ProductionFeatureCatalogDecision,
    pub reason: String,
    pub observed_feature_count: u64,
    pub required_observed_feature_count: u64,
    pub observed_disruptive_floor_wording_allowed: bool,
    pub metric_artifact: MetricArtifact,
    pub unsupported_candidate_feature_ids: Vec<String>,
    pub feature_states: BTreeMap<String, ProductionFeatureState>,
    pub events: Vec<ProductionFeatureCatalogEvent>,
    pub downgrade_text: String,
}

impl ProductionFeatureCatalogReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Production Feature Catalog Gate\n\n");
        out.push_str(&format!("Decision: `{:?}`\n\n", self.decision));
        out.push_str(&format!(
            "Observed features: `{}` / `{}`\n\n",
            self.observed_feature_count, self.required_observed_feature_count
        ));
        out.push_str(&format!("Reason: `{}`\n\n", self.reason));
        if !self.unsupported_candidate_feature_ids.is_empty() {
            out.push_str("Unsupported candidates remain visible:\n");
            for feature_id in &self.unsupported_candidate_feature_ids {
                out.push_str(&format!("- `{feature_id}`\n"));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeatureEvaluation {
    observed: bool,
    counted: bool,
    reason: String,
    remediation: String,
    artifact_path: String,
    artifact_hash: String,
    verification_command: String,
    proof_manifest_id: String,
    redaction_status: String,
}

pub fn evaluate_production_feature_catalog(
    input: &ProductionFeatureCatalogInput,
) -> ProductionFeatureCatalogReport {
    let max_freshness_days = input.max_freshness_days.min(DEFAULT_MAX_FRESHNESS_DAYS);
    let mut global_failures = Vec::new();
    if input.schema_version != SCHEMA_VERSION {
        global_failures.push("schema_version_mismatch".to_string());
    }
    if input.code_revision.trim().is_empty() {
        global_failures.push("missing_code_revision".to_string());
    }
    if input.features.is_empty() {
        global_failures.push("missing_feature_catalog".to_string());
    }

    let duplicate_ids = duplicate_feature_ids(&input.features);
    if !duplicate_ids.is_empty() {
        global_failures.push(format!("duplicate_feature_ids:{}", duplicate_ids.join("|")));
    }

    let policy = RedactionPolicy::default();
    let mut observed_feature_count = 0;
    let mut unsupported_candidate_feature_ids = Vec::new();
    let mut feature_states = BTreeMap::new();
    let mut evaluations = Vec::new();

    for feature in &input.features {
        feature_states.insert(feature.feature_id.clone(), feature.state);
        let evaluation = evaluate_feature(feature, max_freshness_days, &policy);
        if evaluation.counted {
            observed_feature_count += 1;
        }
        if feature.state != ProductionFeatureState::Observed {
            unsupported_candidate_feature_ids.push(feature.feature_id.clone());
        }
        // Mark provisional features as requiring attention
        if feature.state == ProductionFeatureState::Provisional {
            unsupported_candidate_feature_ids.push(format!(
                "{} (PROVISIONAL - lacks evidence)",
                feature.feature_id
            ));
        }
        evaluations.push(evaluation);
    }

    let feature_failures = evaluations
        .iter()
        .filter(|evaluation| evaluation.observed && !evaluation.counted)
        .map(|evaluation| evaluation.reason.clone())
        .collect::<Vec<_>>();

    let reason = if !global_failures.is_empty() {
        global_failures.join(",")
    } else if !feature_failures.is_empty() {
        feature_failures.join(",")
    } else if observed_feature_count < REQUIRED_OBSERVED_FEATURES {
        "fewer_than_three_observed_features".to_string()
    } else {
        "observed_feature_catalog_satisfies_floor".to_string()
    };

    let passed = global_failures.is_empty()
        && feature_failures.is_empty()
        && observed_feature_count >= REQUIRED_OBSERVED_FEATURES;

    let metric_id = DisruptiveMetricId::ImpossibleByDefaultProductionFeatures;
    let coverage_millionths = observed_feature_count
        .min(REQUIRED_OBSERVED_FEATURES)
        .saturating_mul(1_000_000)
        / REQUIRED_OBSERVED_FEATURES;
    let artifact_hash = format!("sha256:{}", catalog_digest(input));
    let artifact_path = "artifacts/production_feature_catalog/catalog_report.json".to_string();
    let verification_command = "scripts/run_production_feature_catalog_gate.sh ci".to_string();

    let metric_artifact = MetricArtifact {
        metric_id,
        threshold: metric_id.threshold(),
        observed_value: observed_feature_count,
        unit: metric_id.unit().to_string(),
        baseline: metric_id.expected_baseline().to_string(),
        candidate: "franken_engine".to_string(),
        denominator_id: format!(
            "production_features:{}",
            input
                .features
                .len()
                .max(REQUIRED_OBSERVED_FEATURES as usize)
        ),
        scenario_set: "impossible_by_default_production_feature_catalog_v1".to_string(),
        artifact_path,
        artifact_hash,
        code_revision: input.code_revision.clone(),
        freshness_days: input
            .features
            .iter()
            .map(|feature| feature.freshness_days)
            .max()
            .unwrap_or(max_freshness_days),
        confidence_millionths: if passed { 990_000 } else { 0 },
        coverage_millionths,
        verification_command,
        redaction_status: "redacted".to_string(),
    };

    let events = input
        .features
        .iter()
        .zip(evaluations)
        .map(|(feature, evaluation)| ProductionFeatureCatalogEvent {
            feature_id: feature.feature_id.clone(),
            feature_state: feature.state,
            artifact_path: evaluation.artifact_path,
            artifact_hash: evaluation.artifact_hash,
            verification_command: evaluation.verification_command,
            node_bun_rationale: feature.impossible_by_default_rationale.clone(),
            freshness_days: feature.freshness_days,
            proof_manifest_id: evaluation.proof_manifest_id,
            command_id: format!("feature-catalog:{}", feature.feature_id),
            code_revision: input.code_revision.clone(),
            duration_ms: 0,
            redaction_status: evaluation.redaction_status,
            decision: if evaluation.counted {
                "observed".to_string()
            } else {
                "not_observed".to_string()
            },
            downgrade_text: feature.downgrade_text.clone(),
            reason: evaluation.reason,
            remediation: evaluation.remediation,
        })
        .collect();

    ProductionFeatureCatalogReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        decision: if passed {
            ProductionFeatureCatalogDecision::Pass
        } else {
            ProductionFeatureCatalogDecision::FailClosed
        },
        reason,
        observed_feature_count,
        required_observed_feature_count: REQUIRED_OBSERVED_FEATURES,
        observed_disruptive_floor_wording_allowed: passed,
        metric_artifact,
        unsupported_candidate_feature_ids,
        feature_states,
        events,
        downgrade_text: if passed {
            "Production impossible-by-default feature count is observed with live proof artifacts."
                .to_string()
        } else {
            metric_id.downgrade_text()
        },
    }
}

fn evaluate_feature(
    feature: &ProductionFeatureCatalogEntry,
    max_freshness_days: u64,
    policy: &RedactionPolicy,
) -> FeatureEvaluation {
    let empty = FeatureEvaluation {
        observed: feature.state == ProductionFeatureState::Observed,
        counted: false,
        reason: "candidate_not_observed".to_string(),
        remediation: "attach a fresh live proof artifact and rerun the catalog gate".to_string(),
        artifact_path: String::new(),
        artifact_hash: String::new(),
        verification_command: String::new(),
        proof_manifest_id: String::new(),
        redaction_status: "redacted".to_string(),
    };

    if feature.feature_id.trim().is_empty() {
        return empty.with_reason("missing_feature_id");
    }
    if feature.user_facing_name.trim().is_empty() {
        return empty.with_reason("missing_user_facing_name");
    }
    if !rationale_mentions_node_and_bun(&feature.impossible_by_default_rationale) {
        return empty.with_reason("invalid_node_bun_rationale");
    }
    if feature.owning_bead.trim().is_empty() {
        return empty.with_reason("missing_owning_bead");
    }
    if feature.downgrade_text.trim().is_empty() {
        return empty.with_reason("missing_downgrade_text");
    }

    if feature.state != ProductionFeatureState::Observed
        && feature.state != ProductionFeatureState::Provisional
    {
        return empty;
    }
    if feature.artifact_handles.is_empty() {
        return empty.with_reason("missing_artifact_handles");
    }
    if feature.freshness_days > max_freshness_days {
        return empty.with_reason("stale_artifact");
    }

    let invalid_artifact = feature
        .artifact_handles
        .iter()
        .find_map(validate_artifact_handle);
    if let Some(reason) = invalid_artifact {
        // If it's an evidence validation failure and marked as Observed,
        // suggest downgrading to Provisional
        if matches!(
            reason,
            "fake_artifact_hash_detected"
                | "missing_evidence_requirements"
                | "invalid_evidence_bead_id_format"
                | "invalid_evidence_commit_hash_format"
                | "missing_evidence_test_name"
        ) && feature.state == ProductionFeatureState::Observed
        {
            return empty.with_reason(&format!(
                "{}: feature should be marked PROVISIONAL until proper evidence is provided",
                reason
            ));
        }
        return empty.with_reason(reason);
    }

    let live = feature
        .artifact_handles
        .iter()
        .find(|artifact| artifact.proof_kind.is_live());
    let Some(artifact) = live else {
        return empty.with_reason("observed_feature_lacks_live_proof");
    };

    FeatureEvaluation {
        observed: true,
        counted: true,
        reason: "fresh_live_proof_artifact_observed".to_string(),
        remediation: "none".to_string(),
        artifact_path: artifact.path.clone(),
        artifact_hash: artifact.sha256.clone(),
        verification_command: redact_text(&artifact.verification_command, policy),
        proof_manifest_id: artifact.proof_manifest_id.clone(),
        redaction_status: artifact.redaction_status.clone(),
    }
}

impl FeatureEvaluation {
    fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

/// Validates evidence requirements for production features against fake data
fn validate_evidence_requirements(artifact: &FeatureArtifactHandle) -> Option<&'static str> {
    // Reject known fake hash patterns
    if is_fake_hash(&artifact.sha256) {
        return Some("fake_artifact_hash_detected");
    }

    // For live proof artifacts claiming production readiness, require evidence
    if artifact.proof_kind.is_live() {
        if let (Some(bead_id), Some(commit_hash), Some(test_name)) = (
            &artifact.evidence_bead_id,
            &artifact.evidence_commit_hash,
            &artifact.evidence_test_name,
        ) {
            // Validate bead ID format (should be bd-xxxxx)
            if !bead_id.starts_with("bd-") || bead_id.len() < 6 {
                return Some("invalid_evidence_bead_id_format");
            }

            // Validate commit hash format (should be 7-40 hex chars)
            if commit_hash.len() < 7
                || commit_hash.len() > 40
                || !commit_hash.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Some("invalid_evidence_commit_hash_format");
            }

            // Validate test name is not empty
            if test_name.trim().is_empty() {
                return Some("missing_evidence_test_name");
            }
        } else {
            return Some("missing_evidence_requirements");
        }
    }

    None
}

/// Detects fake SHA256 hash patterns commonly used in placeholder code
fn is_fake_hash(hash: &str) -> bool {
    if !hash.starts_with("sha256:") || hash.len() != 71 {
        return false; // Invalid format, will be caught by existing validation
    }

    let hex_part = &hash[7..];

    // Common fake patterns
    let fake_patterns = [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // sequential hex
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // all a's
        "1111111111111111111111111111111111111111111111111111111111111111", // all 1's
        "0000000000000000000000000000000000000000000000000000000000000000", // all 0's
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // all f's
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // deadbeef pattern
    ];

    // Check if it matches known fake patterns
    if fake_patterns.contains(&hex_part) {
        return true;
    }

    // Check for repetitive patterns (same 4-char sequence repeated)
    if hex_part.len() == 64 {
        let chunk = &hex_part[0..4];
        if hex_part
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .all(|c| c.iter().collect::<String>() == chunk)
        {
            return true;
        }
    }

    false
}

fn validate_artifact_handle(artifact: &FeatureArtifactHandle) -> Option<&'static str> {
    // Check evidence requirements first to catch fake data
    if let Some(evidence_error) = validate_evidence_requirements(artifact) {
        return Some(evidence_error);
    }

    if artifact.path.trim().is_empty() {
        return Some("missing_artifact_path");
    }
    if validate_sha256(&artifact.sha256).is_err() {
        return Some("invalid_artifact_hash");
    }
    if artifact.role.trim().is_empty() {
        return Some("missing_artifact_role");
    }
    if artifact.verification_command.trim().is_empty() {
        return Some("missing_verification_command");
    }
    if artifact.user_facing_workflow.trim().is_empty() {
        return Some("missing_user_facing_workflow");
    }
    if artifact.proof_manifest_id.trim().is_empty() {
        return Some("missing_proof_manifest_id");
    }
    if artifact.proof_kind.is_live()
        && artifact.proof_manifest_id != PROOF_MANIFEST_SCHEMA_VERSION
        && !artifact.proof_manifest_id.contains("manifest")
    {
        return Some("invalid_proof_manifest_id");
    }
    if artifact.redaction_status != "redacted" {
        return Some("unredacted_command_transcript");
    }
    None
}

fn duplicate_feature_ids(features: &[ProductionFeatureCatalogEntry]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for feature in features {
        if !seen.insert(feature.feature_id.clone()) {
            duplicates.insert(feature.feature_id.clone());
        }
    }
    duplicates.into_iter().collect()
}

fn rationale_mentions_node_and_bun(rationale: &str) -> bool {
    let lower = rationale.to_ascii_lowercase();
    lower.contains("node") && lower.contains("bun") && lower.len() >= 40
}

fn catalog_digest(input: &ProductionFeatureCatalogInput) -> String {
    let mut rows = input
        .features
        .iter()
        .map(|feature| {
            format!(
                "{}:{}:{}:{}",
                feature.feature_id,
                feature.state.as_str(),
                feature.freshness_days,
                feature.artifact_handles.len()
            )
        })
        .collect::<Vec<_>>();
    rows.sort();
    sha256_hex(rows.join("\n"))
}

fn representative_features() -> Vec<ProductionFeatureCatalogEntry> {
    vec![
        observed_feature(
            "posterior_policy_actions",
            "Posterior-explained policy actions",
            "bd-policy",
        ),
        observed_feature(
            "deterministic_replay_counterfactuals",
            "Deterministic replay and counterfactuals",
            "bd-replay",
        ),
        observed_feature(
            "signed_policy_checkpoints",
            "Signed policy checkpoints",
            "bd-checkpoint",
        ),
        target_feature(
            "autonomous_quarantine_mesh",
            "Autonomous quarantine mesh",
            ProductionFeatureState::Target,
        ),
        target_feature(
            "ifc_declassification_receipts",
            "IFC and declassification receipts",
            ProductionFeatureState::Hypothesis,
        ),
    ]
}

fn observed_feature(
    feature_id: impl Into<String>,
    name: impl Into<String>,
    bead: impl Into<String>,
) -> ProductionFeatureCatalogEntry {
    let feature_id = feature_id.into();
    // NOTE: This function creates PROVISIONAL features since the representative
    // data lacks real evidence. In production, features should only be marked
    // as Observed with proper bead IDs, commit hashes, and test evidence.
    ProductionFeatureCatalogEntry {
        feature_id: feature_id.clone(),
        user_facing_name: name.into(),
        impossible_by_default_rationale: format!(
            "{feature_id} is impossible by default versus Node and Bun because it requires signed, replayable runtime proof before release wording can claim production behavior."
        ),
        state: ProductionFeatureState::Provisional, // Downgraded from Observed due to fake data
        artifact_handles: vec![FeatureArtifactHandle {
            path: format!("artifacts/production_feature_catalog/{feature_id}/manifest.json"),
            sha256: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            role: "live_proof_manifest".to_string(),
            proof_kind: FeatureProofKind::LiveProofArtifact,
            verification_command: format!(
                "API_TOKEN=secret scripts/run_{feature_id}_proof.sh --verify"
            ),
            user_facing_workflow: format!("frankenctl proof verify --feature {feature_id}"),
            proof_manifest_id: format!("{PROOF_MANIFEST_SCHEMA_VERSION}:{feature_id}"),
            redaction_status: "redacted".to_string(),
            // Evidence fields left empty - this is what makes it PROVISIONAL
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        }],
        freshness_days: 0,
        owning_bead: bead.into(),
        downgrade_text: format!(
            "PROVISIONAL: {feature_id} requires real evidence (bead ID + commit hash + test name) before marking as Observed."
        ),
    }
}

fn target_feature(
    feature_id: impl Into<String>,
    name: impl Into<String>,
    state: ProductionFeatureState,
) -> ProductionFeatureCatalogEntry {
    let feature_id = feature_id.into();
    ProductionFeatureCatalogEntry {
        feature_id: feature_id.clone(),
        user_facing_name: name.into(),
        impossible_by_default_rationale: format!(
            "{feature_id} is a target impossible-by-default feature relative to Node and Bun, pending a user-facing live proof workflow."
        ),
        state,
        artifact_handles: vec![FeatureArtifactHandle {
            path: format!("tests/fixtures/{feature_id}.json"),
            sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            role: "candidate_fixture".to_string(),
            proof_kind: FeatureProofKind::StaticFixture,
            verification_command: String::new(),
            user_facing_workflow: String::new(),
            proof_manifest_id: String::new(),
            redaction_status: "redacted".to_string(),
            // Target/Hypothesis features don't need evidence yet
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        }],
        freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
        owning_bead: "bd-target".to_string(),
        downgrade_text: format!(
            "Keep {feature_id} as target/hypothesis until live proof artifacts exist."
        ),
    }
}

/// Creates a properly evidenced observed feature for testing (non-fake data)
#[cfg(test)]
fn observed_feature_with_evidence(
    feature_id: impl Into<String>,
    name: impl Into<String>,
    bead: impl Into<String>,
    commit_hash: impl Into<String>,
    test_name: impl Into<String>,
    artifact_hash: impl Into<String>,
) -> ProductionFeatureCatalogEntry {
    let feature_id = feature_id.into();
    ProductionFeatureCatalogEntry {
        feature_id: feature_id.clone(),
        user_facing_name: name.into(),
        impossible_by_default_rationale: format!(
            "{feature_id} is impossible by default versus Node and Bun because it requires signed, replayable runtime proof before release wording can claim production behavior."
        ),
        state: ProductionFeatureState::Observed,
        artifact_handles: vec![FeatureArtifactHandle {
            path: format!("artifacts/production_feature_catalog/{feature_id}/manifest.json"),
            sha256: artifact_hash.into(),
            role: "live_proof_manifest".to_string(),
            proof_kind: FeatureProofKind::LiveProofArtifact,
            verification_command: format!(
                "API_TOKEN=secret scripts/run_{feature_id}_proof.sh --verify"
            ),
            user_facing_workflow: format!("frankenctl proof verify --feature {feature_id}"),
            proof_manifest_id: format!("{PROOF_MANIFEST_SCHEMA_VERSION}:{feature_id}"),
            redaction_status: "redacted".to_string(),
            // Real evidence requirements
            evidence_bead_id: Some(bead.into()),
            evidence_commit_hash: Some(commit_hash.into()),
            evidence_test_name: Some(test_name.into()),
        }],
        freshness_days: 0,
        owning_bead: bead.into(),
        downgrade_text: format!(
            "Keep {feature_id} as a target until a fresh live proof artifact passes."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disruptive_floor_metric_gate::{
        DisruptiveFloorGateConfig, DisruptiveMetricId, GateDecisionState,
        evaluate_disruptive_floor_gate,
    };

    #[test]
    fn representative_catalog_emits_parent_metric_artifact() {
        let report = evaluate_production_feature_catalog(
            &ProductionFeatureCatalogInput::representative_fixture("rev-under-test"),
        );

        assert_eq!(report.decision, ProductionFeatureCatalogDecision::Pass);
        assert_eq!(report.observed_feature_count, 3);
        assert!(report.observed_disruptive_floor_wording_allowed);
        assert_eq!(
            report.metric_artifact.metric_id,
            DisruptiveMetricId::ImpossibleByDefaultProductionFeatures
        );
        assert_eq!(report.metric_artifact.observed_value, 3);
        assert_eq!(report.metric_artifact.threshold, 3);
        assert_eq!(report.metric_artifact.baseline, "feature_catalog");
        assert_eq!(report.metric_artifact.redaction_status, "redacted");
    }

    #[test]
    fn parent_integrator_accepts_feature_catalog_metric_artifact() {
        let child_report = evaluate_production_feature_catalog(
            &ProductionFeatureCatalogInput::representative_fixture("rev-under-test"),
        );
        let mut artifacts = DisruptiveMetricId::ALL
            .into_iter()
            .map(|metric_id| MetricArtifact::for_metric(metric_id, metric_id.threshold()))
            .collect::<Vec<_>>();
        let feature_slot = artifacts
            .iter_mut()
            .find(|artifact| {
                artifact.metric_id == DisruptiveMetricId::ImpossibleByDefaultProductionFeatures
            })
            .expect("parent should require feature metric");
        *feature_slot = child_report.metric_artifact;

        let parent = evaluate_disruptive_floor_gate(
            &DisruptiveFloorGateConfig::new("rev-under-test"),
            &artifacts,
        );

        assert_eq!(parent.decision, GateDecisionState::Pass);
        assert!(parent.observed_disruptive_floor_wording_allowed);
    }

    #[test]
    fn duplicate_feature_ids_fail_closed() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        input.features[1].feature_id = input.features[0].feature_id.clone();

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert!(report.reason.contains("duplicate_feature_ids"));
        assert!(!report.observed_disruptive_floor_wording_allowed);
    }

    #[test]
    fn observed_feature_missing_artifacts_fails_closed() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        input.features[0].artifact_handles.clear();

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert_eq!(report.events[0].reason, "missing_artifact_handles");
        assert_eq!(report.observed_feature_count, 2);
    }

    #[test]
    fn stale_observed_feature_fails_closed() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        input.features[0].freshness_days = DEFAULT_MAX_FRESHNESS_DAYS + 1;

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert_eq!(report.events[0].reason, "stale_artifact");
    }

    #[test]
    fn static_fixture_only_observed_feature_fails_closed() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        input.features[0].artifact_handles[0].proof_kind = FeatureProofKind::StaticFixture;

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert_eq!(report.events[0].reason, "observed_feature_lacks_live_proof");
    }

    #[test]
    fn invalid_node_bun_rationale_fails_closed() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        input.features[0].impossible_by_default_rationale = "generic runtime claim".to_string();

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert_eq!(report.events[0].reason, "invalid_node_bun_rationale");
    }

    #[test]
    fn fewer_than_three_observed_features_fail_closed_but_keep_targets_visible() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        input.features[2].state = ProductionFeatureState::Target;

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert_eq!(report.reason, "fewer_than_three_observed_features");
        assert_eq!(report.observed_feature_count, 2);
        assert!(
            report
                .unsupported_candidate_feature_ids
                .contains(&"signed_policy_checkpoints".to_string())
        );
    }

    #[test]
    fn malformed_input_rejects_invalid_production_state() {
        let json = r#"{
          "schema_version": "franken-engine.production-feature-catalog-gate.v1",
          "code_revision": "rev-under-test",
          "max_freshness_days": 14,
          "features": [{
            "feature_id": "bad",
            "user_facing_name": "Bad",
            "impossible_by_default_rationale": "Bad versus Node and Bun with enough words to parse",
            "state": "maybe",
            "artifact_handles": [],
            "freshness_days": 0,
            "owning_bead": "bd",
            "downgrade_text": "downgrade"
          }]
        }"#;

        let parsed = serde_json::from_str::<ProductionFeatureCatalogInput>(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn deterministic_serialization_and_artifact_path() {
        let input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        let report = evaluate_production_feature_catalog(&input);

        let first = serde_json::to_string(&report).unwrap();
        let second = serde_json::to_string(&report).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            report.metric_artifact.artifact_path,
            "artifacts/production_feature_catalog/catalog_report.json"
        );
        validate_sha256(&report.metric_artifact.artifact_hash).expect("metric hash validates");
    }

    #[test]
    fn report_rendering_and_secret_redaction_are_stable() {
        let input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");
        let report = evaluate_production_feature_catalog(&input);

        let markdown = report.to_markdown();
        assert!(markdown.contains("Production Feature Catalog Gate"));
        assert!(markdown.contains("autonomous_quarantine_mesh"));
        assert!(
            report
                .events
                .iter()
                .all(|event| !event.verification_command.contains("secret"))
        );
        assert!(
            report
                .events
                .iter()
                .any(|event| event.verification_command.contains("API_TOKEN=<redacted>"))
        );
    }

    #[test]
    fn fake_artifact_hash_detected_and_rejected() {
        let mut input = ProductionFeatureCatalogInput::representative_fixture("rev-under-test");

        // The representative fixture already has fake hashes, which should be detected
        let report = evaluate_production_feature_catalog(&input);

        // Since features use fake data, they should be marked as provisional
        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );

        // Check that fake hash detection is working
        assert!(
            report
                .events
                .iter()
                .any(|event| event.reason.contains("fake_artifact_hash_detected")
                    || event.reason.contains("missing_evidence_requirements")),
            "Expected fake hash or missing evidence detection, got: {:?}",
            report.events.iter().map(|e| &e.reason).collect::<Vec<_>>()
        );
    }

    #[test]
    fn observed_feature_with_proper_evidence_passes() {
        let valid_feature = observed_feature_with_evidence(
            "real_feature",
            "Real Feature",
            "bd-12345",
            "a1b2c3d4",
            "test_real_feature_works",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 of empty string
        );

        let input = ProductionFeatureCatalogInput {
            schema_version: SCHEMA_VERSION.to_string(),
            code_revision: "real-revision".to_string(),
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            features: vec![
                valid_feature,
                // Add two more valid features to meet the minimum requirement
                observed_feature_with_evidence(
                    "real_feature_2",
                    "Real Feature 2",
                    "bd-67890",
                    "e5f6g7h8",
                    "test_real_feature_2_works",
                    "sha256:f7c3c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b866", // Different valid hash
                ),
                observed_feature_with_evidence(
                    "real_feature_3",
                    "Real Feature 3",
                    "bd-abcde",
                    "i9j0k1l2",
                    "test_real_feature_3_works",
                    "sha256:a1c3c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b877", // Different valid hash
                ),
            ],
        };

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(report.decision, ProductionFeatureCatalogDecision::Pass);
        assert_eq!(report.observed_feature_count, 3);
        assert!(
            report
                .events
                .iter()
                .all(|event| event.reason == "fresh_live_proof_artifact_observed"),
            "All features should pass with proper evidence"
        );
    }

    #[test]
    fn missing_evidence_requirements_marks_feature_provisional() {
        let mut feature = observed_feature_with_evidence(
            "incomplete_feature",
            "Incomplete Feature",
            "bd-99999",
            "commit123",
            "test_works",
            "sha256:1234567890123456789012345678901234567890123456789012345678901234", // Valid but not fake
        );

        // Remove evidence to simulate missing requirements
        feature.artifact_handles[0].evidence_bead_id = None;
        feature.artifact_handles[0].evidence_commit_hash = None;
        feature.artifact_handles[0].evidence_test_name = None;

        let input = ProductionFeatureCatalogInput {
            schema_version: SCHEMA_VERSION.to_string(),
            code_revision: "test-revision".to_string(),
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            features: vec![feature],
        };

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert!(
            report.events[0]
                .reason
                .contains("missing_evidence_requirements"),
            "Expected missing evidence error, got: {}",
            report.events[0].reason
        );
    }

    #[test]
    fn invalid_evidence_format_rejected() {
        let mut feature = observed_feature_with_evidence(
            "bad_evidence_feature",
            "Bad Evidence Feature",
            "invalid-bead", // Invalid bead ID format
            "xyz",          // Invalid commit hash format
            "",             // Empty test name
            "sha256:1234567890123456789012345678901234567890123456789012345678901234",
        );

        let input = ProductionFeatureCatalogInput {
            schema_version: SCHEMA_VERSION.to_string(),
            code_revision: "test-revision".to_string(),
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            features: vec![feature],
        };

        let report = evaluate_production_feature_catalog(&input);

        assert_eq!(
            report.decision,
            ProductionFeatureCatalogDecision::FailClosed
        );
        assert!(
            report.events[0]
                .reason
                .contains("invalid_evidence_bead_id_format")
                || report.events[0]
                    .reason
                    .contains("invalid_evidence_commit_hash_format")
                || report.events[0]
                    .reason
                    .contains("missing_evidence_test_name"),
            "Expected evidence format validation error, got: {}",
            report.events[0].reason
        );
    }

    #[test]
    fn is_fake_hash_detection_comprehensive() {
        let fake_hashes = [
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];

        for fake_hash in &fake_hashes {
            assert!(
                is_fake_hash(fake_hash),
                "Should detect {} as fake hash",
                fake_hash
            );
        }

        // Real hashes should not be detected as fake
        let real_hashes = [
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        ];

        for real_hash in &real_hashes {
            assert!(
                !is_fake_hash(real_hash),
                "Should not detect {} as fake hash",
                real_hash
            );
        }
    }
}
