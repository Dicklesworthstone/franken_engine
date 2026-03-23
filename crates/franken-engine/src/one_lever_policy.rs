//! Deterministic one-lever performance policy gate for Section 10.6 (`bd-2l6`).
//!
//! This module enforces optimization hygiene:
//! - exactly one optimization lever per change unless explicitly overridden
//! - required baseline/after and semantic-equivalence evidence
//! - opportunity-score threshold (`>= 2.0`)
//! - rollback and post-merge re-profile readiness

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ONE_LEVER_POLICY_COMPONENT: &str = "one_lever_policy_gate";
pub const ONE_LEVER_POLICY_SCHEMA_VERSION: &str = "franken-engine.one-lever-policy.v1";
pub const ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS: i64 = 2_000_000; // 2.0

pub const ERROR_INVALID_REQUEST: &str = "FE-1LEV-1001";
pub const ERROR_MULTI_LEVER_VIOLATION: &str = "FE-1LEV-1002";
pub const ERROR_MISSING_EVIDENCE: &str = "FE-1LEV-1003";
pub const ERROR_SCORE_BELOW_THRESHOLD: &str = "FE-1LEV-1004";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeverCategory {
    Execution,
    Memory,
    Security,
    Benchmark,
    Config,
}

impl LeverCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Memory => "memory",
            Self::Security => "security",
            Self::Benchmark => "benchmark",
            Self::Config => "config",
        }
    }
}

impl fmt::Display for LeverCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OneLeverEvidenceRefs {
    pub baseline_benchmark_run_id: Option<String>,
    pub post_change_benchmark_run_id: Option<String>,
    pub delta_report_ref: Option<String>,
    pub semantic_equivalence_ref: Option<String>,
    pub trace_replay_ref: Option<String>,
    pub isomorphism_ledger_ref: Option<String>,
    pub rollback_instructions_ref: Option<String>,
    pub reprofile_after_merge_ref: Option<String>,
    pub opportunity_score_millionths: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneLeverPolicyRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub commit_sha: String,
    pub commit_message: String,
    pub changed_paths: Vec<String>,
    pub evidence: OneLeverEvidenceRefs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLeverClassification {
    pub path: String,
    pub category: Option<LeverCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneLeverPolicyEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub change_id: Option<String>,
    pub path: Option<String>,
    pub lever_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneLeverPolicyDecision {
    pub schema_version: String,
    pub change_id: Option<String>,
    pub outcome: String,
    pub blocked: bool,
    pub error_code: Option<String>,
    pub optimization_change: bool,
    pub is_multi_lever: bool,
    pub override_reason: Option<String>,
    pub lever_categories: Vec<LeverCategory>,
    pub lever_classification: Vec<PathLeverClassification>,
    pub missing_requirements: Vec<String>,
    pub opportunity_score_millionths: Option<i64>,
    pub score_threshold_millionths: i64,
    pub events: Vec<OneLeverPolicyEvent>,
}

impl OneLeverPolicyDecision {
    pub fn allows_change(&self) -> bool {
        self.outcome == "allow"
    }
}

#[derive(Debug)]
struct EvaluationContext {
    lever_classification: Vec<PathLeverClassification>,
    lever_categories: Vec<LeverCategory>,
    optimization_change: bool,
    is_multi_lever: bool,
    override_reason: Option<String>,
    missing_requirements: Vec<String>,
    opportunity_score_millionths: Option<i64>,
}

/// Evaluate one-lever performance policy constraints for a change.
pub fn evaluate_one_lever_policy(request: &OneLeverPolicyRequest) -> OneLeverPolicyDecision {
    let mut normalized = request.clone();
    normalize_request(&mut normalized);

    let mut events = vec![make_event(
        &normalized,
        "one_lever_policy_started",
        "pass",
        None,
        None,
        None,
        None,
    )];

    if let Some(validation_error) = validate_request(&normalized) {
        events.push(make_event(
            &normalized,
            "one_lever_policy_completed",
            "fail",
            Some(ERROR_INVALID_REQUEST.to_string()),
            None,
            None,
            None,
        ));

        return OneLeverPolicyDecision {
            schema_version: ONE_LEVER_POLICY_SCHEMA_VERSION.to_string(),
            change_id: None,
            outcome: "fail".to_string(),
            blocked: true,
            error_code: Some(ERROR_INVALID_REQUEST.to_string()),
            optimization_change: false,
            is_multi_lever: false,
            override_reason: None,
            lever_categories: Vec::new(),
            lever_classification: Vec::new(),
            missing_requirements: vec![validation_error],
            opportunity_score_millionths: None,
            score_threshold_millionths: ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS,
            events,
        };
    }

    let change_id = build_change_id(&normalized);
    let eval = evaluate_policy(&normalized);

    for path in &eval.lever_classification {
        events.push(make_event(
            &normalized,
            "changed_path_classified",
            "pass",
            None,
            Some(change_id.clone()),
            Some(path.path.clone()),
            path.category.map(|c| c.to_string()),
        ));
    }

    let mut error_code = None;
    let outcome = if eval.is_multi_lever && eval.override_reason.is_none() {
        error_code = Some(ERROR_MULTI_LEVER_VIOLATION.to_string());
        "deny"
    } else if !eval.missing_requirements.is_empty() {
        error_code = Some(ERROR_MISSING_EVIDENCE.to_string());
        "deny"
    } else if let Some(score) = eval.opportunity_score_millionths {
        if eval.optimization_change && score < ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS {
            error_code = Some(ERROR_SCORE_BELOW_THRESHOLD.to_string());
            "deny"
        } else {
            "allow"
        }
    } else if eval.optimization_change {
        error_code = Some(ERROR_MISSING_EVIDENCE.to_string());
        "deny"
    } else {
        "allow"
    };

    events.push(make_event(
        &normalized,
        "one_lever_policy_completed",
        outcome,
        error_code.clone(),
        Some(change_id.clone()),
        None,
        None,
    ));

    OneLeverPolicyDecision {
        schema_version: ONE_LEVER_POLICY_SCHEMA_VERSION.to_string(),
        change_id: Some(change_id),
        outcome: outcome.to_string(),
        blocked: outcome != "allow",
        error_code,
        optimization_change: eval.optimization_change,
        is_multi_lever: eval.is_multi_lever,
        override_reason: eval.override_reason,
        lever_categories: eval.lever_categories,
        lever_classification: eval.lever_classification,
        missing_requirements: eval.missing_requirements,
        opportunity_score_millionths: eval.opportunity_score_millionths,
        score_threshold_millionths: ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS,
        events,
    }
}

fn evaluate_policy(request: &OneLeverPolicyRequest) -> EvaluationContext {
    let mut classification = request
        .changed_paths
        .iter()
        .map(|path| PathLeverClassification {
            path: path.clone(),
            category: classify_changed_path(path),
        })
        .collect::<Vec<_>>();

    classification.sort_by(|left, right| left.path.cmp(&right.path));

    let mut categories = classification
        .iter()
        .filter_map(|entry| entry.category)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    categories.sort();

    let optimization_change = !categories.is_empty();
    let is_multi_lever = categories.len() > 1;
    let override_reason = if is_multi_lever {
        extract_override_reason(&request.commit_message)
    } else {
        None
    };

    let mut missing_requirements = Vec::new();
    if optimization_change {
        if request.evidence.baseline_benchmark_run_id.is_none() {
            missing_requirements.push("baseline_benchmark_run_id".to_string());
        }
        if request.evidence.post_change_benchmark_run_id.is_none() {
            missing_requirements.push("post_change_benchmark_run_id".to_string());
        }
        if request.evidence.delta_report_ref.is_none() {
            missing_requirements.push("delta_report_ref".to_string());
        }
        if request.evidence.semantic_equivalence_ref.is_none() {
            missing_requirements.push("semantic_equivalence_ref".to_string());
        }
        if request.evidence.trace_replay_ref.is_none() {
            missing_requirements.push("trace_replay_ref".to_string());
        }
        if request.evidence.isomorphism_ledger_ref.is_none() {
            missing_requirements.push("isomorphism_ledger_ref".to_string());
        }
        if request.evidence.rollback_instructions_ref.is_none() {
            missing_requirements.push("rollback_instructions_ref".to_string());
        }
        if request.evidence.reprofile_after_merge_ref.is_none() {
            missing_requirements.push("reprofile_after_merge_ref".to_string());
        }
        if request.evidence.opportunity_score_millionths.is_none() {
            missing_requirements.push("opportunity_score_millionths".to_string());
        }
    }

    EvaluationContext {
        lever_classification: classification,
        lever_categories: categories,
        optimization_change,
        is_multi_lever,
        override_reason,
        missing_requirements,
        opportunity_score_millionths: request.evidence.opportunity_score_millionths,
    }
}

fn validate_request(request: &OneLeverPolicyRequest) -> Option<String> {
    if request.trace_id.is_empty() {
        return Some("trace_id must not be empty".to_string());
    }
    if request.decision_id.is_empty() {
        return Some("decision_id must not be empty".to_string());
    }
    if request.policy_id.is_empty() {
        return Some("policy_id must not be empty".to_string());
    }
    if request.commit_sha.is_empty() {
        return Some("commit_sha must not be empty".to_string());
    }
    if request.changed_paths.is_empty() {
        return Some("changed_paths must include at least one path".to_string());
    }
    None
}

fn make_event(
    request: &OneLeverPolicyRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    change_id: Option<String>,
    path: Option<String>,
    lever_category: Option<String>,
) -> OneLeverPolicyEvent {
    OneLeverPolicyEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: ONE_LEVER_POLICY_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        change_id,
        path,
        lever_category,
    }
}

fn normalize_request(request: &mut OneLeverPolicyRequest) {
    request.trace_id = request.trace_id.trim().to_string();
    request.decision_id = request.decision_id.trim().to_string();
    request.policy_id = request.policy_id.trim().to_string();
    request.commit_sha = request.commit_sha.trim().to_string();
    request.commit_message = request.commit_message.trim().to_string();

    request.changed_paths = request
        .changed_paths
        .iter()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    normalize_opt_field(&mut request.evidence.baseline_benchmark_run_id);
    normalize_opt_field(&mut request.evidence.post_change_benchmark_run_id);
    normalize_opt_field(&mut request.evidence.delta_report_ref);
    normalize_opt_field(&mut request.evidence.semantic_equivalence_ref);
    normalize_opt_field(&mut request.evidence.trace_replay_ref);
    normalize_opt_field(&mut request.evidence.isomorphism_ledger_ref);
    normalize_opt_field(&mut request.evidence.rollback_instructions_ref);
    normalize_opt_field(&mut request.evidence.reprofile_after_merge_ref);
}

fn normalize_opt_field(field: &mut Option<String>) {
    let Some(value) = field.as_ref() else {
        return;
    };
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        *field = None;
    } else {
        *field = Some(normalized);
    }
}

fn classify_changed_path(path: &str) -> Option<LeverCategory> {
    let lower = path.to_ascii_lowercase();

    let ext = std::path::Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str());
    if lower.starts_with("docs/")
        || lower.starts_with("artifacts/")
        || lower.starts_with(".beads/")
        || lower.starts_with(".github/workflows/")
        || ext == Some("md")
        || lower.ends_with("/readme")
        || lower.contains("/tests/")
        || lower.starts_with("scripts/check_")
        || lower.contains("workflow")
    {
        return None;
    }

    if lower.starts_with("scripts/") {
        if lower.contains("benchmark")
            || lower.contains("flamegraph")
            || lower.contains("performance")
            || lower.contains("opportunity")
        {
            return Some(LeverCategory::Benchmark);
        }
        return None;
    }

    if lower.contains("benchmark")
        || lower.contains("flamegraph")
        || lower.contains("opportunity")
        || lower.contains("performance")
    {
        return Some(LeverCategory::Benchmark);
    }

    if lower.contains("gc")
        || lower.contains("alloc")
        || lower.contains("memory")
        || lower.contains("heap")
    {
        return Some(LeverCategory::Memory);
    }

    if lower.contains("policy")
        || lower.contains("guard")
        || lower.contains("security")
        || lower.contains("ifc")
        || lower.contains("capability")
        || lower.contains("revocation")
        || lower.contains("quarantine")
        || lower.contains("attestation")
        || lower.contains("declassification")
    {
        return Some(LeverCategory::Security);
    }

    if matches!(
        ext,
        Some("toml") | Some("json") | Some("yaml") | Some("yml") | Some("ron")
    ) {
        return Some(LeverCategory::Config);
    }

    if lower.starts_with("crates/franken-engine/src/")
        || lower.starts_with("crates/franken-extension-host/src/")
        || lower.contains("parser")
        || lower.contains("interpreter")
        || lower.contains("ir_")
        || lower.contains("execution")
        || lower.contains("scheduler")
        || lower.contains("object_model")
    {
        return Some(LeverCategory::Execution);
    }

    None
}

fn extract_override_reason(commit_message: &str) -> Option<String> {
    let lowered = commit_message.to_ascii_lowercase();
    let marker = "[multi-lever:";
    let start = lowered.find(marker)? + marker.len();
    let end = lowered[start..].rfind(']')? + start;
    let reason = commit_message.get(start..end)?.trim();
    if reason.is_empty() {
        None
    } else {
        Some(reason.to_string())
    }
}

fn build_change_id(request: &OneLeverPolicyRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.trace_id.as_bytes());
    hasher.update(request.decision_id.as_bytes());
    hasher.update(request.policy_id.as_bytes());
    hasher.update(request.commit_sha.as_bytes());
    hasher.update(request.commit_message.as_bytes());

    for path in &request.changed_paths {
        hasher.update(path.as_bytes());
    }

    hash_optional_field(&mut hasher, &request.evidence.baseline_benchmark_run_id);
    hash_optional_field(&mut hasher, &request.evidence.post_change_benchmark_run_id);
    hash_optional_field(&mut hasher, &request.evidence.delta_report_ref);
    hash_optional_field(&mut hasher, &request.evidence.semantic_equivalence_ref);
    hash_optional_field(&mut hasher, &request.evidence.trace_replay_ref);
    hash_optional_field(&mut hasher, &request.evidence.isomorphism_ledger_ref);
    hash_optional_field(&mut hasher, &request.evidence.rollback_instructions_ref);
    hash_optional_field(&mut hasher, &request.evidence.reprofile_after_merge_ref);

    if let Some(score) = request.evidence.opportunity_score_millionths {
        hasher.update(score.to_le_bytes());
    }

    format!("olp-{:x}", hasher.finalize())
}

fn hash_optional_field(hasher: &mut Sha256, field: &Option<String>) {
    if let Some(value) = field {
        hasher.update(value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn non_opt_request() -> OneLeverPolicyRequest {
        // Changes only docs → not an optimization change
        OneLeverPolicyRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            commit_sha: "abc123".to_string(),
            commit_message: "docs: update readme".to_string(),
            changed_paths: vec!["docs/design.md".to_string()],
            evidence: OneLeverEvidenceRefs::default(),
        }
    }

    fn full_evidence(score: i64) -> OneLeverEvidenceRefs {
        OneLeverEvidenceRefs {
            baseline_benchmark_run_id: Some("baseline-001".to_string()),
            post_change_benchmark_run_id: Some("post-001".to_string()),
            delta_report_ref: Some("delta-001".to_string()),
            semantic_equivalence_ref: Some("equiv-001".to_string()),
            trace_replay_ref: Some("replay-001".to_string()),
            isomorphism_ledger_ref: Some("iso-001".to_string()),
            rollback_instructions_ref: Some("rollback-001".to_string()),
            reprofile_after_merge_ref: Some("reprofile-001".to_string()),
            opportunity_score_millionths: Some(score),
        }
    }

    fn single_lever_opt_request(score: i64) -> OneLeverPolicyRequest {
        OneLeverPolicyRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            commit_sha: "abc123".to_string(),
            commit_message: "perf: optimize interpreter".to_string(),
            changed_paths: vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()],
            evidence: full_evidence(score),
        }
    }

    // ── LeverCategory ───────────────────────────────────────────────

    #[test]
    fn lever_category_as_str() {
        assert_eq!(LeverCategory::Execution.as_str(), "execution");
        assert_eq!(LeverCategory::Memory.as_str(), "memory");
        assert_eq!(LeverCategory::Security.as_str(), "security");
        assert_eq!(LeverCategory::Benchmark.as_str(), "benchmark");
        assert_eq!(LeverCategory::Config.as_str(), "config");
    }

    #[test]
    fn lever_category_display() {
        assert_eq!(format!("{}", LeverCategory::Execution), "execution");
        assert_eq!(format!("{}", LeverCategory::Config), "config");
    }

    #[test]
    fn lever_category_ordering() {
        assert!(LeverCategory::Execution < LeverCategory::Memory);
        assert!(LeverCategory::Memory < LeverCategory::Security);
        assert!(LeverCategory::Security < LeverCategory::Benchmark);
        assert!(LeverCategory::Benchmark < LeverCategory::Config);
    }

    #[test]
    fn lever_category_serde_roundtrip() {
        for cat in [
            LeverCategory::Execution,
            LeverCategory::Memory,
            LeverCategory::Security,
            LeverCategory::Benchmark,
            LeverCategory::Config,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: LeverCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cat);
        }
    }

    // ── constants ───────────────────────────────────────────────────

    #[test]
    fn constants_stable() {
        assert_eq!(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS, 2_000_000);
        assert_eq!(ERROR_INVALID_REQUEST, "FE-1LEV-1001");
        assert_eq!(ERROR_MULTI_LEVER_VIOLATION, "FE-1LEV-1002");
        assert_eq!(ERROR_MISSING_EVIDENCE, "FE-1LEV-1003");
        assert_eq!(ERROR_SCORE_BELOW_THRESHOLD, "FE-1LEV-1004");
    }

    // ── classify_changed_path ───────────────────────────────────────

    #[test]
    fn classify_docs_and_tests_as_exempt() {
        assert_eq!(classify_changed_path("docs/design.md"), None);
        assert_eq!(
            classify_changed_path("crates/franken-engine/tests/one_lever_policy.rs"),
            None
        );
    }

    #[test]
    fn classify_execution_memory_security_benchmark() {
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/baseline_interpreter.rs"),
            Some(LeverCategory::Execution)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/gc_pause.rs"),
            Some(LeverCategory::Memory)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/policy_controller.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/opportunity_matrix.rs"),
            Some(LeverCategory::Benchmark)
        );
    }

    #[test]
    fn classify_config_files() {
        assert_eq!(
            classify_changed_path("Cargo.toml"),
            Some(LeverCategory::Config)
        );
        assert_eq!(
            classify_changed_path("settings.yaml"),
            Some(LeverCategory::Config)
        );
        assert_eq!(
            classify_changed_path("config.json"),
            Some(LeverCategory::Config)
        );
    }

    #[test]
    fn classify_artifacts_beads_workflows_exempt() {
        assert_eq!(classify_changed_path("artifacts/report.txt"), None);
        assert_eq!(classify_changed_path(".beads/issues.jsonl"), None);
        assert_eq!(classify_changed_path(".github/workflows/ci.yml"), None);
    }

    #[test]
    fn classify_scripts_benchmark_is_benchmark() {
        assert_eq!(
            classify_changed_path("scripts/run_benchmark.sh"),
            Some(LeverCategory::Benchmark)
        );
    }

    #[test]
    fn classify_scripts_check_exempt() {
        assert_eq!(classify_changed_path("scripts/check_lint.sh"), None);
    }

    #[test]
    fn classify_unknown_path_none() {
        assert_eq!(classify_changed_path("random/unknown.txt"), None);
    }

    // ── extract_override_reason ─────────────────────────────────────

    #[test]
    fn extract_override_reason_parses_tag() {
        let message = "perf: coupled fix [multi-lever: scheduler and gc are inseparable]";
        assert_eq!(
            extract_override_reason(message),
            Some("scheduler and gc are inseparable".to_string())
        );
        assert_eq!(extract_override_reason("perf: single lever"), None);
    }

    #[test]
    fn extract_override_reason_empty_reason_returns_none() {
        assert_eq!(extract_override_reason("[multi-lever: ]"), None);
    }

    #[test]
    fn extract_override_reason_case_insensitive_marker() {
        let message = "fix: [MULTI-LEVER: both needed]";
        assert_eq!(
            extract_override_reason(message),
            Some("both needed".to_string())
        );
    }

    // ── normalize_request ───────────────────────────────────────────

    #[test]
    fn normalize_trims_fields() {
        let mut req = OneLeverPolicyRequest {
            trace_id: "  t-1  ".to_string(),
            decision_id: " d-1 ".to_string(),
            policy_id: " p-1 ".to_string(),
            commit_sha: " abc ".to_string(),
            commit_message: " msg ".to_string(),
            changed_paths: vec!["  docs/a.md  ".to_string()],
            evidence: OneLeverEvidenceRefs {
                baseline_benchmark_run_id: Some("  x  ".to_string()),
                ..OneLeverEvidenceRefs::default()
            },
        };
        normalize_request(&mut req);
        assert_eq!(req.trace_id, "t-1");
        assert_eq!(req.commit_sha, "abc");
        assert_eq!(req.changed_paths, vec!["docs/a.md"]);
        assert_eq!(
            req.evidence.baseline_benchmark_run_id,
            Some("x".to_string())
        );
    }

    #[test]
    fn normalize_empty_opt_field_becomes_none() {
        let mut req = non_opt_request();
        req.evidence.baseline_benchmark_run_id = Some("  ".to_string());
        normalize_request(&mut req);
        assert!(req.evidence.baseline_benchmark_run_id.is_none());
    }

    #[test]
    fn normalize_deduplicates_paths() {
        let mut req = non_opt_request();
        req.changed_paths = vec![
            "docs/a.md".to_string(),
            "docs/a.md".to_string(),
            "docs/b.md".to_string(),
        ];
        normalize_request(&mut req);
        assert_eq!(req.changed_paths.len(), 2);
    }

    // ── evaluate_one_lever_policy: validation ───────────────────────

    #[test]
    fn validation_empty_trace_id() {
        let mut req = non_opt_request();
        req.trace_id = "".to_string();
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
        assert!(decision.missing_requirements[0].contains("trace_id"));
    }

    #[test]
    fn validation_empty_decision_id() {
        let mut req = non_opt_request();
        req.decision_id = "  ".to_string();
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
    }

    #[test]
    fn validation_empty_commit_sha() {
        let mut req = non_opt_request();
        req.commit_sha = "".to_string();
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
    }

    #[test]
    fn validation_empty_changed_paths() {
        let mut req = non_opt_request();
        req.changed_paths = Vec::new();
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
    }

    #[test]
    fn validation_whitespace_only_paths_removed() {
        let mut req = non_opt_request();
        req.changed_paths = vec!["  ".to_string()];
        // After normalization, changed_paths is empty → validation fails
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
    }

    // ── evaluate_one_lever_policy: non-optimization ─────────────────

    #[test]
    fn non_optimization_change_allowed() {
        let req = non_opt_request();
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.allows_change());
        assert!(!decision.blocked);
        assert_eq!(decision.outcome, "allow");
        assert!(!decision.optimization_change);
        assert!(decision.missing_requirements.is_empty());
    }

    // ── evaluate_one_lever_policy: single lever ─────────────────────

    #[test]
    fn single_lever_with_full_evidence_above_threshold() {
        let req = single_lever_opt_request(3_000_000); // 3.0 > 2.0
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.allows_change());
        assert!(decision.optimization_change);
        assert!(!decision.is_multi_lever);
        assert_eq!(decision.lever_categories, vec![LeverCategory::Execution]);
    }

    #[test]
    fn single_lever_exactly_at_threshold() {
        let req = single_lever_opt_request(2_000_000); // exactly 2.0
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.allows_change());
    }

    #[test]
    fn single_lever_below_threshold_denied() {
        let req = single_lever_opt_request(1_999_999); // just below 2.0
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert!(decision.blocked);
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_SCORE_BELOW_THRESHOLD)
        );
    }

    #[test]
    fn single_lever_missing_evidence_denied() {
        let mut req = single_lever_opt_request(3_000_000);
        req.evidence.baseline_benchmark_run_id = None;
        req.evidence.delta_report_ref = None;
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
        assert!(
            decision
                .missing_requirements
                .contains(&"baseline_benchmark_run_id".to_string())
        );
        assert!(
            decision
                .missing_requirements
                .contains(&"delta_report_ref".to_string())
        );
    }

    #[test]
    fn single_lever_no_score_denied() {
        let mut req = single_lever_opt_request(3_000_000);
        req.evidence.opportunity_score_millionths = None;
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    }

    // ── evaluate_one_lever_policy: multi-lever ──────────────────────

    #[test]
    fn multi_lever_without_override_denied() {
        let req = OneLeverPolicyRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            commit_sha: "abc".to_string(),
            commit_message: "perf: touches multiple levers".to_string(),
            changed_paths: vec![
                "crates/franken-engine/src/baseline_interpreter.rs".to_string(), // Execution
                "crates/franken-engine/src/gc_pause.rs".to_string(),             // Memory
            ],
            evidence: full_evidence(5_000_000),
        };
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert!(decision.is_multi_lever);
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_MULTI_LEVER_VIOLATION)
        );
    }

    #[test]
    fn multi_lever_with_override_allowed() {
        let req = OneLeverPolicyRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            commit_sha: "abc".to_string(),
            commit_message: "perf: coupled fix [multi-lever: gc and interpreter are inseparable]"
                .to_string(),
            changed_paths: vec![
                "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
                "crates/franken-engine/src/gc_pause.rs".to_string(),
            ],
            evidence: full_evidence(5_000_000),
        };
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.allows_change());
        assert!(decision.is_multi_lever);
        assert_eq!(
            decision.override_reason.as_deref(),
            Some("gc and interpreter are inseparable")
        );
    }

    // ── evaluate_one_lever_policy: metadata ─────────────────────────

    #[test]
    fn decision_has_schema_version() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        assert_eq!(decision.schema_version, ONE_LEVER_POLICY_SCHEMA_VERSION);
    }

    #[test]
    fn decision_has_change_id() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        assert!(decision.change_id.is_some());
        assert!(decision.change_id.unwrap().starts_with("olp-"));
    }

    #[test]
    fn decision_change_id_deterministic() {
        let req = non_opt_request();
        let d1 = evaluate_one_lever_policy(&req);
        let d2 = evaluate_one_lever_policy(&req);
        assert_eq!(d1.change_id, d2.change_id);
    }

    #[test]
    fn decision_has_events() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        assert!(decision.events.len() >= 2); // started + completed
        assert_eq!(decision.events[0].component, ONE_LEVER_POLICY_COMPONENT);
        assert_eq!(decision.events[0].event, "one_lever_policy_started");
    }

    #[test]
    fn decision_lever_classification_populated() {
        let req = single_lever_opt_request(3_000_000);
        let decision = evaluate_one_lever_policy(&req);
        assert_eq!(decision.lever_classification.len(), 1);
        assert_eq!(
            decision.lever_classification[0].category,
            Some(LeverCategory::Execution)
        );
    }

    #[test]
    fn decision_score_threshold_always_set() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        assert_eq!(
            decision.score_threshold_millionths,
            ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS
        );
    }

    // ── serde roundtrips ────────────────────────────────────────────

    #[test]
    fn evidence_refs_serde() {
        let ev = full_evidence(3_000_000);
        let json = serde_json::to_string(&ev).unwrap();
        let back: OneLeverEvidenceRefs = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn policy_request_serde() {
        let req = single_lever_opt_request(3_000_000);
        let json = serde_json::to_string(&req).unwrap();
        let back: OneLeverPolicyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn policy_decision_serde() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        let json = serde_json::to_string(&decision).unwrap();
        let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.outcome, decision.outcome);
        assert_eq!(back.blocked, decision.blocked);
    }

    #[test]
    fn path_lever_classification_serde() {
        let plc = PathLeverClassification {
            path: "src/foo.rs".to_string(),
            category: Some(LeverCategory::Execution),
        };
        let json = serde_json::to_string(&plc).unwrap();
        let back: PathLeverClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plc);
    }

    #[test]
    fn policy_event_serde() {
        let ev = OneLeverPolicyEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            change_id: Some("change".to_string()),
            path: None,
            lever_category: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: OneLeverPolicyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    // -- Enrichment: Display uniqueness, defaults, boundary, std::error --

    #[test]
    fn lever_category_display_all_unique() {
        let categories = [
            LeverCategory::Execution,
            LeverCategory::Memory,
            LeverCategory::Security,
            LeverCategory::Benchmark,
            LeverCategory::Config,
        ];
        let displays: std::collections::BTreeSet<String> =
            categories.iter().map(|c| c.to_string()).collect();
        assert_eq!(displays.len(), categories.len());
    }

    #[test]
    fn evidence_refs_default_all_none() {
        let ev = OneLeverEvidenceRefs::default();
        assert!(ev.baseline_benchmark_run_id.is_none());
        assert!(ev.post_change_benchmark_run_id.is_none());
        assert!(ev.delta_report_ref.is_none());
        assert!(ev.semantic_equivalence_ref.is_none());
        assert!(ev.trace_replay_ref.is_none());
        assert!(ev.isomorphism_ledger_ref.is_none());
        assert!(ev.rollback_instructions_ref.is_none());
        assert!(ev.reprofile_after_merge_ref.is_none());
        assert!(ev.opportunity_score_millionths.is_none());
    }

    #[test]
    fn policy_decision_deterministic_for_same_input() {
        let req = single_lever_opt_request(3_000_000);
        let d1 = evaluate_one_lever_policy(&req);
        let d2 = evaluate_one_lever_policy(&req);
        assert_eq!(d1.outcome, d2.outcome);
        assert_eq!(d1.blocked, d2.blocked);
        assert_eq!(d1.change_id, d2.change_id);
        assert_eq!(d1.lever_categories, d2.lever_categories);
    }

    #[test]
    fn classify_security_related_paths() {
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/capability_witness.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/quarantine_mesh_gate.rs"),
            Some(LeverCategory::Security)
        );
    }

    #[test]
    fn multi_lever_categories_sorted_deterministically() {
        let req = OneLeverPolicyRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            commit_sha: "abc".to_string(),
            commit_message: "perf: multi [multi-lever: coupled]".to_string(),
            changed_paths: vec![
                "crates/franken-engine/src/gc_pause.rs".to_string(),
                "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
            ],
            evidence: full_evidence(5_000_000),
        };
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.is_multi_lever);
        // Categories should be sorted: Execution < Memory
        assert_eq!(decision.lever_categories[0], LeverCategory::Execution);
        assert_eq!(decision.lever_categories[1], LeverCategory::Memory);
    }

    #[test]
    fn policy_decision_serde_roundtrip_full() {
        let req = single_lever_opt_request(3_000_000);
        let decision = evaluate_one_lever_policy(&req);
        let json = serde_json::to_string(&decision).unwrap();
        let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn extract_override_reason_handles_nested_brackets() {
        let msg = "fix: [multi-lever: [a] and [b] coupled]";
        let reason = extract_override_reason(msg);
        // Should capture everything after "multi-lever:" up to the last "]"
        assert!(reason.is_some());
    }

    #[test]
    fn non_optimization_change_has_no_lever_categories() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        assert!(decision.lever_categories.is_empty());
        assert!(!decision.optimization_change);
    }

    // ── Enrichment: clone equality ──────────────────────────────────

    #[test]
    fn enrichment_clone_eq_lever_category() {
        let a = LeverCategory::Security;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_evidence_refs() {
        let a = full_evidence(1_500_000);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_policy_request() {
        let a = single_lever_opt_request(2_500_000);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_path_lever_classification() {
        let a = PathLeverClassification {
            path: "crates/franken-engine/src/parser.rs".to_string(),
            category: Some(LeverCategory::Execution),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_policy_event() {
        let a = OneLeverPolicyEvent {
            trace_id: "t-99".to_string(),
            decision_id: "d-99".to_string(),
            policy_id: "p-99".to_string(),
            component: ONE_LEVER_POLICY_COMPONENT.to_string(),
            event: "test_event".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("FE-1LEV-1001".to_string()),
            change_id: None,
            path: Some("src/foo.rs".to_string()),
            lever_category: Some("execution".to_string()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── Enrichment: JSON field presence ─────────────────────────────

    #[test]
    fn enrichment_json_field_presence_evidence_refs() {
        let ev = full_evidence(4_200_000);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("baseline_benchmark_run_id"));
        assert!(json.contains("post_change_benchmark_run_id"));
        assert!(json.contains("opportunity_score_millionths"));
        assert!(json.contains("rollback_instructions_ref"));
        assert!(json.contains("reprofile_after_merge_ref"));
    }

    #[test]
    fn enrichment_json_field_presence_policy_request() {
        let req = single_lever_opt_request(3_000_000);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("trace_id"));
        assert!(json.contains("decision_id"));
        assert!(json.contains("commit_sha"));
        assert!(json.contains("changed_paths"));
        assert!(json.contains("evidence"));
    }

    #[test]
    fn enrichment_json_field_presence_policy_decision() {
        let decision = evaluate_one_lever_policy(&single_lever_opt_request(3_000_000));
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("lever_categories"));
        assert!(json.contains("lever_classification"));
        assert!(json.contains("score_threshold_millionths"));
        assert!(json.contains("optimization_change"));
    }

    // ── Enrichment: serde roundtrip (decision with deny) ────────────

    #[test]
    fn enrichment_serde_roundtrip_denied_decision() {
        let req = single_lever_opt_request(500_000); // below threshold
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
        let json = serde_json::to_string(&decision).unwrap();
        let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    // ── Enrichment: Display uniqueness ──────────────────────────────

    #[test]
    fn enrichment_display_uniqueness_lever_category_as_str() {
        let all = [
            LeverCategory::Execution,
            LeverCategory::Memory,
            LeverCategory::Security,
            LeverCategory::Benchmark,
            LeverCategory::Config,
        ];
        let strs: BTreeSet<&str> = all.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), all.len());
    }

    // ── Enrichment: boundary condition ──────────────────────────────

    #[test]
    fn enrichment_boundary_zero_score_denied() {
        let req = single_lever_opt_request(0);
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert!(decision.blocked);
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_SCORE_BELOW_THRESHOLD)
        );
        assert_eq!(decision.opportunity_score_millionths, Some(0));
    }

    // ── Enrichment: Ord determinism ─────────────────────────────────

    #[test]
    fn enrichment_ord_determinism_lever_category() {
        let mut cats = vec![
            LeverCategory::Config,
            LeverCategory::Execution,
            LeverCategory::Benchmark,
            LeverCategory::Memory,
            LeverCategory::Security,
        ];
        let mut cats2 = cats.clone();
        cats.sort();
        cats2.sort();
        assert_eq!(cats, cats2);
        // Verify canonical order
        assert_eq!(
            cats,
            vec![
                LeverCategory::Execution,
                LeverCategory::Memory,
                LeverCategory::Security,
                LeverCategory::Benchmark,
                LeverCategory::Config,
            ]
        );
    }

    // ── Enrichment batch 2: Copy semantics, JSON field names, edge cases ──

    #[test]
    fn enrichment_lever_category_copy_semantics() {
        let a = LeverCategory::Memory;
        let b = a; // Copy
        let c = a; // still usable after copy
        assert_eq!(b, c);
        assert_eq!(a, LeverCategory::Memory);
    }

    #[test]
    fn enrichment_lever_category_serde_snake_case_field_names() {
        let json = serde_json::to_string(&LeverCategory::Execution).unwrap();
        assert_eq!(json, "\"execution\"");
        let json = serde_json::to_string(&LeverCategory::Memory).unwrap();
        assert_eq!(json, "\"memory\"");
        let json = serde_json::to_string(&LeverCategory::Security).unwrap();
        assert_eq!(json, "\"security\"");
        let json = serde_json::to_string(&LeverCategory::Benchmark).unwrap();
        assert_eq!(json, "\"benchmark\"");
        let json = serde_json::to_string(&LeverCategory::Config).unwrap();
        assert_eq!(json, "\"config\"");
    }

    #[test]
    fn enrichment_evidence_refs_clone_inequality() {
        let a = full_evidence(1_000_000);
        let mut b = a.clone();
        b.opportunity_score_millionths = Some(2_000_000);
        assert_ne!(a, b);
    }

    #[test]
    fn enrichment_policy_event_json_field_presence() {
        let ev = OneLeverPolicyEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "comp".to_string(),
            event: "started".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("ERR-1".to_string()),
            change_id: Some("chg-1".to_string()),
            path: Some("/a/b.rs".to_string()),
            lever_category: Some("execution".to_string()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
        assert!(json.contains("\"change_id\""));
        assert!(json.contains("\"path\""));
        assert!(json.contains("\"lever_category\""));
    }

    #[test]
    fn enrichment_policy_decision_clone_eq() {
        let req = single_lever_opt_request(3_000_000);
        let decision = evaluate_one_lever_policy(&req);
        let cloned = decision.clone();
        assert_eq!(decision, cloned);
    }

    #[test]
    fn enrichment_path_lever_classification_none_category_serde() {
        let plc = PathLeverClassification {
            path: "docs/readme.md".to_string(),
            category: None,
        };
        let json = serde_json::to_string(&plc).unwrap();
        let back: PathLeverClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plc);
        assert!(json.contains("\"category\":null"));
    }

    #[test]
    fn enrichment_classify_security_keywords_extended() {
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/ifc_artifacts.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/revocation_enforcement.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/attestation_policy.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/declassification_pipeline.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/guard_plane.rs"),
            Some(LeverCategory::Security)
        );
    }

    #[test]
    fn enrichment_classify_memory_keywords_extended() {
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/alloc_pool.rs"),
            Some(LeverCategory::Memory)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/heap_manager.rs"),
            Some(LeverCategory::Memory)
        );
    }

    #[test]
    fn enrichment_classify_execution_keywords_extended() {
        assert_eq!(
            classify_changed_path("some/path/parser_arena.rs"),
            Some(LeverCategory::Execution)
        );
        assert_eq!(
            classify_changed_path("some/path/interpreter_loop.rs"),
            Some(LeverCategory::Execution)
        );
        assert_eq!(
            classify_changed_path("some/path/ir_contract.rs"),
            Some(LeverCategory::Execution)
        );
        assert_eq!(
            classify_changed_path("some/path/scheduler_core.rs"),
            Some(LeverCategory::Execution)
        );
        assert_eq!(
            classify_changed_path("some/path/object_model.rs"),
            Some(LeverCategory::Execution)
        );
    }

    #[test]
    fn enrichment_classify_config_ron_and_yml() {
        assert_eq!(
            classify_changed_path("config/engine.ron"),
            Some(LeverCategory::Config)
        );
        assert_eq!(
            classify_changed_path("deploy/service.yml"),
            Some(LeverCategory::Config)
        );
    }

    #[test]
    fn enrichment_classify_md_outside_docs_exempt() {
        // .md files are exempt regardless of location
        assert_eq!(
            classify_changed_path("crates/franken-engine/CHANGELOG.md"),
            None
        );
        assert_eq!(classify_changed_path("src/notes.md"), None);
    }

    #[test]
    fn enrichment_classify_scripts_benchmark_variants() {
        assert_eq!(
            classify_changed_path("scripts/run_flamegraph.sh"),
            Some(LeverCategory::Benchmark)
        );
        assert_eq!(
            classify_changed_path("scripts/measure_performance.py"),
            Some(LeverCategory::Benchmark)
        );
        assert_eq!(
            classify_changed_path("scripts/calc_opportunity.sh"),
            Some(LeverCategory::Benchmark)
        );
    }

    #[test]
    fn enrichment_normalize_all_evidence_fields_trimmed() {
        let mut req = non_opt_request();
        req.evidence = OneLeverEvidenceRefs {
            baseline_benchmark_run_id: Some("  base  ".to_string()),
            post_change_benchmark_run_id: Some("  post  ".to_string()),
            delta_report_ref: Some("  delta  ".to_string()),
            semantic_equivalence_ref: Some("  equiv  ".to_string()),
            trace_replay_ref: Some("  trace  ".to_string()),
            isomorphism_ledger_ref: Some("  iso  ".to_string()),
            rollback_instructions_ref: Some("  roll  ".to_string()),
            reprofile_after_merge_ref: Some("  repro  ".to_string()),
            opportunity_score_millionths: Some(1_000_000),
        };
        normalize_request(&mut req);
        assert_eq!(
            req.evidence.baseline_benchmark_run_id.as_deref(),
            Some("base")
        );
        assert_eq!(
            req.evidence.post_change_benchmark_run_id.as_deref(),
            Some("post")
        );
        assert_eq!(req.evidence.delta_report_ref.as_deref(), Some("delta"));
        assert_eq!(
            req.evidence.semantic_equivalence_ref.as_deref(),
            Some("equiv")
        );
        assert_eq!(req.evidence.trace_replay_ref.as_deref(), Some("trace"));
        assert_eq!(req.evidence.isomorphism_ledger_ref.as_deref(), Some("iso"));
        assert_eq!(
            req.evidence.rollback_instructions_ref.as_deref(),
            Some("roll")
        );
        assert_eq!(
            req.evidence.reprofile_after_merge_ref.as_deref(),
            Some("repro")
        );
    }

    #[test]
    fn enrichment_change_id_differs_for_different_requests() {
        let req1 = non_opt_request();
        let mut req2 = non_opt_request();
        req2.commit_sha = "def456".to_string();
        let d1 = evaluate_one_lever_policy(&req1);
        let d2 = evaluate_one_lever_policy(&req2);
        assert_ne!(d1.change_id, d2.change_id);
    }

    #[test]
    fn enrichment_multi_lever_override_below_threshold_denied() {
        // Multi-lever override allows past multi-lever check, but score still matters
        let req = OneLeverPolicyRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            commit_sha: "abc".to_string(),
            commit_message: "perf: [multi-lever: coupled gc and interpreter]".to_string(),
            changed_paths: vec![
                "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
                "crates/franken-engine/src/gc_pause.rs".to_string(),
            ],
            evidence: full_evidence(1_500_000), // below 2.0 threshold
        };
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert!(decision.blocked);
        assert!(decision.is_multi_lever);
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_SCORE_BELOW_THRESHOLD)
        );
    }

    #[test]
    fn enrichment_negative_opportunity_score_denied() {
        let req = single_lever_opt_request(-1_000_000);
        let decision = evaluate_one_lever_policy(&req);
        assert!(!decision.allows_change());
        assert!(decision.blocked);
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_SCORE_BELOW_THRESHOLD)
        );
        assert_eq!(decision.opportunity_score_millionths, Some(-1_000_000));
    }

    #[test]
    fn enrichment_events_contain_path_classifications() {
        let req = single_lever_opt_request(3_000_000);
        let decision = evaluate_one_lever_policy(&req);
        // Should have: started, one path classification event, completed
        assert!(decision.events.len() >= 3);
        let classify_events: Vec<_> = decision
            .events
            .iter()
            .filter(|e| e.event == "changed_path_classified")
            .collect();
        assert_eq!(classify_events.len(), 1);
        assert_eq!(
            classify_events[0].lever_category.as_deref(),
            Some("execution")
        );
        assert!(classify_events[0].path.is_some());
    }

    #[test]
    fn enrichment_validation_empty_policy_id_blocked() {
        let mut req = non_opt_request();
        req.policy_id = "   ".to_string();
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.blocked);
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
        assert!(decision.missing_requirements[0].contains("policy_id"));
    }

    #[test]
    fn enrichment_decision_events_json_field_names() {
        let decision = evaluate_one_lever_policy(&non_opt_request());
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"events\""));
        assert!(json.contains("\"missing_requirements\""));
        assert!(json.contains("\"is_multi_lever\""));
        assert!(json.contains("\"override_reason\""));
        assert!(json.contains("\"blocked\""));
        assert!(json.contains("\"error_code\""));
    }

    #[test]
    fn enrichment_large_score_above_threshold_allowed() {
        let req = single_lever_opt_request(i64::MAX);
        let decision = evaluate_one_lever_policy(&req);
        assert!(decision.allows_change());
        assert!(!decision.blocked);
        assert_eq!(decision.opportunity_score_millionths, Some(i64::MAX));
    }
}
