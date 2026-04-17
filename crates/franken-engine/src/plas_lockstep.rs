//! Deterministic lockstep checks for PLAS minimal-policy synthesis.
//!
//! Evaluates whether a synthesized minimal capability policy preserves
//! behavior relative to full-manifest execution, while classifying
//! Node/Bun baseline divergences separately from PLAS regressions.
//!
//! Plan reference: Section 10.15 item 11 (`bd-32d3`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

const PLAS_LOCKSTEP_COMPONENT: &str = "plas_lockstep";

/// Runtime lane participating in lockstep evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockstepRuntime {
    FrankenEngineFull,
    FrankenEngineMinimal,
    Node,
    Bun,
}

impl LockstepRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrankenEngineFull => "franken_engine_full",
            Self::FrankenEngineMinimal => "franken_engine_minimal",
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

impl fmt::Display for LockstepRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Observable behavior from one runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeObservation {
    pub runtime: LockstepRuntime,
    pub output_digest: String,
    pub side_effect_digest: String,
    pub state_digest: String,
    pub error_code: Option<String>,
    #[serde(default)]
    pub capability_denials: Vec<String>,
    pub elapsed_ns: u64,
}

impl RuntimeObservation {
    fn normalize(&mut self) {
        self.output_digest = self.output_digest.trim().to_string();
        self.side_effect_digest = self.side_effect_digest.trim().to_string();
        self.state_digest = self.state_digest.trim().to_string();
        self.error_code = self
            .error_code
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.capability_denials = self
            .capability_denials
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        self.capability_denials.sort();
        self.capability_denials.dedup();
    }

    fn validate(&self, field_name: &str) -> Result<(), PlasLockstepError> {
        if self.output_digest.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: format!("{field_name}.output_digest must not be empty"),
            });
        }
        if self.side_effect_digest.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: format!("{field_name}.side_effect_digest must not be empty"),
            });
        }
        if self.state_digest.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: format!("{field_name}.state_digest must not be empty"),
            });
        }
        Ok(())
    }
}

/// Runtime-specific tolerance for known baseline differences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeTolerance {
    #[serde(default)]
    pub allow_output_digest_mismatch: bool,
    #[serde(default)]
    pub allow_side_effect_digest_mismatch: bool,
    #[serde(default)]
    pub allow_state_digest_mismatch: bool,
    #[serde(default)]
    pub allowed_error_codes: BTreeSet<String>,
}

impl RuntimeTolerance {
    fn normalize(&mut self) {
        self.allowed_error_codes = self
            .allowed_error_codes
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
}

/// One lockstep scenario covering full/minimal FE and Node/Bun references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasLockstepCase {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub scenario_id: String,
    pub full_manifest: RuntimeObservation,
    pub minimal_policy: RuntimeObservation,
    pub node_reference: Option<RuntimeObservation>,
    pub bun_reference: Option<RuntimeObservation>,
    #[serde(default)]
    pub reference_tolerances: BTreeMap<LockstepRuntime, RuntimeTolerance>,
    /// Maximum allowed slowdown for minimal policy vs full-manifest run.
    ///
    /// Units: millionths. Example: 150_000 = 15% slower allowed.
    pub max_performance_degradation_millionths: u64,
}

impl PlasLockstepCase {
    fn normalize(&mut self) {
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.extension_id = self.extension_id.trim().to_string();
        self.scenario_id = self.scenario_id.trim().to_string();

        self.full_manifest.normalize();
        self.minimal_policy.normalize();
        if let Some(reference) = &mut self.node_reference {
            reference.normalize();
        }
        if let Some(reference) = &mut self.bun_reference {
            reference.normalize();
        }
        for tolerance in self.reference_tolerances.values_mut() {
            tolerance.normalize();
        }
    }

    fn validate(&self) -> Result<(), PlasLockstepError> {
        if self.trace_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.extension_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "extension_id must not be empty".to_string(),
            });
        }
        if self.scenario_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "scenario_id must not be empty".to_string(),
            });
        }

        self.full_manifest.validate("full_manifest")?;
        self.minimal_policy.validate("minimal_policy")?;

        if self.full_manifest.runtime != LockstepRuntime::FrankenEngineFull {
            return Err(PlasLockstepError::InvalidCase {
                detail: "full_manifest.runtime must be franken_engine_full".to_string(),
            });
        }
        if self.minimal_policy.runtime != LockstepRuntime::FrankenEngineMinimal {
            return Err(PlasLockstepError::InvalidCase {
                detail: "minimal_policy.runtime must be franken_engine_minimal".to_string(),
            });
        }

        if let Some(reference) = &self.node_reference {
            reference.validate("node_reference")?;
            if reference.runtime != LockstepRuntime::Node {
                return Err(PlasLockstepError::InvalidCase {
                    detail: "node_reference.runtime must be node".to_string(),
                });
            }
        }
        if let Some(reference) = &self.bun_reference {
            reference.validate("bun_reference")?;
            if reference.runtime != LockstepRuntime::Bun {
                return Err(PlasLockstepError::InvalidCase {
                    detail: "bun_reference.runtime must be bun".to_string(),
                });
            }
        }
        if self.node_reference.is_none() && self.bun_reference.is_none() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "at least one Node/Bun reference observation is required".to_string(),
            });
        }
        Ok(())
    }
}

/// Required failure taxonomy for PLAS lockstep checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockstepFailureClass {
    CorrectnessRegression,
    CapabilityGap,
    PlatformDivergence,
}

impl LockstepFailureClass {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::CorrectnessRegression => "correctness_regression",
            Self::CapabilityGap => "capability_gap",
            Self::PlatformDivergence => "platform_divergence",
        }
    }
}

impl fmt::Display for LockstepFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Semantic comparison result between the FE full-manifest baseline and another runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeComparison {
    pub runtime: LockstepRuntime,
    pub semantic_match: bool,
    pub mismatch_fields: Vec<String>,
}

/// Structured lockstep log row with stable keys for replay and scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasLockstepLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Complete lockstep verdict for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasLockstepEvaluation {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub scenario_id: String,
    pub pass: bool,
    pub failure_class: Option<LockstepFailureClass>,
    pub failure_detail: Option<String>,
    pub performance_degradation_millionths: u64,
    pub comparisons: Vec<RuntimeComparison>,
    pub log: PlasLockstepLogEvent,
}

/// Errors from PLAS lockstep evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlasLockstepError {
    InvalidCase { detail: String },
}

impl fmt::Display for PlasLockstepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCase { detail } => write!(f, "invalid lockstep case: {detail}"),
        }
    }
}

impl std::error::Error for PlasLockstepError {}

/// Evaluate one deterministic PLAS lockstep scenario.
pub fn evaluate_plas_lockstep_case(
    mut scenario: PlasLockstepCase,
) -> Result<PlasLockstepEvaluation, PlasLockstepError> {
    scenario.normalize();
    scenario.validate()?;

    let mut comparisons = Vec::new();
    let baseline_tolerance = RuntimeTolerance::default();

    let minimal_vs_full = compare_against_baseline(
        &scenario.full_manifest,
        &scenario.minimal_policy,
        &baseline_tolerance,
    );
    comparisons.push(minimal_vs_full.clone());

    let performance_degradation_millionths = performance_degradation_millionths(
        scenario.full_manifest.elapsed_ns,
        scenario.minimal_policy.elapsed_ns,
    );

    let mut failure_class = None;
    let mut failure_detail = None;

    if !minimal_vs_full.semantic_match {
        if is_capability_gap(&scenario) {
            failure_class = Some(LockstepFailureClass::CapabilityGap);
            failure_detail = Some(format!(
                "minimal policy denied capabilities: {}",
                scenario.minimal_policy.capability_denials.join(",")
            ));
        } else {
            failure_class = Some(LockstepFailureClass::CorrectnessRegression);
            failure_detail = Some(format!(
                "minimal policy diverged from full manifest on {}",
                minimal_vs_full.mismatch_fields.join(",")
            ));
        }
    } else if performance_degradation_millionths > scenario.max_performance_degradation_millionths {
        failure_class = Some(LockstepFailureClass::CorrectnessRegression);
        failure_detail = Some(format!(
            "performance degradation {} exceeded threshold {}",
            performance_degradation_millionths, scenario.max_performance_degradation_millionths
        ));
    }

    let mut reference_divergences = Vec::new();
    if let Some(reference) = &scenario.node_reference {
        let tolerance = scenario
            .reference_tolerances
            .get(&LockstepRuntime::Node)
            .cloned()
            .unwrap_or_default();
        let comparison = compare_against_baseline(&scenario.full_manifest, reference, &tolerance);
        if !comparison.semantic_match {
            reference_divergences.push(reference.runtime.to_string());
        }
        comparisons.push(comparison);
    }
    if let Some(reference) = &scenario.bun_reference {
        let tolerance = scenario
            .reference_tolerances
            .get(&LockstepRuntime::Bun)
            .cloned()
            .unwrap_or_default();
        let comparison = compare_against_baseline(&scenario.full_manifest, reference, &tolerance);
        if !comparison.semantic_match {
            reference_divergences.push(reference.runtime.to_string());
        }
        comparisons.push(comparison);
    }

    if failure_class.is_none() && !reference_divergences.is_empty() {
        failure_class = Some(LockstepFailureClass::PlatformDivergence);
        failure_detail = Some(format!(
            "full-manifest behavior diverges from {} baseline(s)",
            reference_divergences.join(",")
        ));
    }

    let pass = failure_class.is_none();
    let log = PlasLockstepLogEvent {
        trace_id: scenario.trace_id.clone(),
        decision_id: scenario.decision_id.clone(),
        policy_id: scenario.policy_id.clone(),
        component: PLAS_LOCKSTEP_COMPONENT.to_string(),
        event: "plas_lockstep_case_evaluated".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: failure_class.map(|class| class.error_code().to_string()),
    };

    Ok(PlasLockstepEvaluation {
        trace_id: scenario.trace_id,
        decision_id: scenario.decision_id,
        policy_id: scenario.policy_id,
        extension_id: scenario.extension_id,
        scenario_id: scenario.scenario_id,
        pass,
        failure_class,
        failure_detail,
        performance_degradation_millionths,
        comparisons,
        log,
    })
}

fn is_capability_gap(scenario: &PlasLockstepCase) -> bool {
    !scenario.minimal_policy.capability_denials.is_empty()
        && scenario.full_manifest.capability_denials.is_empty()
        && scenario.full_manifest.error_code.is_none()
}

fn compare_against_baseline(
    baseline: &RuntimeObservation,
    observed: &RuntimeObservation,
    tolerance: &RuntimeTolerance,
) -> RuntimeComparison {
    let mut mismatch_fields = Vec::new();

    if baseline.output_digest != observed.output_digest && !tolerance.allow_output_digest_mismatch {
        mismatch_fields.push("output_digest".to_string());
    }
    if baseline.side_effect_digest != observed.side_effect_digest
        && !tolerance.allow_side_effect_digest_mismatch
    {
        mismatch_fields.push("side_effect_digest".to_string());
    }
    if baseline.state_digest != observed.state_digest && !tolerance.allow_state_digest_mismatch {
        mismatch_fields.push("state_digest".to_string());
    }

    if baseline.error_code != observed.error_code {
        let baseline_allowed = baseline
            .error_code
            .as_ref()
            .is_some_and(|error| tolerance.allowed_error_codes.contains(error));
        let observed_allowed = observed
            .error_code
            .as_ref()
            .is_some_and(|error| tolerance.allowed_error_codes.contains(error));
        if !(baseline_allowed || observed_allowed) {
            mismatch_fields.push("error_code".to_string());
        }
    }

    RuntimeComparison {
        runtime: observed.runtime,
        semantic_match: mismatch_fields.is_empty(),
        mismatch_fields,
    }
}

fn performance_degradation_millionths(full_elapsed_ns: u64, minimal_elapsed_ns: u64) -> u64 {
    if full_elapsed_ns == 0 || minimal_elapsed_ns <= full_elapsed_ns {
        return 0;
    }

    let slowdown = minimal_elapsed_ns - full_elapsed_ns;
    let scaled = (u128::from(slowdown) * 1_000_000u128) / u128::from(full_elapsed_ns);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn obs(runtime: LockstepRuntime) -> RuntimeObservation {
        RuntimeObservation {
            runtime,
            output_digest: "out_abc".to_string(),
            side_effect_digest: "se_abc".to_string(),
            state_digest: "st_abc".to_string(),
            error_code: None,
            capability_denials: Vec::new(),
            elapsed_ns: 1_000_000,
        }
    }

    fn make_case() -> PlasLockstepCase {
        PlasLockstepCase {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            extension_id: "e1".to_string(),
            scenario_id: "s1".to_string(),
            full_manifest: obs(LockstepRuntime::FrankenEngineFull),
            minimal_policy: obs(LockstepRuntime::FrankenEngineMinimal),
            node_reference: Some(obs(LockstepRuntime::Node)),
            bun_reference: None,
            reference_tolerances: BTreeMap::new(),
            max_performance_degradation_millionths: 150_000,
        }
    }

    // ── LockstepRuntime ─────────────────────────────────────────────

    #[test]
    fn runtime_as_str() {
        assert_eq!(
            LockstepRuntime::FrankenEngineFull.as_str(),
            "franken_engine_full"
        );
        assert_eq!(
            LockstepRuntime::FrankenEngineMinimal.as_str(),
            "franken_engine_minimal"
        );
        assert_eq!(LockstepRuntime::Node.as_str(), "node");
        assert_eq!(LockstepRuntime::Bun.as_str(), "bun");
    }

    #[test]
    fn runtime_display() {
        assert_eq!(format!("{}", LockstepRuntime::Node), "node");
        assert_eq!(format!("{}", LockstepRuntime::Bun), "bun");
    }

    #[test]
    fn runtime_serde_roundtrip() {
        for variant in [
            LockstepRuntime::FrankenEngineFull,
            LockstepRuntime::FrankenEngineMinimal,
            LockstepRuntime::Node,
            LockstepRuntime::Bun,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: LockstepRuntime = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn runtime_ordering() {
        assert!(LockstepRuntime::FrankenEngineFull < LockstepRuntime::FrankenEngineMinimal);
        assert!(LockstepRuntime::FrankenEngineMinimal < LockstepRuntime::Node);
        assert!(LockstepRuntime::Node < LockstepRuntime::Bun);
    }

    // ── RuntimeObservation ──────────────────────────────────────────

    #[test]
    fn observation_normalize_trims_and_deduplicates() {
        let mut o = RuntimeObservation {
            runtime: LockstepRuntime::Node,
            output_digest: "  abc  ".to_string(),
            side_effect_digest: "  def  ".to_string(),
            state_digest: "  ghi  ".to_string(),
            error_code: Some("  ".to_string()),
            capability_denials: vec![
                " dup ".to_string(),
                " dup ".to_string(),
                "  ".to_string(),
                " alpha ".to_string(),
            ],
            elapsed_ns: 100,
        };
        o.normalize();
        assert_eq!(o.output_digest, "abc");
        assert_eq!(o.side_effect_digest, "def");
        assert_eq!(o.state_digest, "ghi");
        assert!(o.error_code.is_none());
        assert_eq!(o.capability_denials, vec!["alpha", "dup"]);
    }

    #[test]
    fn observation_validate_empty_output_digest() {
        let o = RuntimeObservation {
            runtime: LockstepRuntime::Node,
            output_digest: "".to_string(),
            side_effect_digest: "ok".to_string(),
            state_digest: "ok".to_string(),
            error_code: None,
            capability_denials: Vec::new(),
            elapsed_ns: 0,
        };
        let err = o.validate("test").unwrap_err();
        assert!(matches!(err, PlasLockstepError::InvalidCase { .. }));
        assert!(err.to_string().contains("output_digest"));
    }

    #[test]
    fn observation_validate_empty_side_effect_digest() {
        let o = RuntimeObservation {
            runtime: LockstepRuntime::Node,
            output_digest: "ok".to_string(),
            side_effect_digest: "".to_string(),
            state_digest: "ok".to_string(),
            error_code: None,
            capability_denials: Vec::new(),
            elapsed_ns: 0,
        };
        let err = o.validate("test").unwrap_err();
        assert!(err.to_string().contains("side_effect_digest"));
    }

    #[test]
    fn observation_validate_empty_state_digest() {
        let o = RuntimeObservation {
            runtime: LockstepRuntime::Node,
            output_digest: "ok".to_string(),
            side_effect_digest: "ok".to_string(),
            state_digest: "".to_string(),
            error_code: None,
            capability_denials: Vec::new(),
            elapsed_ns: 0,
        };
        let err = o.validate("test").unwrap_err();
        assert!(err.to_string().contains("state_digest"));
    }

    #[test]
    fn observation_serde_roundtrip() {
        let o = obs(LockstepRuntime::Bun);
        let json = serde_json::to_string(&o).unwrap();
        let back: RuntimeObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // ── RuntimeTolerance ────────────────────────────────────────────

    #[test]
    fn tolerance_default_all_strict() {
        let t = RuntimeTolerance::default();
        assert!(!t.allow_output_digest_mismatch);
        assert!(!t.allow_side_effect_digest_mismatch);
        assert!(!t.allow_state_digest_mismatch);
        assert!(t.allowed_error_codes.is_empty());
    }

    #[test]
    fn tolerance_normalize_trims_and_filters() {
        let mut t = RuntimeTolerance {
            allow_output_digest_mismatch: false,
            allow_side_effect_digest_mismatch: false,
            allow_state_digest_mismatch: false,
            allowed_error_codes: ["  code1 ", "  ", " code2 "]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        t.normalize();
        let codes: Vec<_> = t.allowed_error_codes.iter().cloned().collect();
        assert_eq!(codes, vec!["code1", "code2"]);
    }

    #[test]
    fn tolerance_serde_roundtrip() {
        let t = RuntimeTolerance {
            allow_output_digest_mismatch: true,
            allow_side_effect_digest_mismatch: false,
            allow_state_digest_mismatch: true,
            allowed_error_codes: ["err1"].iter().map(|s| s.to_string()).collect(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: RuntimeTolerance = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    // ── LockstepFailureClass ────────────────────────────────────────

    #[test]
    fn failure_class_error_code() {
        assert_eq!(
            LockstepFailureClass::CorrectnessRegression.error_code(),
            "correctness_regression"
        );
        assert_eq!(
            LockstepFailureClass::CapabilityGap.error_code(),
            "capability_gap"
        );
        assert_eq!(
            LockstepFailureClass::PlatformDivergence.error_code(),
            "platform_divergence"
        );
    }

    #[test]
    fn failure_class_display() {
        for variant in [
            LockstepFailureClass::CorrectnessRegression,
            LockstepFailureClass::CapabilityGap,
            LockstepFailureClass::PlatformDivergence,
        ] {
            assert_eq!(format!("{variant}"), variant.error_code());
        }
    }

    #[test]
    fn failure_class_serde_roundtrip() {
        for variant in [
            LockstepFailureClass::CorrectnessRegression,
            LockstepFailureClass::CapabilityGap,
            LockstepFailureClass::PlatformDivergence,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: LockstepFailureClass = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── PlasLockstepError ───────────────────────────────────────────

    #[test]
    fn error_display() {
        let err = PlasLockstepError::InvalidCase {
            detail: "bad field".to_string(),
        };
        assert_eq!(format!("{err}"), "invalid lockstep case: bad field");
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = PlasLockstepError::InvalidCase {
            detail: "test".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: PlasLockstepError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // ── PlasLockstepCase validation ─────────────────────────────────

    #[test]
    fn validate_empty_trace_id() {
        let mut c = make_case();
        c.trace_id = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn validate_empty_decision_id() {
        let mut c = make_case();
        c.decision_id = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn validate_empty_policy_id() {
        let mut c = make_case();
        c.policy_id = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn validate_empty_extension_id() {
        let mut c = make_case();
        c.extension_id = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("extension_id"));
    }

    #[test]
    fn validate_empty_scenario_id() {
        let mut c = make_case();
        c.scenario_id = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("scenario_id"));
    }

    #[test]
    fn validate_wrong_full_manifest_runtime() {
        let mut c = make_case();
        c.full_manifest.runtime = LockstepRuntime::Node;
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("full_manifest.runtime"));
    }

    #[test]
    fn validate_wrong_minimal_policy_runtime() {
        let mut c = make_case();
        c.minimal_policy.runtime = LockstepRuntime::FrankenEngineFull;
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("minimal_policy.runtime"));
    }

    #[test]
    fn validate_wrong_node_reference_runtime() {
        let mut c = make_case();
        c.node_reference = Some(obs(LockstepRuntime::Bun));
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("node_reference.runtime"));
    }

    #[test]
    fn validate_wrong_bun_reference_runtime() {
        let mut c = make_case();
        c.node_reference = None;
        c.bun_reference = Some(obs(LockstepRuntime::Node));
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("bun_reference.runtime"));
    }

    #[test]
    fn validate_no_references() {
        let mut c = make_case();
        c.node_reference = None;
        c.bun_reference = None;
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn validate_empty_full_manifest_output() {
        let mut c = make_case();
        c.full_manifest.output_digest = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("output_digest"));
    }

    #[test]
    fn validate_empty_minimal_policy_state() {
        let mut c = make_case();
        c.minimal_policy.state_digest = "".to_string();
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("state_digest"));
    }

    #[test]
    fn validate_empty_node_reference_side_effect() {
        let mut c = make_case();
        let mut node = obs(LockstepRuntime::Node);
        node.side_effect_digest = "".to_string();
        c.node_reference = Some(node);
        let err = evaluate_plas_lockstep_case(c).unwrap_err();
        assert!(err.to_string().contains("side_effect_digest"));
    }

    // ── PlasLockstepCase normalize ──────────────────────────────────

    #[test]
    fn normalize_trims_id_fields() {
        let mut c = make_case();
        c.trace_id = "  t1  ".to_string();
        c.decision_id = "  d1  ".to_string();
        c.policy_id = "  p1  ".to_string();
        c.extension_id = "  e1  ".to_string();
        c.scenario_id = "  s1  ".to_string();
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert_eq!(eval.trace_id, "t1");
        assert_eq!(eval.decision_id, "d1");
        assert_eq!(eval.policy_id, "p1");
        assert_eq!(eval.extension_id, "e1");
        assert_eq!(eval.scenario_id, "s1");
    }

    // ── performance_degradation_millionths ───────────────────────────

    #[test]
    fn perf_degrade_zero_when_faster() {
        assert_eq!(performance_degradation_millionths(100, 50), 0);
    }

    #[test]
    fn perf_degrade_zero_when_equal() {
        assert_eq!(performance_degradation_millionths(100, 100), 0);
    }

    #[test]
    fn perf_degrade_zero_when_baseline_zero() {
        assert_eq!(performance_degradation_millionths(0, 100), 0);
    }

    #[test]
    fn perf_degrade_correct_pct() {
        // 150 vs 100 = 50% slower = 500_000 millionths
        assert_eq!(performance_degradation_millionths(100, 150), 500_000);
    }

    #[test]
    fn perf_degrade_exact_double() {
        // 200 vs 100 = 100% slower = 1_000_000 millionths
        assert_eq!(performance_degradation_millionths(100, 200), 1_000_000);
    }

    #[test]
    fn perf_degrade_large_values_no_overflow() {
        let full = u64::MAX / 2;
        let minimal = u64::MAX / 2 + 1_000_000;
        // Should not panic
        let _ = performance_degradation_millionths(full, minimal);
    }

    // ── compare_against_baseline ────────────────────────────────────

    #[test]
    fn compare_matching_observations() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let observed = obs(LockstepRuntime::Node);
        let tol = RuntimeTolerance::default();
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(cmp.semantic_match);
        assert!(cmp.mismatch_fields.is_empty());
        assert_eq!(cmp.runtime, LockstepRuntime::Node);
    }

    #[test]
    fn compare_output_mismatch_detected() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.output_digest = "different".to_string();
        let tol = RuntimeTolerance::default();
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(!cmp.semantic_match);
        assert!(cmp.mismatch_fields.contains(&"output_digest".to_string()));
    }

    #[test]
    fn compare_output_mismatch_tolerated() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.output_digest = "different".to_string();
        let tol = RuntimeTolerance {
            allow_output_digest_mismatch: true,
            ..Default::default()
        };
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(cmp.semantic_match);
    }

    #[test]
    fn compare_side_effect_mismatch() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.side_effect_digest = "different".to_string();
        let tol = RuntimeTolerance::default();
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(!cmp.semantic_match);
        assert!(
            cmp.mismatch_fields
                .contains(&"side_effect_digest".to_string())
        );
    }

    #[test]
    fn compare_side_effect_mismatch_tolerated() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.side_effect_digest = "different".to_string();
        let tol = RuntimeTolerance {
            allow_side_effect_digest_mismatch: true,
            ..Default::default()
        };
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(cmp.semantic_match);
    }

    #[test]
    fn compare_state_mismatch() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.state_digest = "different".to_string();
        let tol = RuntimeTolerance::default();
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(!cmp.semantic_match);
        assert!(cmp.mismatch_fields.contains(&"state_digest".to_string()));
    }

    #[test]
    fn compare_state_mismatch_tolerated() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.state_digest = "different".to_string();
        let tol = RuntimeTolerance {
            allow_state_digest_mismatch: true,
            ..Default::default()
        };
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(cmp.semantic_match);
    }

    #[test]
    fn compare_error_code_mismatch() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.error_code = Some("runtime_error".to_string());
        let tol = RuntimeTolerance::default();
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(!cmp.semantic_match);
        assert!(cmp.mismatch_fields.contains(&"error_code".to_string()));
    }

    #[test]
    fn compare_error_code_mismatch_tolerated_observed() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.error_code = Some("known_err".to_string());
        let tol = RuntimeTolerance {
            allowed_error_codes: ["known_err"].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(cmp.semantic_match);
    }

    #[test]
    fn compare_error_code_mismatch_tolerated_baseline() {
        let mut base = obs(LockstepRuntime::FrankenEngineFull);
        base.error_code = Some("known_err".to_string());
        let observed = obs(LockstepRuntime::Node);
        let tol = RuntimeTolerance {
            allowed_error_codes: ["known_err"].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(cmp.semantic_match);
    }

    #[test]
    fn compare_multiple_mismatches() {
        let base = obs(LockstepRuntime::FrankenEngineFull);
        let mut observed = obs(LockstepRuntime::Node);
        observed.output_digest = "diff".to_string();
        observed.state_digest = "diff".to_string();
        observed.error_code = Some("err".to_string());
        let tol = RuntimeTolerance::default();
        let cmp = compare_against_baseline(&base, &observed, &tol);
        assert!(!cmp.semantic_match);
        assert_eq!(cmp.mismatch_fields.len(), 3);
    }

    // ── is_capability_gap ───────────────────────────────────────────

    #[test]
    fn capability_gap_positive() {
        let mut c = make_case();
        c.minimal_policy.capability_denials = vec!["net.connect".to_string()];
        assert!(is_capability_gap(&c));
    }

    #[test]
    fn capability_gap_negative_no_denials() {
        let c = make_case();
        assert!(!is_capability_gap(&c));
    }

    #[test]
    fn capability_gap_negative_both_have_denials() {
        let mut c = make_case();
        c.full_manifest.capability_denials = vec!["fs.write".to_string()];
        c.minimal_policy.capability_denials = vec!["net.connect".to_string()];
        assert!(!is_capability_gap(&c));
    }

    #[test]
    fn capability_gap_negative_full_has_error() {
        let mut c = make_case();
        c.full_manifest.error_code = Some("runtime_error".to_string());
        c.minimal_policy.capability_denials = vec!["net.connect".to_string()];
        assert!(!is_capability_gap(&c));
    }

    // ── evaluate_plas_lockstep_case: pass ───────────────────────────

    #[test]
    fn evaluate_pass_case() {
        let c = make_case();
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(eval.pass);
        assert!(eval.failure_class.is_none());
        assert!(eval.failure_detail.is_none());
        assert_eq!(eval.performance_degradation_millionths, 0);
        assert_eq!(eval.log.component, "plas_lockstep");
        assert_eq!(eval.log.event, "plas_lockstep_case_evaluated");
        assert_eq!(eval.log.outcome, "pass");
        assert!(eval.log.error_code.is_none());
    }

    #[test]
    fn evaluate_pass_ids_propagated() {
        let c = make_case();
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert_eq!(eval.trace_id, "t1");
        assert_eq!(eval.decision_id, "d1");
        assert_eq!(eval.policy_id, "p1");
        assert_eq!(eval.extension_id, "e1");
        assert_eq!(eval.scenario_id, "s1");
    }

    #[test]
    fn evaluate_pass_with_both_references() {
        let mut c = make_case();
        c.bun_reference = Some(obs(LockstepRuntime::Bun));
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(eval.pass);
        assert_eq!(eval.comparisons.len(), 3); // minimal + node + bun
    }

    #[test]
    fn evaluate_pass_bun_only() {
        let mut c = make_case();
        c.node_reference = None;
        c.bun_reference = Some(obs(LockstepRuntime::Bun));
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(eval.pass);
        assert_eq!(eval.comparisons.len(), 2); // minimal + bun
    }

    // ── evaluate: correctness regression ────────────────────────────

    #[test]
    fn evaluate_correctness_regression_output_mismatch() {
        let mut c = make_case();
        c.minimal_policy.output_digest = "diverged".to_string();
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(!eval.pass);
        assert_eq!(
            eval.failure_class,
            Some(LockstepFailureClass::CorrectnessRegression)
        );
        assert!(
            eval.failure_detail
                .as_ref()
                .unwrap()
                .contains("output_digest")
        );
        assert_eq!(eval.log.outcome, "fail");
        assert_eq!(
            eval.log.error_code.as_deref(),
            Some("correctness_regression")
        );
    }

    // ── evaluate: capability gap ────────────────────────────────────

    #[test]
    fn evaluate_capability_gap() {
        let mut c = make_case();
        c.minimal_policy.output_digest = "different".to_string();
        c.minimal_policy.capability_denials = vec!["net.connect".to_string()];
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(!eval.pass);
        assert_eq!(
            eval.failure_class,
            Some(LockstepFailureClass::CapabilityGap)
        );
        assert!(
            eval.failure_detail
                .as_ref()
                .unwrap()
                .contains("net.connect")
        );
    }

    // ── evaluate: performance degradation ───────────────────────────

    #[test]
    fn evaluate_performance_degradation_exceeds_threshold() {
        let mut c = make_case();
        c.full_manifest.elapsed_ns = 1_000_000;
        c.minimal_policy.elapsed_ns = 1_200_000; // 20% slower = 200_000 millionths
        c.max_performance_degradation_millionths = 100_000; // 10% threshold
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(!eval.pass);
        assert_eq!(
            eval.failure_class,
            Some(LockstepFailureClass::CorrectnessRegression)
        );
        assert!(
            eval.failure_detail
                .as_ref()
                .unwrap()
                .contains("performance")
        );
        assert_eq!(eval.performance_degradation_millionths, 200_000);
    }

    #[test]
    fn evaluate_performance_degradation_within_threshold() {
        let mut c = make_case();
        c.full_manifest.elapsed_ns = 1_000_000;
        c.minimal_policy.elapsed_ns = 1_100_000; // 10% slower = 100_000 millionths
        c.max_performance_degradation_millionths = 150_000; // 15% threshold
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(eval.pass);
        assert_eq!(eval.performance_degradation_millionths, 100_000);
    }

    // ── evaluate: platform divergence ───────────────────────────────

    #[test]
    fn evaluate_platform_divergence_node() {
        let mut c = make_case();
        let mut node = obs(LockstepRuntime::Node);
        node.output_digest = "node_different".to_string();
        c.node_reference = Some(node);
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(!eval.pass);
        assert_eq!(
            eval.failure_class,
            Some(LockstepFailureClass::PlatformDivergence)
        );
        assert!(eval.failure_detail.as_ref().unwrap().contains("node"));
    }

    #[test]
    fn evaluate_platform_divergence_bun() {
        let mut c = make_case();
        c.bun_reference = Some({
            let mut b = obs(LockstepRuntime::Bun);
            b.state_digest = "bun_different".to_string();
            b
        });
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(!eval.pass);
        assert_eq!(
            eval.failure_class,
            Some(LockstepFailureClass::PlatformDivergence)
        );
        assert!(eval.failure_detail.as_ref().unwrap().contains("bun"));
    }

    #[test]
    fn evaluate_platform_divergence_tolerated() {
        let mut c = make_case();
        let mut node = obs(LockstepRuntime::Node);
        node.output_digest = "node_different".to_string();
        c.node_reference = Some(node);
        c.reference_tolerances.insert(
            LockstepRuntime::Node,
            RuntimeTolerance {
                allow_output_digest_mismatch: true,
                ..Default::default()
            },
        );
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(eval.pass);
    }

    // ── evaluate: correctness regression takes priority over divergence ──

    #[test]
    fn correctness_regression_takes_priority_over_platform_divergence() {
        let mut c = make_case();
        // minimal policy diverges from full (correctness issue)
        c.minimal_policy.output_digest = "minimal_diff".to_string();
        // node also diverges (platform issue)
        let mut node = obs(LockstepRuntime::Node);
        node.output_digest = "node_diff".to_string();
        c.node_reference = Some(node);
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        assert!(!eval.pass);
        // Correctness regression should be the failure class, not platform divergence
        assert_eq!(
            eval.failure_class,
            Some(LockstepFailureClass::CorrectnessRegression)
        );
    }

    // ── RuntimeComparison serde ─────────────────────────────────────

    #[test]
    fn runtime_comparison_serde_roundtrip() {
        let cmp = RuntimeComparison {
            runtime: LockstepRuntime::Node,
            semantic_match: false,
            mismatch_fields: vec!["output_digest".to_string()],
        };
        let json = serde_json::to_string(&cmp).unwrap();
        let back: RuntimeComparison = serde_json::from_str(&json).unwrap();
        assert_eq!(cmp, back);
    }

    // ── PlasLockstepLogEvent serde ──────────────────────────────────

    #[test]
    fn log_event_serde_roundtrip() {
        let le = PlasLockstepLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&le).unwrap();
        let back: PlasLockstepLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(le, back);
    }

    // ── PlasLockstepEvaluation serde ────────────────────────────────

    #[test]
    fn evaluation_serde_roundtrip() {
        let c = make_case();
        let eval = evaluate_plas_lockstep_case(c).unwrap();
        let json = serde_json::to_string(&eval).unwrap();
        let back: PlasLockstepEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(eval, back);
    }

    // ── PlasLockstepCase serde ──────────────────────────────────────

    #[test]
    fn case_serde_roundtrip() {
        let c = make_case();
        let json = serde_json::to_string(&c).unwrap();
        let back: PlasLockstepCase = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn case_serde_with_tolerances() {
        let mut c = make_case();
        c.reference_tolerances.insert(
            LockstepRuntime::Node,
            RuntimeTolerance {
                allow_output_digest_mismatch: true,
                ..Default::default()
            },
        );
        let json = serde_json::to_string(&c).unwrap();
        let back: PlasLockstepCase = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
