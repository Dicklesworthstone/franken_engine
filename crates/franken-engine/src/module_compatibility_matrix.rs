//! Explicit compatibility matrix for Node/Bun module edge cases.
//!
//! This module keeps compatibility behavior explicit and machine-readable.
//! Divergences from Node/Bun must include waiver metadata and migration
//! guidance; mode-specific behavior changes must declare explicit, removable
//! shims so compatibility is never hidden in resolver internals.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::feature_parity_tracker::FeatureParityTracker;
use crate::hash_tiers::ContentHash;

const COMPONENT_NAME: &str = "module_compatibility_matrix";
pub const DEFAULT_MATRIX_JSON: &str =
    include_str!("../../../docs/module_compatibility_matrix_v1.json");

pub type CompatibilityResult<T> = Result<T, Box<CompatibilityMatrixError>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleFeature {
    Esm,
    Cjs,
    DualMode,
    ConditionalExports,
    PackageJsonFields,
}

impl ModuleFeature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Esm => "esm",
            Self::Cjs => "cjs",
            Self::DualMode => "dual_mode",
            Self::ConditionalExports => "conditional_exports",
            Self::PackageJsonFields => "package_json_fields",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityRuntime {
    FrankenEngine,
    Node,
    Bun,
}

impl CompatibilityRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrankenEngine => "franken_engine",
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMode {
    Native,
    NodeCompat,
    BunCompat,
}

impl CompatibilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::NodeCompat => "node_compat",
            Self::BunCompat => "bun_compat",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceRuntime {
    Node,
    Bun,
}

impl ReferenceRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceCategory {
    EngineBug,
    IntentionalImprovement,
    CompatibilityDebt,
    EcosystemAmbiguity,
    ReferenceRuntimeBug,
}

impl DivergenceCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EngineBug => "engine_bug",
            Self::IntentionalImprovement => "intentional_improvement",
            Self::CompatibilityDebt => "compatibility_debt",
            Self::EcosystemAmbiguity => "ecosystem_ambiguity",
            Self::ReferenceRuntimeBug => "reference_runtime_bug",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitShim {
    pub shim_id: String,
    pub mode: CompatibilityMode,
    pub description: String,
    pub removable: bool,
    pub test_case_ref: String,
}

impl ExplicitShim {
    fn normalize(&mut self) {
        self.shim_id = self.shim_id.trim().to_string();
        self.description = self.description.trim().to_string();
        self.test_case_ref = self.test_case_ref.trim().to_string();
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "shim_id".to_string(),
            CanonicalValue::String(self.shim_id.clone()),
        );
        map.insert(
            "mode".to_string(),
            CanonicalValue::String(self.mode.as_str().to_string()),
        );
        map.insert(
            "description".to_string(),
            CanonicalValue::String(self.description.clone()),
        );
        map.insert(
            "removable".to_string(),
            CanonicalValue::Bool(self.removable),
        );
        map.insert(
            "test_case_ref".to_string(),
            CanonicalValue::String(self.test_case_ref.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergencePolicy {
    pub diverges_from: Vec<ReferenceRuntime>,
    pub reason: String,
    pub impact: String,
    pub waiver_id: String,
    pub migration_guidance: String,
}

impl DivergencePolicy {
    fn normalize(&mut self) {
        self.diverges_from.sort();
        self.diverges_from.dedup();
        self.reason = self.reason.trim().to_string();
        self.impact = self.impact.trim().to_string();
        self.waiver_id = self.waiver_id.trim().to_string();
        self.migration_guidance = self.migration_guidance.trim().to_string();
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "diverges_from".to_string(),
            CanonicalValue::Array(
                self.diverges_from
                    .iter()
                    .map(|runtime| CanonicalValue::String(runtime.as_str().to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "reason".to_string(),
            CanonicalValue::String(self.reason.clone()),
        );
        map.insert(
            "impact".to_string(),
            CanonicalValue::String(self.impact.clone()),
        );
        map.insert(
            "waiver_id".to_string(),
            CanonicalValue::String(self.waiver_id.clone()),
        );
        map.insert(
            "migration_guidance".to_string(),
            CanonicalValue::String(self.migration_guidance.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrixEntry {
    pub case_id: String,
    pub feature: ModuleFeature,
    pub scenario: String,
    pub node_behavior: String,
    pub bun_behavior: String,
    pub franken_native_behavior: String,
    pub franken_node_compat_behavior: String,
    pub franken_bun_compat_behavior: String,
    pub explicit_shims: Vec<ExplicitShim>,
    pub lockstep_case_refs: Vec<String>,
    pub test262_refs: Vec<String>,
    pub divergence: Option<DivergencePolicy>,
}

impl CompatibilityMatrixEntry {
    fn normalize(&mut self) {
        self.case_id = self.case_id.trim().to_string();
        self.scenario = self.scenario.trim().to_string();
        self.node_behavior = self.node_behavior.trim().to_string();
        self.bun_behavior = self.bun_behavior.trim().to_string();
        self.franken_native_behavior = self.franken_native_behavior.trim().to_string();
        self.franken_node_compat_behavior = self.franken_node_compat_behavior.trim().to_string();
        self.franken_bun_compat_behavior = self.franken_bun_compat_behavior.trim().to_string();

        for shim in &mut self.explicit_shims {
            shim.normalize();
        }
        self.explicit_shims.sort_by(|lhs, rhs| {
            (
                lhs.mode,
                &lhs.shim_id,
                &lhs.description,
                lhs.removable,
                &lhs.test_case_ref,
            )
                .cmp(&(
                    rhs.mode,
                    &rhs.shim_id,
                    &rhs.description,
                    rhs.removable,
                    &rhs.test_case_ref,
                ))
        });

        normalize_string_vec(&mut self.lockstep_case_refs);
        normalize_string_vec(&mut self.test262_refs);

        if let Some(divergence) = &mut self.divergence {
            divergence.normalize();
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "case_id".to_string(),
            CanonicalValue::String(self.case_id.clone()),
        );
        map.insert(
            "feature".to_string(),
            CanonicalValue::String(self.feature.as_str().to_string()),
        );
        map.insert(
            "scenario".to_string(),
            CanonicalValue::String(self.scenario.clone()),
        );
        map.insert(
            "node_behavior".to_string(),
            CanonicalValue::String(self.node_behavior.clone()),
        );
        map.insert(
            "bun_behavior".to_string(),
            CanonicalValue::String(self.bun_behavior.clone()),
        );
        map.insert(
            "franken_native_behavior".to_string(),
            CanonicalValue::String(self.franken_native_behavior.clone()),
        );
        map.insert(
            "franken_node_compat_behavior".to_string(),
            CanonicalValue::String(self.franken_node_compat_behavior.clone()),
        );
        map.insert(
            "franken_bun_compat_behavior".to_string(),
            CanonicalValue::String(self.franken_bun_compat_behavior.clone()),
        );
        map.insert(
            "explicit_shims".to_string(),
            CanonicalValue::Array(
                self.explicit_shims
                    .iter()
                    .map(ExplicitShim::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "lockstep_case_refs".to_string(),
            CanonicalValue::Array(
                self.lockstep_case_refs
                    .iter()
                    .map(|reference| CanonicalValue::String(reference.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "test262_refs".to_string(),
            CanonicalValue::Array(
                self.test262_refs
                    .iter()
                    .map(|reference| CanonicalValue::String(reference.clone()))
                    .collect(),
            ),
        );

        let divergence = match &self.divergence {
            Some(divergence) => divergence.canonical_value(),
            None => CanonicalValue::Null,
        };
        map.insert("divergence".to_string(), divergence);

        CanonicalValue::Map(map)
    }

    fn expected_behavior(&self, runtime: CompatibilityRuntime, mode: CompatibilityMode) -> &str {
        match runtime {
            CompatibilityRuntime::Node => &self.node_behavior,
            CompatibilityRuntime::Bun => &self.bun_behavior,
            CompatibilityRuntime::FrankenEngine => match mode {
                CompatibilityMode::Native => &self.franken_native_behavior,
                CompatibilityMode::NodeCompat => &self.franken_node_compat_behavior,
                CompatibilityMode::BunCompat => &self.franken_bun_compat_behavior,
            },
        }
    }

    fn mismatched_runtimes(&self) -> BTreeSet<ReferenceRuntime> {
        let mut mismatches = BTreeSet::new();
        if self.franken_native_behavior != self.node_behavior {
            mismatches.insert(ReferenceRuntime::Node);
        }
        if self.franken_native_behavior != self.bun_behavior {
            mismatches.insert(ReferenceRuntime::Bun);
        }
        mismatches
    }

    fn has_shim_for_mode(&self, mode: CompatibilityMode) -> bool {
        self.explicit_shims.iter().any(|shim| shim.mode == mode)
    }

    fn duplicate_shim_key(&self) -> Option<(CompatibilityMode, String)> {
        let mut seen = BTreeSet::new();
        for shim in &self.explicit_shims {
            let key = (shim.mode, shim.shim_id.clone());
            if !seen.insert(key.clone()) {
                return Some(key);
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompatibilityMatrixDocument {
    schema_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_readme_fragments: Vec<String>,
    entries: Vec<CompatibilityMatrixEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl CompatibilityContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityEvent {
    pub seq: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub case_id: String,
    pub runtime: String,
    pub mode: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMatrixErrorCode {
    MatrixParseError,
    DuplicateCaseId,
    CaseNotFound,
    HiddenShim,
    MissingWaiver,
    MissingMigrationGuidance,
    InvalidMatrix,
    ObservationMismatch,
}

impl CompatibilityMatrixErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::MatrixParseError => "FE-MODCOMP-0001",
            Self::DuplicateCaseId => "FE-MODCOMP-0002",
            Self::CaseNotFound => "FE-MODCOMP-0003",
            Self::HiddenShim => "FE-MODCOMP-0004",
            Self::MissingWaiver => "FE-MODCOMP-0005",
            Self::MissingMigrationGuidance => "FE-MODCOMP-0006",
            Self::InvalidMatrix => "FE-MODCOMP-0007",
            Self::ObservationMismatch => "FE-MODCOMP-0008",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrixError {
    pub code: CompatibilityMatrixErrorCode,
    pub message: String,
    pub event: Option<CompatibilityEvent>,
}

impl fmt::Display for CompatibilityMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.event {
            Some(event) => write!(
                f,
                "{}: {} (trace_id={}, decision_id={}, policy_id={})",
                self.code.stable_code(),
                self.message,
                event.trace_id,
                event.decision_id,
                event.policy_id,
            ),
            None => write!(f, "{}: {}", self.code.stable_code(), self.message),
        }
    }
}

impl std::error::Error for CompatibilityMatrixError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityObservation {
    pub case_id: String,
    pub runtime: CompatibilityRuntime,
    pub mode: CompatibilityMode,
    pub observed_behavior: String,
}

impl CompatibilityObservation {
    pub fn new(
        case_id: impl Into<String>,
        runtime: CompatibilityRuntime,
        mode: CompatibilityMode,
        observed_behavior: impl Into<String>,
    ) -> Self {
        Self {
            case_id: case_id.into(),
            runtime,
            mode,
            observed_behavior: observed_behavior.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityObservationOutcome {
    pub case_id: String,
    pub runtime: CompatibilityRuntime,
    pub mode: CompatibilityMode,
    pub observed_behavior: String,
    pub expected_behavior: String,
    pub matched: bool,
    pub divergence: Option<DivergencePolicy>,
    pub divergence_category: Option<DivergenceCategory>,
    pub actionable_guidance: Option<String>,
    pub event: CompatibilityEvent,
}

pub const COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.module-interop-scenario-report.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityScenarioReport {
    pub schema_version: String,
    pub scenario_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_unix_ms: u64,
    pub total_observations: usize,
    pub matched_observations: usize,
    pub divergence_category_counts: BTreeMap<String, u64>,
    pub actionable_guidance: BTreeMap<String, String>,
    pub outcomes: Vec<CompatibilityObservationOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCompatibilityMatrix {
    pub schema_version: String,
    required_readme_fragments: Vec<String>,
    entries: BTreeMap<String, CompatibilityMatrixEntry>,
    events: Vec<CompatibilityEvent>,
    next_event_seq: u64,
}

#[derive(Debug, Clone)]
struct EventDraft {
    event: String,
    outcome: String,
    error_code: String,
    case_id: String,
    runtime: CompatibilityRuntime,
    mode: CompatibilityMode,
    detail: String,
}

impl EventDraft {
    fn allow(
        event: impl Into<String>,
        case_id: impl Into<String>,
        runtime: CompatibilityRuntime,
        mode: CompatibilityMode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event: event.into(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
            case_id: case_id.into(),
            runtime,
            mode,
            detail: detail.into(),
        }
    }

    fn deny(
        event: impl Into<String>,
        case_id: impl Into<String>,
        runtime: CompatibilityRuntime,
        mode: CompatibilityMode,
        code: CompatibilityMatrixErrorCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event: event.into(),
            outcome: "deny".to_string(),
            error_code: code.stable_code().to_string(),
            case_id: case_id.into(),
            runtime,
            mode,
            detail: detail.into(),
        }
    }
}

impl ModuleCompatibilityMatrix {
    pub fn from_default_json() -> CompatibilityResult<Self> {
        Self::from_json_str(DEFAULT_MATRIX_JSON)
    }

    pub fn from_json_str(raw: &str) -> CompatibilityResult<Self> {
        let document: CompatibilityMatrixDocument =
            serde_json::from_str(raw).map_err(|error| parse_error(error.to_string()))?;
        Self::from_document_parts(
            document.schema_version,
            document.required_readme_fragments,
            document.entries,
        )
    }

    pub fn from_entries(
        schema_version: impl Into<String>,
        entries: Vec<CompatibilityMatrixEntry>,
    ) -> CompatibilityResult<Self> {
        Self::from_document_parts(schema_version, Vec::new(), entries)
    }

    fn from_document_parts(
        schema_version: impl Into<String>,
        mut required_readme_fragments: Vec<String>,
        mut entries: Vec<CompatibilityMatrixEntry>,
    ) -> CompatibilityResult<Self> {
        let schema_version = schema_version.into().trim().to_string();
        if schema_version.is_empty() {
            return Err(simple_error(
                CompatibilityMatrixErrorCode::InvalidMatrix,
                "schema_version must not be empty",
            ));
        }

        normalize_string_vec(&mut required_readme_fragments);

        let mut catalog = BTreeMap::new();
        for entry in &mut entries {
            entry.normalize();
            if entry.case_id.is_empty() {
                return Err(simple_error(
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "case_id must not be empty",
                ));
            }
            if let Some((mode, shim_id)) = entry.duplicate_shim_key() {
                return Err(simple_error(
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    format!(
                        "duplicate explicit shim_id '{}' for mode '{}' in case '{}'",
                        shim_id,
                        mode.as_str(),
                        entry.case_id
                    ),
                ));
            }
            if catalog
                .insert(entry.case_id.clone(), entry.clone())
                .is_some()
            {
                return Err(simple_error(
                    CompatibilityMatrixErrorCode::DuplicateCaseId,
                    format!("duplicate case_id '{}' in matrix", entry.case_id),
                ));
            }
        }

        Ok(Self {
            schema_version,
            required_readme_fragments,
            entries: catalog,
            events: Vec::new(),
            next_event_seq: 0,
        })
    }

    pub fn entries(&self) -> Vec<&CompatibilityMatrixEntry> {
        self.entries.values().collect()
    }

    pub fn entry(&self, case_id: &str) -> Option<&CompatibilityMatrixEntry> {
        self.entries.get(case_id)
    }

    pub fn required_waiver_ids(&self) -> BTreeSet<String> {
        self.entries
            .values()
            .filter_map(|entry| entry.divergence.as_ref())
            .map(|divergence| divergence.waiver_id.clone())
            .collect()
    }

    pub fn required_readme_fragments(&self) -> &[String] {
        &self.required_readme_fragments
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        let document = CompatibilityMatrixDocument {
            schema_version: self.schema_version.clone(),
            required_readme_fragments: self.required_readme_fragments.clone(),
            entries: self.entries.values().cloned().collect(),
        };
        serde_json::to_string_pretty(&document)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }

    pub fn validate_against_tracker(
        &mut self,
        tracker: &FeatureParityTracker,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<()> {
        let approved = tracker.waivers().keys().cloned().collect::<BTreeSet<_>>();
        self.validate_with_waivers(&approved, context)
    }

    pub fn validate_with_waivers(
        &mut self,
        approved_waivers: &BTreeSet<String>,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<()> {
        let case_ids = self.entries.keys().cloned().collect::<Vec<_>>();
        for case_id in case_ids {
            let entry = self.entries.get(&case_id).cloned().ok_or_else(|| {
                simple_error(CompatibilityMatrixErrorCode::CaseNotFound, case_id.clone())
            })?;

            self.validate_entry(&entry, approved_waivers, context)?;
            self.push_event(
                context,
                EventDraft::allow(
                    "compatibility_entry_validated",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "compatibility entry passed deterministic validation",
                ),
            );
        }
        Ok(())
    }

    pub fn evaluate_observation(
        &mut self,
        observation: &CompatibilityObservation,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<CompatibilityObservationOutcome> {
        let case_id = observation.case_id.trim().to_string();
        let entry = self.entries.get(&case_id).cloned().ok_or_else(|| {
            self.error(
                context,
                CompatibilityMatrixErrorCode::CaseNotFound,
                EventDraft::deny(
                    "compatibility_observation",
                    case_id.clone(),
                    observation.runtime,
                    observation.mode,
                    CompatibilityMatrixErrorCode::CaseNotFound,
                    format!("unknown case_id '{}'", observation.case_id),
                ),
            )
        })?;

        let expected_behavior = entry
            .expected_behavior(observation.runtime, observation.mode)
            .to_string();
        let observed_behavior = observation.observed_behavior.trim().to_string();

        if expected_behavior != observed_behavior {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::ObservationMismatch,
                EventDraft::deny(
                    "compatibility_observation",
                    entry.case_id.clone(),
                    observation.runtime,
                    observation.mode,
                    CompatibilityMatrixErrorCode::ObservationMismatch,
                    format!(
                        "behavior mismatch for case '{}' (expected='{}', observed='{}')",
                        entry.case_id, expected_behavior, observed_behavior
                    ),
                ),
            ));
        }

        let event = self.push_event(
            context,
            EventDraft::allow(
                "compatibility_observation",
                entry.case_id.clone(),
                observation.runtime,
                observation.mode,
                "observed behavior matches documented matrix",
            ),
        );

        let divergence_category = entry.divergence.as_ref().map(classify_divergence);
        let actionable_guidance = divergence_category
            .map(guidance_for_divergence_category)
            .map(std::string::ToString::to_string);

        Ok(CompatibilityObservationOutcome {
            case_id: entry.case_id,
            runtime: observation.runtime,
            mode: observation.mode,
            observed_behavior,
            expected_behavior,
            matched: true,
            divergence: entry.divergence,
            divergence_category,
            actionable_guidance,
            event,
        })
    }

    pub fn evaluate_scenario(
        &mut self,
        scenario_id: impl Into<String>,
        observations: &[CompatibilityObservation],
        context: &CompatibilityContext,
        generated_at_unix_ms: u64,
    ) -> CompatibilityResult<CompatibilityScenarioReport> {
        let scenario_id = scenario_id.into().trim().to_string();
        if scenario_id.is_empty() {
            return Err(simple_error(
                CompatibilityMatrixErrorCode::InvalidMatrix,
                "scenario_id must not be empty",
            ));
        }

        let mut outcomes = Vec::with_capacity(observations.len());
        let mut divergence_category_counts = BTreeMap::<String, u64>::new();
        let mut actionable_guidance = BTreeMap::<String, String>::new();

        for observation in observations {
            let outcome = self.evaluate_observation(observation, context)?;
            if let Some(category) = outcome.divergence_category {
                let key = category.as_str().to_string();
                let guidance = outcome
                    .actionable_guidance
                    .clone()
                    .unwrap_or_else(|| guidance_for_divergence_category(category).to_string());
                *divergence_category_counts.entry(key.clone()).or_insert(0) += 1;
                actionable_guidance.insert(key, guidance);
            }
            outcomes.push(outcome);
        }

        let matched_observations = outcomes.iter().filter(|outcome| outcome.matched).count();

        self.push_event(
            context,
            EventDraft::allow(
                "compatibility_scenario_report",
                scenario_id.clone(),
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::Native,
                format!(
                    "generated scenario report with {} observations",
                    observations.len()
                ),
            ),
        );

        Ok(CompatibilityScenarioReport {
            schema_version: COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION.to_string(),
            scenario_id,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            generated_at_unix_ms,
            total_observations: observations.len(),
            matched_observations,
            divergence_category_counts,
            actionable_guidance,
            outcomes,
        })
    }

    pub fn events(&self) -> &[CompatibilityEvent] {
        &self.events
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        if !self.required_readme_fragments.is_empty() {
            map.insert(
                "required_readme_fragments".to_string(),
                CanonicalValue::Array(
                    self.required_readme_fragments
                        .iter()
                        .cloned()
                        .map(CanonicalValue::String)
                        .collect(),
                ),
            );
        }
        map.insert(
            "entries".to_string(),
            CanonicalValue::Array(
                self.entries
                    .values()
                    .map(CompatibilityMatrixEntry::canonical_value)
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }

    fn validate_entry(
        &mut self,
        entry: &CompatibilityMatrixEntry,
        approved_waivers: &BTreeSet<String>,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<()> {
        if entry.scenario.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "scenario must not be empty",
                ),
            ));
        }

        if entry.lockstep_case_refs.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "lockstep_case_refs must include at least one reference",
                ),
            ));
        }

        if entry.test262_refs.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "test262_refs must include at least one reference",
                ),
            ));
        }

        if let Some((mode, shim_id)) = entry.duplicate_shim_key() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    mode,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    format!(
                        "duplicate explicit shim_id '{}' for mode '{}'",
                        shim_id,
                        mode.as_str()
                    ),
                ),
            ));
        }

        for shim in &entry.explicit_shims {
            if shim.shim_id.is_empty() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must include non-empty shim_id",
                    ),
                ));
            }
            if shim.description.is_empty() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must include non-empty description",
                    ),
                ));
            }
            if shim.test_case_ref.is_empty() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must include non-empty test_case_ref",
                    ),
                ));
            }
            let shim_ref_matches_entry = entry
                .lockstep_case_refs
                .iter()
                .chain(entry.test262_refs.iter())
                .any(|case_ref| case_ref == &shim.test_case_ref);
            if !shim_ref_matches_entry {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim test_case_ref must match an entry lockstep_case_refs or test262_refs reference",
                    ),
                ));
            }
            if !shim.removable {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must be removable",
                    ),
                ));
            }
        }

        if entry.franken_node_compat_behavior != entry.franken_native_behavior
            && !entry.has_shim_for_mode(CompatibilityMode::NodeCompat)
        {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::HiddenShim,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::NodeCompat,
                    CompatibilityMatrixErrorCode::HiddenShim,
                    "node_compat behavior diverges from native without explicit shim",
                ),
            ));
        }

        if entry.franken_bun_compat_behavior != entry.franken_native_behavior
            && !entry.has_shim_for_mode(CompatibilityMode::BunCompat)
        {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::HiddenShim,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::BunCompat,
                    CompatibilityMatrixErrorCode::HiddenShim,
                    "bun_compat behavior diverges from native without explicit shim",
                ),
            ));
        }

        let mismatches = entry.mismatched_runtimes();
        if mismatches.is_empty() {
            if entry.divergence.is_some() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        CompatibilityMode::Native,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "divergence metadata present but native behavior matches Node and Bun",
                    ),
                ));
            }
            return Ok(());
        }

        let divergence = match &entry.divergence {
            Some(divergence) => divergence,
            None => {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::MissingWaiver,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        CompatibilityMode::Native,
                        CompatibilityMatrixErrorCode::MissingWaiver,
                        "native behavior diverges from reference runtimes but no divergence policy is declared",
                    ),
                ));
            }
        };

        let declared = divergence
            .diverges_from
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if declared != mismatches {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    format!(
                        "divergence runtime set mismatch (declared={:?}, actual={:?})",
                        declared, mismatches
                    ),
                ),
            ));
        }

        if divergence.waiver_id.is_empty() || !approved_waivers.contains(&divergence.waiver_id) {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::MissingWaiver,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::MissingWaiver,
                    format!(
                        "missing approved waiver '{}' for documented divergence",
                        divergence.waiver_id
                    ),
                ),
            ));
        }

        if divergence.migration_guidance.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::MissingMigrationGuidance,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::MissingMigrationGuidance,
                    "divergence requires migration guidance",
                ),
            ));
        }

        Ok(())
    }

    fn push_event(
        &mut self,
        context: &CompatibilityContext,
        draft: EventDraft,
    ) -> CompatibilityEvent {
        let event = CompatibilityEvent {
            seq: self.next_event_seq,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT_NAME.to_string(),
            event: draft.event,
            outcome: draft.outcome,
            error_code: draft.error_code,
            case_id: draft.case_id,
            runtime: draft.runtime.as_str().to_string(),
            mode: draft.mode.as_str().to_string(),
            detail: draft.detail,
        };
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        self.events.push(event.clone());
        event
    }

    fn error(
        &mut self,
        context: &CompatibilityContext,
        code: CompatibilityMatrixErrorCode,
        draft: EventDraft,
    ) -> Box<CompatibilityMatrixError> {
        let detail = draft.detail.clone();
        let event = self.push_event(context, draft);
        Box::new(CompatibilityMatrixError {
            code,
            message: detail,
            event: Some(event),
        })
    }
}

impl Default for ModuleCompatibilityMatrix {
    fn default() -> Self {
        Self::from_default_json().expect("default module compatibility matrix must parse")
    }
}

fn normalize_string_vec(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        *value = value.trim().to_string();
    }
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
}

fn parse_error(message: String) -> Box<CompatibilityMatrixError> {
    Box::new(CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::MatrixParseError,
        message,
        event: None,
    })
}

fn simple_error(
    code: CompatibilityMatrixErrorCode,
    message: impl Into<String>,
) -> Box<CompatibilityMatrixError> {
    Box::new(CompatibilityMatrixError {
        code,
        message: message.into(),
        event: None,
    })
}

fn classify_divergence(divergence: &DivergencePolicy) -> DivergenceCategory {
    let reason = divergence.reason.to_ascii_lowercase();
    let impact = divergence.impact.to_ascii_lowercase();

    if reason.contains("reference runtime bug") || reason.contains("upstream runtime bug") {
        return DivergenceCategory::ReferenceRuntimeBug;
    }
    if reason.contains("engine bug")
        || impact.contains("incorrect")
        || impact.contains("regression")
        || impact.contains("broken")
    {
        return DivergenceCategory::EngineBug;
    }
    if reason.contains("strict")
        || reason.contains("security")
        || reason.contains("safety")
        || reason.contains("intentional")
        || impact.contains("compat mode")
    {
        return DivergenceCategory::IntentionalImprovement;
    }
    if divergence.diverges_from.len() == 2 {
        return DivergenceCategory::EcosystemAmbiguity;
    }
    DivergenceCategory::CompatibilityDebt
}

fn guidance_for_divergence_category(category: DivergenceCategory) -> &'static str {
    match category {
        DivergenceCategory::EngineBug => {
            "treat as release blocker; capture minimized reproduction and patch FrankenEngine behavior"
        }
        DivergenceCategory::IntentionalImprovement => {
            "document security/strictness intent and provide migration path or compat-mode fallback"
        }
        DivergenceCategory::CompatibilityDebt => {
            "track compatibility gap, add focused parity tests, and schedule resolver/loader remediation"
        }
        DivergenceCategory::EcosystemAmbiguity => {
            "escalate ambiguity with lockstep evidence and pin deterministic project policy for this edge"
        }
        DivergenceCategory::ReferenceRuntimeBug => {
            "record upstream bug linkage and preserve deterministic local workaround with replay evidence"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CompatibilityContext {
        CompatibilityContext::new("trace-modcompat", "decision-modcompat", "policy-modcompat")
    }

    #[test]
    fn default_matrix_round_trips_and_hashes_deterministically() {
        let matrix_a = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let matrix_b = ModuleCompatibilityMatrix::from_default_json().unwrap();

        assert_eq!(matrix_a.canonical_hash(), matrix_b.canonical_hash());
        assert_eq!(
            matrix_a.to_json_pretty().unwrap(),
            matrix_b.to_json_pretty().unwrap()
        );
    }

    #[test]
    fn validation_requires_explicit_shim_for_mode_specific_divergence() {
        let entry = CompatibilityMatrixEntry {
            case_id: "case-hidden-shim".to_string(),
            feature: ModuleFeature::Cjs,
            scenario: "hidden shim check".to_string(),
            node_behavior: "throw".to_string(),
            bun_behavior: "bridge".to_string(),
            franken_native_behavior: "throw".to_string(),
            franken_node_compat_behavior: "throw".to_string(),
            franken_bun_compat_behavior: "bridge".to_string(),
            explicit_shims: vec![],
            lockstep_case_refs: vec!["lockstep/module/hidden-shim".to_string()],
            test262_refs: vec!["language/module-code/sample.js".to_string()],
            divergence: Some(DivergencePolicy {
                diverges_from: vec![ReferenceRuntime::Bun],
                reason: "strict native mode".to_string(),
                impact: "requires compat mode".to_string(),
                waiver_id: "w-hidden".to_string(),
                migration_guidance: "use import".to_string(),
            }),
        };

        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let mut waivers = BTreeSet::new();
        waivers.insert("w-hidden".to_string());

        let error = matrix
            .validate_with_waivers(&waivers, &context())
            .expect_err("expected hidden shim validation error");
        assert_eq!(error.code, CompatibilityMatrixErrorCode::HiddenShim);
        assert_eq!(
            error
                .event
                .as_ref()
                .expect("event should be attached")
                .error_code,
            CompatibilityMatrixErrorCode::HiddenShim.stable_code(),
        );
    }

    #[test]
    fn validation_requires_approved_waiver_for_native_divergence() {
        let mut matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let waivers = BTreeSet::new();

        let error = matrix
            .validate_with_waivers(&waivers, &context())
            .expect_err("expected missing waiver error");
        assert_eq!(error.code, CompatibilityMatrixErrorCode::MissingWaiver);
    }

    // ── Enum as_str ────────────────────────────────────────────────

    #[test]
    fn module_feature_as_str() {
        assert_eq!(ModuleFeature::Esm.as_str(), "esm");
        assert_eq!(ModuleFeature::Cjs.as_str(), "cjs");
        assert_eq!(ModuleFeature::DualMode.as_str(), "dual_mode");
        assert_eq!(
            ModuleFeature::ConditionalExports.as_str(),
            "conditional_exports"
        );
        assert_eq!(
            ModuleFeature::PackageJsonFields.as_str(),
            "package_json_fields"
        );
    }

    #[test]
    fn compatibility_runtime_as_str() {
        assert_eq!(
            CompatibilityRuntime::FrankenEngine.as_str(),
            "franken_engine"
        );
        assert_eq!(CompatibilityRuntime::Node.as_str(), "node");
        assert_eq!(CompatibilityRuntime::Bun.as_str(), "bun");
    }

    #[test]
    fn compatibility_mode_as_str() {
        assert_eq!(CompatibilityMode::Native.as_str(), "native");
        assert_eq!(CompatibilityMode::NodeCompat.as_str(), "node_compat");
        assert_eq!(CompatibilityMode::BunCompat.as_str(), "bun_compat");
    }

    #[test]
    fn reference_runtime_as_str() {
        assert_eq!(ReferenceRuntime::Node.as_str(), "node");
        assert_eq!(ReferenceRuntime::Bun.as_str(), "bun");
    }

    // ── Error code stable strings ──────────────────────────────────

    #[test]
    fn error_code_stable_code_all_variants() {
        assert_eq!(
            CompatibilityMatrixErrorCode::MatrixParseError.stable_code(),
            "FE-MODCOMP-0001"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::DuplicateCaseId.stable_code(),
            "FE-MODCOMP-0002"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::CaseNotFound.stable_code(),
            "FE-MODCOMP-0003"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::HiddenShim.stable_code(),
            "FE-MODCOMP-0004"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::MissingWaiver.stable_code(),
            "FE-MODCOMP-0005"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::MissingMigrationGuidance.stable_code(),
            "FE-MODCOMP-0006"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::InvalidMatrix.stable_code(),
            "FE-MODCOMP-0007"
        );
        assert_eq!(
            CompatibilityMatrixErrorCode::ObservationMismatch.stable_code(),
            "FE-MODCOMP-0008"
        );
    }

    // ── Error Display ──────────────────────────────────────────────

    #[test]
    fn error_display_without_event() {
        let err = CompatibilityMatrixError {
            code: CompatibilityMatrixErrorCode::InvalidMatrix,
            message: "bad matrix".to_string(),
            event: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("FE-MODCOMP-0007"));
        assert!(msg.contains("bad matrix"));
    }

    #[test]
    fn error_display_with_event() {
        let err = CompatibilityMatrixError {
            code: CompatibilityMatrixErrorCode::CaseNotFound,
            message: "not found".to_string(),
            event: Some(CompatibilityEvent {
                seq: 0,
                trace_id: "t1".to_string(),
                decision_id: "d1".to_string(),
                policy_id: "p1".to_string(),
                component: "test".to_string(),
                event: "lookup".to_string(),
                outcome: "error".to_string(),
                error_code: "FE-MODCOMP-0003".to_string(),
                case_id: "c1".to_string(),
                runtime: "franken_engine".to_string(),
                mode: "native".to_string(),
                detail: "missing".to_string(),
            }),
        };
        let msg = err.to_string();
        assert!(msg.contains("t1"));
        assert!(msg.contains("d1"));
        assert!(msg.contains("p1"));
    }

    #[test]
    fn error_is_std_error() {
        let err = CompatibilityMatrixError {
            code: CompatibilityMatrixErrorCode::InvalidMatrix,
            message: "test".to_string(),
            event: None,
        };
        let _: &dyn std::error::Error = &err;
    }

    // ── from_entries validation ────────────────────────────────────

    #[test]
    fn from_entries_empty_schema_version_fails() {
        let err = ModuleCompatibilityMatrix::from_entries("", Vec::new()).unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
    }

    #[test]
    fn from_entries_empty_case_id_fails() {
        let entry = CompatibilityMatrixEntry {
            case_id: "".to_string(),
            feature: ModuleFeature::Esm,
            scenario: "test".to_string(),
            node_behavior: "ok".to_string(),
            bun_behavior: "ok".to_string(),
            franken_native_behavior: "ok".to_string(),
            franken_node_compat_behavior: "ok".to_string(),
            franken_bun_compat_behavior: "ok".to_string(),
            explicit_shims: Vec::new(),
            lockstep_case_refs: vec!["ref".to_string()],
            test262_refs: vec!["test".to_string()],
            divergence: None,
        };
        let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
    }

    #[test]
    fn from_entries_duplicate_case_id_fails() {
        let entry = || CompatibilityMatrixEntry {
            case_id: "dup-case".to_string(),
            feature: ModuleFeature::Esm,
            scenario: "test".to_string(),
            node_behavior: "ok".to_string(),
            bun_behavior: "ok".to_string(),
            franken_native_behavior: "ok".to_string(),
            franken_node_compat_behavior: "ok".to_string(),
            franken_bun_compat_behavior: "ok".to_string(),
            explicit_shims: Vec::new(),
            lockstep_case_refs: vec!["ref".to_string()],
            test262_refs: vec!["test".to_string()],
            divergence: None,
        };
        let err =
            ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry(), entry()]).unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::DuplicateCaseId);
    }

    #[test]
    fn from_entries_duplicate_explicit_shim_id_for_same_mode_fails() {
        let mut entry = valid_entry("dup-shim");
        entry.franken_bun_compat_behavior = "bun-different".to_string();
        entry.explicit_shims = vec![
            valid_shim(CompatibilityMode::BunCompat),
            ExplicitShim {
                description: "second declaration".to_string(),
                test_case_ref: "test262/ref.js".to_string(),
                ..valid_shim(CompatibilityMode::BunCompat)
            },
        ];

        let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("duplicate explicit shim_id"));
        assert!(err.message.contains("bun_compat"));
    }

    #[test]
    fn from_entries_same_shim_id_across_modes_is_allowed() {
        let mut entry = valid_entry("shared-shim-id");
        entry.franken_node_compat_behavior = "node-different".to_string();
        entry.franken_bun_compat_behavior = "bun-different".to_string();

        let bun_shim = ExplicitShim {
            mode: CompatibilityMode::BunCompat,
            ..valid_shim(CompatibilityMode::NodeCompat)
        };
        entry.explicit_shims = vec![valid_shim(CompatibilityMode::NodeCompat), bun_shim];

        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry])
            .expect("same shim_id may be reused across different compatibility modes");
    }

    #[test]
    fn validate_entry_duplicate_shim_id_for_same_mode_fails_even_if_matrix_construction_was_bypassed()
     {
        let mut entry = valid_entry("dup-shim-validation");
        entry.franken_bun_compat_behavior = "bun-different".to_string();
        entry.explicit_shims = vec![
            valid_shim(CompatibilityMode::BunCompat),
            ExplicitShim {
                description: "second declaration".to_string(),
                test_case_ref: "test262/ref.js".to_string(),
                ..valid_shim(CompatibilityMode::BunCompat)
            },
        ];

        let mut entries = BTreeMap::new();
        entries.insert(entry.case_id.clone(), entry);
        let mut matrix = ModuleCompatibilityMatrix {
            schema_version: "1.0.0".to_string(),
            required_readme_fragments: Vec::new(),
            entries,
            events: Vec::new(),
            next_event_seq: 0,
        };

        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .expect_err("validation should reject duplicate same-mode shim ids");
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("duplicate explicit shim_id"));
        assert!(err.message.contains("bun_compat"));
    }

    // ── from_json_str ──────────────────────────────────────────────

    #[test]
    fn from_json_str_invalid_json_fails() {
        let err = ModuleCompatibilityMatrix::from_json_str("not json").unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::MatrixParseError);
    }

    // ── entry lookup ───────────────────────────────────────────────

    #[test]
    fn entry_lookup_found() {
        let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let entries = matrix.entries();
        assert!(!entries.is_empty());
        let first_id = &entries[0].case_id;
        assert!(matrix.entry(first_id).is_some());
    }

    #[test]
    fn entry_lookup_not_found() {
        let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        assert!(matrix.entry("nonexistent-case-id-xyz").is_none());
    }

    // ── canonical_bytes deterministic ──────────────────────────────

    #[test]
    fn canonical_bytes_deterministic() {
        let a = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let b = ModuleCompatibilityMatrix::from_default_json().unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    // ── events accessor ────────────────────────────────────────────

    #[test]
    fn events_empty_initially() {
        let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        assert!(matrix.events().is_empty());
    }

    // ── serde round-trips ──────────────────────────────────────────

    #[test]
    fn module_feature_serde_round_trip() {
        for variant in [
            ModuleFeature::Esm,
            ModuleFeature::Cjs,
            ModuleFeature::DualMode,
            ModuleFeature::ConditionalExports,
            ModuleFeature::PackageJsonFields,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ModuleFeature = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn compatibility_runtime_serde_round_trip() {
        for variant in [
            CompatibilityRuntime::FrankenEngine,
            CompatibilityRuntime::Node,
            CompatibilityRuntime::Bun,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: CompatibilityRuntime = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn compatibility_mode_serde_round_trip() {
        for variant in [
            CompatibilityMode::Native,
            CompatibilityMode::NodeCompat,
            CompatibilityMode::BunCompat,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: CompatibilityMode = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn error_code_serde_round_trip() {
        for variant in [
            CompatibilityMatrixErrorCode::MatrixParseError,
            CompatibilityMatrixErrorCode::DuplicateCaseId,
            CompatibilityMatrixErrorCode::CaseNotFound,
            CompatibilityMatrixErrorCode::HiddenShim,
            CompatibilityMatrixErrorCode::MissingWaiver,
            CompatibilityMatrixErrorCode::MissingMigrationGuidance,
            CompatibilityMatrixErrorCode::InvalidMatrix,
            CompatibilityMatrixErrorCode::ObservationMismatch,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: CompatibilityMatrixErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── evaluate_observation: case not found ───────────────────────

    #[test]
    fn evaluate_observation_unknown_case_fails() {
        let mut matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let obs = CompatibilityObservation::new(
            "nonexistent-case-xyz",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "some behavior",
        );
        let err = matrix.evaluate_observation(&obs, &context()).unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::CaseNotFound);
    }

    // ── required_waiver_ids ────────────────────────────────────────

    #[test]
    fn required_waiver_ids_from_default() {
        let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let waivers = matrix.required_waiver_ids();
        // Default matrix should have at least one waiver
        assert!(!waivers.is_empty());
    }

    // ── Helper for valid test entries ────────────────────────────

    fn valid_entry(case_id: &str) -> CompatibilityMatrixEntry {
        CompatibilityMatrixEntry {
            case_id: case_id.to_string(),
            feature: ModuleFeature::Esm,
            scenario: "test scenario".to_string(),
            node_behavior: "ok".to_string(),
            bun_behavior: "ok".to_string(),
            franken_native_behavior: "ok".to_string(),
            franken_node_compat_behavior: "ok".to_string(),
            franken_bun_compat_behavior: "ok".to_string(),
            explicit_shims: Vec::new(),
            lockstep_case_refs: vec!["lockstep/ref".to_string()],
            test262_refs: vec!["test262/ref.js".to_string()],
            divergence: None,
        }
    }

    fn valid_shim(mode: CompatibilityMode) -> ExplicitShim {
        ExplicitShim {
            shim_id: "shim-1".to_string(),
            mode,
            description: "shim description".to_string(),
            removable: true,
            test_case_ref: "lockstep/ref".to_string(),
        }
    }

    // ── validate_entry: empty scenario ───────────────────────────

    #[test]
    fn validate_entry_empty_scenario_fails() {
        let mut entry = valid_entry("case-1");
        entry.scenario.clear();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("scenario"));
    }

    #[test]
    fn validate_entry_empty_lockstep_refs_fails() {
        let mut entry = valid_entry("case-1");
        entry.lockstep_case_refs.clear();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("lockstep"));
    }

    #[test]
    fn validate_entry_empty_test262_refs_fails() {
        let mut entry = valid_entry("case-1");
        entry.test262_refs.clear();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("test262"));
    }

    // ── validate_entry: shim field validation ────────────────────

    #[test]
    fn validate_entry_shim_empty_shim_id_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_node_compat_behavior = "different".to_string();
        let mut shim = valid_shim(CompatibilityMode::NodeCompat);
        shim.shim_id.clear();
        entry.explicit_shims.push(shim);
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("shim_id"));
    }

    #[test]
    fn validate_entry_shim_empty_description_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_node_compat_behavior = "different".to_string();
        let mut shim = valid_shim(CompatibilityMode::NodeCompat);
        shim.description.clear();
        entry.explicit_shims.push(shim);
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("description"));
    }

    #[test]
    fn validate_entry_shim_empty_test_case_ref_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_node_compat_behavior = "different".to_string();
        let mut shim = valid_shim(CompatibilityMode::NodeCompat);
        shim.test_case_ref.clear();
        entry.explicit_shims.push(shim);
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("test_case_ref"));
    }

    #[test]
    fn validate_entry_shim_detached_test_case_ref_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_node_compat_behavior = "different".to_string();
        let mut shim = valid_shim(CompatibilityMode::NodeCompat);
        shim.test_case_ref = "lockstep/unknown-ref".to_string();
        entry.explicit_shims.push(shim);
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("test_case_ref"));
    }

    #[test]
    fn validate_entry_shim_not_removable_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_node_compat_behavior = "different".to_string();
        let mut shim = valid_shim(CompatibilityMode::NodeCompat);
        shim.removable = false;
        entry.explicit_shims.push(shim);
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("removable"));
    }

    // ── validate_entry: divergence metadata validation ───────────

    #[test]
    fn validate_entry_divergence_present_but_no_mismatch_fails() {
        let mut entry = valid_entry("case-1");
        // All behaviors match, but divergence is declared — invalid
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "reason".to_string(),
            impact: "impact".to_string(),
            waiver_id: "w-1".to_string(),
            migration_guidance: "guidance".to_string(),
        });
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::from(["w-1".to_string()]), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("native behavior matches"));
    }

    #[test]
    fn validate_entry_declared_runtime_set_mismatch_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_native_behavior = "native".to_string();
        entry.franken_node_compat_behavior = "native".to_string();
        entry.franken_bun_compat_behavior = "native".to_string();
        entry.node_behavior = "node-diff".to_string();
        entry.bun_behavior = "bun-diff".to_string();
        // Declares only Node, but Bun also diverges
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "r".to_string(),
            impact: "i".to_string(),
            waiver_id: "w-1".to_string(),
            migration_guidance: "g".to_string(),
        });
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::from(["w-1".to_string()]), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
        assert!(err.message.contains("runtime set mismatch"));
    }

    #[test]
    fn validate_entry_empty_waiver_id_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_native_behavior = "native".to_string();
        entry.franken_node_compat_behavior = "native".to_string();
        entry.franken_bun_compat_behavior = "native".to_string();
        entry.node_behavior = "different".to_string();
        entry.bun_behavior = "native".to_string();
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "r".to_string(),
            impact: "i".to_string(),
            waiver_id: "".to_string(),
            migration_guidance: "g".to_string(),
        });
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
    }

    #[test]
    fn validate_entry_empty_migration_guidance_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_native_behavior = "native".to_string();
        entry.franken_node_compat_behavior = "native".to_string();
        entry.franken_bun_compat_behavior = "native".to_string();
        entry.node_behavior = "different".to_string();
        entry.bun_behavior = "native".to_string();
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "r".to_string(),
            impact: "i".to_string(),
            waiver_id: "w-1".to_string(),
            migration_guidance: "".to_string(),
        });
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::from(["w-1".to_string()]), &context())
            .unwrap_err();
        assert_eq!(
            err.code,
            CompatibilityMatrixErrorCode::MissingMigrationGuidance
        );
    }

    #[test]
    fn validate_entry_diverges_without_policy_fails() {
        let mut entry = valid_entry("case-1");
        entry.franken_native_behavior = "native".to_string();
        entry.franken_node_compat_behavior = "native".to_string();
        entry.franken_bun_compat_behavior = "native".to_string();
        entry.node_behavior = "different".to_string();
        entry.bun_behavior = "native".to_string();
        // No divergence policy declared
        entry.divergence = None;
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
    }

    // ── validate_entry: fully valid entry passes ─────────────────

    #[test]
    fn validate_entry_fully_valid_passes() {
        let entry = valid_entry("case-ok");
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .expect("valid entry should pass validation");
        assert!(!matrix.events().is_empty());
    }

    #[test]
    fn validate_entry_valid_with_divergence_passes() {
        let mut entry = valid_entry("case-div");
        entry.franken_native_behavior = "native".to_string();
        entry.franken_node_compat_behavior = "native".to_string();
        entry.franken_bun_compat_behavior = "native".to_string();
        entry.node_behavior = "different".to_string();
        entry.bun_behavior = "native".to_string();
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "reason".to_string(),
            impact: "low".to_string(),
            waiver_id: "w-div".to_string(),
            migration_guidance: "use native API".to_string(),
        });
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        matrix
            .validate_with_waivers(&BTreeSet::from(["w-div".to_string()]), &context())
            .expect("valid divergent entry should pass");
    }

    // ── evaluate_observation: behavior mismatch ──────────────────

    #[test]
    fn evaluate_observation_behavior_mismatch_fails() {
        let entry = valid_entry("case-obs");
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-obs",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "unexpected-behavior",
        );
        let err = matrix.evaluate_observation(&obs, &context()).unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::ObservationMismatch);
        assert!(err.message.contains("mismatch"));
    }

    #[test]
    fn evaluate_observation_matching_behavior_succeeds() {
        let entry = valid_entry("case-obs");
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-obs",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "ok",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert!(outcome.matched);
        assert_eq!(outcome.case_id, "case-obs");
        assert_eq!(outcome.expected_behavior, "ok");
        assert_eq!(outcome.observed_behavior, "ok");
        assert!(outcome.divergence.is_none());
    }

    #[test]
    fn evaluate_observation_with_divergence_returns_policy() {
        let mut entry = valid_entry("case-div-obs");
        entry.franken_native_behavior = "native-behavior".to_string();
        entry.node_behavior = "node-different".to_string();
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "intentional".to_string(),
            impact: "low".to_string(),
            waiver_id: "w-obs".to_string(),
            migration_guidance: "use compat mode".to_string(),
        });
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-div-obs",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "native-behavior",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert!(outcome.matched);
        assert!(outcome.divergence.is_some());
    }

    #[test]
    fn evaluate_observation_node_runtime() {
        let mut entry = valid_entry("case-node");
        entry.node_behavior = "node-ok".to_string();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-node",
            CompatibilityRuntime::Node,
            CompatibilityMode::Native,
            "node-ok",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert!(outcome.matched);
    }

    #[test]
    fn evaluate_observation_bun_runtime() {
        let mut entry = valid_entry("case-bun");
        entry.bun_behavior = "bun-ok".to_string();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-bun",
            CompatibilityRuntime::Bun,
            CompatibilityMode::Native,
            "bun-ok",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert!(outcome.matched);
    }

    #[test]
    fn evaluate_observation_franken_node_compat_mode() {
        let mut entry = valid_entry("case-nc");
        entry.franken_node_compat_behavior = "nc-behavior".to_string();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-nc",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::NodeCompat,
            "nc-behavior",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert!(outcome.matched);
    }

    #[test]
    fn evaluate_observation_franken_bun_compat_mode() {
        let mut entry = valid_entry("case-bc");
        entry.franken_bun_compat_behavior = "bc-behavior".to_string();
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let obs = CompatibilityObservation::new(
            "case-bc",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::BunCompat,
            "bc-behavior",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert!(outcome.matched);
    }

    // ── to_json_pretty ──────────────────────────────────────────

    #[test]
    fn to_json_pretty_round_trips() {
        let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let json = matrix.to_json_pretty().unwrap();
        let reparsed = ModuleCompatibilityMatrix::from_json_str(&json).unwrap();
        assert_eq!(matrix.canonical_hash(), reparsed.canonical_hash());
    }

    // ── canonical_hash ──────────────────────────────────────────

    #[test]
    fn canonical_hash_differs_for_different_entries() {
        let entry_a = valid_entry("case-a");
        let entry_b = valid_entry("case-b");
        let ma = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry_a]).unwrap();
        let mb = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry_b]).unwrap();
        assert_ne!(ma.canonical_hash(), mb.canonical_hash());
    }

    // ── bun_compat hidden shim ──────────────────────────────────

    #[test]
    fn validate_entry_bun_compat_hidden_shim_fails() {
        let mut entry = valid_entry("case-bun-shim");
        entry.franken_bun_compat_behavior = "different".to_string();
        // No shim declared for BunCompat
        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let err = matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .unwrap_err();
        assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
    }

    // ── event sequencing ────────────────────────────────────────

    #[test]
    fn events_have_incrementing_sequence_numbers() {
        let mut matrix = ModuleCompatibilityMatrix::from_entries(
            "1.0.0",
            vec![valid_entry("case-1"), valid_entry("case-2")],
        )
        .unwrap();
        matrix
            .validate_with_waivers(&BTreeSet::new(), &context())
            .expect("valid entries should pass");
        let events = matrix.events();
        assert!(events.len() >= 2);
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.seq, i as u64);
        }
    }

    #[test]
    fn module_feature_ord() {
        assert!(ModuleFeature::Esm < ModuleFeature::Cjs);
        assert!(ModuleFeature::Cjs < ModuleFeature::DualMode);
        assert!(ModuleFeature::DualMode < ModuleFeature::ConditionalExports);
        assert!(ModuleFeature::ConditionalExports < ModuleFeature::PackageJsonFields);
    }

    #[test]
    fn compatibility_runtime_ord() {
        assert!(CompatibilityRuntime::FrankenEngine < CompatibilityRuntime::Node);
        assert!(CompatibilityRuntime::Node < CompatibilityRuntime::Bun);
    }

    #[test]
    fn compatibility_mode_ord() {
        assert!(CompatibilityMode::Native < CompatibilityMode::NodeCompat);
        assert!(CompatibilityMode::NodeCompat < CompatibilityMode::BunCompat);
    }

    #[test]
    fn reference_runtime_ord() {
        assert!(ReferenceRuntime::Node < ReferenceRuntime::Bun);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn reference_runtime_serde_round_trip() {
        for variant in [ReferenceRuntime::Node, ReferenceRuntime::Bun] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ReferenceRuntime = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn explicit_shim_serde_round_trip() {
        let shim = valid_shim(CompatibilityMode::NodeCompat);
        let json = serde_json::to_string(&shim).unwrap();
        let back: ExplicitShim = serde_json::from_str(&json).unwrap();
        assert_eq!(shim, back);
    }

    #[test]
    fn divergence_policy_serde_round_trip() {
        let policy = DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "spec extension".to_string(),
            impact: "none".to_string(),
            waiver_id: "waiver-1".to_string(),
            migration_guidance: "wrap in try/catch".to_string(),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: DivergencePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn compatibility_matrix_entry_serde_round_trip() {
        let entry = valid_entry("case-serde");
        let json = serde_json::to_string(&entry).unwrap();
        let back: CompatibilityMatrixEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn compatibility_context_serde_round_trip() {
        let ctx = context();
        let json = serde_json::to_string(&ctx).unwrap();
        let back: CompatibilityContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn compatibility_observation_serde_round_trip() {
        let obs = CompatibilityObservation::new(
            "case-1",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "ok",
        );
        let json = serde_json::to_string(&obs).unwrap();
        let back: CompatibilityObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }

    #[test]
    fn compatibility_matrix_error_serde_round_trip() {
        let err = CompatibilityMatrixError {
            code: CompatibilityMatrixErrorCode::CaseNotFound,
            message: "case not found".to_string(),
            event: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: CompatibilityMatrixError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn required_waiver_ids_empty_for_no_divergences() {
        let matrix = ModuleCompatibilityMatrix::from_entries(
            "v1".to_string(),
            vec![valid_entry("case-no-div")],
        )
        .unwrap();
        let waivers = matrix.required_waiver_ids();
        assert!(waivers.is_empty());
    }

    #[test]
    fn required_waiver_ids_deduplicates() {
        let mut entry_a = valid_entry("case-a");
        entry_a.franken_native_behavior = "divergent".to_string();
        entry_a.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "r".to_string(),
            impact: "none".to_string(),
            waiver_id: "shared-waiver".to_string(),
            migration_guidance: "m".to_string(),
        });
        entry_a.explicit_shims = vec![valid_shim(CompatibilityMode::Native)];

        let mut entry_b = valid_entry("case-b");
        entry_b.franken_native_behavior = "also-divergent".to_string();
        entry_b.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "r2".to_string(),
            impact: "none".to_string(),
            waiver_id: "shared-waiver".to_string(),
            migration_guidance: "m2".to_string(),
        });
        entry_b.explicit_shims = vec![valid_shim(CompatibilityMode::Native)];

        let matrix =
            ModuleCompatibilityMatrix::from_entries("v1".to_string(), vec![entry_a, entry_b])
                .unwrap();
        let waivers = matrix.required_waiver_ids();
        assert_eq!(waivers.len(), 1);
        assert!(waivers.contains("shared-waiver"));
    }

    #[test]
    fn canonical_hash_stable_across_calls() {
        let matrix = ModuleCompatibilityMatrix::from_entries(
            "v1".to_string(),
            vec![valid_entry("case-hash")],
        )
        .unwrap();
        let h1 = matrix.canonical_hash();
        let h2 = matrix.canonical_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn entries_returns_all_added() {
        let matrix = ModuleCompatibilityMatrix::from_entries(
            "v1".to_string(),
            vec![valid_entry("a"), valid_entry("b"), valid_entry("c")],
        )
        .unwrap();
        assert_eq!(matrix.entries().len(), 3);
        assert!(matrix.entry("a").is_some());
        assert!(matrix.entry("b").is_some());
        assert!(matrix.entry("c").is_some());
        assert!(matrix.entry("nonexistent").is_none());
    }

    #[test]
    fn error_code_stable_codes_are_unique() {
        let codes = [
            CompatibilityMatrixErrorCode::MatrixParseError,
            CompatibilityMatrixErrorCode::DuplicateCaseId,
            CompatibilityMatrixErrorCode::CaseNotFound,
            CompatibilityMatrixErrorCode::HiddenShim,
            CompatibilityMatrixErrorCode::MissingWaiver,
            CompatibilityMatrixErrorCode::MissingMigrationGuidance,
            CompatibilityMatrixErrorCode::InvalidMatrix,
            CompatibilityMatrixErrorCode::ObservationMismatch,
        ];
        let strs: Vec<&str> = codes.iter().map(|c| c.stable_code()).collect();
        let mut deduped = strs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(strs.len(), deduped.len());
    }

    #[test]
    fn error_display_contains_message() {
        let err = CompatibilityMatrixError {
            code: CompatibilityMatrixErrorCode::InvalidMatrix,
            message: "schema version is empty".to_string(),
            event: None,
        };
        let display = err.to_string();
        assert!(
            display.contains("schema version is empty"),
            "display: {display}"
        );
    }

    #[test]
    fn evaluate_observation_assigns_divergence_category_and_guidance() {
        let mut entry = valid_entry("case-category");
        entry.franken_native_behavior = "native-strict".to_string();
        entry.franken_node_compat_behavior = "native-strict".to_string();
        entry.franken_bun_compat_behavior = "native-strict".to_string();
        entry.node_behavior = "node-lenient".to_string();
        entry.bun_behavior = "native-strict".to_string();
        entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "Strict security posture for native mode".to_string(),
            impact: "requires compat mode for legacy package".to_string(),
            waiver_id: "waiver-category".to_string(),
            migration_guidance: "switch to node_compat while migrating".to_string(),
        });

        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        matrix
            .validate_with_waivers(&BTreeSet::from(["waiver-category".to_string()]), &context())
            .expect("entry should validate");

        let obs = CompatibilityObservation::new(
            "case-category",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "native-strict",
        );
        let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
        assert_eq!(
            outcome.divergence_category,
            Some(DivergenceCategory::IntentionalImprovement)
        );
        assert!(
            outcome
                .actionable_guidance
                .as_deref()
                .expect("guidance should exist")
                .contains("compat-mode")
        );
    }

    #[test]
    fn evaluate_scenario_produces_deterministic_report() {
        let mut strict_entry = valid_entry("case-strict");
        strict_entry.franken_native_behavior = "native-strict".to_string();
        strict_entry.franken_node_compat_behavior = "native-strict".to_string();
        strict_entry.franken_bun_compat_behavior = "native-strict".to_string();
        strict_entry.node_behavior = "node-lenient".to_string();
        strict_entry.bun_behavior = "native-strict".to_string();
        strict_entry.divergence = Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "strict security behavior".to_string(),
            impact: "requires compat mode".to_string(),
            waiver_id: "waiver-strict".to_string(),
            migration_guidance: "use node_compat".to_string(),
        });

        let mut clean_entry = valid_entry("case-clean");
        clean_entry.scenario = "no divergence case".to_string();

        let mut matrix =
            ModuleCompatibilityMatrix::from_entries("1.0.0", vec![strict_entry, clean_entry])
                .unwrap();
        matrix
            .validate_with_waivers(&BTreeSet::from(["waiver-strict".to_string()]), &context())
            .expect("entries should validate");

        let report = matrix
            .evaluate_scenario(
                "interop-package-scenario",
                &[
                    CompatibilityObservation::new(
                        "case-strict",
                        CompatibilityRuntime::FrankenEngine,
                        CompatibilityMode::Native,
                        "native-strict",
                    ),
                    CompatibilityObservation::new(
                        "case-clean",
                        CompatibilityRuntime::FrankenEngine,
                        CompatibilityMode::Native,
                        "ok",
                    ),
                ],
                &context(),
                1_726_000_000_000,
            )
            .expect("scenario should evaluate");

        assert_eq!(
            report.schema_version,
            COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION
        );
        assert_eq!(report.scenario_id, "interop-package-scenario");
        assert_eq!(report.total_observations, 2);
        assert_eq!(report.matched_observations, 2);
        assert_eq!(
            report
                .divergence_category_counts
                .get("intentional_improvement")
                .copied(),
            Some(1)
        );
        assert!(
            report
                .actionable_guidance
                .contains_key("intentional_improvement")
        );
        assert_eq!(report.trace_id, "trace-modcompat");
        assert_eq!(report.decision_id, "decision-modcompat");
        assert_eq!(report.policy_id, "policy-modcompat");
        assert_eq!(report.generated_at_unix_ms, 1_726_000_000_000);
    }

    #[test]
    fn classify_divergence_detects_reference_runtime_bug() {
        let divergence = DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "Known reference runtime bug in Node resolver".to_string(),
            impact: "temporary shim".to_string(),
            waiver_id: "waiver-ref-bug".to_string(),
            migration_guidance: "keep shim until upstream fix lands".to_string(),
        };
        assert_eq!(
            classify_divergence(&divergence),
            DivergenceCategory::ReferenceRuntimeBug
        );
    }
}
