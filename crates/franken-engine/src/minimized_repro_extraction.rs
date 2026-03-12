//! Minimized repro extraction and owner-routed triage for React ecosystem failures.
//!
//! Bead: bd-1lsy.5.7.3 [RGC-405C]
//!
//! Builds the React-specific failure triage loop so ecosystem incompatibilities
//! become actionable engineering work instead of vague "React still flaky"
//! folklore.
//!
//! # Design
//!
//! - `FailureCategory` classifies the kind of React ecosystem failure.
//! - `ReproInput` captures the original failing workload.
//! - `MinimizationStrategy` — how the repro is minimized.
//! - `MinimizedRepro` — the reduced reproduction case.
//! - `TriageOwner` — who gets routed the triage finding.
//! - `TriageFinding` — actionable finding with owner, severity, repro.
//! - `ExtractionConfig` — thresholds for minimization acceptance.
//! - `ExtractionVerdict` — gate output.
//! - `ExtractionReport` — content-hashed audit trail.
//!
//! All ratios use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-405C]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.minimized-repro-extraction.v1";

/// Component name.
pub const COMPONENT: &str = "minimized_repro_extraction";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.5.7.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-405C";

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Default maximum repro size (lines of code).
pub const DEFAULT_MAX_REPRO_LINES: u64 = 50;

/// Default minimum reduction ratio (millionths). 500_000 = 50%.
pub const DEFAULT_MIN_REDUCTION_RATIO: u64 = 500_000;

/// Default maximum triage latency (nanoseconds). 60 seconds.
pub const DEFAULT_MAX_TRIAGE_LATENCY_NS: u64 = 60_000_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// FailureCategory
// ---------------------------------------------------------------------------

/// Classification of React ecosystem failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    /// Component render crash.
    RenderCrash,
    /// Hydration mismatch.
    HydrationMismatch,
    /// Hook ordering violation.
    HookOrdering,
    /// Concurrent mode race.
    ConcurrentRace,
    /// Suspense boundary failure.
    SuspenseFailure,
    /// Server component serialization error.
    ServerComponentError,
    /// Module resolution failure.
    ModuleResolution,
    /// JSX transform error.
    JsxTransform,
    /// State management incompatibility.
    StateManagement,
    /// Build tool integration failure.
    BuildToolIntegration,
}

impl FailureCategory {
    /// All categories.
    pub fn all() -> &'static [Self] {
        &[
            Self::RenderCrash,
            Self::HydrationMismatch,
            Self::HookOrdering,
            Self::ConcurrentRace,
            Self::SuspenseFailure,
            Self::ServerComponentError,
            Self::ModuleResolution,
            Self::JsxTransform,
            Self::StateManagement,
            Self::BuildToolIntegration,
        ]
    }
}

impl fmt::Display for FailureCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RenderCrash => "render_crash",
            Self::HydrationMismatch => "hydration_mismatch",
            Self::HookOrdering => "hook_ordering",
            Self::ConcurrentRace => "concurrent_race",
            Self::SuspenseFailure => "suspense_failure",
            Self::ServerComponentError => "server_component_error",
            Self::ModuleResolution => "module_resolution",
            Self::JsxTransform => "jsx_transform",
            Self::StateManagement => "state_management",
            Self::BuildToolIntegration => "build_tool_integration",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// MinimizationStrategy
// ---------------------------------------------------------------------------

/// How the repro is minimized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimizationStrategy {
    /// Delta debugging — binary reduction.
    DeltaDebugging,
    /// Hierarchical — reduce component tree.
    HierarchicalReduction,
    /// Dependency stripping — remove unused deps.
    DependencyStripping,
    /// State slicing — isolate relevant state.
    StateSlicing,
    /// Prop elimination — remove unnecessary props.
    PropElimination,
}

impl fmt::Display for MinimizationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DeltaDebugging => "delta_debugging",
            Self::HierarchicalReduction => "hierarchical_reduction",
            Self::DependencyStripping => "dependency_stripping",
            Self::StateSlicing => "state_slicing",
            Self::PropElimination => "prop_elimination",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ReproInput
// ---------------------------------------------------------------------------

/// Original failing workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproInput {
    /// Unique identifier.
    pub input_id: String,
    /// Failure category.
    pub category: FailureCategory,
    /// Original size (lines).
    pub original_lines: u64,
    /// Number of components in original.
    pub component_count: u64,
    /// Number of dependencies.
    pub dependency_count: u64,
    /// Content hash of original.
    pub input_hash: ContentHash,
}

impl ReproInput {
    /// Create with computed hash.
    pub fn new(
        input_id: String,
        category: FailureCategory,
        original_lines: u64,
        component_count: u64,
        dependency_count: u64,
    ) -> Self {
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, &input_id);
        append_str(&mut buf, &category.to_string());
        append_u64(&mut buf, original_lines);
        append_u64(&mut buf, component_count);
        append_u64(&mut buf, dependency_count);
        let input_hash = compute_digest(&buf);
        Self {
            input_id,
            category,
            original_lines,
            component_count,
            dependency_count,
            input_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// MinimizedRepro
// ---------------------------------------------------------------------------

/// Reduced reproduction case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedRepro {
    /// Source input.
    pub source_input_id: String,
    /// Strategy used.
    pub strategy: MinimizationStrategy,
    /// Reduced size (lines).
    pub reduced_lines: u64,
    /// Original size (lines).
    pub original_lines: u64,
    /// Reduction ratio in millionths.
    pub reduction_ratio_millionths: u64,
    /// Whether the failure still reproduces.
    pub reproduces: bool,
    /// Time to minimise (ns).
    pub minimisation_time_ns: u64,
    /// Repro hash.
    pub repro_hash: ContentHash,
}

impl MinimizedRepro {
    /// Create with computed ratio.
    pub fn new(
        source_input_id: String,
        strategy: MinimizationStrategy,
        reduced_lines: u64,
        original_lines: u64,
        reproduces: bool,
        minimisation_time_ns: u64,
    ) -> Self {
        let reduction_ratio_millionths = if original_lines == 0 {
            0
        } else {
            original_lines
                .saturating_sub(reduced_lines)
                .saturating_mul(FIXED_ONE)
                / original_lines
        };
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, &source_input_id);
        append_str(&mut buf, &strategy.to_string());
        append_u64(&mut buf, reduced_lines);
        append_u64(&mut buf, original_lines);
        append_u64(&mut buf, if reproduces { 1 } else { 0 });
        let repro_hash = compute_digest(&buf);
        Self {
            source_input_id,
            strategy,
            reduced_lines,
            original_lines,
            reduction_ratio_millionths,
            reproduces,
            minimisation_time_ns,
            repro_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// TriageOwner
// ---------------------------------------------------------------------------

/// Who gets the triage finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageOwner {
    /// Engine runtime team.
    EngineRuntime,
    /// Parser/compiler team.
    ParserCompiler,
    /// React integration team.
    ReactIntegration,
    /// Module resolution team.
    ModuleResolution,
    /// Build tooling team.
    BuildTooling,
    /// External upstream (React core).
    ExternalUpstream,
}

impl fmt::Display for TriageOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::EngineRuntime => "engine_runtime",
            Self::ParserCompiler => "parser_compiler",
            Self::ReactIntegration => "react_integration",
            Self::ModuleResolution => "module_resolution",
            Self::BuildTooling => "build_tooling",
            Self::ExternalUpstream => "external_upstream",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// TriageSeverity
// ---------------------------------------------------------------------------

/// Severity of a triage finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageSeverity {
    /// Informational.
    Info,
    /// Warning — may affect users.
    Warning,
    /// Error — blocks functionality.
    Error,
    /// Critical — data loss or security.
    Critical,
}

// ---------------------------------------------------------------------------
// TriageFinding
// ---------------------------------------------------------------------------

/// Actionable triage finding with owner routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageFinding {
    /// Failure category.
    pub category: FailureCategory,
    /// Routed owner.
    pub owner: TriageOwner,
    /// Severity.
    pub severity: TriageSeverity,
    /// Summary.
    pub summary: String,
    /// Associated minimized repro (if available).
    pub repro_hash: Option<ContentHash>,
    /// Recommended action.
    pub recommended_action: String,
}

// ---------------------------------------------------------------------------
// ExtractionConfig
// ---------------------------------------------------------------------------

/// Configuration for repro extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionConfig {
    /// Maximum repro size (lines).
    pub max_repro_lines: u64,
    /// Minimum reduction ratio (millionths).
    pub min_reduction_ratio: u64,
    /// Maximum triage latency (ns).
    pub max_triage_latency_ns: u64,
    /// Required failure categories to cover.
    pub required_categories: BTreeSet<FailureCategory>,
}

impl ExtractionConfig {
    /// Strict config.
    pub fn strict() -> Self {
        Self {
            max_repro_lines: 30,
            min_reduction_ratio: 700_000,
            max_triage_latency_ns: 30_000_000_000,
            required_categories: FailureCategory::all().iter().copied().collect(),
        }
    }

    /// Relaxed config.
    pub fn relaxed() -> Self {
        Self {
            max_repro_lines: DEFAULT_MAX_REPRO_LINES,
            min_reduction_ratio: DEFAULT_MIN_REDUCTION_RATIO,
            max_triage_latency_ns: DEFAULT_MAX_TRIAGE_LATENCY_NS,
            required_categories: BTreeSet::new(),
        }
    }
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self::relaxed()
    }
}

// ---------------------------------------------------------------------------
// ExtractionVerdict
// ---------------------------------------------------------------------------

/// Gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionVerdict {
    /// All repros minimized and triaged.
    Complete,
    /// Some repros not sufficiently minimized.
    PartialReduction,
    /// Required categories not covered.
    IncompleteCoverage,
    /// Triage latency exceeded.
    TriageLatencyExceeded,
    /// No inputs processed.
    NoInputs,
    /// Multiple issues.
    MultipleIssues,
}

impl ExtractionVerdict {
    /// Whether work remains.
    pub fn needs_attention(self) -> bool {
        self != Self::Complete
    }
}

impl fmt::Display for ExtractionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Complete => "complete",
            Self::PartialReduction => "partial_reduction",
            Self::IncompleteCoverage => "incomplete_coverage",
            Self::TriageLatencyExceeded => "triage_latency_exceeded",
            Self::NoInputs => "no_inputs",
            Self::MultipleIssues => "multiple_issues",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ExtractionReport
// ---------------------------------------------------------------------------

/// Content-hashed extraction report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionReport {
    /// Verdict.
    pub verdict: ExtractionVerdict,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Inputs processed.
    pub inputs: Vec<ReproInput>,
    /// Minimized repros.
    pub repros: Vec<MinimizedRepro>,
    /// Triage findings.
    pub findings: Vec<TriageFinding>,
    /// Categories covered.
    pub categories_covered: BTreeSet<FailureCategory>,
    /// Categories missing.
    pub categories_missing: BTreeSet<FailureCategory>,
    /// Total reduction ratio (average, millionths).
    pub avg_reduction_ratio_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ExtractionReport {
    fn compute_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &format!("{}", self.verdict));
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.inputs.len() as u64);
        for i in &self.inputs {
            buf.extend_from_slice(i.input_hash.as_bytes());
        }
        append_u64(&mut buf, self.repros.len() as u64);
        for r in &self.repros {
            buf.extend_from_slice(r.repro_hash.as_bytes());
        }
        append_u64(&mut buf, self.findings.len() as u64);
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// ExtractionEngine
// ---------------------------------------------------------------------------

/// Orchestrates repro extraction and triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionEngine {
    /// Configuration.
    pub config: ExtractionConfig,
    /// Inputs.
    pub inputs: Vec<ReproInput>,
    /// Minimized repros.
    pub repros: Vec<MinimizedRepro>,
    /// Triage findings.
    pub findings: Vec<TriageFinding>,
}

impl ExtractionEngine {
    /// Create with config.
    pub fn new(config: ExtractionConfig) -> Self {
        Self {
            config,
            inputs: Vec::new(),
            repros: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Add a failing input.
    pub fn add_input(&mut self, input: ReproInput) {
        self.inputs.push(input);
    }

    /// Add a minimized repro.
    pub fn add_repro(&mut self, repro: MinimizedRepro) {
        self.repros.push(repro);
    }

    /// Add a triage finding.
    pub fn add_finding(&mut self, finding: TriageFinding) {
        self.findings.push(finding);
    }

    /// Route a failure category to the default owner.
    pub fn default_owner(category: FailureCategory) -> TriageOwner {
        match category {
            FailureCategory::RenderCrash | FailureCategory::ConcurrentRace => {
                TriageOwner::EngineRuntime
            }
            FailureCategory::HydrationMismatch | FailureCategory::SuspenseFailure => {
                TriageOwner::ReactIntegration
            }
            FailureCategory::HookOrdering | FailureCategory::StateManagement => {
                TriageOwner::ReactIntegration
            }
            FailureCategory::ServerComponentError => TriageOwner::ReactIntegration,
            FailureCategory::ModuleResolution => TriageOwner::ModuleResolution,
            FailureCategory::JsxTransform => TriageOwner::ParserCompiler,
            FailureCategory::BuildToolIntegration => TriageOwner::BuildTooling,
        }
    }

    /// Evaluate and produce report.
    pub fn evaluate(&self, epoch: SecurityEpoch) -> ExtractionReport {
        let categories_covered: BTreeSet<FailureCategory> =
            self.inputs.iter().map(|i| i.category).collect();

        let mut categories_missing = BTreeSet::new();
        for cat in &self.config.required_categories {
            if !categories_covered.contains(cat) {
                categories_missing.insert(*cat);
            }
        }

        // Compute average reduction ratio.
        let avg_reduction = if self.repros.is_empty() {
            0
        } else {
            let total: u64 = self
                .repros
                .iter()
                .map(|r| r.reduction_ratio_millionths)
                .sum();
            total / self.repros.len() as u64
        };

        // Check for issues.
        let mut issues = Vec::new();

        if self.inputs.is_empty() {
            issues.push(ExtractionVerdict::NoInputs);
        }

        if !categories_missing.is_empty() {
            issues.push(ExtractionVerdict::IncompleteCoverage);
        }

        // Check reduction quality.
        let poorly_reduced = self.repros.iter().any(|r| {
            r.reduction_ratio_millionths < self.config.min_reduction_ratio
                || r.reduced_lines > self.config.max_repro_lines
        });
        if poorly_reduced {
            issues.push(ExtractionVerdict::PartialReduction);
        }

        // Check triage latency.
        let slow_minimisation = self
            .repros
            .iter()
            .any(|r| r.minimisation_time_ns > self.config.max_triage_latency_ns);
        if slow_minimisation {
            issues.push(ExtractionVerdict::TriageLatencyExceeded);
        }

        let verdict = if issues.is_empty() {
            ExtractionVerdict::Complete
        } else if issues.len() == 1 {
            issues[0]
        } else {
            ExtractionVerdict::MultipleIssues
        };

        let mut report = ExtractionReport {
            verdict,
            epoch,
            inputs: self.inputs.clone(),
            repros: self.repros.clone(),
            findings: self.findings.clone(),
            categories_covered,
            categories_missing,
            avg_reduction_ratio_millionths: avg_reduction,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        report.content_hash = report.compute_hash();
        report
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("minimized-repro-extraction"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "minimized_repro_extraction");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.5.7.3");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-405C");
    }

    #[test]
    fn test_failure_category_all_count() {
        assert_eq!(FailureCategory::all().len(), 10);
    }

    #[test]
    fn test_failure_category_ordering() {
        assert!(FailureCategory::RenderCrash < FailureCategory::BuildToolIntegration);
    }

    #[test]
    fn test_failure_category_display() {
        assert_eq!(
            FailureCategory::HydrationMismatch.to_string(),
            "hydration_mismatch"
        );
    }

    #[test]
    fn test_minimization_strategy_display() {
        assert_eq!(
            MinimizationStrategy::DeltaDebugging.to_string(),
            "delta_debugging"
        );
    }

    #[test]
    fn test_repro_input_hash_deterministic() {
        let a = ReproInput::new("input1".into(), FailureCategory::RenderCrash, 500, 10, 5);
        let b = ReproInput::new("input1".into(), FailureCategory::RenderCrash, 500, 10, 5);
        assert_eq!(a.input_hash, b.input_hash);
    }

    #[test]
    fn test_minimized_repro_ratio() {
        let r = MinimizedRepro::new(
            "input1".into(),
            MinimizationStrategy::DeltaDebugging,
            25,
            100,
            true,
            1_000_000,
        );
        assert_eq!(r.reduction_ratio_millionths, 750_000);
        assert!(r.reproduces);
    }

    #[test]
    fn test_minimized_repro_no_reduction() {
        let r = MinimizedRepro::new(
            "input1".into(),
            MinimizationStrategy::DeltaDebugging,
            100,
            100,
            true,
            1_000_000,
        );
        assert_eq!(r.reduction_ratio_millionths, 0);
    }

    #[test]
    fn test_minimized_repro_zero_original() {
        let r = MinimizedRepro::new(
            "input1".into(),
            MinimizationStrategy::DeltaDebugging,
            0,
            0,
            false,
            0,
        );
        assert_eq!(r.reduction_ratio_millionths, 0);
    }

    #[test]
    fn test_default_owner_routing() {
        assert_eq!(
            ExtractionEngine::default_owner(FailureCategory::JsxTransform),
            TriageOwner::ParserCompiler
        );
        assert_eq!(
            ExtractionEngine::default_owner(FailureCategory::ModuleResolution),
            TriageOwner::ModuleResolution
        );
        assert_eq!(
            ExtractionEngine::default_owner(FailureCategory::RenderCrash),
            TriageOwner::EngineRuntime
        );
    }

    #[test]
    fn test_config_strict() {
        let c = ExtractionConfig::strict();
        assert_eq!(c.max_repro_lines, 30);
        assert_eq!(c.required_categories.len(), 10);
    }

    #[test]
    fn test_config_relaxed() {
        let c = ExtractionConfig::relaxed();
        assert!(c.required_categories.is_empty());
    }

    #[test]
    fn test_verdict_needs_attention() {
        assert!(!ExtractionVerdict::Complete.needs_attention());
        assert!(ExtractionVerdict::PartialReduction.needs_attention());
        assert!(ExtractionVerdict::MultipleIssues.needs_attention());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(ExtractionVerdict::Complete.to_string(), "complete");
    }

    #[test]
    fn test_engine_empty_no_inputs() {
        let engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::NoInputs);
    }

    #[test]
    fn test_engine_with_good_repro() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            20,
            200,
            true,
            1_000_000,
        ));
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::Complete);
    }

    #[test]
    fn test_engine_partial_reduction() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            150,
            200,
            true,
            1_000_000,
        ));
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::PartialReduction);
    }

    #[test]
    fn test_engine_repro_too_large() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            1000,
            50,
            20,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            60,
            1000,
            true,
            1_000_000,
        ));
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::PartialReduction);
    }

    #[test]
    fn test_engine_triage_latency_exceeded() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            20,
            200,
            true,
            100_000_000_000, // 100 seconds
        ));
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::TriageLatencyExceeded);
    }

    #[test]
    fn test_engine_incomplete_coverage() {
        let mut config = ExtractionConfig::relaxed();
        config
            .required_categories
            .insert(FailureCategory::HydrationMismatch);
        let mut engine = ExtractionEngine::new(config);
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::IncompleteCoverage);
        assert!(
            report
                .categories_missing
                .contains(&FailureCategory::HydrationMismatch)
        );
    }

    #[test]
    fn test_engine_multiple_issues() {
        let mut config = ExtractionConfig::relaxed();
        config
            .required_categories
            .insert(FailureCategory::HydrationMismatch);
        let mut engine = ExtractionEngine::new(config);
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            150,
            200,
            true,
            1_000_000,
        ));
        let report = engine.evaluate(epoch());
        assert_eq!(report.verdict, ExtractionVerdict::MultipleIssues);
    }

    #[test]
    fn test_engine_avg_reduction_ratio() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i1".into(),
            MinimizationStrategy::DeltaDebugging,
            20,
            200,
            true,
            1_000_000,
        ));
        engine.add_repro(MinimizedRepro::new(
            "i2".into(),
            MinimizationStrategy::HierarchicalReduction,
            50,
            200,
            true,
            1_000_000,
        ));
        let report = engine.evaluate(epoch());
        // 900_000 + 750_000 = 1_650_000 / 2 = 825_000
        assert_eq!(report.avg_reduction_ratio_millionths, 825_000);
    }

    #[test]
    fn test_report_hash_deterministic() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        let r1 = engine.evaluate(epoch());
        let r2 = engine.evaluate(epoch());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_report_hash_changes() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        let r1 = engine.evaluate(epoch());
        engine.add_input(ReproInput::new(
            "i2".into(),
            FailureCategory::HookOrdering,
            300,
            8,
            4,
        ));
        let r2 = engine.evaluate(epoch());
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_triage_finding_construction() {
        let finding = TriageFinding {
            category: FailureCategory::HydrationMismatch,
            owner: TriageOwner::ReactIntegration,
            severity: TriageSeverity::Error,
            summary: "SSR output differs from client render".into(),
            repro_hash: None,
            recommended_action: "Check useLayoutEffect vs useEffect".into(),
        };
        assert_eq!(finding.severity, TriageSeverity::Error);
    }

    #[test]
    fn test_categories_covered_tracking() {
        let mut engine = ExtractionEngine::new(ExtractionConfig::relaxed());
        engine.add_input(ReproInput::new(
            "i1".into(),
            FailureCategory::RenderCrash,
            200,
            5,
            3,
        ));
        engine.add_input(ReproInput::new(
            "i2".into(),
            FailureCategory::HookOrdering,
            300,
            8,
            4,
        ));
        let report = engine.evaluate(epoch());
        assert!(
            report
                .categories_covered
                .contains(&FailureCategory::RenderCrash)
        );
        assert!(
            report
                .categories_covered
                .contains(&FailureCategory::HookOrdering)
        );
        assert_eq!(report.categories_covered.len(), 2);
    }

    #[test]
    fn test_triage_owner_display() {
        assert_eq!(TriageOwner::ParserCompiler.to_string(), "parser_compiler");
    }

    #[test]
    fn test_triage_severity_ordering() {
        assert!(TriageSeverity::Info < TriageSeverity::Critical);
    }
}
