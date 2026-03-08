//! Feature-parity tracker wired to test262, lockstep corpora, and waiver
//! governance.
//!
//! Tracks ES2020 feature implementation status, test262 pass/fail per feature
//! area, lockstep corpus behaviour match against Node/Bun per feature, and
//! formal waiver governance for intentional divergences.
//!
//! Plan reference: Section 10.1 item 7, bd-j7z.
//! Cross-refs: 9F.6 (tri-runtime lockstep oracle), 10.7 (conformance),
//!   Phase A/D exit gates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT: &str = "feature_parity_tracker";

// ---------------------------------------------------------------------------
// Feature status
// ---------------------------------------------------------------------------

/// Implementation status of an ES2020 feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FeatureStatus {
    NotStarted,
    InProgress,
    Passing,
    Waived,
}

impl fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => f.write_str("not_started"),
            Self::InProgress => f.write_str("in_progress"),
            Self::Passing => f.write_str("passing"),
            Self::Waived => f.write_str("waived"),
        }
    }
}

/// ES specification version tracked by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EsVersion {
    Es2020,
}

impl fmt::Display for EsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Es2020 => f.write_str("ES2020"),
        }
    }
}

/// Runtime against which lockstep comparisons are made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LockstepRuntime {
    Node,
    Bun,
}

impl fmt::Display for LockstepRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node => f.write_str("node"),
            Self::Bun => f.write_str("bun"),
        }
    }
}

// ---------------------------------------------------------------------------
// Feature area
// ---------------------------------------------------------------------------

/// Major ES2020 feature area for grouping test262 coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FeatureArea {
    OptionalChaining,
    NullishCoalescing,
    DynamicImport,
    BigInt,
    PromiseAllSettled,
    GlobalThis,
    ModuleNamespaceExports,
    StringMatchAll,
    ImportMeta,
    ForInOrder,
}

impl FeatureArea {
    pub fn all() -> &'static [FeatureArea] {
        &[
            Self::OptionalChaining,
            Self::NullishCoalescing,
            Self::DynamicImport,
            Self::BigInt,
            Self::PromiseAllSettled,
            Self::GlobalThis,
            Self::ModuleNamespaceExports,
            Self::StringMatchAll,
            Self::ImportMeta,
            Self::ForInOrder,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OptionalChaining => "optional_chaining",
            Self::NullishCoalescing => "nullish_coalescing",
            Self::DynamicImport => "dynamic_import",
            Self::BigInt => "bigint",
            Self::PromiseAllSettled => "promise_all_settled",
            Self::GlobalThis => "global_this",
            Self::ModuleNamespaceExports => "module_namespace_exports",
            Self::StringMatchAll => "string_match_all",
            Self::ImportMeta => "import_meta",
            Self::ForInOrder => "for_in_order",
        }
    }
}

impl fmt::Display for FeatureArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Feature entry (per-feature state)
// ---------------------------------------------------------------------------

/// Per-feature tracking record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureEntry {
    pub feature_id: String,
    pub area: FeatureArea,
    pub es_version: EsVersion,
    pub status: FeatureStatus,
    /// test262 total tests for this feature.
    pub test262_total: usize,
    /// test262 tests passing.
    pub test262_passing: usize,
    /// test262 pass rate in millionths (0 = 0%, 1_000_000 = 100%).
    pub test262_pass_rate_millionths: u64,
    /// Per-runtime lockstep match rates in millionths.
    pub lockstep_match_rates_millionths: BTreeMap<String, u64>,
    /// Per-runtime lockstep total comparisons.
    pub lockstep_total_comparisons: BTreeMap<String, usize>,
    /// Per-runtime lockstep matches.
    pub lockstep_matches: BTreeMap<String, usize>,
}

impl FeatureEntry {
    /// Create a new feature entry with no test results.
    pub fn new(area: FeatureArea, es_version: EsVersion) -> Self {
        let feature_id = format!("{}-{}", es_version, area);
        Self {
            feature_id,
            area,
            es_version,
            status: FeatureStatus::NotStarted,
            test262_total: 0,
            test262_passing: 0,
            test262_pass_rate_millionths: 0,
            lockstep_match_rates_millionths: BTreeMap::new(),
            lockstep_total_comparisons: BTreeMap::new(),
            lockstep_matches: BTreeMap::new(),
        }
    }

    /// Recompute derived rates from counts.
    fn recompute_rates(&mut self) {
        self.test262_pass_rate_millionths = if self.test262_total > 0 {
            (self.test262_passing as u64)
                .saturating_mul(1_000_000)
                .checked_div(self.test262_total as u64)
                .unwrap_or(0)
        } else {
            0
        };

        let runtimes: Vec<String> = self.lockstep_total_comparisons.keys().cloned().collect();
        for rt in runtimes {
            let total = self
                .lockstep_total_comparisons
                .get(&rt)
                .copied()
                .unwrap_or(0);
            let matches = self.lockstep_matches.get(&rt).copied().unwrap_or(0);
            let rate = if total > 0 {
                (matches as u64)
                    .saturating_mul(1_000_000)
                    .checked_div(total as u64)
                    .unwrap_or(0)
            } else {
                0
            };
            self.lockstep_match_rates_millionths.insert(rt, rate);
        }
    }
}

// ---------------------------------------------------------------------------
// test262 result
// ---------------------------------------------------------------------------

/// Result of running test262 tests for a feature area.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262Result {
    pub area: FeatureArea,
    pub total: usize,
    pub passing: usize,
    pub failing_test_ids: Vec<String>,
}

impl Test262Result {
    pub fn validate(&self) -> Result<(), ParityTrackerError> {
        if self.passing > self.total {
            return Err(ParityTrackerError::InvalidMetrics {
                detail: format!(
                    "passing ({}) exceeds total ({}) for {:?}",
                    self.passing, self.total, self.area
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Lockstep result
// ---------------------------------------------------------------------------

/// Result of a lockstep comparison run for a feature against a runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepResult {
    pub area: FeatureArea,
    pub runtime: LockstepRuntime,
    pub total_comparisons: usize,
    pub matches: usize,
    pub mismatches: Vec<LockstepMismatch>,
}

/// A single lockstep mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepMismatch {
    pub test_id: String,
    pub expected: String,
    pub actual: String,
}

impl LockstepResult {
    pub fn validate(&self) -> Result<(), ParityTrackerError> {
        if self.matches > self.total_comparisons {
            return Err(ParityTrackerError::InvalidMetrics {
                detail: format!(
                    "matches ({}) exceeds total ({}) for {:?}/{:?}",
                    self.matches, self.total_comparisons, self.area, self.runtime
                ),
            });
        }
        if self.mismatches.len() != self.total_comparisons - self.matches {
            return Err(ParityTrackerError::InvalidMetrics {
                detail: format!(
                    "mismatch count ({}) inconsistent with total-matches ({}) for {:?}/{:?}",
                    self.mismatches.len(),
                    self.total_comparisons - self.matches,
                    self.area,
                    self.runtime
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Waiver governance
// ---------------------------------------------------------------------------

/// Formal waiver for a feature that intentionally diverges from spec or
/// incumbent runtimes. Immutable once sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaiverRecord {
    pub waiver_id: String,
    pub feature_id: String,
    pub reason: String,
    pub approved_by: String,
    pub approved_at_ns: u64,
    pub valid_until_ns: Option<u64>,
    /// Specific test262 test IDs exempted by this waiver.
    pub test262_exemptions: Vec<String>,
    /// Specific lockstep test IDs exempted by this waiver.
    pub lockstep_exemptions: Vec<String>,
    /// Once sealed, the waiver cannot be modified.
    pub sealed: bool,
}

impl WaiverRecord {
    pub fn validate(&self) -> Result<(), ParityTrackerError> {
        if self.waiver_id.trim().is_empty() {
            return Err(ParityTrackerError::InvalidWaiver {
                detail: "waiver_id must not be empty".to_string(),
            });
        }
        if self.feature_id.trim().is_empty() {
            return Err(ParityTrackerError::InvalidWaiver {
                detail: "feature_id must not be empty".to_string(),
            });
        }
        if self.reason.trim().is_empty() {
            return Err(ParityTrackerError::InvalidWaiver {
                detail: "reason must not be empty".to_string(),
            });
        }
        if self.approved_by.trim().is_empty() {
            return Err(ParityTrackerError::InvalidWaiver {
                detail: "approved_by must not be empty".to_string(),
            });
        }
        if let Some(until) = self.valid_until_ns
            && until <= self.approved_at_ns
        {
            return Err(ParityTrackerError::InvalidWaiver {
                detail: "valid_until must be after approved_at".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Release gate
// ---------------------------------------------------------------------------

/// Release-gate criteria for feature parity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateCriteria {
    /// Minimum test262 pass rate (millionths) per feature to pass the gate.
    pub min_test262_pass_rate_millionths: u64,
    /// Minimum lockstep match rate (millionths) per runtime to pass the gate.
    pub min_lockstep_match_rate_millionths: u64,
    /// Whether all failures must be covered by a waiver (zero silent failures).
    pub require_waiver_coverage: bool,
}

impl Default for ReleaseGateCriteria {
    fn default() -> Self {
        Self {
            min_test262_pass_rate_millionths: 950_000, // 95%
            min_lockstep_match_rate_millionths: 950_000,
            require_waiver_coverage: true,
        }
    }
}

/// Outcome of evaluating the release gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateDecision {
    pub passed: bool,
    pub failing_features: Vec<String>,
    pub unwaived_failures: Vec<UnwaivedFailure>,
    pub overall_test262_pass_rate_millionths: u64,
    pub overall_lockstep_match_rate_millionths: u64,
}

/// A test262 or lockstep failure not covered by any waiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwaivedFailure {
    pub feature_id: String,
    pub failure_type: String,
    pub test_id: String,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Structured audit event for feature parity operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from feature parity tracker operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParityTrackerError {
    FeatureNotFound { feature_id: String },
    WaiverNotFound { waiver_id: String },
    WaiverAlreadyExists { waiver_id: String },
    WaiverSealed { waiver_id: String },
    InvalidWaiver { detail: String },
    InvalidMetrics { detail: String },
    DuplicateFeature { feature_id: String },
    GateEvaluationFailed { detail: String },
}

impl ParityTrackerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::FeatureNotFound { .. } => "FE-FPT-0001",
            Self::WaiverNotFound { .. } => "FE-FPT-0002",
            Self::WaiverAlreadyExists { .. } => "FE-FPT-0003",
            Self::WaiverSealed { .. } => "FE-FPT-0004",
            Self::InvalidWaiver { .. } => "FE-FPT-0005",
            Self::InvalidMetrics { .. } => "FE-FPT-0006",
            Self::DuplicateFeature { .. } => "FE-FPT-0007",
            Self::GateEvaluationFailed { .. } => "FE-FPT-0008",
        }
    }
}

impl fmt::Display for ParityTrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureNotFound { feature_id } => {
                write!(f, "{}: feature not found: {feature_id}", self.code())
            }
            Self::WaiverNotFound { waiver_id } => {
                write!(f, "{}: waiver not found: {waiver_id}", self.code())
            }
            Self::WaiverAlreadyExists { waiver_id } => {
                write!(f, "{}: waiver already exists: {waiver_id}", self.code())
            }
            Self::WaiverSealed { waiver_id } => {
                write!(f, "{}: waiver is sealed: {waiver_id}", self.code())
            }
            Self::InvalidWaiver { detail } => {
                write!(f, "{}: invalid waiver: {detail}", self.code())
            }
            Self::InvalidMetrics { detail } => {
                write!(f, "{}: invalid metrics: {detail}", self.code())
            }
            Self::DuplicateFeature { feature_id } => {
                write!(f, "{}: duplicate feature: {feature_id}", self.code())
            }
            Self::GateEvaluationFailed { detail } => {
                write!(f, "{}: gate evaluation failed: {detail}", self.code())
            }
        }
    }
}

impl std::error::Error for ParityTrackerError {}

// ---------------------------------------------------------------------------
// Tracker context
// ---------------------------------------------------------------------------

/// Context for tracker operations that emit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

// ---------------------------------------------------------------------------
// Feature parity tracker
// ---------------------------------------------------------------------------

/// Tracks ES2020 feature implementation status, test262 results, lockstep
/// comparisons, and waiver governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureParityTracker {
    features: BTreeMap<String, FeatureEntry>,
    waivers: BTreeMap<String, WaiverRecord>,
    events: Vec<ParityEvent>,
    gate_criteria: ReleaseGateCriteria,
    /// Waived test262 test IDs (derived from waivers).
    waived_test262_ids: BTreeSet<String>,
    /// Waived lockstep test IDs (derived from waivers).
    waived_lockstep_ids: BTreeSet<String>,
}

impl FeatureParityTracker {
    /// Create a new tracker pre-populated with all ES2020 feature areas.
    pub fn new() -> Self {
        let mut features = BTreeMap::new();
        for &area in FeatureArea::all() {
            let entry = FeatureEntry::new(area, EsVersion::Es2020);
            features.insert(entry.feature_id.clone(), entry);
        }
        Self {
            features,
            waivers: BTreeMap::new(),
            events: Vec::new(),
            gate_criteria: ReleaseGateCriteria::default(),
            waived_test262_ids: BTreeSet::new(),
            waived_lockstep_ids: BTreeSet::new(),
        }
    }

    /// Create an empty tracker (no pre-populated features).
    pub fn empty() -> Self {
        Self {
            features: BTreeMap::new(),
            waivers: BTreeMap::new(),
            events: Vec::new(),
            gate_criteria: ReleaseGateCriteria::default(),
            waived_test262_ids: BTreeSet::new(),
            waived_lockstep_ids: BTreeSet::new(),
        }
    }

    /// Set custom release gate criteria.
    pub fn set_gate_criteria(&mut self, criteria: ReleaseGateCriteria) {
        self.gate_criteria = criteria;
    }

    /// Register a feature. Returns error if the feature ID already exists.
    pub fn register_feature(&mut self, entry: FeatureEntry) -> Result<(), ParityTrackerError> {
        if self.features.contains_key(&entry.feature_id) {
            return Err(ParityTrackerError::DuplicateFeature {
                feature_id: entry.feature_id,
            });
        }
        self.features.insert(entry.feature_id.clone(), entry);
        Ok(())
    }

    /// Get a feature by ID.
    pub fn feature(&self, feature_id: &str) -> Option<&FeatureEntry> {
        self.features.get(feature_id)
    }

    /// All features.
    pub fn features(&self) -> &BTreeMap<String, FeatureEntry> {
        &self.features
    }

    /// Update status for a feature.
    pub fn set_status(
        &mut self,
        feature_id: &str,
        new_status: FeatureStatus,
        ctx: &TrackerContext,
    ) -> Result<FeatureStatus, ParityTrackerError> {
        let entry = self.features.get_mut(feature_id).ok_or_else(|| {
            ParityTrackerError::FeatureNotFound {
                feature_id: feature_id.to_string(),
            }
        })?;
        let old = entry.status;
        entry.status = new_status;
        self.emit_event(ctx, "status_change", &format!("{old}->{new_status}"), None);
        Ok(old)
    }

    /// Ingest test262 results for a feature area.
    pub fn ingest_test262(
        &mut self,
        result: &Test262Result,
        ctx: &TrackerContext,
    ) -> Result<(), ParityTrackerError> {
        result.validate()?;
        let feature_id = format!("{}-{}", EsVersion::Es2020, result.area);
        let entry = self.features.get_mut(&feature_id).ok_or_else(|| {
            ParityTrackerError::FeatureNotFound {
                feature_id: feature_id.clone(),
            }
        })?;

        entry.test262_total = result.total;
        entry.test262_passing = result.passing;
        entry.recompute_rates();

        // Auto-update status based on test262 results
        if entry.status != FeatureStatus::Waived {
            if result.total > 0 && result.passing == result.total {
                entry.status = FeatureStatus::Passing;
            } else if result.passing > 0 {
                entry.status = FeatureStatus::InProgress;
            }
        }

        self.emit_event(
            ctx,
            "test262_ingested",
            &format!("{}/{}", result.passing, result.total),
            None,
        );
        Ok(())
    }

    /// Ingest lockstep comparison results.
    pub fn ingest_lockstep(
        &mut self,
        result: &LockstepResult,
        ctx: &TrackerContext,
    ) -> Result<(), ParityTrackerError> {
        result.validate()?;
        let feature_id = format!("{}-{}", EsVersion::Es2020, result.area);
        let entry = self.features.get_mut(&feature_id).ok_or_else(|| {
            ParityTrackerError::FeatureNotFound {
                feature_id: feature_id.clone(),
            }
        })?;

        let rt_key = result.runtime.to_string();
        entry
            .lockstep_total_comparisons
            .insert(rt_key.clone(), result.total_comparisons);
        entry
            .lockstep_matches
            .insert(rt_key.clone(), result.matches);
        entry.recompute_rates();

        self.emit_event(
            ctx,
            "lockstep_ingested",
            &format!(
                "{}/{} vs {}",
                result.matches, result.total_comparisons, result.runtime
            ),
            None,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Waiver governance
    // -----------------------------------------------------------------------

    /// Register a waiver. The waiver must pass validation.
    pub fn register_waiver(
        &mut self,
        waiver: WaiverRecord,
        ctx: &TrackerContext,
    ) -> Result<(), ParityTrackerError> {
        waiver.validate()?;

        if self.waivers.contains_key(&waiver.waiver_id) {
            return Err(ParityTrackerError::WaiverAlreadyExists {
                waiver_id: waiver.waiver_id,
            });
        }

        // Verify referenced feature exists
        if !self.features.contains_key(&waiver.feature_id) {
            return Err(ParityTrackerError::FeatureNotFound {
                feature_id: waiver.feature_id.clone(),
            });
        }

        // Add exemptions to lookup sets
        for id in &waiver.test262_exemptions {
            self.waived_test262_ids.insert(id.clone());
        }
        for id in &waiver.lockstep_exemptions {
            self.waived_lockstep_ids.insert(id.clone());
        }

        // Mark feature as waived if not already passing
        if let Some(entry) = self.features.get_mut(&waiver.feature_id)
            && entry.status != FeatureStatus::Passing
        {
            entry.status = FeatureStatus::Waived;
        }

        self.emit_event(ctx, "waiver_registered", &waiver.waiver_id, None);
        self.waivers.insert(waiver.waiver_id.clone(), waiver);
        Ok(())
    }

    /// Seal a waiver, making it immutable.
    pub fn seal_waiver(
        &mut self,
        waiver_id: &str,
        ctx: &TrackerContext,
    ) -> Result<(), ParityTrackerError> {
        let waiver =
            self.waivers
                .get_mut(waiver_id)
                .ok_or_else(|| ParityTrackerError::WaiverNotFound {
                    waiver_id: waiver_id.to_string(),
                })?;
        if waiver.sealed {
            return Err(ParityTrackerError::WaiverSealed {
                waiver_id: waiver_id.to_string(),
            });
        }
        waiver.sealed = true;
        self.emit_event(ctx, "waiver_sealed", waiver_id, None);
        Ok(())
    }

    /// All waivers.
    pub fn waivers(&self) -> &BTreeMap<String, WaiverRecord> {
        &self.waivers
    }

    /// Check if a test262 test ID is covered by a waiver.
    pub fn is_test262_waived(&self, test_id: &str) -> bool {
        self.waived_test262_ids.contains(test_id)
    }

    /// Check if a lockstep test ID is covered by a waiver.
    pub fn is_lockstep_waived(&self, test_id: &str) -> bool {
        self.waived_lockstep_ids.contains(test_id)
    }

    // -----------------------------------------------------------------------
    // Dashboard / release gate
    // -----------------------------------------------------------------------

    /// Compute the aggregate dashboard snapshot.
    pub fn dashboard(&self) -> DashboardSnapshot {
        let mut total_test262 = 0usize;
        let mut total_test262_passing = 0usize;
        let mut per_area = BTreeMap::new();

        // Per-runtime lockstep aggregates
        let mut lockstep_totals: BTreeMap<String, usize> = BTreeMap::new();
        let mut lockstep_matches_agg: BTreeMap<String, usize> = BTreeMap::new();

        let mut status_counts = BTreeMap::new();

        for entry in self.features.values() {
            *status_counts
                .entry(format!("{}", entry.status))
                .or_insert(0usize) += 1;

            total_test262 += entry.test262_total;
            total_test262_passing += entry.test262_passing;

            per_area.insert(
                entry.feature_id.clone(),
                FeatureAreaSnapshot {
                    feature_id: entry.feature_id.clone(),
                    area: entry.area,
                    status: entry.status,
                    test262_pass_rate_millionths: entry.test262_pass_rate_millionths,
                    lockstep_match_rates_millionths: entry.lockstep_match_rates_millionths.clone(),
                },
            );

            for (rt, &total) in &entry.lockstep_total_comparisons {
                *lockstep_totals.entry(rt.clone()).or_default() += total;
            }
            for (rt, &m) in &entry.lockstep_matches {
                *lockstep_matches_agg.entry(rt.clone()).or_default() += m;
            }
        }

        let overall_test262_pass_rate_millionths = if total_test262 > 0 {
            (total_test262_passing as u64)
                .saturating_mul(1_000_000)
                .checked_div(total_test262 as u64)
                .unwrap_or(0)
        } else {
            0
        };

        let mut overall_lockstep_match_rates_millionths = BTreeMap::new();
        for (rt, total) in &lockstep_totals {
            let matches = lockstep_matches_agg.get(rt).copied().unwrap_or(0);
            let rate = if *total > 0 {
                (matches as u64)
                    .saturating_mul(1_000_000)
                    .checked_div(*total as u64)
                    .unwrap_or(0)
            } else {
                0
            };
            overall_lockstep_match_rates_millionths.insert(rt.clone(), rate);
        }

        DashboardSnapshot {
            total_features: self.features.len(),
            status_counts,
            total_waivers: self.waivers.len(),
            sealed_waivers: self.waivers.values().filter(|w| w.sealed).count(),
            overall_test262_pass_rate_millionths,
            overall_lockstep_match_rates_millionths,
            per_area,
        }
    }

    /// Evaluate the release gate against current state.
    pub fn evaluate_gate(&mut self, ctx: &TrackerContext) -> ReleaseGateDecision {
        let mut failing_features = Vec::new();
        let mut unwaived_failures = Vec::new();
        let dashboard = self.dashboard();

        for entry in self.features.values() {
            // Skip waived features — they're covered by governance
            if entry.status == FeatureStatus::Waived {
                continue;
            }

            // Check test262 rate
            if entry.test262_total > 0
                && entry.test262_pass_rate_millionths
                    < self.gate_criteria.min_test262_pass_rate_millionths
            {
                failing_features.push(entry.feature_id.clone());
            }

            // Check lockstep rates
            for &rate in entry.lockstep_match_rates_millionths.values() {
                if rate < self.gate_criteria.min_lockstep_match_rate_millionths
                    && !failing_features.contains(&entry.feature_id)
                {
                    failing_features.push(entry.feature_id.clone());
                }
            }
        }

        // Check waiver coverage if required
        if self.gate_criteria.require_waiver_coverage {
            for entry in self.features.values() {
                if entry.status == FeatureStatus::Waived {
                    continue;
                }
                let failing_count = entry.test262_total.saturating_sub(entry.test262_passing);
                if failing_count > 0 {
                    // Check how many of the failures are waived
                    // Since we don't track individual failing test IDs in the entry,
                    // we rely on the waiver coverage by feature
                    let has_waivers = self
                        .waivers
                        .values()
                        .any(|w| w.feature_id == entry.feature_id);
                    if !has_waivers {
                        unwaived_failures.push(UnwaivedFailure {
                            feature_id: entry.feature_id.clone(),
                            failure_type: "test262".to_string(),
                            test_id: format!("{}-unwaived", entry.feature_id),
                        });
                    }
                }
            }
        }

        let passed = failing_features.is_empty() && unwaived_failures.is_empty();

        // Compute aggregate lockstep rate (min across runtimes)
        let overall_lockstep = dashboard
            .overall_lockstep_match_rates_millionths
            .values()
            .copied()
            .min()
            .unwrap_or(0);

        self.emit_event(
            ctx,
            "release_gate_evaluated",
            if passed { "pass" } else { "fail" },
            if passed { None } else { Some("FE-FPT-0007") },
        );

        ReleaseGateDecision {
            passed,
            failing_features,
            unwaived_failures,
            overall_test262_pass_rate_millionths: dashboard.overall_test262_pass_rate_millionths,
            overall_lockstep_match_rate_millionths: overall_lockstep,
        }
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /// All recorded events.
    pub fn events(&self) -> &[ParityEvent] {
        &self.events
    }

    /// Drain events.
    pub fn drain_events(&mut self) -> Vec<ParityEvent> {
        std::mem::take(&mut self.events)
    }

    /// Total number of features tracked.
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }

    /// Total number of waivers.
    pub fn waiver_count(&self) -> usize {
        self.waivers.len()
    }

    fn emit_event(
        &mut self,
        ctx: &TrackerContext,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(ParityEvent {
            trace_id: ctx.trace_id.clone(),
            decision_id: ctx.decision_id.clone(),
            policy_id: ctx.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

impl Default for FeatureParityTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Dashboard snapshot
// ---------------------------------------------------------------------------

/// Point-in-time dashboard snapshot for release gate queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub total_features: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub total_waivers: usize,
    pub sealed_waivers: usize,
    pub overall_test262_pass_rate_millionths: u64,
    pub overall_lockstep_match_rates_millionths: BTreeMap<String, u64>,
    pub per_area: BTreeMap<String, FeatureAreaSnapshot>,
}

/// Per-feature-area snapshot in the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureAreaSnapshot {
    pub feature_id: String,
    pub area: FeatureArea,
    pub status: FeatureStatus,
    pub test262_pass_rate_millionths: u64,
    pub lockstep_match_rates_millionths: BTreeMap<String, u64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> TrackerContext {
        TrackerContext {
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
        }
    }

    fn make_waiver(feature_id: &str, waiver_id: &str) -> WaiverRecord {
        WaiverRecord {
            waiver_id: waiver_id.to_string(),
            feature_id: feature_id.to_string(),
            reason: "intentional divergence".to_string(),
            approved_by: "operator".to_string(),
            approved_at_ns: 1_000_000_000,
            valid_until_ns: None,
            test262_exemptions: vec!["test-fail-1".to_string()],
            lockstep_exemptions: vec!["lockstep-fail-1".to_string()],
            sealed: false,
        }
    }

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    #[test]
    fn new_tracker_has_all_es2020_features() {
        let tracker = FeatureParityTracker::new();
        assert_eq!(tracker.feature_count(), FeatureArea::all().len());
        for &area in FeatureArea::all() {
            let fid = format!("{}-{}", EsVersion::Es2020, area);
            assert!(tracker.feature(&fid).is_some(), "missing {fid}");
        }
    }

    #[test]
    fn empty_tracker_has_no_features() {
        let tracker = FeatureParityTracker::empty();
        assert_eq!(tracker.feature_count(), 0);
    }

    #[test]
    fn default_matches_new() {
        let a = FeatureParityTracker::new();
        let b = FeatureParityTracker::default();
        assert_eq!(a.feature_count(), b.feature_count());
    }

    // -------------------------------------------------------------------
    // Feature registration
    // -------------------------------------------------------------------

    #[test]
    fn register_feature_succeeds() {
        let mut tracker = FeatureParityTracker::empty();
        let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
        tracker.register_feature(entry).unwrap();
        assert_eq!(tracker.feature_count(), 1);
    }

    #[test]
    fn register_duplicate_feature_rejected() {
        let mut tracker = FeatureParityTracker::empty();
        let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
        tracker.register_feature(entry.clone()).unwrap();
        let err = tracker.register_feature(entry).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0007");
    }

    // -------------------------------------------------------------------
    // Status transitions
    // -------------------------------------------------------------------

    #[test]
    fn set_status_updates_and_returns_old() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let old = tracker
            .set_status(&fid, FeatureStatus::InProgress, &ctx)
            .unwrap();
        assert_eq!(old, FeatureStatus::NotStarted);
        assert_eq!(
            tracker.feature(&fid).unwrap().status,
            FeatureStatus::InProgress
        );
    }

    #[test]
    fn set_status_unknown_feature_rejected() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let err = tracker
            .set_status("nonexistent", FeatureStatus::Passing, &ctx)
            .unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0001");
    }

    // -------------------------------------------------------------------
    // test262 ingestion
    // -------------------------------------------------------------------

    #[test]
    fn ingest_test262_updates_metrics() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let result = Test262Result {
            area: FeatureArea::BigInt,
            total: 100,
            passing: 95,
            failing_test_ids: vec![
                "t1".into(),
                "t2".into(),
                "t3".into(),
                "t4".into(),
                "t5".into(),
            ],
        };
        tracker.ingest_test262(&result, &ctx).unwrap();

        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let entry = tracker.feature(&fid).unwrap();
        assert_eq!(entry.test262_total, 100);
        assert_eq!(entry.test262_passing, 95);
        assert_eq!(entry.test262_pass_rate_millionths, 950_000);
    }

    #[test]
    fn ingest_test262_auto_advances_status() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        // Partial pass → InProgress
        let partial = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 5,
            failing_test_ids: (0..5).map(|i| format!("t{i}")).collect(),
        };
        tracker.ingest_test262(&partial, &ctx).unwrap();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        assert_eq!(
            tracker.feature(&fid).unwrap().status,
            FeatureStatus::InProgress
        );

        // Full pass → Passing
        let full = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 10,
            failing_test_ids: vec![],
        };
        tracker.ingest_test262(&full, &ctx).unwrap();
        assert_eq!(
            tracker.feature(&fid).unwrap().status,
            FeatureStatus::Passing
        );
    }

    #[test]
    fn ingest_test262_invalid_rejected() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let bad = Test262Result {
            area: FeatureArea::BigInt,
            total: 5,
            passing: 10, // more passing than total
            failing_test_ids: vec![],
        };
        let err = tracker.ingest_test262(&bad, &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0006");
    }

    // -------------------------------------------------------------------
    // Lockstep ingestion
    // -------------------------------------------------------------------

    #[test]
    fn ingest_lockstep_updates_metrics() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let result = LockstepResult {
            area: FeatureArea::GlobalThis,
            runtime: LockstepRuntime::Node,
            total_comparisons: 50,
            matches: 48,
            mismatches: vec![
                LockstepMismatch {
                    test_id: "m1".into(),
                    expected: "true".into(),
                    actual: "false".into(),
                },
                LockstepMismatch {
                    test_id: "m2".into(),
                    expected: "42".into(),
                    actual: "undefined".into(),
                },
            ],
        };
        tracker.ingest_lockstep(&result, &ctx).unwrap();

        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::GlobalThis);
        let entry = tracker.feature(&fid).unwrap();
        assert_eq!(entry.lockstep_matches.get("node"), Some(&48));
        assert_eq!(entry.lockstep_total_comparisons.get("node"), Some(&50));
        assert_eq!(
            entry.lockstep_match_rates_millionths.get("node"),
            Some(&960_000)
        );
    }

    #[test]
    fn ingest_lockstep_invalid_rejected() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let bad = LockstepResult {
            area: FeatureArea::GlobalThis,
            runtime: LockstepRuntime::Node,
            total_comparisons: 10,
            matches: 15, // more matches than total
            mismatches: vec![],
        };
        let err = tracker.ingest_lockstep(&bad, &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0006");
    }

    // -------------------------------------------------------------------
    // Waiver governance
    // -------------------------------------------------------------------

    #[test]
    fn register_waiver_succeeds() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let waiver = make_waiver(&fid, "w-1");

        tracker.register_waiver(waiver, &ctx).unwrap();
        assert_eq!(tracker.waiver_count(), 1);
        assert!(tracker.is_test262_waived("test-fail-1"));
        assert!(tracker.is_lockstep_waived("lockstep-fail-1"));
    }

    #[test]
    fn register_waiver_duplicate_rejected() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let waiver = make_waiver(&fid, "w-1");

        tracker.register_waiver(waiver.clone(), &ctx).unwrap();
        let err = tracker.register_waiver(waiver, &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0003");
    }

    #[test]
    fn register_waiver_unknown_feature_rejected() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let waiver = make_waiver("nonexistent-feature", "w-1");
        let err = tracker.register_waiver(waiver, &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0001");
    }

    #[test]
    fn waiver_validation_rejects_empty_fields() {
        let bad = WaiverRecord {
            waiver_id: "".to_string(),
            feature_id: "f".to_string(),
            reason: "r".to_string(),
            approved_by: "a".to_string(),
            approved_at_ns: 1,
            valid_until_ns: None,
            test262_exemptions: vec![],
            lockstep_exemptions: vec![],
            sealed: false,
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0005");
    }

    #[test]
    fn waiver_validation_rejects_invalid_expiry() {
        let bad = WaiverRecord {
            waiver_id: "w".to_string(),
            feature_id: "f".to_string(),
            reason: "r".to_string(),
            approved_by: "a".to_string(),
            approved_at_ns: 100,
            valid_until_ns: Some(50), // before approved_at
            test262_exemptions: vec![],
            lockstep_exemptions: vec![],
            sealed: false,
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0005");
    }

    #[test]
    fn seal_waiver_makes_immutable() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let waiver = make_waiver(&fid, "w-1");

        tracker.register_waiver(waiver, &ctx).unwrap();
        tracker.seal_waiver("w-1", &ctx).unwrap();

        assert!(tracker.waivers().get("w-1").unwrap().sealed);
    }

    #[test]
    fn seal_already_sealed_waiver_rejected() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let waiver = make_waiver(&fid, "w-1");

        tracker.register_waiver(waiver, &ctx).unwrap();
        tracker.seal_waiver("w-1", &ctx).unwrap();
        let err = tracker.seal_waiver("w-1", &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0004");
    }

    #[test]
    fn seal_nonexistent_waiver_returns_waiver_not_found() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let err = tracker.seal_waiver("does-not-exist", &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-FPT-0002");
        assert!(matches!(err, ParityTrackerError::WaiverNotFound { .. }));
    }

    // -------------------------------------------------------------------
    // Dashboard
    // -------------------------------------------------------------------

    #[test]
    fn dashboard_reflects_current_state() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        let result = Test262Result {
            area: FeatureArea::BigInt,
            total: 100,
            passing: 80,
            failing_test_ids: (0..20).map(|i| format!("f{i}")).collect(),
        };
        tracker.ingest_test262(&result, &ctx).unwrap();

        let dash = tracker.dashboard();
        assert_eq!(dash.total_features, FeatureArea::all().len());
        assert!(dash.overall_test262_pass_rate_millionths > 0);

        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let area = dash.per_area.get(&fid).unwrap();
        assert_eq!(area.test262_pass_rate_millionths, 800_000);
    }

    #[test]
    fn dashboard_empty_tracker() {
        let tracker = FeatureParityTracker::empty();
        let dash = tracker.dashboard();
        assert_eq!(dash.total_features, 0);
        assert_eq!(dash.overall_test262_pass_rate_millionths, 0);
    }

    // -------------------------------------------------------------------
    // Release gate
    // -------------------------------------------------------------------

    #[test]
    fn gate_passes_when_all_features_meet_criteria() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        // Make all features pass test262 at 100%
        for &area in FeatureArea::all() {
            let result = Test262Result {
                area,
                total: 10,
                passing: 10,
                failing_test_ids: vec![],
            };
            tracker.ingest_test262(&result, &ctx).unwrap();
        }

        let decision = tracker.evaluate_gate(&ctx);
        assert!(decision.passed);
        assert!(decision.failing_features.is_empty());
    }

    #[test]
    fn gate_fails_when_feature_below_threshold() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        // One feature at 50%
        let result = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 5,
            failing_test_ids: (0..5).map(|i| format!("f{i}")).collect(),
        };
        tracker.ingest_test262(&result, &ctx).unwrap();

        let decision = tracker.evaluate_gate(&ctx);
        assert!(!decision.passed);
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        assert!(decision.failing_features.contains(&fid));
    }

    #[test]
    fn gate_skips_waived_features() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        // BigInt has poor test262 results
        let result = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 2,
            failing_test_ids: (0..8).map(|i| format!("f{i}")).collect(),
        };
        tracker.ingest_test262(&result, &ctx).unwrap();

        // Waive it
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let waiver = make_waiver(&fid, "w-bigint");
        tracker.register_waiver(waiver, &ctx).unwrap();

        // Make all other features pass
        for &area in FeatureArea::all() {
            if area == FeatureArea::BigInt {
                continue;
            }
            let r = Test262Result {
                area,
                total: 10,
                passing: 10,
                failing_test_ids: vec![],
            };
            tracker.ingest_test262(&r, &ctx).unwrap();
        }

        let decision = tracker.evaluate_gate(&ctx);
        assert!(decision.passed, "waived feature should not block gate");
    }

    // -------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------

    #[test]
    fn events_emitted_on_operations() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        let result = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 10,
            failing_test_ids: vec![],
        };
        tracker.ingest_test262(&result, &ctx).unwrap();

        let events = tracker.events();
        assert!(!events.is_empty());
        assert!(events.iter().all(|e| e.component == COMPONENT));
        assert!(events.iter().all(|e| e.trace_id == "trace-1"));
        assert!(events.iter().any(|e| e.event == "test262_ingested"));
    }

    #[test]
    fn drain_events_clears() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        tracker
            .set_status(&fid, FeatureStatus::InProgress, &ctx)
            .unwrap();

        let drained = tracker.drain_events();
        assert!(!drained.is_empty());
        assert!(tracker.events().is_empty());
    }

    // -------------------------------------------------------------------
    // Serde roundtrips
    // -------------------------------------------------------------------

    #[test]
    fn feature_entry_serde_roundtrip() {
        let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: FeatureEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn waiver_record_serde_roundtrip() {
        let waiver = make_waiver("feat-1", "w-1");
        let json = serde_json::to_string(&waiver).unwrap();
        let parsed: WaiverRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(waiver, parsed);
    }

    #[test]
    fn dashboard_snapshot_serde_roundtrip() {
        let tracker = FeatureParityTracker::new();
        let dash = tracker.dashboard();
        let json = serde_json::to_string(&dash).unwrap();
        let parsed: DashboardSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(dash, parsed);
    }

    #[test]
    fn release_gate_decision_serde_roundtrip() {
        let decision = ReleaseGateDecision {
            passed: true,
            failing_features: vec![],
            unwaived_failures: vec![],
            overall_test262_pass_rate_millionths: 980_000,
            overall_lockstep_match_rate_millionths: 970_000,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ReleaseGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    #[test]
    fn parity_event_serde_roundtrip() {
        let event = ParityEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: ParityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -------------------------------------------------------------------
    // Error codes
    // -------------------------------------------------------------------

    #[test]
    fn error_codes_stable() {
        let errors = [
            ParityTrackerError::FeatureNotFound {
                feature_id: "x".to_string(),
            },
            ParityTrackerError::WaiverNotFound {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::WaiverAlreadyExists {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::WaiverSealed {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::InvalidWaiver {
                detail: "d".to_string(),
            },
            ParityTrackerError::InvalidMetrics {
                detail: "d".to_string(),
            },
            ParityTrackerError::DuplicateFeature {
                feature_id: "x".to_string(),
            },
            ParityTrackerError::GateEvaluationFailed {
                detail: "d".to_string(),
            },
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
        assert_eq!(
            codes,
            vec![
                "FE-FPT-0001",
                "FE-FPT-0002",
                "FE-FPT-0003",
                "FE-FPT-0004",
                "FE-FPT-0005",
                "FE-FPT-0006",
                "FE-FPT-0007",
                "FE-FPT-0008",
            ]
        );
        for e in &errors {
            assert!(!format!("{e}").is_empty());
        }
    }

    // -------------------------------------------------------------------
    // Display impls
    // -------------------------------------------------------------------

    #[test]
    fn feature_status_display() {
        assert_eq!(FeatureStatus::NotStarted.to_string(), "not_started");
        assert_eq!(FeatureStatus::InProgress.to_string(), "in_progress");
        assert_eq!(FeatureStatus::Passing.to_string(), "passing");
        assert_eq!(FeatureStatus::Waived.to_string(), "waived");
    }

    #[test]
    fn feature_area_display() {
        assert_eq!(
            FeatureArea::OptionalChaining.to_string(),
            "optional_chaining"
        );
        assert_eq!(FeatureArea::BigInt.to_string(), "bigint");
    }

    #[test]
    fn lockstep_runtime_display() {
        assert_eq!(LockstepRuntime::Node.to_string(), "node");
        assert_eq!(LockstepRuntime::Bun.to_string(), "bun");
    }

    #[test]
    fn es_version_display() {
        assert_eq!(EsVersion::Es2020.to_string(), "ES2020");
    }

    // -------------------------------------------------------------------
    // Multi-runtime lockstep
    // -------------------------------------------------------------------

    #[test]
    fn lockstep_tracks_both_runtimes_independently() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();

        // Node results
        let node_result = LockstepResult {
            area: FeatureArea::OptionalChaining,
            runtime: LockstepRuntime::Node,
            total_comparisons: 20,
            matches: 18,
            mismatches: vec![
                LockstepMismatch {
                    test_id: "n1".into(),
                    expected: "a".into(),
                    actual: "b".into(),
                },
                LockstepMismatch {
                    test_id: "n2".into(),
                    expected: "c".into(),
                    actual: "d".into(),
                },
            ],
        };
        tracker.ingest_lockstep(&node_result, &ctx).unwrap();

        // Bun results
        let bun_result = LockstepResult {
            area: FeatureArea::OptionalChaining,
            runtime: LockstepRuntime::Bun,
            total_comparisons: 20,
            matches: 20,
            mismatches: vec![],
        };
        tracker.ingest_lockstep(&bun_result, &ctx).unwrap();

        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::OptionalChaining);
        let entry = tracker.feature(&fid).unwrap();
        assert_eq!(
            entry.lockstep_match_rates_millionths.get("node"),
            Some(&900_000)
        );
        assert_eq!(
            entry.lockstep_match_rates_millionths.get("bun"),
            Some(&1_000_000)
        );
    }

    // -------------------------------------------------------------------
    // Waiver marks feature as waived
    // -------------------------------------------------------------------

    #[test]
    fn waiver_sets_feature_status_to_waived() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::ImportMeta);

        assert_eq!(
            tracker.feature(&fid).unwrap().status,
            FeatureStatus::NotStarted
        );

        let waiver = make_waiver(&fid, "w-import-meta");
        tracker.register_waiver(waiver, &ctx).unwrap();

        assert_eq!(tracker.feature(&fid).unwrap().status, FeatureStatus::Waived);
    }

    #[test]
    fn waiver_does_not_downgrade_passing() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);

        // Set to passing first
        tracker
            .set_status(&fid, FeatureStatus::Passing, &ctx)
            .unwrap();

        let waiver = make_waiver(&fid, "w-bigint");
        tracker.register_waiver(waiver, &ctx).unwrap();

        // Should remain Passing, not downgraded to Waived
        assert_eq!(
            tracker.feature(&fid).unwrap().status,
            FeatureStatus::Passing
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn feature_status_serde_roundtrip() {
        for v in [
            FeatureStatus::NotStarted,
            FeatureStatus::InProgress,
            FeatureStatus::Passing,
            FeatureStatus::Waived,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: FeatureStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn es_version_serde_roundtrip() {
        let json = serde_json::to_string(&EsVersion::Es2020).unwrap();
        let restored: EsVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(EsVersion::Es2020, restored);
    }

    #[test]
    fn lockstep_runtime_serde_roundtrip() {
        for v in [LockstepRuntime::Node, LockstepRuntime::Bun] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: LockstepRuntime = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn feature_area_serde_roundtrip() {
        for v in FeatureArea::all() {
            let json = serde_json::to_string(v).unwrap();
            let restored: FeatureArea = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn parity_tracker_error_serde_all_variants() {
        let errors: [ParityTrackerError; 8] = [
            ParityTrackerError::FeatureNotFound {
                feature_id: "f".to_string(),
            },
            ParityTrackerError::WaiverNotFound {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::WaiverAlreadyExists {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::WaiverSealed {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::InvalidWaiver {
                detail: "d".to_string(),
            },
            ParityTrackerError::InvalidMetrics {
                detail: "d".to_string(),
            },
            ParityTrackerError::DuplicateFeature {
                feature_id: "f".to_string(),
            },
            ParityTrackerError::GateEvaluationFailed {
                detail: "d".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: ParityTrackerError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn test262_result_serde_roundtrip() {
        let r = Test262Result {
            area: FeatureArea::BigInt,
            total: 100,
            passing: 95,
            failing_test_ids: vec!["t1".to_string()],
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: Test262Result = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }

    #[test]
    fn lockstep_mismatch_serde_roundtrip() {
        let m = LockstepMismatch {
            test_id: "t1".to_string(),
            expected: "42".to_string(),
            actual: "43".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let restored: LockstepMismatch = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    #[test]
    fn release_gate_criteria_serde_roundtrip() {
        let c = ReleaseGateCriteria {
            min_test262_pass_rate_millionths: 950_000,
            min_lockstep_match_rate_millionths: 950_000,
            require_waiver_coverage: true,
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: ReleaseGateCriteria = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }

    #[test]
    fn unwaived_failure_serde_roundtrip() {
        let f = UnwaivedFailure {
            feature_id: "f".to_string(),
            failure_type: "test262".to_string(),
            test_id: "t1".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let restored: UnwaivedFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(f, restored);
    }

    #[test]
    fn tracker_context_serde_roundtrip() {
        let c = TrackerContext {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: TrackerContext = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default value assertions
    // -----------------------------------------------------------------------

    #[test]
    fn release_gate_criteria_default_values() {
        let c = ReleaseGateCriteria::default();
        assert_eq!(c.min_test262_pass_rate_millionths, 950_000);
        assert_eq!(c.min_lockstep_match_rate_millionths, 950_000);
        assert!(c.require_waiver_coverage);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering
    // -----------------------------------------------------------------------

    #[test]
    fn feature_status_ordering() {
        assert!(FeatureStatus::NotStarted < FeatureStatus::Waived);
    }

    #[test]
    fn feature_area_ordering() {
        assert!(FeatureArea::OptionalChaining < FeatureArea::ForInOrder);
    }

    #[test]
    fn lockstep_runtime_ordering() {
        assert!(LockstepRuntime::Node < LockstepRuntime::Bun);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParityTrackerError Display + is std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn parity_tracker_error_display_all_non_empty() {
        let errors: [ParityTrackerError; 8] = [
            ParityTrackerError::FeatureNotFound {
                feature_id: "f".to_string(),
            },
            ParityTrackerError::WaiverNotFound {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::WaiverAlreadyExists {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::WaiverSealed {
                waiver_id: "w".to_string(),
            },
            ParityTrackerError::InvalidWaiver {
                detail: "d".to_string(),
            },
            ParityTrackerError::InvalidMetrics {
                detail: "d".to_string(),
            },
            ParityTrackerError::DuplicateFeature {
                feature_id: "f".to_string(),
            },
            ParityTrackerError::GateEvaluationFailed {
                detail: "d".to_string(),
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn parity_tracker_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ParityTrackerError::FeatureNotFound {
            feature_id: "f".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: FeatureArea::all and as_str
    // -----------------------------------------------------------------------

    #[test]
    fn feature_area_all_has_ten() {
        assert_eq!(FeatureArea::all().len(), 10);
    }

    #[test]
    fn feature_area_as_str_matches_display() {
        for area in FeatureArea::all() {
            assert_eq!(area.as_str(), area.to_string());
        }
    }

    #[test]
    fn feature_status_ord() {
        assert!(FeatureStatus::NotStarted < FeatureStatus::InProgress);
        assert!(FeatureStatus::InProgress < FeatureStatus::Passing);
        assert!(FeatureStatus::Passing < FeatureStatus::Waived);
    }

    #[test]
    fn lockstep_runtime_ord() {
        assert!(LockstepRuntime::Node < LockstepRuntime::Bun);
    }

    #[test]
    fn feature_area_ord() {
        assert!(FeatureArea::OptionalChaining < FeatureArea::NullishCoalescing);
        assert!(FeatureArea::NullishCoalescing < FeatureArea::DynamicImport);
        assert!(FeatureArea::DynamicImport < FeatureArea::BigInt);
        assert!(FeatureArea::ImportMeta < FeatureArea::ForInOrder);
    }

    // ── Enrichment: Copy semantics ──────────────────────────────────

    #[test]
    fn feature_status_copy_from_array() {
        let arr = [
            FeatureStatus::NotStarted,
            FeatureStatus::InProgress,
            FeatureStatus::Passing,
            FeatureStatus::Waived,
        ];
        let copied = arr[2];
        assert_eq!(copied, FeatureStatus::Passing);
        assert_eq!(arr[2], FeatureStatus::Passing);
    }

    #[test]
    fn feature_area_copy_from_array() {
        let arr = [FeatureArea::BigInt, FeatureArea::GlobalThis];
        let copied = arr[0];
        assert_eq!(copied, FeatureArea::BigInt);
        assert_eq!(arr[0], FeatureArea::BigInt);
    }

    #[test]
    fn lockstep_runtime_copy_from_array() {
        let arr = [LockstepRuntime::Node, LockstepRuntime::Bun];
        let copied = arr[1];
        assert_eq!(copied, LockstepRuntime::Bun);
        assert_eq!(arr[1], LockstepRuntime::Bun);
    }

    #[test]
    fn es_version_copy_from_array() {
        let arr = [EsVersion::Es2020];
        let copied = arr[0];
        assert_eq!(copied, EsVersion::Es2020);
    }

    // ── Enrichment: Debug distinctness ──────────────────────────────

    #[test]
    fn feature_status_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            FeatureStatus::NotStarted,
            FeatureStatus::InProgress,
            FeatureStatus::Passing,
            FeatureStatus::Waived,
        ]
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
        assert_eq!(dbgs.len(), 4);
    }

    #[test]
    fn feature_area_debug_all_distinct() {
        let dbgs: BTreeSet<String> = FeatureArea::all()
            .iter()
            .map(|a| format!("{a:?}"))
            .collect();
        assert_eq!(dbgs.len(), 10);
    }

    #[test]
    fn lockstep_runtime_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [LockstepRuntime::Node, LockstepRuntime::Bun]
            .iter()
            .map(|r| format!("{r:?}"))
            .collect();
        assert_eq!(dbgs.len(), 2);
    }

    #[test]
    fn parity_tracker_error_debug_all_distinct() {
        let errors = [
            ParityTrackerError::FeatureNotFound {
                feature_id: "f".into(),
            },
            ParityTrackerError::WaiverNotFound {
                waiver_id: "w".into(),
            },
            ParityTrackerError::WaiverAlreadyExists {
                waiver_id: "w".into(),
            },
            ParityTrackerError::WaiverSealed {
                waiver_id: "w".into(),
            },
            ParityTrackerError::InvalidWaiver { detail: "d".into() },
            ParityTrackerError::InvalidMetrics { detail: "d".into() },
            ParityTrackerError::DuplicateFeature {
                feature_id: "f".into(),
            },
            ParityTrackerError::GateEvaluationFailed { detail: "d".into() },
        ];
        let dbgs: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(dbgs.len(), 8);
    }

    // ── Enrichment: Serde variant distinctness ──────────────────────

    #[test]
    fn feature_status_serde_all_distinct() {
        let jsons: BTreeSet<String> = [
            FeatureStatus::NotStarted,
            FeatureStatus::InProgress,
            FeatureStatus::Passing,
            FeatureStatus::Waived,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(jsons.len(), 4);
    }

    #[test]
    fn feature_area_serde_all_distinct() {
        let jsons: BTreeSet<String> = FeatureArea::all()
            .iter()
            .map(|a| serde_json::to_string(a).unwrap())
            .collect();
        assert_eq!(jsons.len(), 10);
    }

    #[test]
    fn parity_tracker_error_serde_all_variants_distinct() {
        let errors = [
            ParityTrackerError::FeatureNotFound {
                feature_id: "f".into(),
            },
            ParityTrackerError::WaiverNotFound {
                waiver_id: "w".into(),
            },
            ParityTrackerError::WaiverAlreadyExists {
                waiver_id: "w2".into(),
            },
            ParityTrackerError::WaiverSealed {
                waiver_id: "w3".into(),
            },
            ParityTrackerError::InvalidWaiver { detail: "d".into() },
            ParityTrackerError::InvalidMetrics {
                detail: "d2".into(),
            },
            ParityTrackerError::DuplicateFeature {
                feature_id: "f2".into(),
            },
            ParityTrackerError::GateEvaluationFailed {
                detail: "d3".into(),
            },
        ];
        let jsons: BTreeSet<String> = errors
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        assert_eq!(jsons.len(), 8);
    }

    // ── Enrichment: Clone independence ──────────────────────────────

    #[test]
    fn feature_entry_clone_independence() {
        let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
        let mut cloned = entry.clone();
        cloned.status = FeatureStatus::Passing;
        cloned.test262_total = 999;
        assert_eq!(entry.status, FeatureStatus::NotStarted);
        assert_eq!(entry.test262_total, 0);
    }

    #[test]
    fn waiver_record_clone_independence() {
        let waiver = make_waiver("feat-1", "w-1");
        let mut cloned = waiver.clone();
        cloned.sealed = true;
        cloned.reason = "changed".into();
        assert!(!waiver.sealed);
        assert_eq!(waiver.reason, "intentional divergence");
    }

    #[test]
    fn release_gate_decision_clone_independence() {
        let decision = ReleaseGateDecision {
            passed: true,
            failing_features: vec![],
            unwaived_failures: vec![],
            overall_test262_pass_rate_millionths: 1_000_000,
            overall_lockstep_match_rate_millionths: 1_000_000,
        };
        let mut cloned = decision.clone();
        cloned.passed = false;
        cloned.failing_features.push("feat-x".into());
        assert!(decision.passed);
        assert!(decision.failing_features.is_empty());
    }

    #[test]
    fn parity_event_clone_independence() {
        let event = ParityEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: COMPONENT.into(),
            event: "test".into(),
            outcome: "ok".into(),
            error_code: None,
        };
        let mut cloned = event.clone();
        cloned.trace_id = "modified".into();
        assert_eq!(event.trace_id, "t");
    }

    #[test]
    fn dashboard_snapshot_clone_independence() {
        let tracker = FeatureParityTracker::new();
        let dash = tracker.dashboard();
        let mut cloned = dash.clone();
        cloned.total_features = 999;
        assert_eq!(dash.total_features, FeatureArea::all().len());
    }

    // ── Enrichment: JSON field-name stability ───────────────────────

    #[test]
    fn feature_entry_json_field_names_stable() {
        let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"feature_id\""));
        assert!(json.contains("\"area\""));
        assert!(json.contains("\"es_version\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"test262_total\""));
        assert!(json.contains("\"test262_passing\""));
        assert!(json.contains("\"test262_pass_rate_millionths\""));
        assert!(json.contains("\"lockstep_match_rates_millionths\""));
        assert!(json.contains("\"lockstep_total_comparisons\""));
        assert!(json.contains("\"lockstep_matches\""));
    }

    #[test]
    fn waiver_record_json_field_names_stable() {
        let waiver = make_waiver("feat-1", "w-1");
        let json = serde_json::to_string(&waiver).unwrap();
        assert!(json.contains("\"waiver_id\""));
        assert!(json.contains("\"feature_id\""));
        assert!(json.contains("\"reason\""));
        assert!(json.contains("\"approved_by\""));
        assert!(json.contains("\"approved_at_ns\""));
        assert!(json.contains("\"valid_until_ns\""));
        assert!(json.contains("\"test262_exemptions\""));
        assert!(json.contains("\"lockstep_exemptions\""));
        assert!(json.contains("\"sealed\""));
    }

    #[test]
    fn release_gate_criteria_json_field_names_stable() {
        let c = ReleaseGateCriteria::default();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"min_test262_pass_rate_millionths\""));
        assert!(json.contains("\"min_lockstep_match_rate_millionths\""));
        assert!(json.contains("\"require_waiver_coverage\""));
    }

    #[test]
    fn release_gate_decision_json_field_names_stable() {
        let decision = ReleaseGateDecision {
            passed: false,
            failing_features: vec!["f1".into()],
            unwaived_failures: vec![],
            overall_test262_pass_rate_millionths: 0,
            overall_lockstep_match_rate_millionths: 0,
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"failing_features\""));
        assert!(json.contains("\"unwaived_failures\""));
        assert!(json.contains("\"overall_test262_pass_rate_millionths\""));
        assert!(json.contains("\"overall_lockstep_match_rate_millionths\""));
    }

    #[test]
    fn dashboard_snapshot_json_field_names_stable() {
        let tracker = FeatureParityTracker::new();
        let dash = tracker.dashboard();
        let json = serde_json::to_string(&dash).unwrap();
        assert!(json.contains("\"total_features\""));
        assert!(json.contains("\"status_counts\""));
        assert!(json.contains("\"total_waivers\""));
        assert!(json.contains("\"sealed_waivers\""));
        assert!(json.contains("\"overall_test262_pass_rate_millionths\""));
        assert!(json.contains("\"overall_lockstep_match_rates_millionths\""));
        assert!(json.contains("\"per_area\""));
    }

    // ── Enrichment: Display format checks ───────────────────────────

    #[test]
    fn feature_status_display_all_unique() {
        let displays: BTreeSet<String> = [
            FeatureStatus::NotStarted,
            FeatureStatus::InProgress,
            FeatureStatus::Passing,
            FeatureStatus::Waived,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn feature_area_display_all_unique() {
        let displays: BTreeSet<String> = FeatureArea::all().iter().map(|a| a.to_string()).collect();
        assert_eq!(displays.len(), 10);
    }

    #[test]
    fn parity_tracker_error_display_includes_code() {
        let err = ParityTrackerError::FeatureNotFound {
            feature_id: "bigint".into(),
        };
        let display = err.to_string();
        assert!(display.contains("FE-FPT-0001"));
        assert!(display.contains("bigint"));
    }

    // ── Enrichment: Hash consistency ────────────────────────────────

    #[test]
    fn feature_status_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        FeatureStatus::Passing.hash(&mut h1);
        FeatureStatus::Passing.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn feature_area_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        FeatureArea::BigInt.hash(&mut h1);
        FeatureArea::BigInt.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // ── Enrichment: boundary/edge cases ─────────────────────────────

    #[test]
    fn feature_entry_new_computes_correct_id() {
        let entry = FeatureEntry::new(FeatureArea::OptionalChaining, EsVersion::Es2020);
        assert_eq!(entry.feature_id, "ES2020-optional_chaining");
    }

    #[test]
    fn feature_entry_new_all_zeroed_rates() {
        let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
        assert_eq!(entry.test262_total, 0);
        assert_eq!(entry.test262_passing, 0);
        assert_eq!(entry.test262_pass_rate_millionths, 0);
        assert!(entry.lockstep_match_rates_millionths.is_empty());
    }

    #[test]
    fn ingest_test262_zero_total_leaves_rate_zero() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let r = Test262Result {
            area: FeatureArea::BigInt,
            total: 0,
            passing: 0,
            failing_test_ids: vec![],
        };
        tracker.ingest_test262(&r, &ctx).unwrap();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        assert_eq!(
            tracker.feature(&fid).unwrap().test262_pass_rate_millionths,
            0
        );
    }

    #[test]
    fn lockstep_zero_comparisons_leaves_rate_zero() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        let r = LockstepResult {
            area: FeatureArea::BigInt,
            runtime: LockstepRuntime::Node,
            total_comparisons: 0,
            matches: 0,
            mismatches: vec![],
        };
        tracker.ingest_lockstep(&r, &ctx).unwrap();
        let fid = format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt);
        let entry = tracker.feature(&fid).unwrap();
        assert_eq!(entry.lockstep_match_rates_millionths.get("node"), Some(&0));
    }

    #[test]
    fn waiver_validation_rejects_empty_feature_id() {
        let bad = WaiverRecord {
            waiver_id: "w".to_string(),
            feature_id: "".to_string(),
            reason: "r".to_string(),
            approved_by: "a".to_string(),
            approved_at_ns: 1,
            valid_until_ns: None,
            test262_exemptions: vec![],
            lockstep_exemptions: vec![],
            sealed: false,
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0005");
    }

    #[test]
    fn waiver_validation_rejects_empty_reason() {
        let bad = WaiverRecord {
            waiver_id: "w".to_string(),
            feature_id: "f".to_string(),
            reason: "  ".to_string(),
            approved_by: "a".to_string(),
            approved_at_ns: 1,
            valid_until_ns: None,
            test262_exemptions: vec![],
            lockstep_exemptions: vec![],
            sealed: false,
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0005");
    }

    #[test]
    fn waiver_validation_rejects_empty_approved_by() {
        let bad = WaiverRecord {
            waiver_id: "w".to_string(),
            feature_id: "f".to_string(),
            reason: "r".to_string(),
            approved_by: "".to_string(),
            approved_at_ns: 1,
            valid_until_ns: None,
            test262_exemptions: vec![],
            lockstep_exemptions: vec![],
            sealed: false,
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0005");
    }

    #[test]
    fn waiver_valid_until_equals_approved_at_rejected() {
        let bad = WaiverRecord {
            waiver_id: "w".to_string(),
            feature_id: "f".to_string(),
            reason: "r".to_string(),
            approved_by: "a".to_string(),
            approved_at_ns: 100,
            valid_until_ns: Some(100),
            test262_exemptions: vec![],
            lockstep_exemptions: vec![],
            sealed: false,
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0005");
    }

    #[test]
    fn test262_result_validate_passing_equals_total_ok() {
        let r = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 10,
            failing_test_ids: vec![],
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn lockstep_result_validate_mismatch_count_inconsistent() {
        let bad = LockstepResult {
            area: FeatureArea::BigInt,
            runtime: LockstepRuntime::Node,
            total_comparisons: 10,
            matches: 8,
            mismatches: vec![],
        };
        assert_eq!(bad.validate().unwrap_err().code(), "FE-FPT-0006");
    }

    #[test]
    fn gate_with_custom_criteria_passes_at_lower_threshold() {
        let mut tracker = FeatureParityTracker::new();
        let ctx = test_ctx();
        tracker.set_gate_criteria(ReleaseGateCriteria {
            min_test262_pass_rate_millionths: 500_000,
            min_lockstep_match_rate_millionths: 500_000,
            require_waiver_coverage: false,
        });
        let result = Test262Result {
            area: FeatureArea::BigInt,
            total: 10,
            passing: 6,
            failing_test_ids: (0..4).map(|i| format!("f{i}")).collect(),
        };
        tracker.ingest_test262(&result, &ctx).unwrap();
        let decision = tracker.evaluate_gate(&ctx);
        assert!(decision.passed);
    }

    #[test]
    fn not_waived_test262_ids_false_by_default() {
        let tracker = FeatureParityTracker::new();
        assert!(!tracker.is_test262_waived("any-test"));
        assert!(!tracker.is_lockstep_waived("any-test"));
    }

    // ── Enrichment: Debug nonempty ──────────────────────────────────

    #[test]
    fn feature_parity_tracker_debug_nonempty() {
        let tracker = FeatureParityTracker::new();
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("FeatureParityTracker"));
    }

    #[test]
    fn tracker_context_debug_nonempty() {
        let ctx = test_ctx();
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("TrackerContext"));
    }

    #[test]
    fn lockstep_mismatch_debug_nonempty() {
        let m = LockstepMismatch {
            test_id: "t1".into(),
            expected: "42".into(),
            actual: "43".into(),
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("LockstepMismatch"));
    }
}
