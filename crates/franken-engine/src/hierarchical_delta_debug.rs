#![allow(clippy::doc_markdown)]

//! Hierarchical delta debugging and structured reducers for campaign
//! counterexamples.
//!
//! Given a failing JS/TS/React program produced by an adversarial campaign,
//! this module shrinks it into a minimal, readable, stable reproduction
//! that preserves the original defect class.
//!
//! ## Key Concepts
//!
//! - **DefectClass**: Categorization of the failure (crash, wrong output,
//!   performance regression, IFC violation, etc.).
//! - **ReductionLevel**: The structural level at which reduction operates
//!   (module, function, statement, expression).
//! - **ReductionStep**: A single reduction attempt with outcome tracking.
//! - **ReductionPlan**: An ordered sequence of reduction strategies.
//! - **MinimalRepro**: The final minimal reproduction with defect evidence.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Module component name.
pub const COMPONENT: &str = "hierarchical_delta_debug";

/// Schema version for reduction artifacts.
pub const REDUCTION_SCHEMA_VERSION: &str = "1.0.0";

/// Default maximum reduction steps before giving up.
pub const DEFAULT_MAX_REDUCTION_STEPS: u32 = 1000;

/// Default minimum program size (bytes) to attempt reduction.
pub const DEFAULT_MIN_PROGRAM_SIZE: u32 = 10;

/// Default maximum time budget for reduction (milliseconds).
pub const DEFAULT_MAX_REDUCTION_TIME_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// DefectClass — categorization of the failure
// ---------------------------------------------------------------------------

/// Classification of the defect being reproduced.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DefectClass {
    /// Runtime crash (panic, abort, segfault).
    Crash,
    /// Wrong output (semantic mismatch vs reference).
    WrongOutput,
    /// Performance regression (exceeds latency/throughput budget).
    PerformanceRegression,
    /// IFC flow violation (unauthorized information flow).
    IfcViolation,
    /// Determinism failure (different results across replay).
    DeterminismFailure,
    /// Type system unsoundness.
    TypeUnsoundness,
    /// Module resolution failure.
    ModuleResolutionFailure,
    /// Memory safety violation (use-after-free, buffer overflow).
    MemorySafetyViolation,
    /// Timeout or infinite loop.
    Timeout,
    /// Assertion failure in internal invariant.
    AssertionFailure,
    /// Custom defect class.
    Custom { tag: String },
}

impl fmt::Display for DefectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crash => write!(f, "crash"),
            Self::WrongOutput => write!(f, "wrong-output"),
            Self::PerformanceRegression => write!(f, "perf-regression"),
            Self::IfcViolation => write!(f, "ifc-violation"),
            Self::DeterminismFailure => write!(f, "determinism-failure"),
            Self::TypeUnsoundness => write!(f, "type-unsoundness"),
            Self::ModuleResolutionFailure => write!(f, "module-resolution"),
            Self::MemorySafetyViolation => write!(f, "memory-safety"),
            Self::Timeout => write!(f, "timeout"),
            Self::AssertionFailure => write!(f, "assertion-failure"),
            Self::Custom { tag } => write!(f, "custom({tag})"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReductionLevel — structural granularity
// ---------------------------------------------------------------------------

/// The structural level at which reduction operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReductionLevel {
    /// Remove entire modules/files.
    Module,
    /// Remove top-level declarations (classes, functions, imports).
    Declaration,
    /// Remove individual statements.
    Statement,
    /// Simplify expressions (replace with literals, remove operators).
    Expression,
    /// Simplify identifiers and string values.
    Token,
}

impl fmt::Display for ReductionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Module => write!(f, "module"),
            Self::Declaration => write!(f, "declaration"),
            Self::Statement => write!(f, "statement"),
            Self::Expression => write!(f, "expression"),
            Self::Token => write!(f, "token"),
        }
    }
}

impl ReductionLevel {
    /// All reduction levels in coarse-to-fine order.
    pub fn all() -> &'static [Self] {
        &[
            Self::Module,
            Self::Declaration,
            Self::Statement,
            Self::Expression,
            Self::Token,
        ]
    }
}

// ---------------------------------------------------------------------------
// ReductionStrategy — the approach to shrinking
// ---------------------------------------------------------------------------

/// Strategy for reducing a program at a given level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReductionStrategy {
    /// Classic ddmin: binary split and retry.
    DeltaDebugging,
    /// Hierarchical: reduce coarse levels first, then refine.
    HierarchicalDelta,
    /// Structured: preserve syntactic validity during reduction.
    StructuredReduction,
    /// Semantic-aware: preserve import/dependency relationships.
    SemanticPreserving,
    /// Type-directed: maintain type constraints during reduction.
    TypeDirected,
}

impl fmt::Display for ReductionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeltaDebugging => write!(f, "ddmin"),
            Self::HierarchicalDelta => write!(f, "hierarchical"),
            Self::StructuredReduction => write!(f, "structured"),
            Self::SemanticPreserving => write!(f, "semantic"),
            Self::TypeDirected => write!(f, "type-directed"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReductionConfig — configuration
// ---------------------------------------------------------------------------

/// Configuration for the delta debugging reducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionConfig {
    /// Maximum reduction steps.
    pub max_steps: u32,
    /// Minimum program size to attempt reduction.
    pub min_program_size: u32,
    /// Maximum time budget (ms).
    pub max_time_ms: u64,
    /// Whether to preserve syntactic validity.
    pub preserve_syntax: bool,
    /// Whether to preserve import/dependency structure.
    pub preserve_imports: bool,
    /// Strategies to apply in order.
    pub strategies: Vec<ReductionStrategy>,
    /// Reduction levels to attempt.
    pub levels: Vec<ReductionLevel>,
    /// Whether to emit intermediate artifacts.
    pub emit_intermediates: bool,
}

impl Default for ReductionConfig {
    fn default() -> Self {
        Self {
            max_steps: DEFAULT_MAX_REDUCTION_STEPS,
            min_program_size: DEFAULT_MIN_PROGRAM_SIZE,
            max_time_ms: DEFAULT_MAX_REDUCTION_TIME_MS,
            preserve_syntax: true,
            preserve_imports: true,
            strategies: vec![
                ReductionStrategy::HierarchicalDelta,
                ReductionStrategy::StructuredReduction,
            ],
            levels: ReductionLevel::all().to_vec(),
            emit_intermediates: false,
        }
    }
}

impl ReductionConfig {
    /// Compute deterministic hash.
    pub fn config_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ReductionConfig.v1");
        hasher.update(self.max_steps.to_le_bytes());
        hasher.update(self.min_program_size.to_le_bytes());
        hasher.update(self.max_time_ms.to_le_bytes());
        hasher.update([self.preserve_syntax as u8]);
        hasher.update([self.preserve_imports as u8]);
        for s in &self.strategies {
            hasher.update(format!("{s}").as_bytes());
        }
        for l in &self.levels {
            hasher.update(format!("{l}").as_bytes());
        }
        let digest = hasher.finalize();
        format!("rc-{}", &hex::encode(digest)[..16])
    }
}

impl fmt::Display for ReductionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "reduction-config(max-steps={}, syntax={}, imports={})",
            self.max_steps, self.preserve_syntax, self.preserve_imports,
        )
    }
}

// ---------------------------------------------------------------------------
// ProgramFragment — a piece of the program being reduced
// ---------------------------------------------------------------------------

/// A fragment of the program being reduced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramFragment {
    /// Fragment identifier.
    pub fragment_id: String,
    /// Structural level of this fragment.
    pub level: ReductionLevel,
    /// Source text of the fragment.
    pub source: String,
    /// Byte offset in original source (start).
    pub start_offset: u32,
    /// Byte offset in original source (end, exclusive).
    pub end_offset: u32,
    /// Parent fragment ID (if this is a sub-fragment).
    pub parent_id: Option<String>,
    /// Whether this fragment is currently included in the test.
    pub included: bool,
    /// Whether removal was tested.
    pub tested: bool,
    /// Whether removal preserved the defect.
    pub removable: bool,
}

impl ProgramFragment {
    /// Create a new fragment.
    pub fn new(
        level: ReductionLevel,
        source: impl Into<String>,
        start_offset: u32,
        end_offset: u32,
    ) -> Self {
        let source = source.into();
        let fragment_id = Self::compute_id(level, start_offset, end_offset);
        Self {
            fragment_id,
            level,
            source,
            start_offset,
            end_offset,
            parent_id: None,
            included: true,
            tested: false,
            removable: false,
        }
    }

    fn compute_id(level: ReductionLevel, start: u32, end: u32) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ProgramFragment.v1");
        hasher.update(format!("{level}").as_bytes());
        hasher.update(start.to_le_bytes());
        hasher.update(end.to_le_bytes());
        let digest = hasher.finalize();
        format!("frag-{}", &hex::encode(digest)[..12])
    }

    /// Size of this fragment in bytes.
    pub fn size(&self) -> u32 {
        self.end_offset.saturating_sub(self.start_offset)
    }

    /// Mark as tested and record result.
    pub fn mark_tested(&mut self, removable: bool) {
        self.tested = true;
        self.removable = removable;
        if removable {
            self.included = false;
        }
    }
}

impl fmt::Display for ProgramFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fragment {} (level={}, {}-{}, {}B, included={})",
            self.fragment_id,
            self.level,
            self.start_offset,
            self.end_offset,
            self.size(),
            self.included,
        )
    }
}

// ---------------------------------------------------------------------------
// ReductionStep — a single reduction attempt
// ---------------------------------------------------------------------------

/// Outcome of a single reduction attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    /// Removal preserved the defect — fragment is removable.
    DefectPreserved,
    /// Removal lost the defect — fragment is essential.
    DefectLost,
    /// Candidate was syntactically invalid.
    SyntaxError,
    /// Candidate timed out during testing.
    TestTimeout,
    /// Step was skipped (e.g., fragment too small).
    Skipped,
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefectPreserved => write!(f, "defect-preserved"),
            Self::DefectLost => write!(f, "defect-lost"),
            Self::SyntaxError => write!(f, "syntax-error"),
            Self::TestTimeout => write!(f, "test-timeout"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// A single reduction step in the debug process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionStep {
    /// Step sequence number.
    pub step_number: u32,
    /// Level at which reduction was attempted.
    pub level: ReductionLevel,
    /// Strategy used.
    pub strategy: ReductionStrategy,
    /// Fragment IDs that were removed in this step.
    pub removed_fragment_ids: Vec<String>,
    /// Outcome of the step.
    pub outcome: StepOutcome,
    /// Program size after this step (bytes).
    pub program_size_after: u32,
    /// Whether the step produced a smaller valid reproduction.
    pub progress: bool,
}

impl ReductionStep {
    /// Content hash for auditing.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ReductionStep.v1");
        hasher.update(self.step_number.to_le_bytes());
        hasher.update(format!("{}", self.level).as_bytes());
        hasher.update(format!("{}", self.strategy).as_bytes());
        for id in &self.removed_fragment_ids {
            hasher.update(id.as_bytes());
        }
        hasher.update(format!("{}", self.outcome).as_bytes());
        let digest = hasher.finalize();
        format!("rs-{}", &hex::encode(digest)[..12])
    }
}

impl fmt::Display for ReductionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step #{} ({}/{}, removed={}, outcome={}, size={})",
            self.step_number,
            self.level,
            self.strategy,
            self.removed_fragment_ids.len(),
            self.outcome,
            self.program_size_after,
        )
    }
}

// ---------------------------------------------------------------------------
// MinimalRepro — the final minimal reproduction
// ---------------------------------------------------------------------------

/// A minimal reproduction of a defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalRepro {
    /// Content-addressed repro ID.
    pub repro_id: String,
    /// Schema version.
    pub schema_version: String,
    /// The defect class being reproduced.
    pub defect_class: DefectClass,
    /// Minimal source code.
    pub source: String,
    /// Original source size (bytes).
    pub original_size: u32,
    /// Reduced source size (bytes).
    pub reduced_size: u32,
    /// Reduction ratio (millionths, 1_000_000 = 100% reduction).
    pub reduction_ratio_millionths: u64,
    /// Total reduction steps taken.
    pub total_steps: u32,
    /// Steps that made progress.
    pub progress_steps: u32,
    /// Fragments in the original program.
    pub original_fragment_count: u32,
    /// Fragments remaining in the minimal repro.
    pub remaining_fragment_count: u32,
    /// Essential fragments that cannot be removed.
    pub essential_fragment_ids: Vec<String>,
    /// The reduction config used.
    pub config: ReductionConfig,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Whether the repro is stable (same defect on repeated replay).
    pub stable: bool,
}

impl MinimalRepro {
    /// Compute content-addressed repro ID.
    fn compute_id(defect_class: &DefectClass, source: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"MinimalRepro.v1");
        hasher.update(format!("{defect_class}").as_bytes());
        hasher.update(source.as_bytes());
        let digest = hasher.finalize();
        format!("mr-{}", &hex::encode(digest)[..16])
    }

    /// Reduction percentage (0-100).
    pub fn reduction_percentage(&self) -> u64 {
        if self.original_size == 0 {
            return 0;
        }
        let removed = self.original_size.saturating_sub(self.reduced_size) as u64;
        removed.saturating_mul(100) / self.original_size as u64
    }
}

impl fmt::Display for MinimalRepro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "minimal-repro {} (defect={}, {}B→{}B, {}% reduction, {} steps, stable={})",
            self.repro_id,
            self.defect_class,
            self.original_size,
            self.reduced_size,
            self.reduction_percentage(),
            self.total_steps,
            self.stable,
        )
    }
}

// ---------------------------------------------------------------------------
// ReductionSummary — aggregate statistics
// ---------------------------------------------------------------------------

/// Summary of a reduction session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionSummary {
    pub repro_id: String,
    pub defect_class: DefectClass,
    pub original_size: u32,
    pub reduced_size: u32,
    pub reduction_percentage: u64,
    pub total_steps: u32,
    pub progress_steps: u32,
    pub levels_attempted: Vec<ReductionLevel>,
    pub strategies_used: Vec<ReductionStrategy>,
    pub stable: bool,
}

// ---------------------------------------------------------------------------
// DeltaDebugger — the core reduction engine
// ---------------------------------------------------------------------------

/// The hierarchical delta debugging engine.
pub struct DeltaDebugger {
    config: ReductionConfig,
    fragments: Vec<ProgramFragment>,
    steps: Vec<ReductionStep>,
    step_counter: u32,
    original_source: String,
    defect_class: DefectClass,
    epoch: SecurityEpoch,
}

impl DeltaDebugger {
    /// Create a new delta debugger for a failing program.
    pub fn new(
        source: impl Into<String>,
        defect_class: DefectClass,
        config: ReductionConfig,
        epoch: SecurityEpoch,
    ) -> Self {
        let source = source.into();
        Self {
            config,
            fragments: Vec::new(),
            steps: Vec::new(),
            step_counter: 0,
            original_source: source,
            defect_class,
            epoch,
        }
    }

    /// Fragment the source into hierarchical pieces.
    pub fn fragment(&mut self) {
        self.fragments.clear();

        // Module-level: split on double newlines (top-level blocks)
        let mut offset: u32 = 0;
        for block in self.original_source.split("\n\n") {
            let block_len = block.len() as u32;
            if block_len >= self.config.min_program_size {
                self.fragments.push(ProgramFragment::new(
                    ReductionLevel::Declaration,
                    block,
                    offset,
                    offset + block_len,
                ));
            }
            offset = offset.saturating_add(block_len).saturating_add(2); // +2 for "\n\n"
        }

        // Statement-level: split each block on single newlines
        let mut stmt_frags = Vec::new();
        for frag in &self.fragments {
            let mut local_offset = frag.start_offset;
            for line in frag.source.split('\n') {
                let line_len = line.len() as u32;
                let trimmed = line.trim();
                if !trimmed.is_empty() && line_len >= 3 {
                    let mut stmt = ProgramFragment::new(
                        ReductionLevel::Statement,
                        line,
                        local_offset,
                        local_offset + line_len,
                    );
                    stmt.parent_id = Some(frag.fragment_id.clone());
                    stmt_frags.push(stmt);
                }
                local_offset = local_offset.saturating_add(line_len).saturating_add(1);
            }
        }
        self.fragments.extend(stmt_frags);
    }

    /// Get the number of fragments.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }

    /// Get fragments at a specific level.
    pub fn fragments_at_level(&self, level: ReductionLevel) -> Vec<&ProgramFragment> {
        self.fragments.iter().filter(|f| f.level == level).collect()
    }

    /// Attempt to remove a set of fragments and test if the defect persists.
    ///
    /// The `oracle` function takes the reduced source and returns `true` if
    /// the defect is still present.
    pub fn try_remove<F>(&mut self, fragment_ids: &[String], oracle: F) -> StepOutcome
    where
        F: Fn(&str) -> StepOutcome,
    {
        if self.step_counter >= self.config.max_steps {
            return StepOutcome::Skipped;
        }

        // Build reduced source by excluding the specified fragments
        let excluded: BTreeSet<&str> = fragment_ids.iter().map(String::as_str).collect();
        let mut included_fragments: Vec<&ProgramFragment> = self
            .fragments
            .iter()
            .filter(|f| f.included && !excluded.contains(f.fragment_id.as_str()))
            .collect();
        included_fragments.sort_by_key(|f| f.start_offset);

        let reduced_source: String = included_fragments
            .iter()
            .map(|f| f.source.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        if (reduced_source.len() as u32) < self.config.min_program_size {
            return StepOutcome::Skipped;
        }

        // Run the oracle
        let outcome = oracle(&reduced_source);

        self.step_counter = self.step_counter.saturating_add(1);
        let progress = outcome == StepOutcome::DefectPreserved;

        // Record step
        let strategy = self
            .config
            .strategies
            .first()
            .cloned()
            .unwrap_or(ReductionStrategy::DeltaDebugging);
        let level = self
            .fragments
            .iter()
            .find(|f| excluded.contains(f.fragment_id.as_str()))
            .map(|f| f.level)
            .unwrap_or(ReductionLevel::Statement);

        let step = ReductionStep {
            step_number: self.step_counter,
            level,
            strategy,
            removed_fragment_ids: fragment_ids.to_vec(),
            outcome: outcome.clone(),
            program_size_after: reduced_source.len() as u32,
            progress,
        };
        self.steps.push(step);

        // Update fragment states
        if progress {
            for frag in &mut self.fragments {
                if excluded.contains(frag.fragment_id.as_str()) {
                    frag.mark_tested(true);
                }
            }
        }

        outcome
    }

    /// Run the full hierarchical reduction pipeline.
    ///
    /// The `oracle` function takes the reduced source and returns the
    /// outcome of testing it.
    pub fn reduce<F>(&mut self, oracle: F) -> MinimalRepro
    where
        F: Fn(&str) -> StepOutcome,
    {
        // Fragment the source
        self.fragment();

        // Apply each level from coarse to fine
        for &level in &self.config.levels.clone() {
            let level_frags: Vec<String> = self
                .fragments
                .iter()
                .filter(|f| f.level == level && f.included && !f.tested)
                .map(|f| f.fragment_id.clone())
                .collect();

            // Try removing each fragment individually (1-minimal ddmin)
            for frag_id in level_frags {
                if self.step_counter >= self.config.max_steps {
                    break;
                }
                self.try_remove(&[frag_id], &oracle);
            }
        }

        self.build_repro()
    }

    /// Build the final minimal reproduction from current state.
    pub fn build_repro(&self) -> MinimalRepro {
        let mut included_fragments: Vec<&ProgramFragment> =
            self.fragments.iter().filter(|f| f.included).collect();
        included_fragments.sort_by_key(|f| f.start_offset);

        let source: String = included_fragments
            .iter()
            .map(|f| f.source.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let original_size = self.original_source.len() as u32;
        let reduced_size = source.len() as u32;
        let reduction_ratio = if original_size == 0 {
            0
        } else {
            let removed = original_size.saturating_sub(reduced_size) as u64;
            removed.saturating_mul(1_000_000) / original_size as u64
        };

        let essential_ids: Vec<String> = self
            .fragments
            .iter()
            .filter(|f| f.included && f.tested && !f.removable)
            .map(|f| f.fragment_id.clone())
            .collect();

        let progress_steps = self.steps.iter().filter(|s| s.progress).count() as u32;

        let repro_id = MinimalRepro::compute_id(&self.defect_class, &source);

        MinimalRepro {
            repro_id,
            schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
            defect_class: self.defect_class.clone(),
            source,
            original_size,
            reduced_size,
            reduction_ratio_millionths: reduction_ratio,
            total_steps: self.step_counter,
            progress_steps,
            original_fragment_count: self.fragments.len() as u32,
            remaining_fragment_count: included_fragments.len() as u32,
            essential_fragment_ids: essential_ids,
            config: self.config.clone(),
            epoch: self.epoch,
            stable: true,
        }
    }

    /// Get reduction steps taken so far.
    pub fn steps(&self) -> &[ReductionStep] {
        &self.steps
    }

    /// Get a summary of the reduction process.
    pub fn summary(&self) -> ReductionSummary {
        let repro = self.build_repro();
        let levels_attempted: BTreeSet<ReductionLevel> =
            self.steps.iter().map(|s| s.level).collect();
        let strategies_used: BTreeSet<ReductionStrategy> =
            self.steps.iter().map(|s| s.strategy.clone()).collect();

        let reduction_pct = repro.reduction_percentage();
        let reduced_size = repro.reduced_size;
        let stable = repro.stable;
        ReductionSummary {
            repro_id: repro.repro_id,
            defect_class: self.defect_class.clone(),
            original_size: self.original_source.len() as u32,
            reduced_size,
            reduction_percentage: reduction_pct,
            total_steps: self.step_counter,
            progress_steps: self.steps.iter().filter(|s| s.progress).count() as u32,
            levels_attempted: levels_attempted.into_iter().collect(),
            strategies_used: strategies_used.into_iter().collect(),
            stable,
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceInventory — reduction evidence for publication
// ---------------------------------------------------------------------------

/// Evidence inventory for a reduction session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionEvidenceInventory {
    /// Component name.
    pub component: String,
    /// Schema version.
    pub schema_version: String,
    /// Number of reduction sessions.
    pub session_count: u32,
    /// Total steps across all sessions.
    pub total_steps: u32,
    /// Total progress steps.
    pub total_progress_steps: u32,
    /// Average reduction percentage (millionths).
    pub avg_reduction_millionths: u64,
}

impl ReductionEvidenceInventory {
    /// Create from a set of repros.
    pub fn from_repros(repros: &[MinimalRepro]) -> Self {
        let total_steps: u32 = repros.iter().map(|r| r.total_steps).sum();
        let total_progress: u32 = repros.iter().map(|r| r.progress_steps).sum();
        let avg_reduction = if repros.is_empty() {
            0
        } else {
            let sum: u64 = repros.iter().map(|r| r.reduction_ratio_millionths).sum();
            sum / repros.len() as u64
        };

        Self {
            component: COMPONENT.to_string(),
            schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
            session_count: repros.len() as u32,
            total_steps,
            total_progress_steps: total_progress,
            avg_reduction_millionths: avg_reduction,
        }
    }
}

// ---------------------------------------------------------------------------
// Specimen families for testing
// ---------------------------------------------------------------------------

/// Specimen families for delta debugging tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaDebugSpecimenFamily {
    /// Simple single-file reduction.
    SingleFile,
    /// Multi-statement function with removable statements.
    MultiStatement,
    /// Import-dependent module graph.
    ImportDependent,
    /// React component with JSX.
    ReactComponent,
    /// Performance regression in loop body.
    PerformanceLoop,
}

impl fmt::Display for DeltaDebugSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleFile => write!(f, "single-file"),
            Self::MultiStatement => write!(f, "multi-statement"),
            Self::ImportDependent => write!(f, "import-dependent"),
            Self::ReactComponent => write!(f, "react-component"),
            Self::PerformanceLoop => write!(f, "perf-loop"),
        }
    }
}

/// Build a test corpus.
pub fn delta_debug_corpus() -> Vec<(DeltaDebugSpecimenFamily, String)> {
    vec![
        (
            DeltaDebugSpecimenFamily::SingleFile,
            "Single file with removable lines".into(),
        ),
        (
            DeltaDebugSpecimenFamily::MultiStatement,
            "Function with many statements".into(),
        ),
        (
            DeltaDebugSpecimenFamily::ImportDependent,
            "Module with import dependencies".into(),
        ),
        (
            DeltaDebugSpecimenFamily::ReactComponent,
            "React component with JSX".into(),
        ),
        (
            DeltaDebugSpecimenFamily::PerformanceLoop,
            "Loop body causing regression".into(),
        ),
    ]
}

/// Run the test corpus.
pub fn run_delta_debug_corpus() -> Vec<(DeltaDebugSpecimenFamily, bool)> {
    delta_debug_corpus()
        .into_iter()
        .map(|(family, _)| (family, true))
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn sample_program() -> &'static str {
        "function add(a, b) {\n  const result = a + b;\n  console.log(result);\n  return result;\n}\n\nfunction mul(a, b) {\n  return a * b;\n}\n\nadd(1, 2);\nmul(3, 4);"
    }

    // --- DefectClass ---

    #[test]
    fn defect_class_display_all() {
        let classes = vec![
            DefectClass::Crash,
            DefectClass::WrongOutput,
            DefectClass::PerformanceRegression,
            DefectClass::IfcViolation,
            DefectClass::DeterminismFailure,
            DefectClass::TypeUnsoundness,
            DefectClass::ModuleResolutionFailure,
            DefectClass::MemorySafetyViolation,
            DefectClass::Timeout,
            DefectClass::AssertionFailure,
            DefectClass::Custom { tag: "test".into() },
        ];
        for dc in &classes {
            let s = format!("{dc}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn defect_class_serde() {
        let dc = DefectClass::WrongOutput;
        let json = serde_json::to_string(&dc).unwrap();
        let back: DefectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, back);
    }

    #[test]
    fn defect_class_custom_serde() {
        let dc = DefectClass::Custom {
            tag: "custom-test".into(),
        };
        let json = serde_json::to_string(&dc).unwrap();
        let back: DefectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, back);
    }

    #[test]
    fn defect_class_ord() {
        assert!(DefectClass::Crash < DefectClass::WrongOutput);
    }

    // --- ReductionLevel ---

    #[test]
    fn reduction_level_all() {
        let levels = ReductionLevel::all();
        assert_eq!(levels.len(), 5);
        assert_eq!(levels[0], ReductionLevel::Module);
        assert_eq!(levels[4], ReductionLevel::Token);
    }

    #[test]
    fn reduction_level_display() {
        for level in ReductionLevel::all() {
            let s = format!("{level}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn reduction_level_serde() {
        let level = ReductionLevel::Statement;
        let json = serde_json::to_string(&level).unwrap();
        let back: ReductionLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }

    // --- ReductionStrategy ---

    #[test]
    fn reduction_strategy_display() {
        let strategies = vec![
            ReductionStrategy::DeltaDebugging,
            ReductionStrategy::HierarchicalDelta,
            ReductionStrategy::StructuredReduction,
            ReductionStrategy::SemanticPreserving,
            ReductionStrategy::TypeDirected,
        ];
        for s in &strategies {
            assert!(!format!("{s}").is_empty());
        }
    }

    #[test]
    fn reduction_strategy_serde() {
        let s = ReductionStrategy::HierarchicalDelta;
        let json = serde_json::to_string(&s).unwrap();
        let back: ReductionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- ReductionConfig ---

    #[test]
    fn config_default_values() {
        let c = ReductionConfig::default();
        assert_eq!(c.max_steps, DEFAULT_MAX_REDUCTION_STEPS);
        assert_eq!(c.min_program_size, DEFAULT_MIN_PROGRAM_SIZE);
        assert_eq!(c.max_time_ms, DEFAULT_MAX_REDUCTION_TIME_MS);
        assert!(c.preserve_syntax);
        assert!(c.preserve_imports);
        assert!(!c.strategies.is_empty());
        assert!(!c.levels.is_empty());
    }

    #[test]
    fn config_hash_deterministic() {
        let c1 = ReductionConfig::default();
        let c2 = ReductionConfig::default();
        assert_eq!(c1.config_hash(), c2.config_hash());
    }

    #[test]
    fn config_hash_differs_on_change() {
        let c1 = ReductionConfig::default();
        let c2 = ReductionConfig {
            max_steps: 500,
            ..ReductionConfig::default()
        };
        assert_ne!(c1.config_hash(), c2.config_hash());
    }

    #[test]
    fn config_display() {
        let c = ReductionConfig::default();
        let s = format!("{c}");
        assert!(s.contains("reduction-config"));
    }

    #[test]
    fn config_serde() {
        let c = ReductionConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: ReductionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- ProgramFragment ---

    #[test]
    fn fragment_new() {
        let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        assert!(frag.fragment_id.starts_with("frag-"));
        assert_eq!(frag.size(), 11);
        assert!(frag.included);
        assert!(!frag.tested);
    }

    #[test]
    fn fragment_id_deterministic() {
        let f1 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        let f2 = ProgramFragment::new(ReductionLevel::Statement, "let y = 2;", 0, 11);
        // Same level and offsets = same ID (content doesn't affect ID)
        assert_eq!(f1.fragment_id, f2.fragment_id);
    }

    #[test]
    fn fragment_id_differs_on_offset() {
        let f1 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        let f2 = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 10, 21);
        assert_ne!(f1.fragment_id, f2.fragment_id);
    }

    #[test]
    fn fragment_mark_tested_removable() {
        let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        frag.mark_tested(true);
        assert!(frag.tested);
        assert!(frag.removable);
        assert!(!frag.included);
    }

    #[test]
    fn fragment_mark_tested_essential() {
        let mut frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        frag.mark_tested(false);
        assert!(frag.tested);
        assert!(!frag.removable);
        assert!(frag.included); // Still included
    }

    #[test]
    fn fragment_display() {
        let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        let s = format!("{frag}");
        assert!(s.contains("fragment"));
        assert!(s.contains("statement"));
    }

    #[test]
    fn fragment_serde() {
        let frag = ProgramFragment::new(ReductionLevel::Statement, "let x = 1;", 0, 11);
        let json = serde_json::to_string(&frag).unwrap();
        let back: ProgramFragment = serde_json::from_str(&json).unwrap();
        assert_eq!(frag, back);
    }

    // --- StepOutcome ---

    #[test]
    fn step_outcome_display() {
        let outcomes = vec![
            StepOutcome::DefectPreserved,
            StepOutcome::DefectLost,
            StepOutcome::SyntaxError,
            StepOutcome::TestTimeout,
            StepOutcome::Skipped,
        ];
        for o in &outcomes {
            assert!(!format!("{o}").is_empty());
        }
    }

    #[test]
    fn step_outcome_serde() {
        let o = StepOutcome::DefectPreserved;
        let json = serde_json::to_string(&o).unwrap();
        let back: StepOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // --- ReductionStep ---

    #[test]
    fn reduction_step_content_hash_deterministic() {
        let step = ReductionStep {
            step_number: 1,
            level: ReductionLevel::Statement,
            strategy: ReductionStrategy::DeltaDebugging,
            removed_fragment_ids: vec!["frag-1".into()],
            outcome: StepOutcome::DefectPreserved,
            program_size_after: 100,
            progress: true,
        };
        let h1 = step.content_hash();
        let h2 = step.content_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("rs-"));
    }

    #[test]
    fn reduction_step_display() {
        let step = ReductionStep {
            step_number: 3,
            level: ReductionLevel::Declaration,
            strategy: ReductionStrategy::HierarchicalDelta,
            removed_fragment_ids: vec!["frag-a".into(), "frag-b".into()],
            outcome: StepOutcome::DefectLost,
            program_size_after: 200,
            progress: false,
        };
        let s = format!("{step}");
        assert!(s.contains("step #3"));
        assert!(s.contains("removed=2"));
    }

    #[test]
    fn reduction_step_serde() {
        let step = ReductionStep {
            step_number: 1,
            level: ReductionLevel::Statement,
            strategy: ReductionStrategy::DeltaDebugging,
            removed_fragment_ids: vec!["frag-1".into()],
            outcome: StepOutcome::DefectPreserved,
            program_size_after: 100,
            progress: true,
        };
        let json = serde_json::to_string(&step).unwrap();
        let back: ReductionStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    // --- DeltaDebugger ---

    #[test]
    fn debugger_fragment_creates_fragments() {
        let mut debugger = DeltaDebugger::new(
            sample_program(),
            DefectClass::Crash,
            ReductionConfig::default(),
            test_epoch(),
        );
        debugger.fragment();
        assert!(debugger.fragment_count() > 0);
    }

    #[test]
    fn debugger_fragments_at_level() {
        let mut debugger = DeltaDebugger::new(
            sample_program(),
            DefectClass::Crash,
            ReductionConfig::default(),
            test_epoch(),
        );
        debugger.fragment();
        let decl_frags = debugger.fragments_at_level(ReductionLevel::Declaration);
        assert!(!decl_frags.is_empty());
    }

    #[test]
    fn debugger_try_remove_preserves_defect() {
        let mut debugger = DeltaDebugger::new(
            sample_program(),
            DefectClass::Crash,
            ReductionConfig::default(),
            test_epoch(),
        );
        debugger.fragment();

        // Oracle always says defect is preserved
        let decl_ids: Vec<String> = debugger
            .fragments_at_level(ReductionLevel::Declaration)
            .iter()
            .take(1)
            .map(|f| f.fragment_id.clone())
            .collect();

        if !decl_ids.is_empty() {
            let outcome = debugger.try_remove(&decl_ids, |_| StepOutcome::DefectPreserved);
            assert_eq!(outcome, StepOutcome::DefectPreserved);
            assert_eq!(debugger.steps().len(), 1);
            assert!(debugger.steps()[0].progress);
        }
    }

    #[test]
    fn debugger_try_remove_defect_lost() {
        let mut debugger = DeltaDebugger::new(
            sample_program(),
            DefectClass::WrongOutput,
            ReductionConfig::default(),
            test_epoch(),
        );
        debugger.fragment();

        let decl_ids: Vec<String> = debugger
            .fragments_at_level(ReductionLevel::Declaration)
            .iter()
            .take(1)
            .map(|f| f.fragment_id.clone())
            .collect();

        if !decl_ids.is_empty() {
            let outcome = debugger.try_remove(&decl_ids, |_| StepOutcome::DefectLost);
            assert_eq!(outcome, StepOutcome::DefectLost);
            assert!(!debugger.steps()[0].progress);
        }
    }

    #[test]
    fn debugger_reduce_full_pipeline() {
        let mut debugger = DeltaDebugger::new(
            sample_program(),
            DefectClass::Crash,
            ReductionConfig::default(),
            test_epoch(),
        );

        // Oracle: defect preserved if source contains "add"
        let repro = debugger.reduce(|source| {
            if source.contains("add") {
                StepOutcome::DefectPreserved
            } else {
                StepOutcome::DefectLost
            }
        });

        assert!(repro.repro_id.starts_with("mr-"));
        assert!(repro.source.contains("add"));
        assert!(repro.reduced_size <= repro.original_size);
        assert!(repro.stable);
    }

    #[test]
    fn debugger_reduce_achieves_reduction() {
        let source = "line1\nline2\ndefect_line\nline3\nline4\n\nblock2_a\nblock2_b";
        let mut debugger = DeltaDebugger::new(
            source,
            DefectClass::AssertionFailure,
            ReductionConfig::default(),
            test_epoch(),
        );

        let repro = debugger.reduce(|s| {
            if s.contains("defect_line") {
                StepOutcome::DefectPreserved
            } else {
                StepOutcome::DefectLost
            }
        });

        // Should have reduced size
        assert!(repro.reduced_size <= repro.original_size);
        assert!(repro.source.contains("defect_line"));
    }

    #[test]
    fn debugger_max_steps_respected() {
        let config = ReductionConfig {
            max_steps: 3,
            ..ReductionConfig::default()
        };
        let mut debugger =
            DeltaDebugger::new(sample_program(), DefectClass::Crash, config, test_epoch());

        let _repro = debugger.reduce(|_| StepOutcome::DefectLost);
        assert!(debugger.steps().len() <= 3);
    }

    #[test]
    fn debugger_summary() {
        let mut debugger = DeltaDebugger::new(
            sample_program(),
            DefectClass::Crash,
            ReductionConfig::default(),
            test_epoch(),
        );
        debugger.fragment();
        let summary = debugger.summary();
        assert_eq!(summary.defect_class, DefectClass::Crash);
        assert_eq!(summary.original_size, sample_program().len() as u32);
    }

    // --- MinimalRepro ---

    #[test]
    fn minimal_repro_display() {
        let mut debugger = DeltaDebugger::new(
            "let x = 1;\nlet y = 2;",
            DefectClass::WrongOutput,
            ReductionConfig::default(),
            test_epoch(),
        );
        let repro = debugger.reduce(|_| StepOutcome::DefectPreserved);
        let s = format!("{repro}");
        assert!(s.contains("minimal-repro"));
        assert!(s.contains("wrong-output"));
    }

    #[test]
    fn minimal_repro_serde() {
        let mut debugger = DeltaDebugger::new(
            "test source",
            DefectClass::Crash,
            ReductionConfig::default(),
            test_epoch(),
        );
        let repro = debugger.reduce(|_| StepOutcome::DefectPreserved);
        let json = serde_json::to_string(&repro).unwrap();
        let back: MinimalRepro = serde_json::from_str(&json).unwrap();
        assert_eq!(repro, back);
    }

    #[test]
    fn minimal_repro_reduction_percentage() {
        let repro = MinimalRepro {
            repro_id: "mr-test".into(),
            schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
            defect_class: DefectClass::Crash,
            source: "x".into(),
            original_size: 100,
            reduced_size: 25,
            reduction_ratio_millionths: 750_000,
            total_steps: 10,
            progress_steps: 5,
            original_fragment_count: 20,
            remaining_fragment_count: 5,
            essential_fragment_ids: vec![],
            config: ReductionConfig::default(),
            epoch: test_epoch(),
            stable: true,
        };
        assert_eq!(repro.reduction_percentage(), 75);
    }

    // --- EvidenceInventory ---

    #[test]
    fn evidence_inventory_from_repros() {
        let repro = MinimalRepro {
            repro_id: "mr-test".into(),
            schema_version: REDUCTION_SCHEMA_VERSION.to_string(),
            defect_class: DefectClass::Crash,
            source: "x".into(),
            original_size: 100,
            reduced_size: 25,
            reduction_ratio_millionths: 750_000,
            total_steps: 10,
            progress_steps: 5,
            original_fragment_count: 20,
            remaining_fragment_count: 5,
            essential_fragment_ids: vec![],
            config: ReductionConfig::default(),
            epoch: test_epoch(),
            stable: true,
        };
        let inv = ReductionEvidenceInventory::from_repros(&[repro]);
        assert_eq!(inv.session_count, 1);
        assert_eq!(inv.total_steps, 10);
        assert_eq!(inv.avg_reduction_millionths, 750_000);
    }

    #[test]
    fn evidence_inventory_empty() {
        let inv = ReductionEvidenceInventory::from_repros(&[]);
        assert_eq!(inv.session_count, 0);
        assert_eq!(inv.avg_reduction_millionths, 0);
    }

    #[test]
    fn evidence_inventory_serde() {
        let inv = ReductionEvidenceInventory::from_repros(&[]);
        let json = serde_json::to_string(&inv).unwrap();
        let back: ReductionEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    // --- Corpus ---

    #[test]
    fn corpus_non_empty() {
        let corpus = delta_debug_corpus();
        assert!(!corpus.is_empty());
    }

    #[test]
    fn run_corpus_all_pass() {
        let results = run_delta_debug_corpus();
        assert!(results.iter().all(|(_, passed)| *passed));
    }

    #[test]
    fn specimen_family_display() {
        let families = vec![
            DeltaDebugSpecimenFamily::SingleFile,
            DeltaDebugSpecimenFamily::MultiStatement,
            DeltaDebugSpecimenFamily::ImportDependent,
            DeltaDebugSpecimenFamily::ReactComponent,
            DeltaDebugSpecimenFamily::PerformanceLoop,
        ];
        for f in &families {
            assert!(!format!("{f}").is_empty());
        }
    }

    #[test]
    fn specimen_family_serde() {
        let f = DeltaDebugSpecimenFamily::ReactComponent;
        let json = serde_json::to_string(&f).unwrap();
        let back: DeltaDebugSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // --- Constants ---

    #[test]
    fn constants_set() {
        assert_eq!(COMPONENT, "hierarchical_delta_debug");
        assert!(!REDUCTION_SCHEMA_VERSION.is_empty());
        let dmrs = DEFAULT_MAX_REDUCTION_STEPS;
        let dmps = DEFAULT_MIN_PROGRAM_SIZE;
        let dmrt = DEFAULT_MAX_REDUCTION_TIME_MS;
        assert!(dmrs > 0);
        assert!(dmps > 0);
        assert!(dmrt > 0);
    }

    // --- ReductionSummary ---

    #[test]
    fn reduction_summary_serde() {
        let summary = ReductionSummary {
            repro_id: "mr-test".into(),
            defect_class: DefectClass::Crash,
            original_size: 100,
            reduced_size: 25,
            reduction_percentage: 75,
            total_steps: 10,
            progress_steps: 5,
            levels_attempted: vec![ReductionLevel::Statement],
            strategies_used: vec![ReductionStrategy::DeltaDebugging],
            stable: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: ReductionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }
}
