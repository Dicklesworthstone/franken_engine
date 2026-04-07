//! Dual-backend parser/binder abstraction with SWC/OXC pluggability.
//!
//! Provides a policy-driven abstraction over parser backends (SWC, OXC,
//! or FrankenEngine canonical) that guarantees identical normalized AST
//! contract, deterministic diagnostics envelopes, stable source-map
//! fidelity, and backend selection as policy.
//!
//! Design requirements (FRX-03.1):
//! - Identical normalized AST contract regardless of backend
//! - Deterministic diagnostics envelope
//! - Stable source-map fidelity and span mapping
//! - Backend selection as policy (not hardcoded)
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.  Collections use BTreeMap/BTreeSet for
//! deterministic iteration.
//!
//! Plan references: FRX-03.1, FRX-03 (Compiler Architecture).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ast::{ParseGoal, SourceSpan, SyntaxTree};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLION: i64 = 1_000_000;

/// Schema version for dual-backend parser artifacts.
pub const DUAL_BACKEND_SCHEMA_VERSION: &str = "franken-engine.dual-backend-parser.v1";

/// Maximum backends supported.
const MAX_BACKENDS: usize = 8;

// ---------------------------------------------------------------------------
// BackendId — typed backend identifier
// ---------------------------------------------------------------------------

/// Typed identifier for a parser backend.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BackendId(pub String);

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl BackendId {
    /// SWC-based TypeScript/JavaScript parser backend.
    pub fn swc() -> Self {
        Self("swc".into())
    }

    /// OXC-based TypeScript/JavaScript parser backend.
    pub fn oxc() -> Self {
        Self("oxc".into())
    }

    /// FrankenEngine canonical parser (scalar reference).
    pub fn franken_canonical() -> Self {
        Self("franken_canonical".into())
    }
}

// ---------------------------------------------------------------------------
// BackendCapability — what a backend can do
// ---------------------------------------------------------------------------

/// Capabilities declared by a parser backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapability {
    /// Whether the backend supports TypeScript input.
    pub typescript: bool,
    /// Whether the backend supports JSX input.
    pub jsx: bool,
    /// Whether the backend produces stable source maps.
    pub source_maps: bool,
    /// Whether the backend supports incremental reparsing.
    pub incremental: bool,
    /// Whether the backend preserves all comment positions.
    pub comment_preservation: bool,
    /// Maximum source size the backend supports (bytes, 0 = unlimited).
    pub max_source_bytes: u64,
}

impl BackendCapability {
    /// Default capability set for a full-featured backend.
    pub fn full() -> Self {
        Self {
            typescript: true,
            jsx: true,
            source_maps: true,
            incremental: false,
            comment_preservation: true,
            max_source_bytes: 0,
        }
    }

    /// Minimal capability set (ES2020 only, no TS/JSX).
    pub fn minimal() -> Self {
        Self {
            typescript: false,
            jsx: false,
            source_maps: false,
            incremental: false,
            comment_preservation: false,
            max_source_bytes: 1_048_576, // 1MB
        }
    }

    /// Check if all required capabilities are met.
    pub fn satisfies(&self, required: &BackendRequirements) -> bool {
        if required.needs_typescript && !self.typescript {
            return false;
        }
        if required.needs_jsx && !self.jsx {
            return false;
        }
        if required.needs_source_maps && !self.source_maps {
            return false;
        }
        if required.needs_incremental && !self.incremental {
            return false;
        }
        true
    }
}

/// Requirements for backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackendRequirements {
    /// Whether TypeScript support is needed.
    pub needs_typescript: bool,
    /// Whether JSX support is needed.
    pub needs_jsx: bool,
    /// Whether source maps are needed.
    pub needs_source_maps: bool,
    /// Whether incremental reparsing is needed.
    pub needs_incremental: bool,
}

// ---------------------------------------------------------------------------
// BackendRegistration — registered backend metadata
// ---------------------------------------------------------------------------

/// Registration entry for a parser backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendRegistration {
    /// Backend identifier.
    pub backend_id: BackendId,
    /// Human-readable name.
    pub display_name: String,
    /// Version string (semver).
    pub version: String,
    /// Declared capabilities.
    pub capabilities: BackendCapability,
    /// Priority for selection (lower = preferred).
    pub priority: u32,
    /// Whether this backend is currently healthy.
    pub healthy: bool,
}

// ---------------------------------------------------------------------------
// NormalizedParseOutput — backend-agnostic parse result
// ---------------------------------------------------------------------------

/// Backend-agnostic normalized parse output.
///
/// Regardless of which backend produced it, this output is structurally
/// identical and produces the same canonical hash for equivalent inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedParseOutput {
    /// The normalized AST.
    pub tree: SyntaxTree,
    /// Canonical hash of the normalized AST.
    pub canonical_hash: String,
    /// Source-map entries for span mapping fidelity.
    pub source_map: Vec<SpanMappingEntry>,
    /// Deterministic diagnostics envelope.
    pub diagnostics: DiagnosticsEnvelope,
    /// Backend that produced this output.
    pub backend_id: BackendId,
    /// Parse latency (microseconds).
    pub latency_us: u64,
    /// Whether the output was verified against the normalization contract.
    pub normalization_verified: bool,
}

impl NormalizedParseOutput {
    /// Verify that this output's canonical hash matches the tree.
    pub fn verify_hash(&self) -> bool {
        let computed = self.tree.canonical_hash();
        computed == self.canonical_hash
    }
}

// ---------------------------------------------------------------------------
// SpanMappingEntry — source-map fidelity
// ---------------------------------------------------------------------------

/// A single span-mapping entry linking backend-local spans to canonical spans.
///
/// When backends produce slightly different span representations (e.g.,
/// one uses byte offsets, another uses UTF-16 code units), this entry
/// records both and the deviation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanMappingEntry {
    /// Index of the AST node this entry maps.
    pub node_index: u64,
    /// Canonical span (byte offsets, 1-based line/column).
    pub canonical_span: SourceSpan,
    /// Backend-reported span (may differ in encoding).
    pub backend_span: SourceSpan,
    /// Deviation between canonical and backend spans (bytes).
    pub deviation_bytes: u64,
}

impl SpanMappingEntry {
    /// Check if this mapping is exact (zero deviation).
    pub fn is_exact(&self) -> bool {
        self.deviation_bytes == 0
    }
}

// ---------------------------------------------------------------------------
// DiagnosticsEnvelope — deterministic diagnostics
// ---------------------------------------------------------------------------

/// Deterministic diagnostics envelope produced by any backend.
///
/// Normalizes backend-specific error messages into a stable taxonomy
/// so diagnostics are identical regardless of which backend was used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsEnvelope {
    /// Schema version.
    pub schema_version: String,
    /// Taxonomy version for diagnostic codes.
    pub taxonomy_version: String,
    /// Normalized diagnostic entries.
    pub entries: Vec<NormalizedDiagnostic>,
    /// Canonical hash of the entire diagnostics envelope.
    pub envelope_hash: String,
}

impl DiagnosticsEnvelope {
    /// Create an empty diagnostics envelope (no errors).
    pub fn empty() -> Self {
        Self {
            schema_version: DUAL_BACKEND_SCHEMA_VERSION.to_string(),
            taxonomy_version: "franken-engine.diagnostics-taxonomy.v1".to_string(),
            entries: Vec::new(),
            envelope_hash: Self::compute_hash(&[]),
        }
    }

    /// Create an envelope from normalized diagnostics.
    pub fn from_diagnostics(entries: Vec<NormalizedDiagnostic>) -> Self {
        let hash = Self::compute_hash(&entries);
        Self {
            schema_version: DUAL_BACKEND_SCHEMA_VERSION.to_string(),
            taxonomy_version: "franken-engine.diagnostics-taxonomy.v1".to_string(),
            entries,
            envelope_hash: hash,
        }
    }

    /// Compute the canonical hash for a set of diagnostics.
    fn compute_hash(entries: &[NormalizedDiagnostic]) -> String {
        let canonical = serde_json::to_vec(entries).unwrap_or_default();
        let hash = ContentHash::compute(&canonical);
        format!("sha256:{}", hash.to_hex())
    }

    /// Number of diagnostics.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the envelope is empty (no diagnostics).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the envelope has any errors (not just warnings).
    pub fn has_errors(&self) -> bool {
        self.entries.iter().any(|e| {
            e.severity == DiagnosticSeverity::Error || e.severity == DiagnosticSeverity::Fatal
        })
    }
}

/// Severity level for normalized diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DiagnosticSeverity {
    /// Informational hint.
    Hint,
    /// Potential issue.
    Warning,
    /// Parse error.
    Error,
    /// Unrecoverable failure.
    Fatal,
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hint => write!(f, "hint"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

/// Diagnostic category for normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DiagnosticCategory {
    /// Syntax errors.
    Syntax,
    /// Semantic errors (binding, scope).
    Semantic,
    /// Type errors (TS-specific).
    Type,
    /// Resource/budget errors.
    Resource,
    /// Encoding/input errors.
    Encoding,
}

impl fmt::Display for DiagnosticCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax => write!(f, "syntax"),
            Self::Semantic => write!(f, "semantic"),
            Self::Type => write!(f, "type"),
            Self::Resource => write!(f, "resource"),
            Self::Encoding => write!(f, "encoding"),
        }
    }
}

/// A single normalized diagnostic entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedDiagnostic {
    /// Stable diagnostic code (e.g., "FE-PARSE-0001").
    pub code: String,
    /// Category.
    pub category: DiagnosticCategory,
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Stable message template (backend-agnostic).
    pub message_template: String,
    /// Span in the source (if applicable).
    pub span: Option<SourceSpan>,
    /// Additional context key-value pairs.
    pub context: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// BackendSelectionPolicy — policy-driven backend selection
// ---------------------------------------------------------------------------

/// Policy for selecting which parser backend to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSelectionPolicy {
    /// Policy identifier.
    pub policy_id: String,
    /// Default backend when no specific preference.
    pub default_backend: BackendId,
    /// Fallback backend when primary is unhealthy.
    pub fallback_backend: BackendId,
    /// Per-goal backend overrides.
    pub goal_overrides: BTreeMap<String, BackendId>,
    /// Per-file-extension backend overrides.
    pub extension_overrides: BTreeMap<String, BackendId>,
    /// Minimum acceptable fidelity score (millionths).
    pub min_fidelity_millionths: i64,
    /// Whether to verify normalization on every parse.
    pub verify_normalization: bool,
    /// Whether to run differential comparison across backends.
    pub differential_mode: bool,
}

impl BackendSelectionPolicy {
    /// Create a default policy preferring SWC with franken_canonical fallback.
    pub fn default_swc_primary() -> Self {
        Self {
            policy_id: "default-swc-primary".into(),
            default_backend: BackendId::swc(),
            fallback_backend: BackendId::franken_canonical(),
            goal_overrides: BTreeMap::new(),
            extension_overrides: BTreeMap::new(),
            min_fidelity_millionths: 990_000, // 99%
            verify_normalization: true,
            differential_mode: false,
        }
    }

    /// Create a policy preferring OXC with SWC fallback.
    pub fn default_oxc_primary() -> Self {
        Self {
            policy_id: "default-oxc-primary".into(),
            default_backend: BackendId::oxc(),
            fallback_backend: BackendId::swc(),
            goal_overrides: BTreeMap::new(),
            extension_overrides: BTreeMap::new(),
            min_fidelity_millionths: 990_000,
            verify_normalization: true,
            differential_mode: false,
        }
    }

    /// Create a differential policy that compares all backends.
    pub fn differential() -> Self {
        Self {
            policy_id: "differential-all".into(),
            default_backend: BackendId::franken_canonical(),
            fallback_backend: BackendId::franken_canonical(),
            goal_overrides: BTreeMap::new(),
            extension_overrides: BTreeMap::new(),
            min_fidelity_millionths: MILLION,
            verify_normalization: true,
            differential_mode: true,
        }
    }

    /// Select the backend for a given parse request.
    pub fn select_backend(
        &self,
        goal: ParseGoal,
        file_extension: Option<&str>,
        registered_backends: &[BackendRegistration],
    ) -> BackendId {
        // Check file extension overrides first.
        if let Some(ext) = file_extension
            && let Some(backend_id) = self.extension_overrides.get(ext)
            && is_backend_available(backend_id, registered_backends)
        {
            return backend_id.clone();
        }

        // Check goal overrides.
        let goal_key = match goal {
            ParseGoal::Script => "script",
            ParseGoal::Module => "module",
        };
        if let Some(backend_id) = self.goal_overrides.get(goal_key)
            && is_backend_available(backend_id, registered_backends)
        {
            return backend_id.clone();
        }

        // Use default, with fallback if unhealthy.
        if is_backend_available(&self.default_backend, registered_backends) {
            self.default_backend.clone()
        } else {
            self.fallback_backend.clone()
        }
    }
}

/// Check if a backend is registered and healthy.
fn is_backend_available(backend_id: &BackendId, backends: &[BackendRegistration]) -> bool {
    backends
        .iter()
        .any(|b| b.backend_id == *backend_id && b.healthy)
}

// ---------------------------------------------------------------------------
// FidelityReport — source-map and span fidelity analysis
// ---------------------------------------------------------------------------

/// Report on source-map fidelity between backend output and canonical spans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidelityReport {
    /// Backend that produced the output.
    pub backend_id: BackendId,
    /// Total spans compared.
    pub total_spans: u64,
    /// Spans with zero deviation.
    pub exact_spans: u64,
    /// Maximum deviation observed (bytes).
    pub max_deviation_bytes: u64,
    /// Fidelity score (millionths): exact_spans / total_spans * MILLION.
    pub fidelity_score_millionths: i64,
    /// Whether fidelity meets the policy threshold.
    pub meets_threshold: bool,
    /// Entries with non-zero deviation (for debugging).
    pub deviations: Vec<SpanMappingEntry>,
}

impl FidelityReport {
    /// Compute a fidelity report from span mappings.
    pub fn from_mappings(
        backend_id: BackendId,
        mappings: &[SpanMappingEntry],
        threshold_millionths: i64,
    ) -> Self {
        let total_spans = mappings.len() as u64;
        let exact_spans = mappings.iter().filter(|m| m.is_exact()).count() as u64;
        let max_deviation_bytes = mappings
            .iter()
            .map(|m| m.deviation_bytes)
            .max()
            .unwrap_or(0);
        let fidelity_score_millionths = if total_spans == 0 {
            MILLION
        } else {
            (exact_spans as i64).saturating_mul(MILLION) / (total_spans as i64)
        };
        let deviations: Vec<SpanMappingEntry> =
            mappings.iter().filter(|m| !m.is_exact()).cloned().collect();

        Self {
            backend_id,
            total_spans,
            exact_spans,
            max_deviation_bytes,
            fidelity_score_millionths,
            meets_threshold: fidelity_score_millionths >= threshold_millionths,
            deviations,
        }
    }
}

// ---------------------------------------------------------------------------
// DifferentialComparisonResult — cross-backend comparison
// ---------------------------------------------------------------------------

/// Result of a differential comparison across backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialComparisonResult {
    /// Source label parsed.
    pub source_label: String,
    /// Parse goal.
    pub goal: String,
    /// Results per backend.
    pub backend_results: Vec<BackendParseResult>,
    /// Whether all backends produced identical canonical hashes.
    pub all_equivalent: bool,
    /// Distinct canonical hashes observed.
    pub distinct_hashes: Vec<String>,
    /// Divergence classification.
    pub divergence: Option<DivergenceClass>,
}

/// A single backend's parse result in a differential comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendParseResult {
    /// Backend that produced this result.
    pub backend_id: BackendId,
    /// Canonical hash of the normalized AST (if successful).
    pub canonical_hash: Option<String>,
    /// Whether parse succeeded.
    pub success: bool,
    /// Error code if parse failed.
    pub error_code: Option<String>,
    /// Diagnostics envelope hash.
    pub diagnostics_hash: String,
    /// Latency (microseconds).
    pub latency_us: u64,
    /// Fidelity score (millionths).
    pub fidelity_score_millionths: i64,
}

/// Classification of divergence across backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceClass {
    /// AST structure differs.
    AstDivergence,
    /// Diagnostics differ but AST is equivalent.
    DiagnosticsDivergence,
    /// Spans differ but AST content is equivalent.
    SpanDivergence,
    /// One backend errors, another succeeds.
    ErrorDivergence,
}

impl fmt::Display for DivergenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AstDivergence => write!(f, "ast_divergence"),
            Self::DiagnosticsDivergence => write!(f, "diagnostics_divergence"),
            Self::SpanDivergence => write!(f, "span_divergence"),
            Self::ErrorDivergence => write!(f, "error_divergence"),
        }
    }
}

// ---------------------------------------------------------------------------
// DualBackendParserError — error types
// ---------------------------------------------------------------------------

/// Errors from the dual-backend parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DualBackendParserError {
    /// No backends registered.
    NoBackendsRegistered,
    /// Selected backend not found.
    BackendNotFound(String),
    /// Backend is unhealthy.
    BackendUnhealthy(String),
    /// All backends failed.
    AllBackendsFailed(Vec<String>),
    /// Normalization verification failed.
    NormalizationVerificationFailed {
        backend_id: String,
        expected_hash: String,
        actual_hash: String,
    },
    /// Fidelity below threshold.
    FidelityBelowThreshold {
        backend_id: String,
        fidelity_millionths: i64,
        threshold_millionths: i64,
    },
    /// Too many backends registered.
    TooManyBackends { count: usize, max: usize },
    /// Invalid configuration.
    InvalidConfig(String),
}

impl fmt::Display for DualBackendParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackendsRegistered => write!(f, "no backends registered"),
            Self::BackendNotFound(id) => write!(f, "backend not found: {id}"),
            Self::BackendUnhealthy(id) => write!(f, "backend unhealthy: {id}"),
            Self::AllBackendsFailed(ids) => write!(f, "all backends failed: {}", ids.join(", ")),
            Self::NormalizationVerificationFailed {
                backend_id,
                expected_hash,
                actual_hash,
            } => write!(
                f,
                "normalization verification failed for {backend_id}: expected={expected_hash}, actual={actual_hash}"
            ),
            Self::FidelityBelowThreshold {
                backend_id,
                fidelity_millionths,
                threshold_millionths,
            } => write!(
                f,
                "fidelity below threshold for {backend_id}: {fidelity_millionths} < {threshold_millionths}"
            ),
            Self::TooManyBackends { count, max } => {
                write!(f, "too many backends: {count} > {max}")
            }
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for DualBackendParserError {}

// ---------------------------------------------------------------------------
// ParseEvent — audit trail for backend selection and parsing
// ---------------------------------------------------------------------------

/// Audit event for dual-backend parser operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualBackendParseEvent {
    /// Event sequence number.
    pub seq: u64,
    /// Event kind.
    pub kind: DualBackendEventKind,
    /// Backend involved.
    pub backend_id: Option<BackendId>,
    /// Source label.
    pub source_label: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (logical tick).
    pub timestamp_ns: u64,
}

/// Kinds of dual-backend parse events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DualBackendEventKind {
    /// Backend selected by policy.
    BackendSelected,
    /// Parse completed successfully.
    ParseCompleted { latency_us: u64, hash: String },
    /// Parse failed, attempting fallback.
    ParseFailed { error: String },
    /// Fallback backend selected.
    FallbackSelected,
    /// Normalization verified.
    NormalizationVerified,
    /// Fidelity report generated.
    FidelityReported { score_millionths: i64 },
    /// Differential comparison completed.
    DifferentialCompleted { all_equivalent: bool },
    /// Backend registered.
    BackendRegistered,
    /// Backend health changed.
    HealthChanged { healthy: bool },
}

// ---------------------------------------------------------------------------
// DualBackendParser — main orchestrator
// ---------------------------------------------------------------------------

/// Dual-backend parser orchestrator.
///
/// Manages backend registration, policy-driven selection, normalization
/// verification, fidelity checking, and differential comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualBackendParser {
    /// Parser identifier.
    pub parser_id: String,
    /// Registered backends.
    pub backends: Vec<BackendRegistration>,
    /// Selection policy.
    pub policy: BackendSelectionPolicy,
    /// Audit event log.
    pub events: Vec<DualBackendParseEvent>,
    /// Event sequence counter.
    pub event_seq: u64,
    /// Total parses completed.
    pub parse_count: u64,
    /// Total fallbacks triggered.
    pub fallback_count: u64,
    /// Total normalization failures.
    pub normalization_failure_count: u64,
    /// Current epoch.
    pub epoch: SecurityEpoch,
}

impl DualBackendParser {
    /// Create a new dual-backend parser with the given policy.
    pub fn new(
        parser_id: impl Into<String>,
        policy: BackendSelectionPolicy,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            parser_id: parser_id.into(),
            backends: Vec::new(),
            policy,
            events: Vec::new(),
            event_seq: 0,
            parse_count: 0,
            fallback_count: 0,
            normalization_failure_count: 0,
            epoch,
        }
    }

    /// Register a parser backend.
    pub fn register_backend(
        &mut self,
        registration: BackendRegistration,
    ) -> Result<(), DualBackendParserError> {
        if self.backends.len() >= MAX_BACKENDS {
            return Err(DualBackendParserError::TooManyBackends {
                count: self.backends.len() + 1,
                max: MAX_BACKENDS,
            });
        }

        // Avoid duplicate registration.
        if self
            .backends
            .iter()
            .any(|b| b.backend_id == registration.backend_id)
        {
            // Update existing registration.
            if let Some(existing) = self
                .backends
                .iter_mut()
                .find(|b| b.backend_id == registration.backend_id)
            {
                *existing = registration.clone();
            }
        } else {
            self.backends.push(registration.clone());
        }

        self.emit_event(
            DualBackendEventKind::BackendRegistered,
            Some(registration.backend_id),
            "",
        );
        Ok(())
    }

    /// Set a backend's health status.
    pub fn set_backend_health(
        &mut self,
        backend_id: &BackendId,
        healthy: bool,
    ) -> Result<(), DualBackendParserError> {
        if let Some(backend) = self
            .backends
            .iter_mut()
            .find(|b| &b.backend_id == backend_id)
        {
            backend.healthy = healthy;
            self.emit_event(
                DualBackendEventKind::HealthChanged { healthy },
                Some(backend_id.clone()),
                "",
            );
            Ok(())
        } else {
            Err(DualBackendParserError::BackendNotFound(
                backend_id.to_string(),
            ))
        }
    }

    /// Select the best backend for a parse request.
    pub fn select_backend(
        &mut self,
        goal: ParseGoal,
        file_extension: Option<&str>,
    ) -> Result<BackendId, DualBackendParserError> {
        if self.backends.is_empty() {
            return Err(DualBackendParserError::NoBackendsRegistered);
        }

        let selected = self
            .policy
            .select_backend(goal, file_extension, &self.backends);

        // The policy may already choose the fallback when the default backend
        // is unhealthy; count and emit this as an explicit fallback action.
        if selected == self.policy.fallback_backend
            && !is_backend_available(&self.policy.default_backend, &self.backends)
            && is_backend_available(&selected, &self.backends)
        {
            self.emit_event(
                DualBackendEventKind::FallbackSelected,
                Some(selected.clone()),
                "",
            );
            self.fallback_count += 1;
            return Ok(selected);
        }

        if !is_backend_available(&selected, &self.backends) {
            // Try fallback.
            if is_backend_available(&self.policy.fallback_backend, &self.backends) {
                self.emit_event(
                    DualBackendEventKind::FallbackSelected,
                    Some(self.policy.fallback_backend.clone()),
                    "",
                );
                self.fallback_count += 1;
                return Ok(self.policy.fallback_backend.clone());
            }
            // Try any healthy backend.
            if let Some(any_healthy_backend_id) = self
                .backends
                .iter()
                .find(|b| b.healthy)
                .map(|b| b.backend_id.clone())
            {
                self.emit_event(
                    DualBackendEventKind::FallbackSelected,
                    Some(any_healthy_backend_id.clone()),
                    "",
                );
                self.fallback_count += 1;
                return Ok(any_healthy_backend_id);
            }
            return Err(DualBackendParserError::AllBackendsFailed(
                self.backends
                    .iter()
                    .map(|b| b.backend_id.to_string())
                    .collect(),
            ));
        }

        self.emit_event(
            DualBackendEventKind::BackendSelected,
            Some(selected.clone()),
            "",
        );
        Ok(selected)
    }

    /// Record a completed parse.
    pub fn record_parse(
        &mut self,
        backend_id: &BackendId,
        source_label: &str,
        canonical_hash: &str,
        latency_us: u64,
    ) {
        self.parse_count += 1;
        self.emit_event(
            DualBackendEventKind::ParseCompleted {
                latency_us,
                hash: canonical_hash.to_string(),
            },
            Some(backend_id.clone()),
            source_label,
        );
    }

    /// Record a parse failure.
    pub fn record_failure(&mut self, backend_id: &BackendId, source_label: &str, error: &str) {
        self.emit_event(
            DualBackendEventKind::ParseFailed {
                error: error.to_string(),
            },
            Some(backend_id.clone()),
            source_label,
        );
    }

    /// Verify normalization: recompute canonical hash and compare.
    pub fn verify_normalization(
        &mut self,
        output: &NormalizedParseOutput,
    ) -> Result<(), DualBackendParserError> {
        let computed_hash = output.tree.canonical_hash();
        if computed_hash != output.canonical_hash {
            self.normalization_failure_count += 1;
            return Err(DualBackendParserError::NormalizationVerificationFailed {
                backend_id: output.backend_id.to_string(),
                expected_hash: output.canonical_hash.clone(),
                actual_hash: computed_hash,
            });
        }
        self.emit_event(
            DualBackendEventKind::NormalizationVerified,
            Some(output.backend_id.clone()),
            "",
        );
        Ok(())
    }

    /// Compute fidelity report for a parse output.
    pub fn compute_fidelity(&mut self, output: &NormalizedParseOutput) -> FidelityReport {
        let report = FidelityReport::from_mappings(
            output.backend_id.clone(),
            &output.source_map,
            self.policy.min_fidelity_millionths,
        );
        self.emit_event(
            DualBackendEventKind::FidelityReported {
                score_millionths: report.fidelity_score_millionths,
            },
            Some(output.backend_id.clone()),
            "",
        );
        report
    }

    /// Get the number of registered backends.
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Get the number of healthy backends.
    pub fn healthy_backend_count(&self) -> usize {
        self.backends.iter().filter(|b| b.healthy).count()
    }

    /// Emit an audit event.
    fn emit_event(
        &mut self,
        kind: DualBackendEventKind,
        backend_id: Option<BackendId>,
        source_label: &str,
    ) {
        let event = DualBackendParseEvent {
            seq: self.event_seq,
            kind,
            backend_id,
            source_label: source_label.to_string(),
            epoch: self.epoch,
            timestamp_ns: self.event_seq * 1_000_000,
        };
        self.event_seq += 1;
        self.events.push(event);
        // Trim to prevent unbounded growth.
        if self.events.len() > 10_000 {
            self.events.remove(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn make_registration(id: BackendId, priority: u32, healthy: bool) -> BackendRegistration {
        BackendRegistration {
            backend_id: id,
            display_name: "Test Backend".into(),
            version: "1.0.0".into(),
            capabilities: BackendCapability::full(),
            priority,
            healthy,
        }
    }

    fn make_parser() -> DualBackendParser {
        let mut parser = DualBackendParser::new(
            "test-parser",
            BackendSelectionPolicy::default_swc_primary(),
            epoch(1),
        );
        parser
            .register_backend(make_registration(BackendId::swc(), 1, true))
            .unwrap();
        parser
            .register_backend(make_registration(BackendId::oxc(), 2, true))
            .unwrap();
        parser
            .register_backend(make_registration(BackendId::franken_canonical(), 3, true))
            .unwrap();
        parser
    }

    fn make_span(start: u64, end: u64) -> SourceSpan {
        SourceSpan {
            start_offset: start,
            end_offset: end,
            start_line: 1,
            start_column: start + 1,
            end_line: 1,
            end_column: end + 1,
        }
    }

    // -- BackendId tests --

    #[test]
    fn backend_id_display() {
        assert_eq!(BackendId::swc().to_string(), "swc");
        assert_eq!(BackendId::oxc().to_string(), "oxc");
        assert_eq!(
            BackendId::franken_canonical().to_string(),
            "franken_canonical"
        );
    }

    #[test]
    fn backend_id_ordering() {
        let mut ids = vec![
            BackendId::oxc(),
            BackendId::swc(),
            BackendId::franken_canonical(),
        ];
        ids.sort();
        assert_eq!(
            ids,
            vec![
                BackendId::franken_canonical(),
                BackendId::oxc(),
                BackendId::swc(),
            ]
        );
    }

    #[test]
    fn backend_id_serde_roundtrip() {
        let id = BackendId::swc();
        let json = serde_json::to_string(&id).unwrap();
        let back: BackendId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -- BackendCapability tests --

    #[test]
    fn capability_full_supports_all() {
        let cap = BackendCapability::full();
        assert!(cap.typescript);
        assert!(cap.jsx);
        assert!(cap.source_maps);
    }

    #[test]
    fn capability_minimal_supports_none() {
        let cap = BackendCapability::minimal();
        assert!(!cap.typescript);
        assert!(!cap.jsx);
        assert!(!cap.source_maps);
    }

    #[test]
    fn capability_satisfies_requirements() {
        let cap = BackendCapability::full();
        let req = BackendRequirements {
            needs_typescript: true,
            needs_jsx: true,
            needs_source_maps: true,
            needs_incremental: false,
        };
        assert!(cap.satisfies(&req));
    }

    #[test]
    fn capability_fails_requirements() {
        let cap = BackendCapability::minimal();
        let req = BackendRequirements {
            needs_typescript: true,
            needs_jsx: false,
            needs_source_maps: false,
            needs_incremental: false,
        };
        assert!(!cap.satisfies(&req));
    }

    // -- DiagnosticsEnvelope tests --

    #[test]
    fn diagnostics_empty_is_empty() {
        let env = DiagnosticsEnvelope::empty();
        assert!(env.is_empty());
        assert_eq!(env.len(), 0);
        assert!(!env.has_errors());
    }

    #[test]
    fn diagnostics_with_error_has_errors() {
        let diag = NormalizedDiagnostic {
            code: "FE-PARSE-0001".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Error,
            message_template: "Unexpected token".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
        assert_eq!(env.len(), 1);
        assert!(env.has_errors());
    }

    #[test]
    fn diagnostics_warning_only_no_errors() {
        let diag = NormalizedDiagnostic {
            code: "FE-PARSE-W001".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Warning,
            message_template: "Unused import".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
        assert_eq!(env.len(), 1);
        assert!(!env.has_errors());
    }

    #[test]
    fn diagnostics_hash_deterministic() {
        let diag = NormalizedDiagnostic {
            code: "FE-PARSE-0001".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Error,
            message_template: "test".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let env1 = DiagnosticsEnvelope::from_diagnostics(vec![diag.clone()]);
        let env2 = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
        assert_eq!(env1.envelope_hash, env2.envelope_hash);
    }

    #[test]
    fn diagnostics_serde_roundtrip() {
        let env = DiagnosticsEnvelope::empty();
        let json = serde_json::to_string(&env).unwrap();
        let back: DiagnosticsEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env.envelope_hash, back.envelope_hash);
    }

    // -- DiagnosticSeverity tests --

    #[test]
    fn severity_display() {
        assert_eq!(DiagnosticSeverity::Hint.to_string(), "hint");
        assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
        assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
        assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
    }

    #[test]
    fn severity_ordering() {
        assert!(DiagnosticSeverity::Hint < DiagnosticSeverity::Warning);
        assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
        assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
    }

    // -- DiagnosticCategory tests --

    #[test]
    fn category_display() {
        assert_eq!(DiagnosticCategory::Syntax.to_string(), "syntax");
        assert_eq!(DiagnosticCategory::Semantic.to_string(), "semantic");
        assert_eq!(DiagnosticCategory::Type.to_string(), "type");
        assert_eq!(DiagnosticCategory::Resource.to_string(), "resource");
        assert_eq!(DiagnosticCategory::Encoding.to_string(), "encoding");
    }

    // -- SpanMappingEntry tests --

    #[test]
    fn span_mapping_exact() {
        let span = make_span(0, 10);
        let entry = SpanMappingEntry {
            node_index: 0,
            canonical_span: span.clone(),
            backend_span: span,
            deviation_bytes: 0,
        };
        assert!(entry.is_exact());
    }

    #[test]
    fn span_mapping_deviation() {
        let entry = SpanMappingEntry {
            node_index: 0,
            canonical_span: make_span(0, 10),
            backend_span: make_span(0, 11),
            deviation_bytes: 1,
        };
        assert!(!entry.is_exact());
    }

    // -- FidelityReport tests --

    #[test]
    fn fidelity_all_exact() {
        let mappings = vec![
            SpanMappingEntry {
                node_index: 0,
                canonical_span: make_span(0, 5),
                backend_span: make_span(0, 5),
                deviation_bytes: 0,
            },
            SpanMappingEntry {
                node_index: 1,
                canonical_span: make_span(5, 10),
                backend_span: make_span(5, 10),
                deviation_bytes: 0,
            },
        ];
        let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 990_000);
        assert_eq!(report.fidelity_score_millionths, MILLION);
        assert!(report.meets_threshold);
        assert!(report.deviations.is_empty());
    }

    #[test]
    fn fidelity_half_exact() {
        let mappings = vec![
            SpanMappingEntry {
                node_index: 0,
                canonical_span: make_span(0, 5),
                backend_span: make_span(0, 5),
                deviation_bytes: 0,
            },
            SpanMappingEntry {
                node_index: 1,
                canonical_span: make_span(5, 10),
                backend_span: make_span(5, 11),
                deviation_bytes: 1,
            },
        ];
        let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 990_000);
        assert_eq!(report.fidelity_score_millionths, 500_000);
        assert!(!report.meets_threshold);
        assert_eq!(report.deviations.len(), 1);
    }

    #[test]
    fn fidelity_empty_is_perfect() {
        let report = FidelityReport::from_mappings(BackendId::swc(), &[], 990_000);
        assert_eq!(report.fidelity_score_millionths, MILLION);
        assert!(report.meets_threshold);
    }

    // -- BackendSelectionPolicy tests --

    #[test]
    fn policy_default_swc() {
        let policy = BackendSelectionPolicy::default_swc_primary();
        assert_eq!(policy.default_backend, BackendId::swc());
        assert_eq!(policy.fallback_backend, BackendId::franken_canonical());
    }

    #[test]
    fn policy_default_oxc() {
        let policy = BackendSelectionPolicy::default_oxc_primary();
        assert_eq!(policy.default_backend, BackendId::oxc());
        assert_eq!(policy.fallback_backend, BackendId::swc());
    }

    #[test]
    fn policy_selects_default_when_healthy() {
        let policy = BackendSelectionPolicy::default_swc_primary();
        let backends = vec![make_registration(BackendId::swc(), 1, true)];
        let selected = policy.select_backend(ParseGoal::Module, None, &backends);
        assert_eq!(selected, BackendId::swc());
    }

    #[test]
    fn policy_selects_fallback_when_default_unhealthy() {
        let policy = BackendSelectionPolicy::default_swc_primary();
        let backends = vec![
            make_registration(BackendId::swc(), 1, false),
            make_registration(BackendId::franken_canonical(), 3, true),
        ];
        let selected = policy.select_backend(ParseGoal::Module, None, &backends);
        assert_eq!(selected, BackendId::franken_canonical());
    }

    #[test]
    fn policy_goal_override() {
        let mut policy = BackendSelectionPolicy::default_swc_primary();
        policy
            .goal_overrides
            .insert("script".into(), BackendId::oxc());
        let backends = vec![
            make_registration(BackendId::swc(), 1, true),
            make_registration(BackendId::oxc(), 2, true),
        ];
        let selected = policy.select_backend(ParseGoal::Script, None, &backends);
        assert_eq!(selected, BackendId::oxc());
    }

    #[test]
    fn policy_extension_override() {
        let mut policy = BackendSelectionPolicy::default_swc_primary();
        policy
            .extension_overrides
            .insert("tsx".into(), BackendId::oxc());
        let backends = vec![
            make_registration(BackendId::swc(), 1, true),
            make_registration(BackendId::oxc(), 2, true),
        ];
        let selected = policy.select_backend(ParseGoal::Module, Some("tsx"), &backends);
        assert_eq!(selected, BackendId::oxc());
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = BackendSelectionPolicy::default_swc_primary();
        let json = serde_json::to_string(&policy).unwrap();
        let back: BackendSelectionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.policy_id, back.policy_id);
    }

    // -- DualBackendParser tests --

    #[test]
    fn parser_creation() {
        let parser = make_parser();
        assert_eq!(parser.backend_count(), 3);
        assert_eq!(parser.healthy_backend_count(), 3);
        assert_eq!(parser.parse_count, 0);
    }

    #[test]
    fn parser_empty_fails() {
        let mut parser = DualBackendParser::new(
            "empty",
            BackendSelectionPolicy::default_swc_primary(),
            epoch(1),
        );
        let result = parser.select_backend(ParseGoal::Module, None);
        assert!(result.is_err());
    }

    #[test]
    fn parser_selects_swc_primary() {
        let mut parser = make_parser();
        let selected = parser.select_backend(ParseGoal::Module, None).unwrap();
        assert_eq!(selected, BackendId::swc());
    }

    #[test]
    fn parser_fallback_when_primary_unhealthy() {
        let mut parser = make_parser();
        parser.set_backend_health(&BackendId::swc(), false).unwrap();
        let selected = parser.select_backend(ParseGoal::Module, None).unwrap();
        assert_eq!(selected, BackendId::franken_canonical());
        assert_eq!(parser.fallback_count, 1);
    }

    #[test]
    fn parser_health_toggle() {
        let mut parser = make_parser();
        parser.set_backend_health(&BackendId::swc(), false).unwrap();
        assert_eq!(parser.healthy_backend_count(), 2);
        parser.set_backend_health(&BackendId::swc(), true).unwrap();
        assert_eq!(parser.healthy_backend_count(), 3);
    }

    #[test]
    fn parser_health_unknown_backend_fails() {
        let mut parser = make_parser();
        let result = parser.set_backend_health(&BackendId(String::from("unknown")), false);
        assert!(result.is_err());
    }

    #[test]
    fn parser_record_parse() {
        let mut parser = make_parser();
        parser.record_parse(&BackendId::swc(), "test.js", "sha256:abc", 1_000);
        assert_eq!(parser.parse_count, 1);
    }

    #[test]
    fn parser_record_failure() {
        let mut parser = make_parser();
        parser.record_failure(&BackendId::swc(), "test.js", "syntax error");
        assert_eq!(parser.parse_count, 0);
    }

    #[test]
    fn parser_max_backends_enforced() {
        let mut parser = DualBackendParser::new(
            "test",
            BackendSelectionPolicy::default_swc_primary(),
            epoch(1),
        );
        for i in 0..MAX_BACKENDS {
            let reg = make_registration(BackendId(format!("b{i}")), i as u32, true);
            parser.register_backend(reg).unwrap();
        }
        let extra = make_registration(BackendId("extra".into()), 99, true);
        let result = parser.register_backend(extra);
        assert!(result.is_err());
    }

    #[test]
    fn parser_duplicate_registration_updates() {
        let mut parser = make_parser();
        let updated = BackendRegistration {
            backend_id: BackendId::swc(),
            display_name: "Updated SWC".into(),
            version: "2.0.0".into(),
            capabilities: BackendCapability::full(),
            priority: 0,
            healthy: true,
        };
        parser.register_backend(updated).unwrap();
        assert_eq!(parser.backend_count(), 3); // same count, not duplicated
        let swc = parser
            .backends
            .iter()
            .find(|b| b.backend_id == BackendId::swc())
            .unwrap();
        assert_eq!(swc.version, "2.0.0");
    }

    #[test]
    fn parser_events_grow() {
        let mut parser = make_parser();
        let initial_events = parser.events.len();
        parser.record_parse(&BackendId::swc(), "test.js", "sha256:abc", 1_000);
        assert!(parser.events.len() > initial_events);
    }

    #[test]
    fn parser_serde_roundtrip() {
        let parser = make_parser();
        let json = serde_json::to_string(&parser).unwrap();
        let back: DualBackendParser = serde_json::from_str(&json).unwrap();
        assert_eq!(parser.parser_id, back.parser_id);
        assert_eq!(parser.backend_count(), back.backend_count());
    }

    // -- DivergenceClass tests --

    #[test]
    fn divergence_class_display() {
        assert_eq!(DivergenceClass::AstDivergence.to_string(), "ast_divergence");
        assert_eq!(
            DivergenceClass::DiagnosticsDivergence.to_string(),
            "diagnostics_divergence"
        );
        assert_eq!(
            DivergenceClass::SpanDivergence.to_string(),
            "span_divergence"
        );
        assert_eq!(
            DivergenceClass::ErrorDivergence.to_string(),
            "error_divergence"
        );
    }

    // -- DualBackendParserError tests --

    #[test]
    fn error_display() {
        assert_eq!(
            DualBackendParserError::NoBackendsRegistered.to_string(),
            "no backends registered"
        );
        assert_eq!(
            DualBackendParserError::BackendNotFound("swc".into()).to_string(),
            "backend not found: swc"
        );
        assert_eq!(
            DualBackendParserError::TooManyBackends { count: 9, max: 8 }.to_string(),
            "too many backends: 9 > 8"
        );
    }

    // -- DifferentialComparisonResult tests --

    #[test]
    fn differential_result_serde_roundtrip() {
        let result = DifferentialComparisonResult {
            source_label: "test.js".into(),
            goal: "module".into(),
            backend_results: vec![BackendParseResult {
                backend_id: BackendId::swc(),
                canonical_hash: Some("sha256:abc".into()),
                success: true,
                error_code: None,
                diagnostics_hash: "sha256:def".into(),
                latency_us: 1_000,
                fidelity_score_millionths: MILLION,
            }],
            all_equivalent: true,
            distinct_hashes: vec!["sha256:abc".into()],
            divergence: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: DifferentialComparisonResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.source_label, back.source_label);
    }

    // -- NormalizedDiagnostic tests --

    #[test]
    fn normalized_diagnostic_serde_roundtrip() {
        let diag = NormalizedDiagnostic {
            code: "FE-PARSE-0001".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Error,
            message_template: "Unexpected token '{token}'".into(),
            span: Some(make_span(0, 5)),
            context: {
                let mut m = BTreeMap::new();
                m.insert("token".into(), "if".into());
                m
            },
        };
        let json = serde_json::to_string(&diag).unwrap();
        let back: NormalizedDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(diag.code, back.code);
    }

    // -- BackendRequirements tests --

    #[test]
    fn requirements_default_is_minimal() {
        let req = BackendRequirements::default();
        assert!(!req.needs_typescript);
        assert!(!req.needs_jsx);
        assert!(!req.needs_source_maps);
        assert!(!req.needs_incremental);
    }

    // -- DualBackendEventKind tests --

    #[test]
    fn event_kind_serde_roundtrip() {
        let kind = DualBackendEventKind::ParseCompleted {
            latency_us: 1_000,
            hash: "sha256:abc".into(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: DualBackendEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }

    #[test]
    fn all_backends_failed_error() {
        let mut parser = DualBackendParser::new(
            "test",
            BackendSelectionPolicy::default_swc_primary(),
            epoch(1),
        );
        parser
            .register_backend(make_registration(BackendId::swc(), 1, false))
            .unwrap();
        parser
            .register_backend(make_registration(BackendId::franken_canonical(), 2, false))
            .unwrap();
        let result = parser.select_backend(ParseGoal::Module, None);
        assert!(matches!(
            result,
            Err(DualBackendParserError::AllBackendsFailed(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: DualBackendParserError Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn parser_error_display_all_unique() {
        let errors: Vec<DualBackendParserError> = vec![
            DualBackendParserError::NoBackendsRegistered,
            DualBackendParserError::BackendNotFound("test".into()),
            DualBackendParserError::TooManyBackends { count: 10, max: 8 },
            DualBackendParserError::AllBackendsFailed(vec!["swc".into()]),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all error variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: DualBackendParserError implements std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn parser_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(DualBackendParserError::NoBackendsRegistered),
            Box::new(DualBackendParserError::BackendNotFound("x".into())),
            Box::new(DualBackendParserError::TooManyBackends { count: 9, max: 8 }),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: DiagnosticSeverity Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostic_severity_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for sev in &[
            DiagnosticSeverity::Hint,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Fatal,
        ] {
            displays.insert(sev.to_string());
        }
        assert_eq!(displays.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DiagnosticCategory Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostic_category_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for cat in &[
            DiagnosticCategory::Syntax,
            DiagnosticCategory::Semantic,
            DiagnosticCategory::Type,
            DiagnosticCategory::Resource,
            DiagnosticCategory::Encoding,
        ] {
            displays.insert(cat.to_string());
        }
        assert_eq!(displays.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Enrichment: BackendCapability serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn backend_capability_serde_roundtrip() {
        let caps = [BackendCapability::full(), BackendCapability::minimal()];
        for cap in &caps {
            let json = serde_json::to_string(cap).unwrap();
            let back: BackendCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap.typescript, back.typescript);
            assert_eq!(cap.jsx, back.jsx);
            assert_eq!(cap.source_maps, back.source_maps);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: BackendRegistration serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn backend_registration_serde_roundtrip() {
        let reg = make_registration(BackendId::swc(), 1, true);
        let json = serde_json::to_string(&reg).unwrap();
        let back: BackendRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg.backend_id, back.backend_id);
        assert_eq!(reg.priority, back.priority);
        assert_eq!(reg.healthy, back.healthy);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DualBackendParser parse_count and fallback_count initial
    // -----------------------------------------------------------------------

    #[test]
    fn parser_initial_counts_are_zero() {
        let parser = make_parser();
        assert_eq!(parser.parse_count, 0);
        assert_eq!(parser.fallback_count, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DivergenceClass serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn divergence_class_serde_roundtrip() {
        for dc in &[
            DivergenceClass::AstDivergence,
            DivergenceClass::DiagnosticsDivergence,
            DivergenceClass::SpanDivergence,
            DivergenceClass::ErrorDivergence,
        ] {
            let json = serde_json::to_string(dc).unwrap();
            let back: DivergenceClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*dc, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-28
    // -----------------------------------------------------------------------

    #[test]
    fn capability_incremental_requirement() {
        let cap = BackendCapability::full();
        let req = BackendRequirements {
            needs_typescript: false,
            needs_jsx: false,
            needs_source_maps: false,
            needs_incremental: true,
        };
        // full() has incremental: false, so should fail
        assert!(!cap.satisfies(&req));
    }

    #[test]
    fn capability_satisfies_empty_requirements() {
        let cap = BackendCapability::minimal();
        let req = BackendRequirements::default();
        assert!(cap.satisfies(&req));
    }

    #[test]
    fn diagnostics_with_fatal_has_errors() {
        let diag = NormalizedDiagnostic {
            code: "FE-FATAL-0001".into(),
            category: DiagnosticCategory::Resource,
            severity: DiagnosticSeverity::Fatal,
            message_template: "Out of memory".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
        assert!(env.has_errors());
    }

    #[test]
    fn diagnostics_hint_only_no_errors() {
        let diag = NormalizedDiagnostic {
            code: "FE-HINT-0001".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Hint,
            message_template: "consider refactoring".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let env = DiagnosticsEnvelope::from_diagnostics(vec![diag]);
        assert!(!env.has_errors());
    }

    #[test]
    fn diagnostics_mixed_severities() {
        let entries = vec![
            NormalizedDiagnostic {
                code: "FE-H-1".into(),
                category: DiagnosticCategory::Syntax,
                severity: DiagnosticSeverity::Hint,
                message_template: "hint".into(),
                span: None,
                context: BTreeMap::new(),
            },
            NormalizedDiagnostic {
                code: "FE-W-1".into(),
                category: DiagnosticCategory::Semantic,
                severity: DiagnosticSeverity::Warning,
                message_template: "warning".into(),
                span: None,
                context: BTreeMap::new(),
            },
            NormalizedDiagnostic {
                code: "FE-E-1".into(),
                category: DiagnosticCategory::Type,
                severity: DiagnosticSeverity::Error,
                message_template: "error".into(),
                span: None,
                context: BTreeMap::new(),
            },
        ];
        let env = DiagnosticsEnvelope::from_diagnostics(entries);
        assert_eq!(env.len(), 3);
        assert!(env.has_errors());
    }

    #[test]
    fn diagnostics_hash_differs_by_content() {
        let diag1 = NormalizedDiagnostic {
            code: "FE-1".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Error,
            message_template: "one".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let diag2 = NormalizedDiagnostic {
            code: "FE-2".into(),
            category: DiagnosticCategory::Semantic,
            severity: DiagnosticSeverity::Warning,
            message_template: "two".into(),
            span: None,
            context: BTreeMap::new(),
        };
        let env1 = DiagnosticsEnvelope::from_diagnostics(vec![diag1]);
        let env2 = DiagnosticsEnvelope::from_diagnostics(vec![diag2]);
        assert_ne!(env1.envelope_hash, env2.envelope_hash);
    }

    #[test]
    fn requirements_serde_roundtrip() {
        let req = BackendRequirements {
            needs_typescript: true,
            needs_jsx: true,
            needs_source_maps: false,
            needs_incremental: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: BackendRequirements = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn parse_event_serde_roundtrip() {
        let event = DualBackendParseEvent {
            seq: 42,
            kind: DualBackendEventKind::ParseCompleted {
                latency_us: 5_000,
                hash: "sha256:xyz".into(),
            },
            backend_id: Some(BackendId::oxc()),
            source_label: "test.ts".into(),
            epoch: epoch(7),
            timestamp_ns: 42_000_000,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: DualBackendParseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn backend_parse_result_serde_roundtrip() {
        let result = BackendParseResult {
            backend_id: BackendId::swc(),
            canonical_hash: Some("sha256:abc".into()),
            success: true,
            error_code: None,
            diagnostics_hash: "sha256:diag".into(),
            latency_us: 2_000,
            fidelity_score_millionths: 995_000,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: BackendParseResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn backend_parse_result_failure() {
        let result = BackendParseResult {
            backend_id: BackendId::oxc(),
            canonical_hash: None,
            success: false,
            error_code: Some("PARSE_FAILED".into()),
            diagnostics_hash: "sha256:err".into(),
            latency_us: 500,
            fidelity_score_millionths: 0,
        };
        assert!(!result.success);
        assert!(result.canonical_hash.is_none());
        assert!(result.error_code.is_some());
    }

    #[test]
    fn fidelity_report_serde_roundtrip() {
        let mappings = vec![
            SpanMappingEntry {
                node_index: 0,
                canonical_span: make_span(0, 5),
                backend_span: make_span(0, 5),
                deviation_bytes: 0,
            },
            SpanMappingEntry {
                node_index: 1,
                canonical_span: make_span(5, 10),
                backend_span: make_span(5, 12),
                deviation_bytes: 2,
            },
        ];
        let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 990_000);
        let json = serde_json::to_string(&report).unwrap();
        let back: FidelityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn error_display_normalization_verification_failed() {
        let e = DualBackendParserError::NormalizationVerificationFailed {
            backend_id: "swc".into(),
            expected_hash: "sha256:aaa".into(),
            actual_hash: "sha256:bbb".into(),
        };
        let s = e.to_string();
        assert!(s.contains("swc"));
        assert!(s.contains("sha256:aaa"));
        assert!(s.contains("sha256:bbb"));
    }

    #[test]
    fn error_display_fidelity_below_threshold() {
        let e = DualBackendParserError::FidelityBelowThreshold {
            backend_id: "oxc".into(),
            fidelity_millionths: 500_000,
            threshold_millionths: 990_000,
        };
        let s = e.to_string();
        assert!(s.contains("oxc"));
        assert!(s.contains("500000"));
        assert!(s.contains("990000"));
    }

    #[test]
    fn error_display_backend_unhealthy() {
        let e = DualBackendParserError::BackendUnhealthy("swc".into());
        assert!(e.to_string().contains("unhealthy"));
        assert!(e.to_string().contains("swc"));
    }

    #[test]
    fn error_display_invalid_config() {
        let e = DualBackendParserError::InvalidConfig("missing field".into());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let variants = vec![
            DualBackendParserError::NoBackendsRegistered,
            DualBackendParserError::BackendNotFound("swc".into()),
            DualBackendParserError::BackendUnhealthy("oxc".into()),
            DualBackendParserError::AllBackendsFailed(vec!["a".into(), "b".into()]),
            DualBackendParserError::NormalizationVerificationFailed {
                backend_id: "swc".into(),
                expected_hash: "h1".into(),
                actual_hash: "h2".into(),
            },
            DualBackendParserError::FidelityBelowThreshold {
                backend_id: "oxc".into(),
                fidelity_millionths: 500_000,
                threshold_millionths: 990_000,
            },
            DualBackendParserError::TooManyBackends { count: 9, max: 8 },
            DualBackendParserError::InvalidConfig("bad".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DualBackendParserError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn policy_differential_creation() {
        let policy = BackendSelectionPolicy::differential();
        assert_eq!(policy.policy_id, "differential-all");
        assert!(policy.differential_mode);
        assert!(policy.verify_normalization);
        assert_eq!(policy.min_fidelity_millionths, MILLION);
    }

    #[test]
    fn extension_override_unhealthy_falls_to_default() {
        let mut policy = BackendSelectionPolicy::default_swc_primary();
        policy
            .extension_overrides
            .insert("tsx".into(), BackendId::oxc());
        let backends = vec![
            make_registration(BackendId::swc(), 1, true),
            make_registration(BackendId::oxc(), 2, false), // unhealthy
        ];
        let selected = policy.select_backend(ParseGoal::Module, Some("tsx"), &backends);
        // OXC is unhealthy, should fall through to goal/default
        assert_eq!(selected, BackendId::swc());
    }

    #[test]
    fn goal_override_unhealthy_falls_to_default() {
        let mut policy = BackendSelectionPolicy::default_swc_primary();
        policy
            .goal_overrides
            .insert("module".into(), BackendId::oxc());
        let backends = vec![
            make_registration(BackendId::swc(), 1, true),
            make_registration(BackendId::oxc(), 2, false), // unhealthy
        ];
        let selected = policy.select_backend(ParseGoal::Module, None, &backends);
        assert_eq!(selected, BackendId::swc());
    }

    #[test]
    fn parser_selects_any_healthy_when_default_and_fallback_unhealthy() {
        let mut parser = DualBackendParser::new(
            "test",
            BackendSelectionPolicy::default_swc_primary(),
            epoch(1),
        );
        parser
            .register_backend(make_registration(BackendId::swc(), 1, false))
            .unwrap();
        parser
            .register_backend(make_registration(BackendId::franken_canonical(), 2, false))
            .unwrap();
        parser
            .register_backend(make_registration(BackendId::oxc(), 3, true))
            .unwrap();
        let selected = parser.select_backend(ParseGoal::Module, None).unwrap();
        assert_eq!(selected, BackendId::oxc());
    }

    #[test]
    fn span_mapping_serde_roundtrip() {
        let entry = SpanMappingEntry {
            node_index: 42,
            canonical_span: make_span(10, 20),
            backend_span: make_span(10, 21),
            deviation_bytes: 1,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: SpanMappingEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn diagnostic_severity_serde_roundtrip() {
        for sev in [
            DiagnosticSeverity::Hint,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn diagnostic_category_serde_roundtrip() {
        for cat in [
            DiagnosticCategory::Syntax,
            DiagnosticCategory::Semantic,
            DiagnosticCategory::Type,
            DiagnosticCategory::Resource,
            DiagnosticCategory::Encoding,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: DiagnosticCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn category_ordering() {
        assert!(DiagnosticCategory::Syntax < DiagnosticCategory::Semantic);
        assert!(DiagnosticCategory::Semantic < DiagnosticCategory::Type);
        assert!(DiagnosticCategory::Type < DiagnosticCategory::Resource);
        assert!(DiagnosticCategory::Resource < DiagnosticCategory::Encoding);
    }

    #[test]
    fn divergence_class_ordering() {
        assert!(DivergenceClass::AstDivergence < DivergenceClass::DiagnosticsDivergence);
        assert!(DivergenceClass::DiagnosticsDivergence < DivergenceClass::SpanDivergence);
        assert!(DivergenceClass::SpanDivergence < DivergenceClass::ErrorDivergence);
    }

    #[test]
    fn event_kind_all_variants_serde() {
        let kinds = vec![
            DualBackendEventKind::BackendSelected,
            DualBackendEventKind::ParseCompleted {
                latency_us: 100,
                hash: "h".into(),
            },
            DualBackendEventKind::ParseFailed {
                error: "err".into(),
            },
            DualBackendEventKind::FallbackSelected,
            DualBackendEventKind::NormalizationVerified,
            DualBackendEventKind::FidelityReported {
                score_millionths: 900_000,
            },
            DualBackendEventKind::DifferentialCompleted {
                all_equivalent: true,
            },
            DualBackendEventKind::BackendRegistered,
            DualBackendEventKind::HealthChanged { healthy: false },
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: DualBackendEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn fidelity_max_deviation_tracked() {
        let mappings = vec![
            SpanMappingEntry {
                node_index: 0,
                canonical_span: make_span(0, 5),
                backend_span: make_span(0, 7),
                deviation_bytes: 2,
            },
            SpanMappingEntry {
                node_index: 1,
                canonical_span: make_span(5, 10),
                backend_span: make_span(5, 15),
                deviation_bytes: 5,
            },
            SpanMappingEntry {
                node_index: 2,
                canonical_span: make_span(10, 15),
                backend_span: make_span(10, 18),
                deviation_bytes: 3,
            },
        ];
        let report = FidelityReport::from_mappings(BackendId::swc(), &mappings, 0);
        assert_eq!(report.max_deviation_bytes, 5);
        assert_eq!(report.exact_spans, 0);
        assert_eq!(report.total_spans, 3);
        assert_eq!(report.deviations.len(), 3);
    }

    #[test]
    fn parser_event_seq_increments() {
        let mut parser = make_parser();
        let initial_seq = parser.event_seq;
        parser.record_parse(&BackendId::swc(), "a.js", "h1", 100);
        parser.record_parse(&BackendId::swc(), "b.js", "h2", 200);
        assert_eq!(parser.event_seq, initial_seq + 2);
    }

    #[test]
    fn differential_result_with_divergence() {
        let result = DifferentialComparisonResult {
            source_label: "test.js".into(),
            goal: "module".into(),
            backend_results: vec![
                BackendParseResult {
                    backend_id: BackendId::swc(),
                    canonical_hash: Some("sha256:aaa".into()),
                    success: true,
                    error_code: None,
                    diagnostics_hash: "sha256:d1".into(),
                    latency_us: 1_000,
                    fidelity_score_millionths: MILLION,
                },
                BackendParseResult {
                    backend_id: BackendId::oxc(),
                    canonical_hash: Some("sha256:bbb".into()),
                    success: true,
                    error_code: None,
                    diagnostics_hash: "sha256:d2".into(),
                    latency_us: 800,
                    fidelity_score_millionths: 995_000,
                },
            ],
            all_equivalent: false,
            distinct_hashes: vec!["sha256:aaa".into(), "sha256:bbb".into()],
            divergence: Some(DivergenceClass::AstDivergence),
        };
        assert!(!result.all_equivalent);
        assert_eq!(result.distinct_hashes.len(), 2);
        assert_eq!(result.divergence, Some(DivergenceClass::AstDivergence));

        let json = serde_json::to_string(&result).unwrap();
        let back: DifferentialComparisonResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn normalized_diagnostic_with_span_and_context() {
        let mut ctx = BTreeMap::new();
        ctx.insert("expected".into(), "identifier".into());
        ctx.insert("found".into(), "number".into());
        let diag = NormalizedDiagnostic {
            code: "FE-PARSE-0042".into(),
            category: DiagnosticCategory::Syntax,
            severity: DiagnosticSeverity::Error,
            message_template: "Expected {expected}, found {found}".into(),
            span: Some(make_span(100, 105)),
            context: ctx,
        };
        assert_eq!(diag.context.len(), 2);
        assert!(diag.span.is_some());
        let json = serde_json::to_string(&diag).unwrap();
        let back: NormalizedDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, back);
    }

    #[test]
    fn schema_version_correct() {
        assert_eq!(
            DUAL_BACKEND_SCHEMA_VERSION,
            "franken-engine.dual-backend-parser.v1"
        );
    }

    #[test]
    fn parser_multiple_fallbacks_counted() {
        let mut parser = make_parser();
        parser.set_backend_health(&BackendId::swc(), false).unwrap();
        // Each select_backend when primary is unhealthy increments fallback_count
        parser.select_backend(ParseGoal::Module, None).unwrap();
        parser.select_backend(ParseGoal::Script, None).unwrap();
        assert_eq!(parser.fallback_count, 2);
    }
}
