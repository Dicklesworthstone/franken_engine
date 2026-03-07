//! Deterministic Replay, Failover, and Incident Artifact Pipeline (FRX-04.4)
//!
//! Captures minimal nondeterminism traces, replays compile/runtime decisions
//! bit-stably, provides deterministic failover to fallback paths, and generates
//! postmortem-ready incident artifact bundles.

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn replay_schema() -> SchemaId {
    SchemaId::from_definition(b"deterministic_replay-v1")
}

/// Fixed-point multiplier: 1_000_000 ≡ 1.0.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Nondeterminism trace
// ---------------------------------------------------------------------------

/// Source of nondeterminism that must be captured for replay.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NondeterminismSource {
    /// Random value used for lane selection.
    LaneSelectionRandom,
    /// Timer/clock reading.
    TimerRead,
    /// External API response.
    ExternalApiResponse,
    /// Thread scheduling decision.
    ThreadSchedule,
    /// Resource availability check.
    ResourceCheck,
    /// User interaction timing.
    UserInteractionTiming,
}

impl NondeterminismSource {
    pub const ALL: [NondeterminismSource; 6] = [
        NondeterminismSource::LaneSelectionRandom,
        NondeterminismSource::TimerRead,
        NondeterminismSource::ExternalApiResponse,
        NondeterminismSource::ThreadSchedule,
        NondeterminismSource::ResourceCheck,
        NondeterminismSource::UserInteractionTiming,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LaneSelectionRandom => "lane_selection_random",
            Self::TimerRead => "timer_read",
            Self::ExternalApiResponse => "external_api_response",
            Self::ThreadSchedule => "thread_schedule",
            Self::ResourceCheck => "resource_check",
            Self::UserInteractionTiming => "user_interaction_timing",
        }
    }
}

/// A single captured nondeterminism event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub sequence: u64,
    pub source: NondeterminismSource,
    /// The captured deterministic value (opaque bytes).
    pub value: Vec<u8>,
    /// Virtual timestamp (monotonic counter, not wall clock).
    pub virtual_ts: u64,
    /// Component that produced this event.
    pub component: String,
}

impl TraceEvent {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "trace-{}-{}-{}",
            self.sequence,
            self.source.as_str(),
            self.virtual_ts
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for trace event")
    }
}

/// Nondeterminism trace: a complete record of all nondeterministic decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NondeterminismTrace {
    pub session_id: String,
    pub events: Vec<TraceEvent>,
    pub next_sequence: u64,
    pub capture_started_vts: u64,
    pub capture_ended_vts: Option<u64>,
}

impl NondeterminismTrace {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            events: Vec::new(),
            next_sequence: 0,
            capture_started_vts: 0,
            capture_ended_vts: None,
        }
    }

    /// Record a nondeterminism event.
    pub fn capture(
        &mut self,
        source: NondeterminismSource,
        value: Vec<u8>,
        virtual_ts: u64,
        component: impl Into<String>,
    ) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.events.push(TraceEvent {
            sequence: seq,
            source,
            value,
            virtual_ts,
            component: component.into(),
        });
        seq
    }

    /// Finalise the trace.
    pub fn finalise(&mut self, end_vts: u64) {
        self.capture_ended_vts = Some(end_vts);
    }

    /// Total events captured.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Whether the trace is finalised.
    pub fn is_finalised(&self) -> bool {
        self.capture_ended_vts.is_some()
    }

    /// Validate that the trace is ready for deterministic replay.
    pub fn validate_for_replay(&self) -> Result<(), ReplayError> {
        if self.is_finalised() {
            Ok(())
        } else {
            Err(ReplayError::TraceNotFinalised)
        }
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("trace-{}-events-{}", self.session_id, self.events.len());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for trace")
    }
}

// ---------------------------------------------------------------------------
// Replay engine
// ---------------------------------------------------------------------------

/// Replay mode: how strictly to follow the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplayMode {
    /// Exact bit-stable replay: divergence is an error.
    Strict,
    /// Best-effort replay: log divergences but continue.
    BestEffort,
    /// Validation mode: compare live decisions against trace.
    Validate,
}

/// A divergence detected during replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDivergence {
    pub sequence: u64,
    pub source: NondeterminismSource,
    pub expected_value: Vec<u8>,
    pub actual_value: Vec<u8>,
    pub virtual_ts: u64,
    pub severity: DivergenceSeverity,
}

/// How severe a replay divergence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceSeverity {
    /// Benign: does not affect correctness (e.g. timing jitter).
    Benign,
    /// Warning: may affect behaviour but not safety.
    Warning,
    /// Critical: affects correctness or safety.
    Critical,
}

/// Replay engine state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEngine {
    pub mode: ReplayMode,
    pub trace: NondeterminismTrace,
    pub cursor: usize,
    pub divergences: Vec<ReplayDivergence>,
    pub replayed_events: u64,
    pub virtual_ts: u64,
}

/// Errors from replay operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayError {
    /// Trace exhausted: no more events to replay.
    TraceExhausted { cursor: usize, total: usize },
    /// Critical divergence in strict mode.
    CriticalDivergence {
        sequence: u64,
        source: NondeterminismSource,
    },
    /// Source mismatch: expected one source, got another.
    SourceMismatch {
        sequence: u64,
        expected: NondeterminismSource,
        actual: NondeterminismSource,
    },
    /// Trace not finalised.
    TraceNotFinalised,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TraceExhausted { cursor, total } => {
                write!(f, "trace exhausted at cursor {cursor} of {total}")
            }
            Self::CriticalDivergence { sequence, source } => {
                write!(
                    f,
                    "critical replay divergence at sequence {sequence} ({})",
                    source.as_str()
                )
            }
            Self::SourceMismatch {
                sequence,
                expected,
                actual,
            } => write!(
                f,
                "replay source mismatch at sequence {sequence}: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::TraceNotFinalised => f.write_str("trace is not finalised"),
        }
    }
}

impl ReplayEngine {
    /// Create a replay engine from a captured trace.
    pub fn new(trace: NondeterminismTrace, mode: ReplayMode) -> Self {
        Self {
            mode,
            trace,
            cursor: 0,
            divergences: Vec::new(),
            replayed_events: 0,
            virtual_ts: 0,
        }
    }

    /// Replay the next event, providing the live value for comparison.
    pub fn replay_next(
        &mut self,
        source: NondeterminismSource,
        live_value: &[u8],
    ) -> Result<Vec<u8>, ReplayError> {
        self.trace.validate_for_replay()?;

        if self.cursor >= self.trace.events.len() {
            return Err(ReplayError::TraceExhausted {
                cursor: self.cursor,
                total: self.trace.events.len(),
            });
        }

        let event = &self.trace.events[self.cursor];

        // Check source matches
        if event.source != source {
            return Err(ReplayError::SourceMismatch {
                sequence: event.sequence,
                expected: event.source.clone(),
                actual: source,
            });
        }

        // Compare values
        let traced_value = event.value.clone();
        if live_value != traced_value.as_slice() {
            let severity = classify_divergence(&source, &traced_value, live_value);
            let divergence = ReplayDivergence {
                sequence: event.sequence,
                source: source.clone(),
                expected_value: traced_value.clone(),
                actual_value: live_value.to_vec(),
                virtual_ts: event.virtual_ts,
                severity,
            };

            match self.mode {
                ReplayMode::Strict => {
                    if severity == DivergenceSeverity::Critical {
                        self.divergences.push(divergence);
                        return Err(ReplayError::CriticalDivergence {
                            sequence: event.sequence,
                            source,
                        });
                    }
                    self.divergences.push(divergence);
                }
                ReplayMode::BestEffort | ReplayMode::Validate => {
                    self.divergences.push(divergence);
                }
            }
        }

        self.virtual_ts = event.virtual_ts;
        self.cursor += 1;
        self.replayed_events += 1;

        // In replay mode, return the traced value (not live) for determinism
        match self.mode {
            ReplayMode::Strict | ReplayMode::BestEffort => Ok(traced_value),
            ReplayMode::Validate => Ok(live_value.to_vec()),
        }
    }

    /// Whether all trace events have been replayed.
    pub fn is_complete(&self) -> bool {
        self.trace.is_finalised() && self.cursor >= self.trace.events.len()
    }

    /// Remaining events to replay.
    pub fn remaining(&self) -> usize {
        self.trace.events.len().saturating_sub(self.cursor)
    }

    /// Total divergences detected.
    pub fn divergence_count(&self) -> usize {
        self.divergences.len()
    }

    /// Critical divergence count.
    pub fn critical_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| d.severity == DivergenceSeverity::Critical)
            .count()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("replay-{}-cursor-{}", self.trace.session_id, self.cursor);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for replay engine")
    }
}

/// Classify divergence severity based on source type and value difference.
fn classify_divergence(
    source: &NondeterminismSource,
    _expected: &[u8],
    _actual: &[u8],
) -> DivergenceSeverity {
    match source {
        NondeterminismSource::TimerRead | NondeterminismSource::UserInteractionTiming => {
            DivergenceSeverity::Benign
        }
        NondeterminismSource::ThreadSchedule => DivergenceSeverity::Warning,
        NondeterminismSource::LaneSelectionRandom
        | NondeterminismSource::ExternalApiResponse
        | NondeterminismSource::ResourceCheck => DivergenceSeverity::Critical,
    }
}

// ---------------------------------------------------------------------------
// Failover controller
// ---------------------------------------------------------------------------

/// Failover strategy when the primary execution path fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailoverStrategy {
    /// Switch to the baseline-safe lane immediately.
    ImmediateBaseline,
    /// Retry on the same lane once before failing over.
    RetryThenBaseline,
    /// Halt execution and report the failure.
    Halt,
}

/// Reason for failover.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FailoverReason {
    /// Lane exceeded its resource budget.
    BudgetExhausted {
        metric: String,
        value: u64,
        limit: u64,
    },
    /// Lane returned an error.
    LaneError { message: String },
    /// Lane entered safe mode.
    SafeModeTriggered,
    /// Timeout exceeded.
    Timeout { elapsed_us: u64, limit_us: u64 },
    /// Replay divergence during execution.
    ReplayDivergence { divergence_count: usize },
    /// Operator-initiated failover.
    Manual,
}

/// Record of a failover event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverRecord {
    pub sequence: u64,
    pub reason: FailoverReason,
    pub strategy: FailoverStrategy,
    pub from_component: String,
    pub to_component: String,
    pub virtual_ts: u64,
    pub success: bool,
}

impl FailoverRecord {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "failover-{}-{}-{}",
            self.sequence, self.from_component, self.virtual_ts
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for failover record")
    }
}

/// Failover controller: manages deterministic failover decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverController {
    pub default_strategy: FailoverStrategy,
    /// Per-component strategy overrides.
    pub strategy_overrides: BTreeMap<String, FailoverStrategy>,
    pub records: Vec<FailoverRecord>,
    pub next_sequence: u64,
    pub total_failovers: u64,
    pub successful_failovers: u64,
    /// Maximum failovers before halting.
    pub max_failovers: u64,
    pub halted: bool,
}

impl FailoverController {
    pub fn new(default_strategy: FailoverStrategy, max_failovers: u64) -> Self {
        Self {
            default_strategy,
            strategy_overrides: BTreeMap::new(),
            records: Vec::new(),
            next_sequence: 0,
            total_failovers: 0,
            successful_failovers: 0,
            max_failovers,
            halted: false,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(FailoverStrategy::RetryThenBaseline, 10)
    }

    /// Set a strategy override for a specific component.
    pub fn set_override(&mut self, component: impl Into<String>, strategy: FailoverStrategy) {
        self.strategy_overrides.insert(component.into(), strategy);
    }

    /// Get the failover strategy for a component.
    pub fn strategy_for(&self, component: &str) -> FailoverStrategy {
        self.strategy_overrides
            .get(component)
            .copied()
            .unwrap_or(self.default_strategy)
    }

    /// Record a failover event.
    pub fn record_failover(
        &mut self,
        reason: FailoverReason,
        from_component: impl Into<String>,
        to_component: impl Into<String>,
        virtual_ts: u64,
        success: bool,
    ) -> Result<FailoverRecord, FailoverError> {
        if self.halted {
            return Err(FailoverError::Halted);
        }
        if self.total_failovers >= self.max_failovers {
            self.halted = true;
            return Err(FailoverError::MaxFailoversExceeded {
                count: self.total_failovers,
                limit: self.max_failovers,
            });
        }

        let from = from_component.into();
        let strategy = self.strategy_for(&from);

        let record = FailoverRecord {
            sequence: self.next_sequence,
            reason,
            strategy,
            from_component: from,
            to_component: to_component.into(),
            virtual_ts,
            success,
        };

        self.next_sequence += 1;
        self.total_failovers += 1;
        if success {
            self.successful_failovers += 1;
        }
        self.records.push(record.clone());

        Ok(record)
    }

    /// Success rate in millionths.
    pub fn success_rate_millionths(&self) -> i64 {
        if self.total_failovers == 0 {
            return MILLION;
        }
        (self.successful_failovers as i64 * MILLION) / self.total_failovers as i64
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("failover-ctrl-seq-{}", self.next_sequence);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for failover controller")
    }
}

/// Errors from failover operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverError {
    /// Controller is halted due to too many failovers.
    Halted,
    /// Maximum failover count exceeded.
    MaxFailoversExceeded { count: u64, limit: u64 },
}

// ---------------------------------------------------------------------------
// Incident artifact bundle
// ---------------------------------------------------------------------------

/// Severity of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IncidentSeverity {
    /// Informational: no user impact.
    Info,
    /// Warning: degraded but functional.
    Warning,
    /// Error: user-visible impact.
    Error,
    /// Critical: requires immediate attention.
    Critical,
}

impl IncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// An artifact included in an incident bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentArtifact {
    pub name: String,
    pub kind: ArtifactKind,
    pub data: Vec<u8>,
    pub content_hash: String,
}

/// Kind of artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// Nondeterminism trace for replay.
    NondeterminismTrace,
    /// Decision log from the router.
    DecisionLog,
    /// Failover records.
    FailoverLog,
    /// Signal graph snapshot.
    SignalGraphSnapshot,
    /// DOM state snapshot.
    DomSnapshot,
    /// Performance metrics.
    PerformanceMetrics,
    /// Configuration at time of incident.
    Configuration,
    /// Replay divergence report.
    DivergenceReport,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NondeterminismTrace => "nondeterminism_trace",
            Self::DecisionLog => "decision_log",
            Self::FailoverLog => "failover_log",
            Self::SignalGraphSnapshot => "signal_graph_snapshot",
            Self::DomSnapshot => "dom_snapshot",
            Self::PerformanceMetrics => "performance_metrics",
            Self::Configuration => "configuration",
            Self::DivergenceReport => "divergence_report",
        }
    }
}

impl IncidentArtifact {
    pub fn new(name: impl Into<String>, kind: ArtifactKind, data: Vec<u8>) -> Self {
        let hash = compute_simple_hash(&data);
        Self {
            name: name.into(),
            kind,
            data,
            content_hash: hash,
        }
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("artifact-{}-{}", self.name, self.content_hash);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for artifact")
    }
}

/// Incident artifact bundle: everything needed for postmortem analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentBundle {
    pub incident_id: String,
    pub severity: IncidentSeverity,
    pub summary: String,
    pub trigger_component: String,
    pub virtual_ts: u64,
    pub artifacts: Vec<IncidentArtifact>,
    pub tags: Vec<String>,
    pub bundle_hash: String,
}

impl IncidentBundle {
    pub fn new(
        incident_id: impl Into<String>,
        severity: IncidentSeverity,
        summary: impl Into<String>,
        trigger_component: impl Into<String>,
        virtual_ts: u64,
    ) -> Self {
        Self {
            incident_id: incident_id.into(),
            severity,
            summary: summary.into(),
            trigger_component: trigger_component.into(),
            virtual_ts,
            artifacts: Vec::new(),
            tags: Vec::new(),
            bundle_hash: String::new(),
        }
    }

    /// Add an artifact to the bundle.
    pub fn add_artifact(&mut self, artifact: IncidentArtifact) {
        self.artifacts.push(artifact);
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    /// Finalise the bundle by computing its hash.
    pub fn finalise(&mut self) {
        let mut content = Vec::new();
        content.extend_from_slice(self.incident_id.as_bytes());
        content.extend_from_slice(self.severity.as_str().as_bytes());
        for artifact in &self.artifacts {
            content.extend_from_slice(artifact.content_hash.as_bytes());
        }
        self.bundle_hash = compute_simple_hash(&content);
    }

    /// Whether the bundle has been finalised.
    pub fn is_finalised(&self) -> bool {
        !self.bundle_hash.is_empty()
    }

    /// Artifact count.
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Total data size across all artifacts.
    pub fn total_data_size(&self) -> usize {
        self.artifacts.iter().map(|a| a.data.len()).sum()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("bundle-{}-{}", self.incident_id, self.severity.as_str());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for bundle")
    }
}

// ---------------------------------------------------------------------------
// Incident bundle builder (convenience)
// ---------------------------------------------------------------------------

/// Builder for constructing incident bundles from replay/failover state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentBundleBuilder {
    incident_id: String,
    severity: IncidentSeverity,
    summary: String,
    trigger_component: String,
    virtual_ts: u64,
    include_trace: bool,
    include_decisions: bool,
    include_failovers: bool,
    include_divergences: bool,
}

impl IncidentBundleBuilder {
    pub fn new(
        incident_id: impl Into<String>,
        severity: IncidentSeverity,
        summary: impl Into<String>,
        trigger_component: impl Into<String>,
        virtual_ts: u64,
    ) -> Self {
        Self {
            incident_id: incident_id.into(),
            severity,
            summary: summary.into(),
            trigger_component: trigger_component.into(),
            virtual_ts,
            include_trace: true,
            include_decisions: true,
            include_failovers: true,
            include_divergences: true,
        }
    }

    pub fn with_trace(mut self, include: bool) -> Self {
        self.include_trace = include;
        self
    }

    pub fn with_decisions(mut self, include: bool) -> Self {
        self.include_decisions = include;
        self
    }

    pub fn with_failovers(mut self, include: bool) -> Self {
        self.include_failovers = include;
        self
    }

    pub fn with_divergences(mut self, include: bool) -> Self {
        self.include_divergences = include;
        self
    }

    /// Build the bundle from replay engine and failover controller state.
    pub fn build(
        &self,
        trace: Option<&NondeterminismTrace>,
        replay: Option<&ReplayEngine>,
        failover: Option<&FailoverController>,
    ) -> IncidentBundle {
        let mut bundle = IncidentBundle::new(
            &self.incident_id,
            self.severity,
            &self.summary,
            &self.trigger_component,
            self.virtual_ts,
        );

        if self.include_trace
            && let Some(t) = trace
        {
            let data = serde_json::to_vec(t).unwrap_or_default();
            bundle.add_artifact(IncidentArtifact::new(
                "nondeterminism_trace",
                ArtifactKind::NondeterminismTrace,
                data,
            ));
        }

        if self.include_failovers
            && let Some(fc) = failover
        {
            let data = serde_json::to_vec(&fc.records).unwrap_or_default();
            bundle.add_artifact(IncidentArtifact::new(
                "failover_log",
                ArtifactKind::FailoverLog,
                data,
            ));
        }

        if self.include_divergences
            && let Some(re) = replay
            && !re.divergences.is_empty()
        {
            let data = serde_json::to_vec(&re.divergences).unwrap_or_default();
            bundle.add_artifact(IncidentArtifact::new(
                "divergence_report",
                ArtifactKind::DivergenceReport,
                data,
            ));
        }

        bundle.add_tag("auto-generated");
        bundle.add_tag(self.severity.as_str());
        bundle.finalise();
        bundle
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Simple deterministic hash (FNV-1a) for content hashing.
fn compute_simple_hash(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- NondeterminismSource --

    #[test]
    fn source_as_str_all_variants() {
        for source in &NondeterminismSource::ALL {
            let s = source.as_str();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn source_serde_roundtrip() {
        for source in &NondeterminismSource::ALL {
            let json = serde_json::to_string(source).unwrap();
            let back: NondeterminismSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*source, back);
        }
    }

    // -- NondeterminismTrace --

    #[test]
    fn trace_new_empty() {
        let trace = NondeterminismTrace::new("session-1");
        assert_eq!(trace.event_count(), 0);
        assert!(!trace.is_finalised());
    }

    #[test]
    fn trace_capture_events() {
        let mut trace = NondeterminismTrace::new("session-1");
        let seq0 = trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        let seq1 = trace.capture(
            NondeterminismSource::TimerRead,
            vec![0, 0, 0, 1],
            200,
            "scheduler",
        );
        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(trace.event_count(), 2);
    }

    #[test]
    fn trace_finalise() {
        let mut trace = NondeterminismTrace::new("session-1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
        trace.finalise(200);
        assert!(trace.is_finalised());
        assert_eq!(trace.capture_ended_vts, Some(200));
    }

    #[test]
    fn trace_derive_id_stable() {
        let t1 = NondeterminismTrace::new("s1");
        let t2 = NondeterminismTrace::new("s1");
        assert_eq!(t1.derive_id(), t2.derive_id());
    }

    #[test]
    fn trace_serde_roundtrip() {
        let mut trace = NondeterminismTrace::new("session-1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        let json = serde_json::to_string(&trace).unwrap();
        let back: NondeterminismTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }

    // -- TraceEvent --

    #[test]
    fn trace_event_derive_id() {
        let event = TraceEvent {
            sequence: 0,
            source: NondeterminismSource::TimerRead,
            value: vec![1, 2, 3],
            virtual_ts: 100,
            component: "clock".to_string(),
        };
        let id1 = event.derive_id();
        let id2 = event.derive_id();
        assert_eq!(id1, id2);
    }

    // -- ReplayEngine --

    #[test]
    fn replay_empty_trace_exhausted() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.finalise(0);
        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::TimerRead, &[1]);
        assert!(matches!(result, Err(ReplayError::TraceExhausted { .. })));
    }

    #[test]
    fn replay_unfinalised_trace_rejected() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::TimerRead, &[1]);
        assert!(matches!(result, Err(ReplayError::TraceNotFinalised)));
        assert!(!engine.is_complete());
    }

    #[test]
    fn replay_exact_match() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
            .unwrap();
        assert_eq!(result, vec![42]);
        assert!(engine.is_complete());
        assert_eq!(engine.divergence_count(), 0);
    }

    #[test]
    fn replay_source_mismatch() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::TimerRead, &[42]);
        assert!(matches!(result, Err(ReplayError::SourceMismatch { .. })));
    }

    #[test]
    fn replay_strict_critical_divergence() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::LaneSelectionRandom, &[99]);
        assert!(matches!(
            result,
            Err(ReplayError::CriticalDivergence { .. })
        ));
        assert_eq!(engine.critical_divergences(), 1);
    }

    #[test]
    fn replay_strict_benign_divergence_continues() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        // Timer divergence is benign
        let result = engine
            .replay_next(NondeterminismSource::TimerRead, &[2])
            .unwrap();
        // Returns traced value in strict mode
        assert_eq!(result, vec![1]);
        assert_eq!(engine.divergence_count(), 1);
        assert_eq!(engine.critical_divergences(), 0);
    }

    #[test]
    fn replay_best_effort_logs_divergences() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);
        let result = engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
            .unwrap();
        // Returns traced value in best-effort mode
        assert_eq!(result, vec![42]);
        assert_eq!(engine.divergence_count(), 1);
    }

    #[test]
    fn replay_validate_uses_live_value() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Validate);
        let result = engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
            .unwrap();
        // Validate mode returns live value
        assert_eq!(result, vec![99]);
        assert_eq!(engine.divergence_count(), 1);
    }

    #[test]
    fn replay_multi_event_sequence() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![10],
            100,
            "router",
        );
        trace.capture(NondeterminismSource::TimerRead, vec![20], 200, "clock");
        trace.capture(NondeterminismSource::ResourceCheck, vec![30], 300, "budget");
        trace.finalise(400);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        assert_eq!(engine.remaining(), 3);

        engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[10])
            .unwrap();
        assert_eq!(engine.remaining(), 2);

        engine
            .replay_next(NondeterminismSource::TimerRead, &[20])
            .unwrap();
        engine
            .replay_next(NondeterminismSource::ResourceCheck, &[30])
            .unwrap();

        assert!(engine.is_complete());
        assert_eq!(engine.replayed_events, 3);
    }

    #[test]
    fn replay_derive_id_stable() {
        let trace = NondeterminismTrace::new("s1");
        let e1 = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
        let e2 = ReplayEngine::new(trace, ReplayMode::Strict);
        assert_eq!(e1.derive_id(), e2.derive_id());
    }

    // -- FailoverController --

    #[test]
    fn failover_new() {
        let fc = FailoverController::with_defaults();
        assert_eq!(fc.total_failovers, 0);
        assert!(!fc.halted);
        assert_eq!(fc.default_strategy, FailoverStrategy::RetryThenBaseline);
    }

    #[test]
    fn failover_record() {
        let mut fc = FailoverController::with_defaults();
        let record = fc
            .record_failover(
                FailoverReason::SafeModeTriggered,
                "wasm-lane",
                "js-lane",
                100,
                true,
            )
            .unwrap();
        assert_eq!(record.sequence, 0);
        assert!(record.success);
        assert_eq!(fc.total_failovers, 1);
        assert_eq!(fc.successful_failovers, 1);
    }

    #[test]
    fn failover_strategy_override() {
        let mut fc = FailoverController::with_defaults();
        fc.set_override("critical-path", FailoverStrategy::Halt);
        assert_eq!(fc.strategy_for("critical-path"), FailoverStrategy::Halt);
        assert_eq!(
            fc.strategy_for("other"),
            FailoverStrategy::RetryThenBaseline
        );
    }

    #[test]
    fn failover_max_exceeded() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 2);
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        fc.record_failover(FailoverReason::Manual, "a", "b", 200, true)
            .unwrap();
        let err = fc
            .record_failover(FailoverReason::Manual, "a", "b", 300, true)
            .unwrap_err();
        assert!(matches!(err, FailoverError::MaxFailoversExceeded { .. }));
        assert!(fc.halted);
    }

    #[test]
    fn failover_halted_rejects() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 1);
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        // Exceed max
        let _ = fc.record_failover(FailoverReason::Manual, "a", "b", 200, true);
        // Now halted
        let err = fc
            .record_failover(FailoverReason::Manual, "a", "b", 300, true)
            .unwrap_err();
        assert_eq!(err, FailoverError::Halted);
    }

    #[test]
    fn failover_success_rate() {
        let mut fc = FailoverController::with_defaults();
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        fc.record_failover(FailoverReason::Manual, "a", "b", 200, false)
            .unwrap();
        assert_eq!(fc.success_rate_millionths(), 500_000); // 50%
    }

    #[test]
    fn failover_success_rate_no_failovers() {
        let fc = FailoverController::with_defaults();
        assert_eq!(fc.success_rate_millionths(), MILLION); // 100%
    }

    #[test]
    fn failover_derive_id_stable() {
        let f1 = FailoverController::with_defaults();
        let f2 = FailoverController::with_defaults();
        assert_eq!(f1.derive_id(), f2.derive_id());
    }

    #[test]
    fn failover_record_derive_id() {
        let record = FailoverRecord {
            sequence: 0,
            reason: FailoverReason::SafeModeTriggered,
            strategy: FailoverStrategy::ImmediateBaseline,
            from_component: "wasm".to_string(),
            to_component: "js".to_string(),
            virtual_ts: 100,
            success: true,
        };
        let id1 = record.derive_id();
        let id2 = record.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn failover_serde_roundtrip() {
        let mut fc = FailoverController::with_defaults();
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        let json = serde_json::to_string(&fc).unwrap();
        let back: FailoverController = serde_json::from_str(&json).unwrap();
        assert_eq!(fc, back);
    }

    // -- FailoverReason --

    #[test]
    fn failover_reason_variants_serde() {
        let reasons = vec![
            FailoverReason::BudgetExhausted {
                metric: "signals".to_string(),
                value: 100,
                limit: 50,
            },
            FailoverReason::LaneError {
                message: "boom".to_string(),
            },
            FailoverReason::SafeModeTriggered,
            FailoverReason::Timeout {
                elapsed_us: 20_000,
                limit_us: 16_000,
            },
            FailoverReason::ReplayDivergence {
                divergence_count: 3,
            },
            FailoverReason::Manual,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: FailoverReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    // -- IncidentBundle --

    #[test]
    fn incident_severity_as_str() {
        assert_eq!(IncidentSeverity::Info.as_str(), "info");
        assert_eq!(IncidentSeverity::Warning.as_str(), "warning");
        assert_eq!(IncidentSeverity::Error.as_str(), "error");
        assert_eq!(IncidentSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn incident_artifact_new() {
        let artifact =
            IncidentArtifact::new("test", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
        assert!(!artifact.content_hash.is_empty());
        assert_eq!(artifact.data, vec![1, 2, 3]);
    }

    #[test]
    fn incident_artifact_derive_id() {
        let artifact =
            IncidentArtifact::new("test", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
        let id1 = artifact.derive_id();
        let id2 = artifact.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn incident_bundle_new() {
        let bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Error,
            "Test incident",
            "router",
            1000,
        );
        assert_eq!(bundle.artifact_count(), 0);
        assert!(!bundle.is_finalised());
    }

    #[test]
    fn incident_bundle_add_artifacts() {
        let mut bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Error,
            "Test incident",
            "router",
            1000,
        );
        bundle.add_artifact(IncidentArtifact::new(
            "trace",
            ArtifactKind::NondeterminismTrace,
            vec![1, 2, 3],
        ));
        bundle.add_artifact(IncidentArtifact::new(
            "config",
            ArtifactKind::Configuration,
            vec![4, 5, 6],
        ));
        assert_eq!(bundle.artifact_count(), 2);
        assert_eq!(bundle.total_data_size(), 6);
    }

    #[test]
    fn incident_bundle_tags_dedup() {
        let mut bundle =
            IncidentBundle::new("INC-001", IncidentSeverity::Info, "Test", "comp", 100);
        bundle.add_tag("replay");
        bundle.add_tag("replay");
        bundle.add_tag("critical");
        assert_eq!(bundle.tags.len(), 2);
    }

    #[test]
    fn incident_bundle_finalise() {
        let mut bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Critical,
            "Major issue",
            "router",
            1000,
        );
        bundle.add_artifact(IncidentArtifact::new(
            "trace",
            ArtifactKind::NondeterminismTrace,
            vec![1, 2, 3],
        ));
        bundle.finalise();
        assert!(bundle.is_finalised());
        assert!(!bundle.bundle_hash.is_empty());
    }

    #[test]
    fn incident_bundle_derive_id() {
        let bundle = IncidentBundle::new("INC-001", IncidentSeverity::Error, "Test", "comp", 100);
        let id1 = bundle.derive_id();
        let id2 = bundle.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn incident_bundle_serde_roundtrip() {
        let mut bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Warning,
            "Test incident",
            "router",
            1000,
        );
        bundle.add_artifact(IncidentArtifact::new(
            "trace",
            ArtifactKind::NondeterminismTrace,
            vec![1, 2, 3],
        ));
        bundle.finalise();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: IncidentBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    // -- IncidentBundleBuilder --

    #[test]
    fn builder_constructs_bundle() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let builder = IncidentBundleBuilder::new(
            "INC-001",
            IncidentSeverity::Error,
            "Test incident",
            "router",
            1000,
        );
        let bundle = builder.build(Some(&trace), None, None);
        assert!(bundle.is_finalised());
        assert_eq!(bundle.artifact_count(), 1); // trace only
        assert!(bundle.tags.contains(&"auto-generated".to_string()));
    }

    #[test]
    fn builder_with_all_sources() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
        trace.finalise(200);

        let mut replay = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
        let _ = replay.replay_next(NondeterminismSource::TimerRead, &[2]);

        let mut failover = FailoverController::with_defaults();
        failover
            .record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();

        let builder = IncidentBundleBuilder::new(
            "INC-002",
            IncidentSeverity::Critical,
            "Full incident",
            "router",
            2000,
        );
        let bundle = builder.build(Some(&trace), Some(&replay), Some(&failover));
        assert!(bundle.is_finalised());
        // trace + failover_log + divergence_report = 3
        assert_eq!(bundle.artifact_count(), 3);
    }

    #[test]
    fn builder_exclude_options() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let builder =
            IncidentBundleBuilder::new("INC-003", IncidentSeverity::Info, "Minimal", "comp", 100)
                .with_trace(false)
                .with_decisions(false)
                .with_failovers(false)
                .with_divergences(false);

        let bundle = builder.build(Some(&trace), None, None);
        assert_eq!(bundle.artifact_count(), 0); // everything excluded
    }

    // -- compute_simple_hash --

    #[test]
    fn hash_deterministic() {
        let h1 = compute_simple_hash(b"hello world");
        let h2 = compute_simple_hash(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_differs_for_different_input() {
        let h1 = compute_simple_hash(b"hello");
        let h2 = compute_simple_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_format() {
        let h = compute_simple_hash(b"test");
        assert_eq!(h.len(), 16); // 16 hex chars for u64
    }

    // -- classify_divergence --

    #[test]
    fn classify_timer_is_benign() {
        let s = classify_divergence(&NondeterminismSource::TimerRead, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Benign);
    }

    #[test]
    fn classify_thread_is_warning() {
        let s = classify_divergence(&NondeterminismSource::ThreadSchedule, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Warning);
    }

    #[test]
    fn classify_lane_random_is_critical() {
        let s = classify_divergence(&NondeterminismSource::LaneSelectionRandom, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Critical);
    }

    // -- ArtifactKind --

    #[test]
    fn artifact_kind_as_str() {
        let kinds = [
            ArtifactKind::NondeterminismTrace,
            ArtifactKind::DecisionLog,
            ArtifactKind::FailoverLog,
            ArtifactKind::SignalGraphSnapshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::PerformanceMetrics,
            ArtifactKind::Configuration,
            ArtifactKind::DivergenceReport,
        ];
        for k in &kinds {
            assert!(!k.as_str().is_empty());
        }
    }

    #[test]
    fn artifact_kind_serde() {
        let kind = ArtifactKind::DivergenceReport;
        let json = serde_json::to_string(&kind).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }

    // -- E2E: Full capture-replay-failover-incident pipeline --

    #[test]
    fn e2e_capture_replay_incident() {
        // 1. Capture trace
        let mut trace = NondeterminismTrace::new("session-e2e");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.capture(
            NondeterminismSource::TimerRead,
            vec![0, 0, 3, 232],
            200,
            "clock",
        );
        trace.capture(NondeterminismSource::ResourceCheck, vec![1], 300, "budget");
        trace.finalise(400);

        // 2. Replay with some divergence
        let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
        engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
            .unwrap();
        engine
            .replay_next(NondeterminismSource::TimerRead, &[0, 0, 4, 0]) // timer divergence
            .unwrap();
        engine
            .replay_next(NondeterminismSource::ResourceCheck, &[1])
            .unwrap();
        assert!(engine.is_complete());
        assert_eq!(engine.divergence_count(), 1);
        assert_eq!(engine.critical_divergences(), 0); // timer is benign

        // 3. Record a failover
        let mut failover = FailoverController::with_defaults();
        failover
            .record_failover(
                FailoverReason::SafeModeTriggered,
                "wasm-lane",
                "js-lane",
                500,
                true,
            )
            .unwrap();

        // 4. Build incident bundle
        let builder = IncidentBundleBuilder::new(
            "INC-E2E-001",
            IncidentSeverity::Warning,
            "WASM lane degraded, failover to JS",
            "wasm-lane",
            500,
        );
        let bundle = builder.build(Some(&trace), Some(&engine), Some(&failover));

        assert!(bundle.is_finalised());
        assert_eq!(bundle.severity, IncidentSeverity::Warning);
        assert_eq!(bundle.artifact_count(), 3); // trace + failover + divergence
        assert!(bundle.tags.contains(&"auto-generated".to_string()));
        assert!(bundle.tags.contains(&"warning".to_string()));
        assert!(!bundle.bundle_hash.is_empty());
    }

    #[test]
    fn e2e_strict_replay_halts_on_critical() {
        let mut trace = NondeterminismTrace::new("session-strict");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.capture(
            NondeterminismSource::ExternalApiResponse,
            vec![1, 2, 3],
            200,
            "api",
        );
        trace.finalise(300);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
            .unwrap();

        // Critical divergence on external API response
        let result = engine.replay_next(NondeterminismSource::ExternalApiResponse, &[4, 5, 6]);
        assert!(matches!(
            result,
            Err(ReplayError::CriticalDivergence { .. })
        ));
    }

    // -- DivergenceSeverity --

    #[test]
    fn divergence_severity_ordering() {
        assert!(DivergenceSeverity::Benign < DivergenceSeverity::Warning);
        assert!(DivergenceSeverity::Warning < DivergenceSeverity::Critical);
    }

    #[test]
    fn divergence_severity_serde() {
        for s in [
            DivergenceSeverity::Benign,
            DivergenceSeverity::Warning,
            DivergenceSeverity::Critical,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: DivergenceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn nondeterminism_source_as_str_all_unique() {
        let strs: std::collections::BTreeSet<&str> = NondeterminismSource::ALL
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(strs.len(), 6);
    }

    #[test]
    fn incident_severity_as_str_all_unique() {
        let strs: std::collections::BTreeSet<&str> = [
            IncidentSeverity::Info,
            IncidentSeverity::Warning,
            IncidentSeverity::Error,
            IncidentSeverity::Critical,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        assert_eq!(strs.len(), 4);
    }

    // ── Enrichment: replay error serde ──────────────────────────

    #[test]
    fn replay_error_serde_all_variants() {
        let errors = vec![
            ReplayError::TraceExhausted {
                cursor: 3,
                total: 10,
            },
            ReplayError::SourceMismatch {
                expected: NondeterminismSource::TimerRead,
                actual: NondeterminismSource::LaneSelectionRandom,
                sequence: 0,
            },
            ReplayError::CriticalDivergence {
                source: NondeterminismSource::ExternalApiResponse,
                sequence: 1,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ReplayError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // ── Enrichment: ReplayMode serde ────────────────────────────

    #[test]
    fn replay_mode_serde_roundtrip() {
        for mode in [
            ReplayMode::Strict,
            ReplayMode::BestEffort,
            ReplayMode::Validate,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: ReplayMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // ── Enrichment: FailoverError serde ─────────────────────────

    #[test]
    fn failover_error_serde_roundtrip() {
        let errors = vec![
            FailoverError::MaxFailoversExceeded {
                count: 11,
                limit: 10,
            },
            FailoverError::Halted,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: FailoverError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // ── Enrichment: FailoverStrategy serde ──────────────────────

    #[test]
    fn failover_strategy_serde_all_variants() {
        for strategy in [
            FailoverStrategy::RetryThenBaseline,
            FailoverStrategy::ImmediateBaseline,
            FailoverStrategy::Halt,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let back: FailoverStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, back);
        }
    }

    // ── Enrichment: IncidentBundle empty finalise ────────────────

    #[test]
    fn incident_bundle_finalise_empty_produces_hash() {
        let mut bundle =
            IncidentBundle::new("INC-EMPTY", IncidentSeverity::Info, "Empty", "comp", 0);
        bundle.finalise();
        assert!(bundle.is_finalised());
        assert!(!bundle.bundle_hash.is_empty());
    }

    // ── Enrichment: classify_divergence all sources ─────────────

    #[test]
    fn classify_divergence_user_interaction_is_benign() {
        let s = classify_divergence(&NondeterminismSource::UserInteractionTiming, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Benign);
    }

    #[test]
    fn classify_divergence_resource_check_is_critical() {
        let s = classify_divergence(&NondeterminismSource::ResourceCheck, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Critical);
    }

    // ── JSON field-name stability ──────────────────────────────

    #[test]
    fn json_field_names_trace_event() {
        let ev = TraceEvent {
            sequence: 7,
            source: NondeterminismSource::TimerRead,
            value: vec![0xAB],
            virtual_ts: 999,
            component: "clk".to_string(),
        };
        let json = serde_json::to_value(&ev).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("sequence"));
        assert!(obj.contains_key("source"));
        assert!(obj.contains_key("value"));
        assert!(obj.contains_key("virtual_ts"));
        assert!(obj.contains_key("component"));
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn json_field_names_nondeterminism_trace() {
        let t = NondeterminismTrace::new("sess");
        let json = serde_json::to_value(&t).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("session_id"));
        assert!(obj.contains_key("events"));
        assert!(obj.contains_key("next_sequence"));
        assert!(obj.contains_key("capture_started_vts"));
        assert!(obj.contains_key("capture_ended_vts"));
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn json_field_names_replay_divergence() {
        let d = ReplayDivergence {
            sequence: 0,
            source: NondeterminismSource::TimerRead,
            expected_value: vec![1],
            actual_value: vec![2],
            virtual_ts: 50,
            severity: DivergenceSeverity::Benign,
        };
        let json = serde_json::to_value(&d).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("sequence"));
        assert!(obj.contains_key("source"));
        assert!(obj.contains_key("expected_value"));
        assert!(obj.contains_key("actual_value"));
        assert!(obj.contains_key("virtual_ts"));
        assert!(obj.contains_key("severity"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn json_field_names_replay_engine() {
        let trace = NondeterminismTrace::new("s");
        let eng = ReplayEngine::new(trace, ReplayMode::Strict);
        let json = serde_json::to_value(&eng).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("mode"));
        assert!(obj.contains_key("trace"));
        assert!(obj.contains_key("cursor"));
        assert!(obj.contains_key("divergences"));
        assert!(obj.contains_key("replayed_events"));
        assert!(obj.contains_key("virtual_ts"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn json_field_names_failover_record() {
        let rec = FailoverRecord {
            sequence: 0,
            reason: FailoverReason::Manual,
            strategy: FailoverStrategy::Halt,
            from_component: "a".into(),
            to_component: "b".into(),
            virtual_ts: 10,
            success: false,
        };
        let json = serde_json::to_value(&rec).unwrap();
        let obj = json.as_object().unwrap();
        for key in &[
            "sequence",
            "reason",
            "strategy",
            "from_component",
            "to_component",
            "virtual_ts",
            "success",
        ] {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
        assert_eq!(obj.len(), 7);
    }

    #[test]
    fn json_field_names_failover_controller() {
        let fc = FailoverController::with_defaults();
        let json = serde_json::to_value(&fc).unwrap();
        let obj = json.as_object().unwrap();
        for key in &[
            "default_strategy",
            "strategy_overrides",
            "records",
            "next_sequence",
            "total_failovers",
            "successful_failovers",
            "max_failovers",
            "halted",
        ] {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
        assert_eq!(obj.len(), 8);
    }

    #[test]
    fn json_field_names_incident_artifact() {
        let art = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![9]);
        let json = serde_json::to_value(&art).unwrap();
        let obj = json.as_object().unwrap();
        for key in &["name", "kind", "data", "content_hash"] {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn json_field_names_incident_bundle() {
        let b = IncidentBundle::new("id", IncidentSeverity::Info, "s", "c", 0);
        let json = serde_json::to_value(&b).unwrap();
        let obj = json.as_object().unwrap();
        for key in &[
            "incident_id",
            "severity",
            "summary",
            "trigger_component",
            "virtual_ts",
            "artifacts",
            "tags",
            "bundle_hash",
        ] {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
        assert_eq!(obj.len(), 8);
    }

    #[test]
    fn json_field_names_incident_bundle_builder() {
        let bb = IncidentBundleBuilder::new("id", IncidentSeverity::Info, "s", "c", 0);
        let json = serde_json::to_value(&bb).unwrap();
        let obj = json.as_object().unwrap();
        for key in &[
            "incident_id",
            "severity",
            "summary",
            "trigger_component",
            "virtual_ts",
            "include_trace",
            "include_decisions",
            "include_failovers",
            "include_divergences",
        ] {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
        assert_eq!(obj.len(), 9);
    }

    // ── Debug distinctness ──────────────────────────────────────

    #[test]
    fn debug_nondeterminism_source_all_distinct() {
        let dbgs: std::collections::BTreeSet<String> = NondeterminismSource::ALL
            .iter()
            .map(|s| format!("{s:?}"))
            .collect();
        assert_eq!(dbgs.len(), 6);
    }

    #[test]
    fn debug_replay_mode_all_distinct() {
        let dbgs: std::collections::BTreeSet<String> = [
            ReplayMode::Strict,
            ReplayMode::BestEffort,
            ReplayMode::Validate,
        ]
        .iter()
        .map(|m| format!("{m:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn debug_divergence_severity_all_distinct() {
        let dbgs: std::collections::BTreeSet<String> = [
            DivergenceSeverity::Benign,
            DivergenceSeverity::Warning,
            DivergenceSeverity::Critical,
        ]
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn debug_failover_strategy_all_distinct() {
        let dbgs: std::collections::BTreeSet<String> = [
            FailoverStrategy::ImmediateBaseline,
            FailoverStrategy::RetryThenBaseline,
            FailoverStrategy::Halt,
        ]
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn debug_incident_severity_all_distinct() {
        let dbgs: std::collections::BTreeSet<String> = [
            IncidentSeverity::Info,
            IncidentSeverity::Warning,
            IncidentSeverity::Error,
            IncidentSeverity::Critical,
        ]
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
        assert_eq!(dbgs.len(), 4);
    }

    #[test]
    fn debug_artifact_kind_all_distinct() {
        let dbgs: std::collections::BTreeSet<String> = [
            ArtifactKind::NondeterminismTrace,
            ArtifactKind::DecisionLog,
            ArtifactKind::FailoverLog,
            ArtifactKind::SignalGraphSnapshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::PerformanceMetrics,
            ArtifactKind::Configuration,
            ArtifactKind::DivergenceReport,
        ]
        .iter()
        .map(|k| format!("{k:?}"))
        .collect();
        assert_eq!(dbgs.len(), 8);
    }

    // ── Clone independence ──────────────────────────────────────

    #[test]
    fn clone_nondeterminism_trace_independent() {
        let mut orig = NondeterminismTrace::new("sess-clone");
        orig.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
        let mut cloned = orig.clone();
        cloned.capture(NondeterminismSource::ResourceCheck, vec![2], 20, "d");
        assert_eq!(orig.event_count(), 1);
        assert_eq!(cloned.event_count(), 2);
    }

    #[test]
    fn clone_replay_engine_independent() {
        let mut trace = NondeterminismTrace::new("s");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
        trace.capture(NondeterminismSource::TimerRead, vec![2], 20, "c");
        trace.finalise(30);
        let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
        let cloned = eng.clone();
        eng.replay_next(NondeterminismSource::TimerRead, &[1])
            .unwrap();
        assert_eq!(eng.cursor, 1);
        assert_eq!(cloned.cursor, 0);
    }

    #[test]
    fn clone_failover_controller_independent() {
        let mut fc = FailoverController::with_defaults();
        fc.record_failover(FailoverReason::Manual, "a", "b", 10, true)
            .unwrap();
        let cloned = fc.clone();
        fc.record_failover(FailoverReason::Manual, "a", "b", 20, false)
            .unwrap();
        assert_eq!(fc.total_failovers, 2);
        assert_eq!(cloned.total_failovers, 1);
    }

    #[test]
    fn clone_incident_bundle_independent() {
        let mut b = IncidentBundle::new("INC-CL", IncidentSeverity::Info, "s", "c", 0);
        b.add_artifact(IncidentArtifact::new(
            "a1",
            ArtifactKind::DecisionLog,
            vec![1],
        ));
        let mut cloned = b.clone();
        cloned.add_artifact(IncidentArtifact::new(
            "a2",
            ArtifactKind::Configuration,
            vec![2],
        ));
        assert_eq!(b.artifact_count(), 1);
        assert_eq!(cloned.artifact_count(), 2);
    }

    // ── Copy semantics ─────────────────────────────────────────

    #[test]
    fn copy_replay_mode() {
        let m = ReplayMode::Validate;
        let m2 = m;
        assert_eq!(m, m2);
    }

    #[test]
    fn copy_divergence_severity() {
        let s = DivergenceSeverity::Warning;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn copy_failover_strategy() {
        let s = FailoverStrategy::Halt;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn copy_incident_severity() {
        let s = IncidentSeverity::Critical;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn copy_artifact_kind() {
        let k = ArtifactKind::DomSnapshot;
        let k2 = k;
        assert_eq!(k, k2);
    }

    // ── Serde variant distinctness ─────────────────────────────

    #[test]
    fn serde_nondeterminism_source_variant_strings_distinct() {
        let jsons: std::collections::BTreeSet<String> = NondeterminismSource::ALL
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect();
        assert_eq!(jsons.len(), 6);
    }

    #[test]
    fn serde_replay_mode_variant_strings_distinct() {
        let jsons: std::collections::BTreeSet<String> = [
            ReplayMode::Strict,
            ReplayMode::BestEffort,
            ReplayMode::Validate,
        ]
        .iter()
        .map(|m| serde_json::to_string(m).unwrap())
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn serde_divergence_severity_variant_strings_distinct() {
        let jsons: std::collections::BTreeSet<String> = [
            DivergenceSeverity::Benign,
            DivergenceSeverity::Warning,
            DivergenceSeverity::Critical,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn serde_failover_strategy_variant_strings_distinct() {
        let jsons: std::collections::BTreeSet<String> = [
            FailoverStrategy::ImmediateBaseline,
            FailoverStrategy::RetryThenBaseline,
            FailoverStrategy::Halt,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn serde_incident_severity_variant_strings_distinct() {
        let jsons: std::collections::BTreeSet<String> = [
            IncidentSeverity::Info,
            IncidentSeverity::Warning,
            IncidentSeverity::Error,
            IncidentSeverity::Critical,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(jsons.len(), 4);
    }

    #[test]
    fn serde_artifact_kind_variant_strings_distinct() {
        let jsons: std::collections::BTreeSet<String> = [
            ArtifactKind::NondeterminismTrace,
            ArtifactKind::DecisionLog,
            ArtifactKind::FailoverLog,
            ArtifactKind::SignalGraphSnapshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::PerformanceMetrics,
            ArtifactKind::Configuration,
            ArtifactKind::DivergenceReport,
        ]
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
        assert_eq!(jsons.len(), 8);
    }

    // ── Hash consistency ────────────────────────────────────────

    #[test]
    fn hash_nondeterminism_source_consistent() {
        use std::hash::{Hash, Hasher};
        for s in &NondeterminismSource::ALL {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut h1);
            s.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn hash_replay_mode_consistent() {
        use std::hash::{Hash, Hasher};
        for m in [
            ReplayMode::Strict,
            ReplayMode::BestEffort,
            ReplayMode::Validate,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            m.hash(&mut h1);
            m.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn hash_divergence_severity_consistent() {
        use std::hash::{Hash, Hasher};
        for s in [
            DivergenceSeverity::Benign,
            DivergenceSeverity::Warning,
            DivergenceSeverity::Critical,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut h1);
            s.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn hash_failover_strategy_consistent() {
        use std::hash::{Hash, Hasher};
        for s in [
            FailoverStrategy::ImmediateBaseline,
            FailoverStrategy::RetryThenBaseline,
            FailoverStrategy::Halt,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut h1);
            s.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn hash_incident_severity_consistent() {
        use std::hash::{Hash, Hasher};
        for s in [
            IncidentSeverity::Info,
            IncidentSeverity::Warning,
            IncidentSeverity::Error,
            IncidentSeverity::Critical,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut h1);
            s.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn hash_artifact_kind_consistent() {
        use std::hash::{Hash, Hasher};
        for k in [
            ArtifactKind::NondeterminismTrace,
            ArtifactKind::DecisionLog,
            ArtifactKind::FailoverLog,
            ArtifactKind::SignalGraphSnapshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::PerformanceMetrics,
            ArtifactKind::Configuration,
            ArtifactKind::DivergenceReport,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            k.hash(&mut h1);
            k.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    // ── Serde roundtrips for remaining structs ──────────────────

    #[test]
    fn serde_roundtrip_trace_event() {
        let ev = TraceEvent {
            sequence: 42,
            source: NondeterminismSource::ExternalApiResponse,
            value: vec![0xFF, 0x00, 0xAB],
            virtual_ts: 12345,
            component: "api-proxy".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn serde_roundtrip_replay_divergence() {
        let d = ReplayDivergence {
            sequence: 7,
            source: NondeterminismSource::ResourceCheck,
            expected_value: vec![1, 2],
            actual_value: vec![3, 4],
            virtual_ts: 500,
            severity: DivergenceSeverity::Critical,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: ReplayDivergence = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn serde_roundtrip_replay_engine_with_divergences() {
        let mut trace = NondeterminismTrace::new("srd");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "clk");
        trace.finalise(20);
        let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
        eng.replay_next(NondeterminismSource::TimerRead, &[2])
            .unwrap();
        assert_eq!(eng.divergence_count(), 1);
        let json = serde_json::to_string(&eng).unwrap();
        let back: ReplayEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(eng, back);
    }

    #[test]
    fn serde_roundtrip_failover_record() {
        let rec = FailoverRecord {
            sequence: 3,
            reason: FailoverReason::Timeout {
                elapsed_us: 50_000,
                limit_us: 30_000,
            },
            strategy: FailoverStrategy::RetryThenBaseline,
            from_component: "wasm".into(),
            to_component: "js".into(),
            virtual_ts: 777,
            success: true,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: FailoverRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn serde_roundtrip_incident_artifact() {
        let art = IncidentArtifact::new("perf", ArtifactKind::PerformanceMetrics, vec![9, 8, 7]);
        let json = serde_json::to_string(&art).unwrap();
        let back: IncidentArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(art, back);
    }

    #[test]
    fn serde_roundtrip_incident_bundle_builder() {
        let bb =
            IncidentBundleBuilder::new("INC-BB", IncidentSeverity::Warning, "test", "comp", 999)
                .with_trace(false)
                .with_decisions(true)
                .with_failovers(false)
                .with_divergences(true);
        let json = serde_json::to_string(&bb).unwrap();
        let back: IncidentBundleBuilder = serde_json::from_str(&json).unwrap();
        assert_eq!(bb, back);
    }

    // ── Boundary / edge cases ──────────────────────────────────

    #[test]
    fn trace_event_empty_value() {
        let ev = TraceEvent {
            sequence: 0,
            source: NondeterminismSource::LaneSelectionRandom,
            value: vec![],
            virtual_ts: 0,
            component: String::new(),
        };
        let id = ev.derive_id();
        let json = serde_json::to_string(&ev).unwrap();
        let back: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
        assert_eq!(id, back.derive_id());
    }

    #[test]
    fn trace_max_virtual_ts() {
        let mut trace = NondeterminismTrace::new("max-vts");
        trace.capture(NondeterminismSource::TimerRead, vec![1], u64::MAX, "clk");
        assert_eq!(trace.events[0].virtual_ts, u64::MAX);
        let json = serde_json::to_string(&trace).unwrap();
        let back: NondeterminismTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }

    #[test]
    fn replay_engine_remaining_after_partial() {
        let mut trace = NondeterminismTrace::new("s");
        for i in 0..5u64 {
            trace.capture(
                NondeterminismSource::TimerRead,
                vec![i as u8],
                i * 10,
                "clk",
            );
        }
        trace.finalise(50);
        let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
        assert_eq!(eng.remaining(), 5);
        eng.replay_next(NondeterminismSource::TimerRead, &[0])
            .unwrap();
        eng.replay_next(NondeterminismSource::TimerRead, &[1])
            .unwrap();
        assert_eq!(eng.remaining(), 3);
        assert!(!eng.is_complete());
    }

    #[test]
    fn failover_success_rate_all_failures() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 10);
        for _ in 0..5 {
            fc.record_failover(FailoverReason::Manual, "a", "b", 100, false)
                .unwrap();
        }
        assert_eq!(fc.success_rate_millionths(), 0);
    }

    #[test]
    fn failover_success_rate_all_successes() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 10);
        for _ in 0..5 {
            fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
                .unwrap();
        }
        assert_eq!(fc.success_rate_millionths(), MILLION);
    }

    #[test]
    fn failover_max_zero_rejects_immediately() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 0);
        let err = fc
            .record_failover(FailoverReason::Manual, "a", "b", 10, true)
            .unwrap_err();
        assert!(matches!(
            err,
            FailoverError::MaxFailoversExceeded { count: 0, limit: 0 }
        ));
    }

    #[test]
    fn incident_bundle_total_data_size_empty() {
        let b = IncidentBundle::new("INC-SZ", IncidentSeverity::Info, "s", "c", 0);
        assert_eq!(b.total_data_size(), 0);
    }

    #[test]
    fn incident_bundle_tag_order_preserved() {
        let mut b = IncidentBundle::new("INC-ORD", IncidentSeverity::Info, "s", "c", 0);
        b.add_tag("alpha");
        b.add_tag("beta");
        b.add_tag("gamma");
        assert_eq!(b.tags, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn hash_empty_data() {
        let h = compute_simple_hash(&[]);
        assert_eq!(h.len(), 16);
        let h2 = compute_simple_hash(&[]);
        assert_eq!(h, h2);
    }

    #[test]
    fn hash_single_byte_distinct() {
        let hashes: std::collections::BTreeSet<String> =
            (0..=255u8).map(|b| compute_simple_hash(&[b])).collect();
        assert_eq!(hashes.len(), 256);
    }

    #[test]
    fn derive_id_trace_different_sessions() {
        let t1 = NondeterminismTrace::new("session-a");
        let t2 = NondeterminismTrace::new("session-b");
        assert_ne!(t1.derive_id(), t2.derive_id());
    }

    #[test]
    fn derive_id_trace_different_event_counts() {
        let t1 = NondeterminismTrace::new("s");
        let mut t2 = NondeterminismTrace::new("s");
        t2.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
        assert_ne!(t1.derive_id(), t2.derive_id());
    }

    #[test]
    fn derive_id_replay_engine_different_cursors() {
        let mut trace = NondeterminismTrace::new("s");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
        trace.finalise(20);
        let eng0 = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
        let mut eng1 = ReplayEngine::new(trace, ReplayMode::Strict);
        eng1.replay_next(NondeterminismSource::TimerRead, &[1])
            .unwrap();
        assert_ne!(eng0.derive_id(), eng1.derive_id());
    }

    #[test]
    fn derive_id_failover_controller_advances() {
        let mut fc = FailoverController::with_defaults();
        let id0 = fc.derive_id();
        fc.record_failover(FailoverReason::Manual, "a", "b", 10, true)
            .unwrap();
        let id1 = fc.derive_id();
        assert_ne!(id0, id1);
    }

    // ── Ordering tests ─────────────────────────────────────────

    #[test]
    fn nondeterminism_source_ord_total() {
        let mut sorted = NondeterminismSource::ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, NondeterminismSource::ALL.to_vec());
    }

    #[test]
    fn replay_mode_ordering() {
        assert!(ReplayMode::Strict < ReplayMode::BestEffort);
        assert!(ReplayMode::BestEffort < ReplayMode::Validate);
    }

    #[test]
    fn failover_strategy_ordering() {
        assert!(FailoverStrategy::ImmediateBaseline < FailoverStrategy::RetryThenBaseline);
        assert!(FailoverStrategy::RetryThenBaseline < FailoverStrategy::Halt);
    }

    #[test]
    fn incident_severity_ordering() {
        assert!(IncidentSeverity::Info < IncidentSeverity::Warning);
        assert!(IncidentSeverity::Warning < IncidentSeverity::Error);
        assert!(IncidentSeverity::Error < IncidentSeverity::Critical);
    }

    #[test]
    fn artifact_kind_ordering() {
        assert!(ArtifactKind::NondeterminismTrace < ArtifactKind::DecisionLog);
        assert!(ArtifactKind::DecisionLog < ArtifactKind::FailoverLog);
    }

    // ── Replay error variant coverage ──────────────────────────

    #[test]
    fn replay_error_trace_not_finalised_serde() {
        let err = ReplayError::TraceNotFinalised;
        let json = serde_json::to_string(&err).unwrap();
        let back: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn replay_error_all_variants_debug_distinct() {
        let errs: Vec<ReplayError> = vec![
            ReplayError::TraceExhausted {
                cursor: 0,
                total: 0,
            },
            ReplayError::CriticalDivergence {
                sequence: 0,
                source: NondeterminismSource::TimerRead,
            },
            ReplayError::SourceMismatch {
                sequence: 0,
                expected: NondeterminismSource::TimerRead,
                actual: NondeterminismSource::ResourceCheck,
            },
            ReplayError::TraceNotFinalised,
        ];
        let dbgs: std::collections::BTreeSet<String> =
            errs.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(dbgs.len(), 4);
    }

    // ── FailoverReason Debug ───────────────────────────────────

    #[test]
    fn failover_reason_debug_distinct() {
        let reasons = vec![
            FailoverReason::BudgetExhausted {
                metric: "m".into(),
                value: 1,
                limit: 0,
            },
            FailoverReason::LaneError {
                message: "e".into(),
            },
            FailoverReason::SafeModeTriggered,
            FailoverReason::Timeout {
                elapsed_us: 1,
                limit_us: 0,
            },
            FailoverReason::ReplayDivergence {
                divergence_count: 1,
            },
            FailoverReason::Manual,
        ];
        let dbgs: std::collections::BTreeSet<String> =
            reasons.iter().map(|r| format!("{r:?}")).collect();
        assert_eq!(dbgs.len(), 6);
    }

    // ── Builder edge cases ─────────────────────────────────────

    #[test]
    fn builder_no_divergences_skips_divergence_artifact() {
        let mut trace = NondeterminismTrace::new("s");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
        trace.finalise(20);
        let mut eng = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
        eng.replay_next(NondeterminismSource::TimerRead, &[1])
            .unwrap();
        assert_eq!(eng.divergence_count(), 0);

        let bb = IncidentBundleBuilder::new("INC-NODIV", IncidentSeverity::Info, "s", "c", 0);
        let bundle = bb.build(Some(&trace), Some(&eng), None);
        let has_div = bundle
            .artifacts
            .iter()
            .any(|a| a.kind == ArtifactKind::DivergenceReport);
        assert!(!has_div);
    }

    #[test]
    fn builder_none_sources_produces_no_artifacts() {
        let bb = IncidentBundleBuilder::new("INC-NONE", IncidentSeverity::Info, "s", "c", 0);
        let bundle = bb.build(None, None, None);
        assert_eq!(bundle.artifact_count(), 0);
        assert!(bundle.is_finalised());
    }

    #[test]
    fn incident_artifact_content_hash_deterministic() {
        let a1 = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![1, 2, 3]);
        let a2 = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![1, 2, 3]);
        assert_eq!(a1.content_hash, a2.content_hash);
    }

    #[test]
    fn incident_artifact_different_data_different_hash() {
        let a1 = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![1, 2, 3]);
        let a2 = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![4, 5, 6]);
        assert_ne!(a1.content_hash, a2.content_hash);
    }

    #[test]
    fn incident_bundle_finalise_deterministic() {
        let mut b1 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
        b1.add_artifact(IncidentArtifact::new(
            "a",
            ArtifactKind::DecisionLog,
            vec![1],
        ));
        b1.finalise();

        let mut b2 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
        b2.add_artifact(IncidentArtifact::new(
            "a",
            ArtifactKind::DecisionLog,
            vec![1],
        ));
        b2.finalise();

        assert_eq!(b1.bundle_hash, b2.bundle_hash);
    }

    #[test]
    fn incident_bundle_different_artifacts_different_hash() {
        let mut b1 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
        b1.add_artifact(IncidentArtifact::new(
            "a",
            ArtifactKind::DecisionLog,
            vec![1],
        ));
        b1.finalise();

        let mut b2 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
        b2.add_artifact(IncidentArtifact::new(
            "a",
            ArtifactKind::DecisionLog,
            vec![2],
        ));
        b2.finalise();

        assert_ne!(b1.bundle_hash, b2.bundle_hash);
    }

    // ── classify_divergence remaining source ────────────────────

    #[test]
    fn classify_divergence_external_api_is_critical() {
        let s = classify_divergence(&NondeterminismSource::ExternalApiResponse, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Critical);
    }

    // ── Failover with diverse reasons ───────────────────────────

    #[test]
    fn failover_records_all_reason_types() {
        let mut fc = FailoverController::new(FailoverStrategy::RetryThenBaseline, 100);
        let reasons = vec![
            FailoverReason::BudgetExhausted {
                metric: "mem".into(),
                value: 100,
                limit: 50,
            },
            FailoverReason::LaneError {
                message: "oops".into(),
            },
            FailoverReason::SafeModeTriggered,
            FailoverReason::Timeout {
                elapsed_us: 20_000,
                limit_us: 10_000,
            },
            FailoverReason::ReplayDivergence {
                divergence_count: 5,
            },
            FailoverReason::Manual,
        ];
        for (i, reason) in reasons.into_iter().enumerate() {
            let rec = fc
                .record_failover(reason, "src", "dst", (i as u64) * 100, true)
                .unwrap();
            assert_eq!(rec.sequence, i as u64);
        }
        assert_eq!(fc.total_failovers, 6);
        assert_eq!(fc.records.len(), 6);
    }

    #[test]
    fn failover_strategy_override_multiple_components() {
        let mut fc = FailoverController::with_defaults();
        fc.set_override("wasm-lane", FailoverStrategy::Halt);
        fc.set_override("gpu-lane", FailoverStrategy::ImmediateBaseline);
        assert_eq!(fc.strategy_for("wasm-lane"), FailoverStrategy::Halt);
        assert_eq!(
            fc.strategy_for("gpu-lane"),
            FailoverStrategy::ImmediateBaseline
        );
        assert_eq!(
            fc.strategy_for("unknown"),
            FailoverStrategy::RetryThenBaseline
        );
    }

    #[test]
    fn failover_strategy_override_replacement() {
        let mut fc = FailoverController::with_defaults();
        fc.set_override("comp", FailoverStrategy::Halt);
        assert_eq!(fc.strategy_for("comp"), FailoverStrategy::Halt);
        fc.set_override("comp", FailoverStrategy::ImmediateBaseline);
        assert_eq!(fc.strategy_for("comp"), FailoverStrategy::ImmediateBaseline);
    }

    // ── ArtifactKind as_str stability ───────────────────────────

    #[test]
    fn artifact_kind_as_str_all_unique() {
        let strs: std::collections::BTreeSet<&str> = [
            ArtifactKind::NondeterminismTrace,
            ArtifactKind::DecisionLog,
            ArtifactKind::FailoverLog,
            ArtifactKind::SignalGraphSnapshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::PerformanceMetrics,
            ArtifactKind::Configuration,
            ArtifactKind::DivergenceReport,
        ]
        .iter()
        .map(|k| k.as_str())
        .collect();
        assert_eq!(strs.len(), 8);
    }
}
