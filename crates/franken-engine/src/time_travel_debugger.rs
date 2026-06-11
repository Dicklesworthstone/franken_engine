//! Evidence-aware time-travel debugger surfaces: event breakpoints, a
//! `--robot` JSON-line protocol for AI agents, and a `why <tick>` causal
//! explainer (E3.T5b, `bd-fqlfw.3.5.2`).
//!
//! Builds on the reverse-via-re-run cursor (`replay_time_travel`, E3.T5a).
//! Breakpoints are predicates over a normalized, tick-ordered stream of
//! security-relevant [`DebuggerEvent`]s, sourced from IR4 witness events
//! ([`crate::ir_contract::WitnessEvent`]) and evidence-ledger-derived
//! enrichments (IFC label levels, capability-check outcomes, guardplane
//! posterior observations in millionths).
//!
//! The robot protocol is a pure request-line → response-line function: every
//! input line yields exactly one JSON object line, malformed input yields a
//! structured `{"ok":false,...}` line, and identical command transcripts
//! yield byte-identical response transcripts (replay-friendly by
//! construction).
//!
//! `why <tick>` renders the causal chain of security-relevant precursors at
//! or before the tick and carries the evidence-ledger `decision_id` (when
//! present) so callers can escalate to
//! [`crate::forensic_causation_operator::ForensicOperator::investigate_decision`]
//! for the deep causation subgraph.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::forensic_causation_operator::{ForensicOperator, InvestigationReport, OperatorError};
use crate::ir_contract::{WitnessEvent, WitnessEventKind};
use crate::replay_time_travel::{CursorState, TimeTravelCursor, TimeTravelError};

/// Fixed-point scale for probabilities: 1_000_000 = 1.0.
pub const POSTERIOR_MILLIONTHS_SCALE: i64 = 1_000_000;

/// IFC label level corresponding to `Secret` in the built-in lattice
/// (`Public(0) < Internal(1) < Confidential(2) < Secret(3) < TopSecret(4)`).
pub const SECRET_LABEL_LEVEL: u32 = 3;

/// Normalized kind taxonomy for debugger events. Mirrors
/// [`WitnessEventKind`] and adds evidence-derived kinds that have no witness
/// representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DebuggerEventKind {
    HostcallDispatched,
    CapabilityChecked,
    ExceptionRaised,
    GcTriggered,
    ExecutionCompleted,
    FlowLabelChecked,
    DeclassificationRequested,
    ContainmentAction,
    /// Guardplane posterior observation (evidence-derived; no witness kind).
    PosteriorObserved,
}

impl DebuggerEventKind {
    pub fn from_witness(kind: WitnessEventKind) -> Self {
        match kind {
            WitnessEventKind::HostcallDispatched => Self::HostcallDispatched,
            WitnessEventKind::CapabilityChecked => Self::CapabilityChecked,
            WitnessEventKind::ExceptionRaised => Self::ExceptionRaised,
            WitnessEventKind::GcTriggered => Self::GcTriggered,
            WitnessEventKind::ExecutionCompleted => Self::ExecutionCompleted,
            WitnessEventKind::FlowLabelChecked => Self::FlowLabelChecked,
            WitnessEventKind::DeclassificationRequested => Self::DeclassificationRequested,
            WitnessEventKind::ContainmentAction => Self::ContainmentAction,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostcallDispatched => "hostcall_dispatched",
            Self::CapabilityChecked => "capability_checked",
            Self::ExceptionRaised => "exception_raised",
            Self::GcTriggered => "gc_triggered",
            Self::ExecutionCompleted => "execution_completed",
            Self::FlowLabelChecked => "flow_label_checked",
            Self::DeclassificationRequested => "declassification_requested",
            Self::ContainmentAction => "containment_action",
            Self::PosteriorObserved => "posterior_observed",
        }
    }
}

/// A normalized security-relevant event on the logical-tick axis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebuggerEvent {
    /// Logical tick the event occurred at (witness `timestamp_tick`).
    pub tick: u64,
    /// Monotonic sequence within the execution (orders events within a tick).
    pub seq: u64,
    pub kind: DebuggerEventKind,
    /// IFC label level carried by the event, if any (`Secret` = 3).
    pub label_level: Option<u32>,
    /// Capability-check outcome, if applicable (`Some(false)` = denied).
    pub capability_allowed: Option<bool>,
    /// Guardplane malicious-posterior in millionths, if observed here.
    pub malicious_posterior_millionths: Option<i64>,
    /// Evidence-ledger decision id, when the event corresponds to a recorded
    /// decision (enables deep forensics via `ForensicOperator`).
    pub decision_id: Option<String>,
    /// Free-form operator-facing detail.
    pub detail: String,
}

impl DebuggerEvent {
    /// Adapt an IR4 witness event. Witness events carry only kind + tick +
    /// payload hash, so enrichment fields are `None`.
    pub fn from_witness(event: &WitnessEvent) -> Self {
        Self {
            tick: event.timestamp_tick,
            seq: event.seq,
            kind: DebuggerEventKind::from_witness(event.kind),
            label_level: None,
            capability_allowed: None,
            malicious_posterior_millionths: None,
            decision_id: None,
            detail: format!(
                "witness {} at instruction {}",
                event.kind.as_str(),
                event.instruction_index
            ),
        }
    }
}

/// Breakpoint predicates, matching the bead's three motivating examples plus
/// a plain kind trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Breakpoint {
    /// Break on any event of this kind (e.g. first `ContainmentAction`).
    KindIs { kind: DebuggerEventKind },
    /// Break when a value labeled at or above this level is created/checked
    /// ("break when any value labeled Secret is created" => `min_level: 3`).
    LabelLevelAtLeast { min_level: u32 },
    /// Break on the first denied capability check.
    CapabilityDenied,
    /// Break when the malicious posterior strictly exceeds this many
    /// millionths ("crosses 0.2" => `threshold_millionths: 200_000`).
    MaliciousPosteriorAbove { threshold_millionths: i64 },
}

impl Breakpoint {
    pub fn matches(&self, event: &DebuggerEvent) -> bool {
        match self {
            Self::KindIs { kind } => event.kind == *kind,
            Self::LabelLevelAtLeast { min_level } => {
                event.label_level.is_some_and(|level| level >= *min_level)
            }
            Self::CapabilityDenied => event.capability_allowed == Some(false),
            Self::MaliciousPosteriorAbove {
                threshold_millionths,
            } => event
                .malicious_posterior_millionths
                .is_some_and(|posterior| posterior > *threshold_millionths),
        }
    }
}

/// A breakpoint hit returned by `run_until_breakpoint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakHit {
    pub breakpoint_id: u64,
    pub event: DebuggerEvent,
    /// Where the navigation cursor was positioned (event tick clamped to the
    /// nondeterminism-trace range).
    pub cursor_tick: u64,
}

/// Role a precursor plays in a causal chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRole {
    DataSensitivityPrecursor,
    AuthorityPrecursor,
    RiskSignalPrecursor,
    FailurePrecursor,
    ContainmentOutcome,
    Context,
}

/// One link in a `why <tick>` causal chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalLink {
    pub tick: u64,
    pub seq: u64,
    pub kind: DebuggerEventKind,
    pub role: CausalRole,
    pub detail: String,
}

/// The single structured answer to "at exactly which tick and why".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhyReport {
    /// The tick the question was asked about.
    pub asked_tick: u64,
    /// The subject event the explanation centers on (latest security-relevant
    /// event at or before `asked_tick`; containment preferred at equal tick).
    pub subject: Option<DebuggerEvent>,
    /// Tick-ordered security-relevant precursors up to and including the
    /// subject.
    pub causal_chain: Vec<CausalLink>,
    /// Evidence-ledger decision id for deep forensics, when the subject
    /// carries one.
    pub decision_id: Option<String>,
    /// One-sentence operator-facing verdict.
    pub verdict: String,
}

fn causal_role_for(event: &DebuggerEvent) -> CausalRole {
    match event.kind {
        DebuggerEventKind::ContainmentAction => CausalRole::ContainmentOutcome,
        DebuggerEventKind::FlowLabelChecked | DebuggerEventKind::DeclassificationRequested => {
            CausalRole::DataSensitivityPrecursor
        }
        DebuggerEventKind::CapabilityChecked | DebuggerEventKind::HostcallDispatched => {
            CausalRole::AuthorityPrecursor
        }
        DebuggerEventKind::PosteriorObserved => CausalRole::RiskSignalPrecursor,
        DebuggerEventKind::ExceptionRaised => CausalRole::FailurePrecursor,
        DebuggerEventKind::GcTriggered | DebuggerEventKind::ExecutionCompleted => {
            CausalRole::Context
        }
    }
}

/// Whether an event belongs in a causal chain (context noise excluded).
fn is_causally_relevant(event: &DebuggerEvent) -> bool {
    !matches!(
        causal_role_for(event),
        CausalRole::Context // GC / completion are context, not causation
    )
}

/// The evidence-aware time-travel debugger.
#[derive(Debug, Clone)]
pub struct TimeTravelDebugger {
    cursor: TimeTravelCursor,
    /// Security-relevant events sorted by (tick, seq).
    events: Vec<DebuggerEvent>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    next_breakpoint_id: u64,
}

impl TimeTravelDebugger {
    /// Build a debugger over a navigation cursor plus a normalized event
    /// stream. Events are sorted by (tick, seq) at construction.
    pub fn new(cursor: TimeTravelCursor, mut events: Vec<DebuggerEvent>) -> Self {
        events.sort_by(|a, b| (a.tick, a.seq).cmp(&(b.tick, b.seq)));
        Self {
            cursor,
            events,
            breakpoints: BTreeMap::new(),
            next_breakpoint_id: 0,
        }
    }

    /// Build from raw IR4 witness events (kind + tick only; no enrichment).
    pub fn from_witness_events(cursor: TimeTravelCursor, witness: &[WitnessEvent]) -> Self {
        Self::new(
            cursor,
            witness.iter().map(DebuggerEvent::from_witness).collect(),
        )
    }

    /// Read-only view of the navigation cursor.
    pub fn cursor(&self) -> &TimeTravelCursor {
        &self.cursor
    }

    /// Mutable navigation access (step/back/goto are the cursor's surface).
    pub fn cursor_mut(&mut self) -> &mut TimeTravelCursor {
        &mut self.cursor
    }

    /// All normalized events, tick-ordered.
    pub fn events(&self) -> &[DebuggerEvent] {
        &self.events
    }

    /// Events at exactly this tick.
    pub fn events_at_tick(&self, tick: u64) -> Vec<&DebuggerEvent> {
        self.events
            .iter()
            .filter(|event| event.tick == tick)
            .collect()
    }

    /// Register a breakpoint; returns its id.
    pub fn add_breakpoint(&mut self, breakpoint: Breakpoint) -> u64 {
        let id = self.next_breakpoint_id;
        self.next_breakpoint_id = self.next_breakpoint_id.saturating_add(1);
        self.breakpoints.insert(id, breakpoint);
        id
    }

    /// Remove a breakpoint by id. Returns whether it existed.
    pub fn remove_breakpoint(&mut self, id: u64) -> bool {
        self.breakpoints.remove(&id).is_some()
    }

    /// Active breakpoints, id-ordered.
    pub fn breakpoints(&self) -> Vec<(u64, Breakpoint)> {
        self.breakpoints
            .iter()
            .map(|(id, breakpoint)| (*id, breakpoint.clone()))
            .collect()
    }

    /// Scan events strictly after the cursor's current tick, in (tick, seq)
    /// order, for the first breakpoint match. On a hit, positions the cursor
    /// at the event's tick (clamped to the trace range) and returns the hit.
    /// Returns `Ok(None)` when no remaining event matches (cursor unmoved).
    pub fn run_until_breakpoint(&mut self) -> Result<Option<BreakHit>, TimeTravelError> {
        if self.breakpoints.is_empty() {
            return Ok(None);
        }
        let current = self.cursor.current_tick();
        let hit = self.events.iter().find_map(|event| {
            if event.tick <= current {
                return None;
            }
            self.breakpoints
                .iter()
                .find(|(_, breakpoint)| breakpoint.matches(event))
                .map(|(id, _)| (*id, event.clone()))
        });
        match hit {
            Some((breakpoint_id, event)) => {
                let target = event.tick.min(self.cursor.total_ticks());
                let cursor_tick = self.cursor.goto_tick(target)?;
                Ok(Some(BreakHit {
                    breakpoint_id,
                    event,
                    cursor_tick,
                }))
            }
            None => Ok(None),
        }
    }

    /// Render the causal chain answering "at exactly which tick and why".
    ///
    /// The subject is the latest security-relevant event at or before
    /// `tick`, preferring a `ContainmentAction` among events sharing the
    /// subject tick. The chain lists every causally relevant event up to and
    /// including the subject, in (tick, seq) order, with assigned roles.
    pub fn why(&self, tick: u64) -> WhyReport {
        let candidates: Vec<&DebuggerEvent> = self
            .events
            .iter()
            .filter(|event| event.tick <= tick && is_causally_relevant(event))
            .collect();

        let subject = candidates
            .last()
            .map(|last| {
                // Prefer a containment action within the subject tick.
                candidates
                    .iter()
                    .rev()
                    .filter(|event| event.tick == last.tick)
                    .find(|event| event.kind == DebuggerEventKind::ContainmentAction)
                    .copied()
                    .unwrap_or(last)
            })
            .cloned();

        let causal_chain: Vec<CausalLink> = match &subject {
            None => Vec::new(),
            Some(subject_event) => candidates
                .iter()
                .filter(|event| (event.tick, event.seq) <= (subject_event.tick, subject_event.seq))
                .map(|event| CausalLink {
                    tick: event.tick,
                    seq: event.seq,
                    kind: event.kind,
                    role: causal_role_for(event),
                    detail: event.detail.clone(),
                })
                .collect(),
        };

        let verdict = match &subject {
            None => format!("no security-relevant event at or before tick {tick}"),
            Some(subject_event) => format!(
                "{} at tick {} after {} causal precursor(s)",
                subject_event.kind.as_str(),
                subject_event.tick,
                causal_chain.len().saturating_sub(1)
            ),
        };

        WhyReport {
            asked_tick: tick,
            decision_id: subject.as_ref().and_then(|event| event.decision_id.clone()),
            subject,
            causal_chain,
            verdict,
        }
    }

    /// Escalate a `why` subject to the deep forensic causation operator.
    /// Returns `Ok(None)` when no decision id is recorded at or before the
    /// tick; otherwise delegates to
    /// [`ForensicOperator::investigate_decision`].
    pub fn investigate_tick(
        &self,
        operator: &mut ForensicOperator,
        tick: u64,
    ) -> Result<Option<InvestigationReport>, OperatorError> {
        match self.why(tick).decision_id {
            None => Ok(None),
            Some(decision_id) => operator.investigate_decision(&decision_id).map(Some),
        }
    }
}

// ---------------------------------------------------------------------------
// --robot JSON line protocol
// ---------------------------------------------------------------------------

/// Robot-protocol request: one JSON object per line, tagged by `cmd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum RobotRequest {
    State,
    Step,
    Back,
    Goto { tick: u64 },
    RunUntilBreak,
    AddBreakpoint { breakpoint: Breakpoint },
    RemoveBreakpoint { id: u64 },
    ListBreakpoints,
    Why { tick: u64 },
    EventsAt { tick: u64 },
}

/// Robot-protocol response: exactly one JSON object per request line.
/// `ok=false` responses carry a structured error string; the session never
/// panics on malformed input (fail-closed, agent-friendly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RobotResponsePayload {
    State {
        state: CursorState,
    },
    Stepped {
        state: CursorState,
    },
    BreakpointAdded {
        id: u64,
    },
    BreakpointRemoved {
        id: u64,
        existed: bool,
    },
    Breakpoints {
        breakpoints: Vec<(u64, Breakpoint)>,
    },
    BreakHit {
        hit: Box<BreakHit>,
        state: CursorState,
    },
    NoBreakHit {
        state: CursorState,
    },
    Why {
        report: Box<WhyReport>,
    },
    Events {
        tick: u64,
        events: Vec<DebuggerEvent>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<RobotResponsePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RobotResponse {
    fn success(payload: RobotResponsePayload) -> Self {
        Self {
            ok: true,
            payload: Some(payload),
            error: None,
        }
    }

    fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            payload: None,
            error: Some(error.into()),
        }
    }
}

/// A `--robot` session: feed request lines, receive response lines.
/// Deterministic: an identical request transcript yields a byte-identical
/// response transcript.
#[derive(Debug, Clone)]
pub struct RobotSession {
    debugger: TimeTravelDebugger,
}

impl RobotSession {
    pub fn new(debugger: TimeTravelDebugger) -> Self {
        Self { debugger }
    }

    pub fn debugger(&self) -> &TimeTravelDebugger {
        &self.debugger
    }

    /// Handle one request line, returning exactly one JSON response line
    /// (no trailing newline). Never panics on malformed input.
    pub fn handle_line(&mut self, line: &str) -> String {
        let response = match serde_json::from_str::<RobotRequest>(line) {
            Ok(request) => self.execute(request),
            Err(parse_error) => RobotResponse::failure(format!("bad request: {parse_error}")),
        };
        serde_json::to_string(&response)
            .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"response serialization failed\"}".into())
    }

    fn execute(&mut self, request: RobotRequest) -> RobotResponse {
        match request {
            RobotRequest::State => RobotResponse::success(RobotResponsePayload::State {
                state: self.debugger.cursor().observable_state(),
            }),
            RobotRequest::Step => match self.debugger.cursor_mut().step_forward() {
                Ok(_) => RobotResponse::success(RobotResponsePayload::Stepped {
                    state: self.debugger.cursor().observable_state(),
                }),
                Err(error) => RobotResponse::failure(error.to_string()),
            },
            RobotRequest::Back => match self.debugger.cursor_mut().back() {
                Ok(_) => RobotResponse::success(RobotResponsePayload::Stepped {
                    state: self.debugger.cursor().observable_state(),
                }),
                Err(error) => RobotResponse::failure(error.to_string()),
            },
            RobotRequest::Goto { tick } => match self.debugger.cursor_mut().goto_tick(tick) {
                Ok(_) => RobotResponse::success(RobotResponsePayload::Stepped {
                    state: self.debugger.cursor().observable_state(),
                }),
                Err(error) => RobotResponse::failure(error.to_string()),
            },
            RobotRequest::RunUntilBreak => match self.debugger.run_until_breakpoint() {
                Ok(Some(hit)) => RobotResponse::success(RobotResponsePayload::BreakHit {
                    hit: Box::new(hit),
                    state: self.debugger.cursor().observable_state(),
                }),
                Ok(None) => RobotResponse::success(RobotResponsePayload::NoBreakHit {
                    state: self.debugger.cursor().observable_state(),
                }),
                Err(error) => RobotResponse::failure(error.to_string()),
            },
            RobotRequest::AddBreakpoint { breakpoint } => {
                let id = self.debugger.add_breakpoint(breakpoint);
                RobotResponse::success(RobotResponsePayload::BreakpointAdded { id })
            }
            RobotRequest::RemoveBreakpoint { id } => {
                let existed = self.debugger.remove_breakpoint(id);
                RobotResponse::success(RobotResponsePayload::BreakpointRemoved { id, existed })
            }
            RobotRequest::ListBreakpoints => {
                RobotResponse::success(RobotResponsePayload::Breakpoints {
                    breakpoints: self.debugger.breakpoints(),
                })
            }
            RobotRequest::Why { tick } => RobotResponse::success(RobotResponsePayload::Why {
                report: Box::new(self.debugger.why(tick)),
            }),
            RobotRequest::EventsAt { tick } => {
                RobotResponse::success(RobotResponsePayload::Events {
                    tick,
                    events: self
                        .debugger
                        .events_at_tick(tick)
                        .into_iter()
                        .cloned()
                        .collect(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_replay::{NondeterminismSource, NondeterminismTrace, ReplayMode};
    use crate::replay_time_travel::TimeTravelConfig;

    fn make_cursor(ticks: usize) -> TimeTravelCursor {
        let mut trace = NondeterminismTrace::new("ttd-test");
        for index in 0..ticks {
            trace.capture(
                NondeterminismSource::TimerRead,
                vec![index as u8],
                (index as u64).saturating_add(1),
                "ttd",
            );
        }
        trace.finalise(ticks as u64);
        TimeTravelCursor::new(
            trace,
            ReplayMode::Strict,
            TimeTravelConfig {
                checkpoint_interval: 4,
            },
        )
        .expect("cursor construction should succeed")
    }

    fn event(tick: u64, seq: u64, kind: DebuggerEventKind) -> DebuggerEvent {
        DebuggerEvent {
            tick,
            seq,
            kind,
            label_level: None,
            capability_allowed: None,
            malicious_posterior_millionths: None,
            decision_id: None,
            detail: format!("{} @{tick}", kind.as_str()),
        }
    }

    /// The bead's canonical scenario: a secret value is created, a
    /// capability is denied, the malicious posterior crosses 0.2, then the
    /// guardplane contains the extension.
    fn scenario_events() -> Vec<DebuggerEvent> {
        let mut secret_created = event(3, 0, DebuggerEventKind::FlowLabelChecked);
        secret_created.label_level = Some(SECRET_LABEL_LEVEL);

        let mut cap_denied = event(5, 1, DebuggerEventKind::CapabilityChecked);
        cap_denied.capability_allowed = Some(false);

        let mut posterior = event(7, 2, DebuggerEventKind::PosteriorObserved);
        posterior.malicious_posterior_millionths = Some(310_000);

        let mut contained = event(9, 3, DebuggerEventKind::ContainmentAction);
        contained.decision_id = Some("decision-quarantine-001".to_string());

        let gc_noise = event(4, 4, DebuggerEventKind::GcTriggered);
        let cap_ok = {
            let mut ok = event(2, 5, DebuggerEventKind::CapabilityChecked);
            ok.capability_allowed = Some(true);
            ok
        };

        vec![
            contained,
            posterior,
            cap_denied,
            secret_created,
            gc_noise,
            cap_ok,
        ]
    }

    fn make_debugger() -> TimeTravelDebugger {
        TimeTravelDebugger::new(make_cursor(12), scenario_events())
    }

    #[test]
    fn events_sorted_by_tick_then_seq_at_construction() {
        let debugger = make_debugger();
        let ticks: Vec<u64> = debugger.events().iter().map(|event| event.tick).collect();
        let mut sorted = ticks.clone();
        sorted.sort_unstable();
        assert_eq!(ticks, sorted);
    }

    #[test]
    fn kind_breakpoint_matches_only_its_kind() {
        let breakpoint = Breakpoint::KindIs {
            kind: DebuggerEventKind::ContainmentAction,
        };
        assert!(breakpoint.matches(&event(1, 0, DebuggerEventKind::ContainmentAction)));
        assert!(!breakpoint.matches(&event(1, 0, DebuggerEventKind::GcTriggered)));
    }

    #[test]
    fn label_breakpoint_respects_lattice_threshold() {
        let breakpoint = Breakpoint::LabelLevelAtLeast {
            min_level: SECRET_LABEL_LEVEL,
        };
        let mut secret = event(1, 0, DebuggerEventKind::FlowLabelChecked);
        secret.label_level = Some(3);
        let mut top_secret = secret.clone();
        top_secret.label_level = Some(4);
        let mut confidential = secret.clone();
        confidential.label_level = Some(2);
        let unlabeled = event(1, 0, DebuggerEventKind::FlowLabelChecked);

        assert!(breakpoint.matches(&secret));
        assert!(breakpoint.matches(&top_secret));
        assert!(!breakpoint.matches(&confidential));
        assert!(!breakpoint.matches(&unlabeled));
    }

    #[test]
    fn capability_denied_breakpoint_ignores_allowed_checks() {
        let breakpoint = Breakpoint::CapabilityDenied;
        let mut denied = event(1, 0, DebuggerEventKind::CapabilityChecked);
        denied.capability_allowed = Some(false);
        let mut allowed = denied.clone();
        allowed.capability_allowed = Some(true);
        let unknown = event(1, 0, DebuggerEventKind::CapabilityChecked);

        assert!(breakpoint.matches(&denied));
        assert!(!breakpoint.matches(&allowed));
        assert!(!breakpoint.matches(&unknown));
    }

    #[test]
    fn posterior_breakpoint_is_strictly_above_threshold() {
        let breakpoint = Breakpoint::MaliciousPosteriorAbove {
            threshold_millionths: 200_000,
        };
        let mut at_threshold = event(1, 0, DebuggerEventKind::PosteriorObserved);
        at_threshold.malicious_posterior_millionths = Some(200_000);
        let mut above = at_threshold.clone();
        above.malicious_posterior_millionths = Some(200_001);

        assert!(!breakpoint.matches(&at_threshold));
        assert!(breakpoint.matches(&above));
    }

    #[test]
    fn run_until_breakpoint_stops_at_first_match_in_tick_order() {
        let mut debugger = make_debugger();
        debugger.add_breakpoint(Breakpoint::CapabilityDenied);
        debugger.add_breakpoint(Breakpoint::LabelLevelAtLeast {
            min_level: SECRET_LABEL_LEVEL,
        });
        let hit = debugger
            .run_until_breakpoint()
            .expect("run should succeed")
            .expect("a breakpoint should hit");
        // Secret-label creation at tick 3 precedes the denial at tick 5.
        assert_eq!(hit.event.tick, 3);
        assert_eq!(hit.event.kind, DebuggerEventKind::FlowLabelChecked);
        assert_eq!(hit.cursor_tick, 3);
        assert_eq!(debugger.cursor().current_tick(), 3);
    }

    #[test]
    fn run_until_breakpoint_resumes_strictly_after_current_tick() {
        let mut debugger = make_debugger();
        debugger.add_breakpoint(Breakpoint::CapabilityDenied);
        debugger.add_breakpoint(Breakpoint::LabelLevelAtLeast {
            min_level: SECRET_LABEL_LEVEL,
        });
        let first = debugger
            .run_until_breakpoint()
            .expect("run should succeed")
            .expect("first hit");
        assert_eq!(first.event.tick, 3);
        let second = debugger
            .run_until_breakpoint()
            .expect("run should succeed")
            .expect("second hit");
        assert_eq!(second.event.tick, 5);
        assert_eq!(second.event.kind, DebuggerEventKind::CapabilityChecked);
    }

    #[test]
    fn run_until_breakpoint_without_breakpoints_returns_none() {
        let mut debugger = make_debugger();
        let result = debugger.run_until_breakpoint().expect("run should succeed");
        assert!(result.is_none());
        assert_eq!(debugger.cursor().current_tick(), 0);
    }

    #[test]
    fn run_until_breakpoint_with_no_match_leaves_cursor_unmoved() {
        let mut debugger = make_debugger();
        debugger.add_breakpoint(Breakpoint::MaliciousPosteriorAbove {
            threshold_millionths: 900_000,
        });
        let result = debugger.run_until_breakpoint().expect("run should succeed");
        assert!(result.is_none());
        assert_eq!(debugger.cursor().current_tick(), 0);
    }

    #[test]
    fn breakpoint_hit_tick_clamps_to_trace_range() {
        // Containment at tick 9 exceeds a 6-tick trace; cursor clamps to 6.
        let mut debugger = TimeTravelDebugger::new(make_cursor(6), scenario_events());
        debugger.add_breakpoint(Breakpoint::KindIs {
            kind: DebuggerEventKind::ContainmentAction,
        });
        let hit = debugger
            .run_until_breakpoint()
            .expect("run should succeed")
            .expect("hit");
        assert_eq!(hit.event.tick, 9);
        assert_eq!(hit.cursor_tick, 6);
    }

    #[test]
    fn remove_breakpoint_disarms_it() {
        let mut debugger = make_debugger();
        let id = debugger.add_breakpoint(Breakpoint::CapabilityDenied);
        assert!(debugger.remove_breakpoint(id));
        assert!(!debugger.remove_breakpoint(id));
        let result = debugger.run_until_breakpoint().expect("run should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn why_centers_on_containment_and_orders_chain() {
        let debugger = make_debugger();
        let report = debugger.why(9);
        let subject = report.subject.expect("subject should exist");
        assert_eq!(subject.kind, DebuggerEventKind::ContainmentAction);
        assert_eq!(subject.tick, 9);
        assert_eq!(
            report.decision_id.as_deref(),
            Some("decision-quarantine-001")
        );
        // Chain: cap_ok(2), secret(3), denial(5), posterior(7), containment(9)
        // — GC noise at tick 4 excluded as context.
        let kinds: Vec<DebuggerEventKind> =
            report.causal_chain.iter().map(|link| link.kind).collect();
        assert_eq!(
            kinds,
            vec![
                DebuggerEventKind::CapabilityChecked,
                DebuggerEventKind::FlowLabelChecked,
                DebuggerEventKind::CapabilityChecked,
                DebuggerEventKind::PosteriorObserved,
                DebuggerEventKind::ContainmentAction,
            ]
        );
        assert_eq!(
            report.causal_chain.last().map(|link| link.role),
            Some(CausalRole::ContainmentOutcome)
        );
    }

    #[test]
    fn why_roles_classify_precursors() {
        let debugger = make_debugger();
        let report = debugger.why(9);
        let roles: Vec<CausalRole> = report.causal_chain.iter().map(|link| link.role).collect();
        assert!(roles.contains(&CausalRole::DataSensitivityPrecursor));
        assert!(roles.contains(&CausalRole::AuthorityPrecursor));
        assert!(roles.contains(&CausalRole::RiskSignalPrecursor));
    }

    #[test]
    fn why_before_any_event_reports_empty_chain() {
        let debugger = make_debugger();
        let report = debugger.why(1);
        assert!(report.subject.is_none());
        assert!(report.causal_chain.is_empty());
        assert!(report.verdict.contains("no security-relevant event"));
    }

    #[test]
    fn why_mid_stream_subject_is_latest_relevant_event() {
        let debugger = make_debugger();
        let report = debugger.why(6);
        let subject = report.subject.expect("subject should exist");
        assert_eq!(subject.tick, 5);
        assert_eq!(subject.kind, DebuggerEventKind::CapabilityChecked);
        assert!(report.decision_id.is_none());
    }

    #[test]
    fn investigate_tick_without_decision_id_is_none() {
        use crate::causation_graph_schema::CausationGraph;
        use crate::forensic_query_api::ForensicQueryEngine;
        let debugger = make_debugger();
        let mut operator = ForensicOperator::new(ForensicQueryEngine::new(CausationGraph::new()));
        let result = debugger
            .investigate_tick(&mut operator, 6)
            .expect("investigation routing should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn robot_state_and_goto_round_trip() {
        let mut session = RobotSession::new(make_debugger());
        let state_line = session.handle_line(r#"{"cmd":"state"}"#);
        assert!(state_line.contains("\"ok\":true"));
        assert!(state_line.contains("\"tick\":0"));
        let goto_line = session.handle_line(r#"{"cmd":"goto","tick":5}"#);
        assert!(goto_line.contains("\"ok\":true"));
        assert!(goto_line.contains("\"tick\":5"));
    }

    #[test]
    fn robot_step_back_symmetry() {
        let mut session = RobotSession::new(make_debugger());
        session.handle_line(r#"{"cmd":"goto","tick":4}"#);
        let stepped = session.handle_line(r#"{"cmd":"step"}"#);
        assert!(stepped.contains("\"tick\":5"));
        let back = session.handle_line(r#"{"cmd":"back"}"#);
        assert!(back.contains("\"tick\":4"));
    }

    #[test]
    fn robot_breakpoint_lifecycle_and_run() {
        let mut session = RobotSession::new(make_debugger());
        let added = session
            .handle_line(r#"{"cmd":"add_breakpoint","breakpoint":{"type":"capability_denied"}}"#);
        assert!(added.contains("\"ok\":true"));
        assert!(added.contains("\"id\":0"));

        let listed = session.handle_line(r#"{"cmd":"list_breakpoints"}"#);
        assert!(listed.contains("capability_denied"));

        let run = session.handle_line(r#"{"cmd":"run_until_break"}"#);
        assert!(run.contains("break_hit"));
        assert!(run.contains("\"tick\":5"));

        let removed = session.handle_line(r#"{"cmd":"remove_breakpoint","id":0}"#);
        assert!(removed.contains("\"existed\":true"));
    }

    #[test]
    fn robot_why_returns_single_structured_answer() {
        let mut session = RobotSession::new(make_debugger());
        let line = session.handle_line(r#"{"cmd":"why","tick":9}"#);
        assert!(line.contains("\"ok\":true"));
        assert!(line.contains("containment_action"));
        assert!(line.contains("decision-quarantine-001"));
        assert!(!line.contains('\n'), "response must be a single line");
    }

    #[test]
    fn robot_rejects_malformed_input_without_panicking() {
        let mut session = RobotSession::new(make_debugger());
        for bad in ["not json", "{}", r#"{"cmd":"warp"}"#, ""] {
            let line = session.handle_line(bad);
            assert!(
                line.contains("\"ok\":false"),
                "input {bad:?} must fail closed"
            );
            assert!(line.contains("bad request"));
        }
    }

    #[test]
    fn robot_goto_out_of_range_fails_closed() {
        let mut session = RobotSession::new(make_debugger());
        let line = session.handle_line(r#"{"cmd":"goto","tick":99}"#);
        assert!(line.contains("\"ok\":false"));
        assert!(line.contains("out of range"));
    }

    #[test]
    fn robot_transcript_is_deterministic() {
        let script = [
            r#"{"cmd":"add_breakpoint","breakpoint":{"type":"label_level_at_least","min_level":3}}"#,
            r#"{"cmd":"run_until_break"}"#,
            r#"{"cmd":"why","tick":9}"#,
            r#"{"cmd":"state"}"#,
        ];
        let mut first_session = RobotSession::new(make_debugger());
        let mut second_session = RobotSession::new(make_debugger());
        let first: Vec<String> = script
            .iter()
            .map(|line| first_session.handle_line(line))
            .collect();
        let second: Vec<String> = script
            .iter()
            .map(|line| second_session.handle_line(line))
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn from_witness_events_adapts_kind_and_tick() {
        use crate::hash_tiers::ContentHash;
        let witness = vec![WitnessEvent {
            seq: 7,
            kind: WitnessEventKind::ContainmentAction,
            instruction_index: 42,
            payload_hash: ContentHash::compute(b"payload"),
            timestamp_tick: 11,
        }];
        let debugger = TimeTravelDebugger::from_witness_events(make_cursor(12), &witness);
        assert_eq!(debugger.events().len(), 1);
        let adapted = &debugger.events()[0];
        assert_eq!(adapted.tick, 11);
        assert_eq!(adapted.seq, 7);
        assert_eq!(adapted.kind, DebuggerEventKind::ContainmentAction);
        assert!(adapted.detail.contains("instruction 42"));
    }

    #[test]
    fn events_at_tick_filters_exactly() {
        let debugger = make_debugger();
        assert_eq!(debugger.events_at_tick(5).len(), 1);
        assert_eq!(debugger.events_at_tick(6).len(), 0);
    }

    #[test]
    fn breakpoint_serde_round_trip() {
        let breakpoints = vec![
            Breakpoint::KindIs {
                kind: DebuggerEventKind::ContainmentAction,
            },
            Breakpoint::LabelLevelAtLeast { min_level: 3 },
            Breakpoint::CapabilityDenied,
            Breakpoint::MaliciousPosteriorAbove {
                threshold_millionths: 200_000,
            },
        ];
        for breakpoint in breakpoints {
            let json = serde_json::to_string(&breakpoint).expect("serialize should succeed");
            let decoded: Breakpoint =
                serde_json::from_str(&json).expect("deserialize should succeed");
            assert_eq!(decoded, breakpoint);
        }
    }

    #[test]
    fn why_report_serde_round_trip() {
        let debugger = make_debugger();
        let report = debugger.why(9);
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let decoded: WhyReport = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(decoded, report);
    }

    #[test]
    fn debugger_event_kind_strings_are_stable() {
        assert_eq!(
            DebuggerEventKind::PosteriorObserved.as_str(),
            "posterior_observed"
        );
        assert_eq!(
            DebuggerEventKind::from_witness(WitnessEventKind::FlowLabelChecked),
            DebuggerEventKind::FlowLabelChecked
        );
    }
}
