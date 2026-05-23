#![forbid(unsafe_code)]

//! Mazurkiewicz-trace independence relation for replay events.
//!
//! HH.1 derives the static independence relation from two declarations that
//! already exist at lowering time:
//! - Track C effect sets (`EffectSet`)
//! - IFC label dependencies attached to the event
//!
//! Two events commute exactly when their effect sets are disjoint and their
//! IFC label-dependency sets are disjoint. The relation is represented with
//! `BTreeMap`/`BTreeSet` only so serialized relation artifacts remain stable.

use crate::effect_set::{EffectKind, EffectSet};
use crate::hash_tiers::ContentHash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const TRACE_INDEPENDENCE_SCHEMA_VERSION: &str = "frankenengine.trace-independence-relation.v1";

fn append_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_len_prefixed(buf: &mut Vec<u8>, value: &[u8]) {
    append_u64(buf, value.len() as u64);
    buf.extend_from_slice(value);
}

fn append_string(buf: &mut Vec<u8>, value: &str) {
    append_len_prefixed(buf, value.as_bytes());
}

/// Replay-stable trace event identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TraceEventId(String);

impl TraceEventId {
    /// Construct a non-empty trace event id.
    pub fn new(value: impl Into<String>) -> Result<Self, TraceIndependenceError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TraceIndependenceError::EmptyTraceEventId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TraceEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// IFC label dependency named by lowering-time flow analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IfcLabelDependency(String);

impl IfcLabelDependency {
    /// Construct a non-empty IFC label dependency id.
    pub fn new(value: impl Into<String>) -> Result<Self, TraceIndependenceError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TraceIndependenceError::EmptyIfcLabelDependency);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IfcLabelDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Static event declaration consumed by the HH.1 relation builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEventDeclaration {
    /// Event id in the replay trace.
    pub event_id: TraceEventId,
    /// Track C effect-set declaration for this event.
    pub effect_set: EffectSet,
    /// IFC labels whose values this event observes or influences.
    pub ifc_label_dependencies: BTreeSet<IfcLabelDependency>,
}

impl TraceEventDeclaration {
    /// Construct an event declaration from typed effect and IFC dependencies.
    pub fn new(
        event_id: TraceEventId,
        effect_set: EffectSet,
        ifc_label_dependencies: BTreeSet<IfcLabelDependency>,
    ) -> Self {
        Self {
            event_id,
            effect_set,
            ifc_label_dependencies,
        }
    }
}

/// Canonical unordered pair of distinct trace events.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TraceEventPair {
    /// Lexicographically first event id.
    pub first: TraceEventId,
    /// Lexicographically second event id.
    pub second: TraceEventId,
}

impl TraceEventPair {
    /// Construct a canonical unordered pair.
    pub fn new(left: TraceEventId, right: TraceEventId) -> Result<Self, TraceIndependenceError> {
        if left == right {
            return Err(TraceIndependenceError::IdenticalTraceEventPair(left));
        }
        if left < right {
            Ok(Self {
                first: left,
                second: right,
            })
        } else {
            Ok(Self {
                first: right,
                second: left,
            })
        }
    }
}

/// Reason a pair is not independent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TraceDependencyReason {
    /// Both events declare at least one shared effect.
    SharedEffect(EffectKind),
    /// Both events depend on the same IFC label.
    SharedIfcLabel(IfcLabelDependency),
}

/// Pairwise HH.1 independence decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIndependenceDecision {
    /// Pair evaluated by this decision.
    pub pair: TraceEventPair,
    /// Intersected effects; empty means there is no effect conflict.
    pub shared_effects: BTreeSet<EffectKind>,
    /// Intersected IFC labels; empty means there is no label dependency.
    pub shared_ifc_label_dependencies: BTreeSet<IfcLabelDependency>,
    /// Whether the events commute.
    pub commute: bool,
    /// Stable dependent reasons, empty when `commute` is true.
    pub dependency_reasons: BTreeSet<TraceDependencyReason>,
}

impl TraceIndependenceDecision {
    fn derive(left: &TraceEventDeclaration, right: &TraceEventDeclaration) -> Self {
        let shared_effects: BTreeSet<EffectKind> = left
            .effect_set
            .intersection(&right.effect_set)
            .iter()
            .collect();
        let shared_ifc_label_dependencies: BTreeSet<IfcLabelDependency> = left
            .ifc_label_dependencies
            .intersection(&right.ifc_label_dependencies)
            .cloned()
            .collect();
        let mut dependency_reasons = BTreeSet::new();
        for effect in &shared_effects {
            dependency_reasons.insert(TraceDependencyReason::SharedEffect(*effect));
        }
        for label in &shared_ifc_label_dependencies {
            dependency_reasons.insert(TraceDependencyReason::SharedIfcLabel(label.clone()));
        }
        Self {
            pair: TraceEventPair::new(left.event_id.clone(), right.event_id.clone())
                .expect("caller only compares distinct event ids"),
            commute: shared_effects.is_empty() && shared_ifc_label_dependencies.is_empty(),
            shared_effects,
            shared_ifc_label_dependencies,
            dependency_reasons,
        }
    }
}

/// Static independence relation for a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIndependenceRelation {
    /// Stable schema id for persisted relation artifacts.
    pub schema_version: String,
    /// Event ids included in the relation.
    pub events: BTreeSet<TraceEventId>,
    /// Commuting event pairs.
    pub independent_pairs: BTreeSet<TraceEventPair>,
    /// Non-commuting event pairs.
    pub dependent_pairs: BTreeSet<TraceEventPair>,
    /// Full pairwise decisions for diagnostics and replay proofs.
    pub decisions: BTreeMap<TraceEventPair, TraceIndependenceDecision>,
}

impl TraceIndependenceRelation {
    /// Derive the HH.1 relation from static event declarations.
    pub fn derive<I>(events: I) -> Result<Self, TraceIndependenceError>
    where
        I: IntoIterator<Item = TraceEventDeclaration>,
    {
        let mut declarations = BTreeMap::new();
        for event in events {
            if declarations
                .insert(event.event_id.clone(), event.clone())
                .is_some()
            {
                return Err(TraceIndependenceError::DuplicateTraceEventId(
                    event.event_id,
                ));
            }
        }

        let ordered_events: Vec<&TraceEventDeclaration> = declarations.values().collect();
        let mut independent_pairs = BTreeSet::new();
        let mut dependent_pairs = BTreeSet::new();
        let mut decisions = BTreeMap::new();

        for left_index in 0..ordered_events.len() {
            for right_index in (left_index + 1)..ordered_events.len() {
                let decision = TraceIndependenceDecision::derive(
                    ordered_events[left_index],
                    ordered_events[right_index],
                );
                if decision.commute {
                    independent_pairs.insert(decision.pair.clone());
                } else {
                    dependent_pairs.insert(decision.pair.clone());
                }
                decisions.insert(decision.pair.clone(), decision);
            }
        }

        Ok(Self {
            schema_version: TRACE_INDEPENDENCE_SCHEMA_VERSION.to_string(),
            events: declarations.keys().cloned().collect(),
            independent_pairs,
            dependent_pairs,
            decisions,
        })
    }

    /// Return the pairwise decision for two events, if both exist in the relation.
    pub fn decision(
        &self,
        left: &TraceEventId,
        right: &TraceEventId,
    ) -> Option<&TraceIndependenceDecision> {
        TraceEventPair::new(left.clone(), right.clone())
            .ok()
            .and_then(|pair| self.decisions.get(&pair))
    }

    /// Whether two events commute under the derived relation.
    pub fn commute(&self, left: &TraceEventId, right: &TraceEventId) -> bool {
        self.decision(left, right)
            .map(|decision| decision.commute)
            .unwrap_or(false)
    }

    /// Deterministic content hash over the relation.
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }

    /// Canonical bytes for relation artifacts.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_string(&mut buf, &self.schema_version);
        append_u64(&mut buf, self.events.len() as u64);
        for event in &self.events {
            append_string(&mut buf, event.as_str());
        }
        append_u64(&mut buf, self.decisions.len() as u64);
        for (pair, decision) in &self.decisions {
            append_string(&mut buf, pair.first.as_str());
            append_string(&mut buf, pair.second.as_str());
            append_u8(&mut buf, u8::from(decision.commute));
            append_u64(&mut buf, decision.shared_effects.len() as u64);
            for effect in &decision.shared_effects {
                append_u8(&mut buf, effect.discriminant());
            }
            append_u64(
                &mut buf,
                decision.shared_ifc_label_dependencies.len() as u64,
            );
            for label in &decision.shared_ifc_label_dependencies {
                append_string(&mut buf, label.as_str());
            }
        }
        buf
    }
}

/// Errors from static independence derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceIndependenceError {
    /// Trace event ids must not be blank.
    EmptyTraceEventId,
    /// IFC label dependency ids must not be blank.
    EmptyIfcLabelDependency,
    /// A relation cannot contain the same event id twice.
    DuplicateTraceEventId(TraceEventId),
    /// Pairwise relation queries must use two distinct events.
    IdenticalTraceEventPair(TraceEventId),
}

impl fmt::Display for TraceIndependenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTraceEventId => f.write_str("trace event id must not be empty"),
            Self::EmptyIfcLabelDependency => f.write_str("IFC label dependency must not be empty"),
            Self::DuplicateTraceEventId(id) => write!(f, "duplicate trace event id: {id}"),
            Self::IdenticalTraceEventPair(id) => {
                write!(f, "trace event pair must contain distinct events: {id}")
            }
        }
    }
}

impl std::error::Error for TraceIndependenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> TraceEventId {
        TraceEventId::new(value).unwrap()
    }

    fn label(value: &str) -> IfcLabelDependency {
        IfcLabelDependency::new(value).unwrap()
    }

    fn labels(values: &[&str]) -> BTreeSet<IfcLabelDependency> {
        values.iter().map(|value| label(value)).collect()
    }

    fn effects(values: &[EffectKind]) -> EffectSet {
        EffectSet::from_iter_of(values.iter().copied())
    }

    fn event(name: &str, effects: &[EffectKind], labels: &[&str]) -> TraceEventDeclaration {
        TraceEventDeclaration::new(id(name), self::effects(effects), self::labels(labels))
    }

    #[test]
    fn disjoint_effects_and_disjoint_ifc_labels_commute() {
        let relation = TraceIndependenceRelation::derive([
            event("read_config", &[EffectKind::FsRead], &["public"]),
            event("open_socket", &[EffectKind::NetConnect], &["network"]),
        ])
        .unwrap();

        assert!(relation.commute(&id("read_config"), &id("open_socket")));
        assert_eq!(relation.independent_pairs.len(), 1);
        assert!(relation.dependent_pairs.is_empty());
    }

    #[test]
    fn shared_effect_prevents_commutation() {
        let relation = TraceIndependenceRelation::derive([
            event("read_a", &[EffectKind::FsRead], &["public"]),
            event("read_b", &[EffectKind::FsRead], &["private"]),
        ])
        .unwrap();
        let decision = relation.decision(&id("read_a"), &id("read_b")).unwrap();

        assert!(!decision.commute);
        assert_eq!(
            decision.dependency_reasons,
            BTreeSet::from([TraceDependencyReason::SharedEffect(EffectKind::FsRead)])
        );
    }

    #[test]
    fn shared_ifc_label_prevents_commutation_even_when_effects_are_disjoint() {
        let relation = TraceIndependenceRelation::derive([
            event("policy", &[EffectKind::PolicyRequest], &["tenant-secret"]),
            event("clock", &[EffectKind::ClockRead], &["tenant-secret"]),
        ])
        .unwrap();
        let decision = relation.decision(&id("policy"), &id("clock")).unwrap();

        assert!(!decision.commute);
        assert!(decision.shared_effects.is_empty());
        assert_eq!(
            decision.shared_ifc_label_dependencies,
            BTreeSet::from([label("tenant-secret")])
        );
    }

    #[test]
    fn relation_is_derived_in_canonical_event_order() {
        let forward = TraceIndependenceRelation::derive([
            event("c", &[EffectKind::Eval], &["gamma"]),
            event("a", &[EffectKind::FsRead], &["alpha"]),
            event("b", &[EffectKind::NetConnect], &["beta"]),
        ])
        .unwrap();
        let reverse = TraceIndependenceRelation::derive([
            event("b", &[EffectKind::NetConnect], &["beta"]),
            event("a", &[EffectKind::FsRead], &["alpha"]),
            event("c", &[EffectKind::Eval], &["gamma"]),
        ])
        .unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(forward.content_hash(), reverse.content_hash());
    }

    #[test]
    fn unordered_pair_queries_are_symmetric() {
        let relation = TraceIndependenceRelation::derive([
            event("left", &[EffectKind::FsWrite], &["x"]),
            event("right", &[EffectKind::NetListen], &["y"]),
        ])
        .unwrap();

        assert_eq!(
            relation.decision(&id("left"), &id("right")),
            relation.decision(&id("right"), &id("left"))
        );
        assert!(relation.commute(&id("right"), &id("left")));
    }

    #[test]
    fn duplicate_event_ids_are_rejected() {
        let err = TraceIndependenceRelation::derive([
            event("same", &[EffectKind::FsRead], &[]),
            event("same", &[EffectKind::FsWrite], &[]),
        ])
        .expect_err("duplicate ids should fail");

        assert_eq!(
            err,
            TraceIndependenceError::DuplicateTraceEventId(id("same"))
        );
    }

    #[test]
    fn empty_ids_are_rejected() {
        assert_eq!(
            TraceEventId::new(" ").expect_err("blank event id"),
            TraceIndependenceError::EmptyTraceEventId
        );
        assert_eq!(
            IfcLabelDependency::new("").expect_err("blank label"),
            TraceIndependenceError::EmptyIfcLabelDependency
        );
    }

    #[test]
    fn self_pair_is_never_independent() {
        let relation =
            TraceIndependenceRelation::derive([event("only", &[EffectKind::FsRead], &[])]).unwrap();

        assert!(relation.decision(&id("only"), &id("only")).is_none());
        assert!(!relation.commute(&id("only"), &id("only")));
    }

    #[test]
    fn serde_round_trip_preserves_relation_artifact() {
        let relation = TraceIndependenceRelation::derive([
            event("a", &[EffectKind::FsRead], &["public"]),
            event("b", &[EffectKind::NetConnect], &["network"]),
            event("c", &[EffectKind::FsRead], &["public"]),
        ])
        .unwrap();

        let json = serde_json::to_string(&relation).expect("serialize relation");
        let restored: TraceIndependenceRelation =
            serde_json::from_str(&json).expect("deserialize relation");

        assert_eq!(relation, restored);
        assert_eq!(relation.content_hash(), restored.content_hash());
    }

    #[test]
    fn all_pairwise_decisions_are_recorded_for_trace() {
        let relation = TraceIndependenceRelation::derive([
            event("a", &[EffectKind::FsRead], &["a"]),
            event("b", &[EffectKind::FsWrite], &["b"]),
            event("c", &[EffectKind::NetConnect], &["c"]),
            event("d", &[EffectKind::FsRead], &["d"]),
        ])
        .unwrap();

        assert_eq!(relation.decisions.len(), 6);
        assert_eq!(relation.independent_pairs.len(), 5);
        assert_eq!(relation.dependent_pairs.len(), 1);
    }
}
