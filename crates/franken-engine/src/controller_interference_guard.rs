//! Deterministic interference guard for multi-controller metric access.
//!
//! Plan reference: Section 10.13 item 14 (`bd-2py0`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const CONTROLLER_INTERFERENCE_GUARD_DOMAIN: &[u8] = b"FrankenEngine.ControllerInterferenceGuard.v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolutionMode {
    Serialize,
    Reject,
}

impl fmt::Display for ConflictResolutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize => f.write_str("serialize"),
            Self::Reject => f.write_str("reject"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceConfig {
    pub min_timescale_separation_millionths: i64,
    pub conflict_resolution_mode: ConflictResolutionMode,
}

impl Default for InterferenceConfig {
    fn default() -> Self {
        Self {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimescaleSeparationStatement {
    /// Observation cadence in millionths of one second.
    pub observation_interval_millionths: i64,
    /// Mutation cadence in millionths of one second.
    pub write_interval_millionths: i64,
    /// Human-readable declaration attached to registration.
    pub statement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerRegistration {
    pub controller_id: String,
    pub read_metrics: BTreeSet<String>,
    pub write_metrics: BTreeSet<String>,
    pub timescale: TimescaleSeparationStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricReadRequest {
    pub controller_id: String,
    pub metric: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricWriteRequest {
    pub controller_id: String,
    pub metric: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSubscription {
    pub controller_id: String,
    pub metric: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricUpdate {
    pub sequence: u64,
    pub metric: String,
    pub value: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InterferenceFailureCode {
    DuplicateController,
    MissingTimescaleStatement,
    InvalidTimescaleInterval,
    UnknownController,
    UnauthorizedRead,
    UnauthorizedWrite,
    TimescaleConflict,
}

impl fmt::Display for InterferenceFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateController => f.write_str("duplicate_controller"),
            Self::MissingTimescaleStatement => f.write_str("missing_timescale_statement"),
            Self::InvalidTimescaleInterval => f.write_str("invalid_timescale_interval"),
            Self::UnknownController => f.write_str("unknown_controller"),
            Self::UnauthorizedRead => f.write_str("unauthorized_read"),
            Self::UnauthorizedWrite => f.write_str("unauthorized_write"),
            Self::TimescaleConflict => f.write_str("timescale_conflict"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceFinding {
    pub code: InterferenceFailureCode,
    pub metric: Option<String>,
    pub controller_ids: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceResolution {
    pub metric: String,
    pub controller_ids: Vec<String>,
    pub mode: ConflictResolutionMode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub metric: Option<String>,
    pub controller_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceEvaluation {
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
    pub read_snapshots: BTreeMap<String, i64>,
    pub applied_writes: Vec<MetricWriteRequest>,
    pub rejected_writes: Vec<MetricWriteRequest>,
    pub resolutions: Vec<InterferenceResolution>,
    pub subscription_streams: BTreeMap<String, Vec<MetricUpdate>>,
    pub final_metrics: BTreeMap<String, i64>,
    pub findings: Vec<InterferenceFinding>,
    pub logs: Vec<InterferenceLogEvent>,
}

pub struct InterferenceScenario<'a> {
    pub trace_id: &'a str,
    pub policy_id: &'a str,
    pub config: &'a InterferenceConfig,
    pub registrations: &'a [ControllerRegistration],
    pub read_requests: &'a [MetricReadRequest],
    pub write_requests: &'a [MetricWriteRequest],
    pub subscriptions: &'a [MetricSubscription],
    pub initial_metrics: &'a BTreeMap<String, i64>,
}

fn evaluate_canonical_value(scenario: &InterferenceScenario<'_>) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(scenario.trace_id.to_string()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(scenario.policy_id.to_string()),
    );

    let mut config_map = BTreeMap::new();
    config_map.insert(
        "min_timescale_separation_millionths".to_string(),
        CanonicalValue::I64(scenario.config.min_timescale_separation_millionths),
    );
    config_map.insert(
        "conflict_resolution_mode".to_string(),
        CanonicalValue::String(scenario.config.conflict_resolution_mode.to_string()),
    );
    map.insert("config".to_string(), CanonicalValue::Map(config_map));

    map.insert(
        "initial_metrics".to_string(),
        CanonicalValue::Map(
            scenario
                .initial_metrics
                .iter()
                .map(|(metric, value)| (metric.clone(), CanonicalValue::I64(*value)))
                .collect(),
        ),
    );

    map.insert(
        "registrations".to_string(),
        CanonicalValue::Array(
            scenario
                .registrations
                .iter()
                .map(|registration| {
                    let mut registration_map = BTreeMap::new();
                    registration_map.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(registration.controller_id.clone()),
                    );
                    registration_map.insert(
                        "read_metrics".to_string(),
                        CanonicalValue::Array(
                            registration
                                .read_metrics
                                .iter()
                                .map(|metric| CanonicalValue::String(metric.clone()))
                                .collect(),
                        ),
                    );
                    registration_map.insert(
                        "write_metrics".to_string(),
                        CanonicalValue::Array(
                            registration
                                .write_metrics
                                .iter()
                                .map(|metric| CanonicalValue::String(metric.clone()))
                                .collect(),
                        ),
                    );
                    let mut timescale_map = BTreeMap::new();
                    timescale_map.insert(
                        "observation_interval_millionths".to_string(),
                        CanonicalValue::I64(registration.timescale.observation_interval_millionths),
                    );
                    timescale_map.insert(
                        "write_interval_millionths".to_string(),
                        CanonicalValue::I64(registration.timescale.write_interval_millionths),
                    );
                    timescale_map.insert(
                        "statement".to_string(),
                        CanonicalValue::String(registration.timescale.statement.clone()),
                    );
                    registration_map
                        .insert("timescale".to_string(), CanonicalValue::Map(timescale_map));
                    CanonicalValue::Map(registration_map)
                })
                .collect(),
        ),
    );

    map.insert(
        "read_requests".to_string(),
        CanonicalValue::Array(
            scenario
                .read_requests
                .iter()
                .map(|request| {
                    let mut req = BTreeMap::new();
                    req.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(request.controller_id.clone()),
                    );
                    req.insert(
                        "metric".to_string(),
                        CanonicalValue::String(request.metric.clone()),
                    );
                    CanonicalValue::Map(req)
                })
                .collect(),
        ),
    );

    map.insert(
        "write_requests".to_string(),
        CanonicalValue::Array(
            scenario
                .write_requests
                .iter()
                .map(|request| {
                    let mut req = BTreeMap::new();
                    req.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(request.controller_id.clone()),
                    );
                    req.insert(
                        "metric".to_string(),
                        CanonicalValue::String(request.metric.clone()),
                    );
                    req.insert("value".to_string(), CanonicalValue::I64(request.value));
                    CanonicalValue::Map(req)
                })
                .collect(),
        ),
    );

    map.insert(
        "subscriptions".to_string(),
        CanonicalValue::Array(
            scenario
                .subscriptions
                .iter()
                .map(|subscription| {
                    let mut s = BTreeMap::new();
                    s.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(subscription.controller_id.clone()),
                    );
                    s.insert(
                        "metric".to_string(),
                        CanonicalValue::String(subscription.metric.clone()),
                    );
                    CanonicalValue::Map(s)
                })
                .collect(),
        ),
    );

    CanonicalValue::Map(map)
}

fn lookup_registration<'a>(
    registrations: &'a BTreeMap<String, &'a ControllerRegistration>,
    controller_id: &str,
) -> Option<&'a ControllerRegistration> {
    registrations.get(controller_id).copied()
}

/// Evaluate shared metric access with deterministic conflict handling.
pub fn evaluate_controller_interference(
    scenario: &InterferenceScenario<'_>,
) -> InterferenceEvaluation {
    let input_hash = hash_bytes(&deterministic_serde::encode_value(&CanonicalValue::Array(
        vec![
            CanonicalValue::Bytes(CONTROLLER_INTERFERENCE_GUARD_DOMAIN.to_vec()),
            evaluate_canonical_value(scenario),
        ],
    )));
    let decision_id = format!("ctrl-interference-{}", to_hex(&input_hash[..16]));

    let mut logs = Vec::new();
    let mut findings = Vec::new();
    let mut final_metrics = scenario.initial_metrics.clone();
    let mut read_snapshots = BTreeMap::new();
    let mut applied_writes = Vec::new();
    let mut rejected_writes = Vec::new();
    let mut resolutions = Vec::new();
    let mut subscription_streams: BTreeMap<String, Vec<MetricUpdate>> = BTreeMap::new();

    let mut registration_index = BTreeMap::new();
    for registration in scenario.registrations {
        if registration_index
            .insert(registration.controller_id.clone(), registration)
            .is_some()
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::DuplicateController,
                metric: None,
                controller_ids: vec![registration.controller_id.clone()],
                detail: "duplicate controller registration".to_string(),
            });
            continue;
        }

        if registration.timescale.statement.trim().is_empty() {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::MissingTimescaleStatement,
                metric: None,
                controller_ids: vec![registration.controller_id.clone()],
                detail: "timescale statement must be present".to_string(),
            });
        }

        if registration.timescale.observation_interval_millionths <= 0
            || registration.timescale.write_interval_millionths <= 0
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::InvalidTimescaleInterval,
                metric: None,
                controller_ids: vec![registration.controller_id.clone()],
                detail: "timescale intervals must be positive".to_string(),
            });
        }
    }

    let mut writes_by_metric: BTreeMap<String, Vec<MetricWriteRequest>> = BTreeMap::new();
    for write in scenario.write_requests {
        let Some(registration) = lookup_registration(&registration_index, &write.controller_id)
        else {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnknownController,
                metric: Some(write.metric.clone()),
                controller_ids: vec![write.controller_id.clone()],
                detail: "write request references unknown controller".to_string(),
            });
            rejected_writes.push(write.clone());
            continue;
        };

        if !registration.write_metrics.contains(&write.metric) {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnauthorizedWrite,
                metric: Some(write.metric.clone()),
                controller_ids: vec![write.controller_id.clone()],
                detail: "controller not authorized to write metric".to_string(),
            });
            rejected_writes.push(write.clone());
            continue;
        }

        writes_by_metric
            .entry(write.metric.clone())
            .or_default()
            .push(write.clone());
    }

    for read in scenario.read_requests {
        let Some(registration) = lookup_registration(&registration_index, &read.controller_id)
        else {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnknownController,
                metric: Some(read.metric.clone()),
                controller_ids: vec![read.controller_id.clone()],
                detail: "read request references unknown controller".to_string(),
            });
            continue;
        };

        if !(registration.read_metrics.contains(&read.metric)
            || registration.write_metrics.contains(&read.metric))
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnauthorizedRead,
                metric: Some(read.metric.clone()),
                controller_ids: vec![read.controller_id.clone()],
                detail: "controller not authorized to read metric".to_string(),
            });
            continue;
        }

        let snapshot_key = format!("{}:{}", read.controller_id, read.metric);
        let snapshot_value = scenario
            .initial_metrics
            .get(&read.metric)
            .copied()
            .unwrap_or(0);
        read_snapshots.insert(snapshot_key, snapshot_value);

        logs.push(InterferenceLogEvent {
            trace_id: scenario.trace_id.to_string(),
            decision_id: decision_id.clone(),
            policy_id: scenario.policy_id.to_string(),
            component: "controller_interference_guard".to_string(),
            event: "read_snapshot".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            metric: Some(read.metric.clone()),
            controller_ids: vec![read.controller_id.clone()],
        });
    }

    for (metric, mut writes) in writes_by_metric {
        writes.sort_by(|left, right| left.controller_id.cmp(&right.controller_id));

        if writes.len() > 1 {
            let mut conflicting_pair: Option<(String, String, i64)> = None;
            for i in 0..writes.len() {
                for j in (i + 1)..writes.len() {
                    let left_reg =
                        lookup_registration(&registration_index, &writes[i].controller_id)
                            .expect("registration must exist");
                    let right_reg =
                        lookup_registration(&registration_index, &writes[j].controller_id)
                            .expect("registration must exist");
                    let separation = left_reg
                        .timescale
                        .write_interval_millionths
                        .abs_diff(right_reg.timescale.write_interval_millionths)
                        as i64;
                    if separation < scenario.config.min_timescale_separation_millionths {
                        conflicting_pair = Some((
                            writes[i].controller_id.clone(),
                            writes[j].controller_id.clone(),
                            separation,
                        ));
                        break;
                    }
                }
                if conflicting_pair.is_some() {
                    break;
                }
            }

            if let Some((left_id, right_id, separation)) = conflicting_pair {
                match scenario.config.conflict_resolution_mode {
                    ConflictResolutionMode::Reject => {
                        findings.push(InterferenceFinding {
                            code: InterferenceFailureCode::TimescaleConflict,
                            metric: Some(metric.clone()),
                            controller_ids: vec![left_id.clone(), right_id.clone()],
                            detail: format!(
                                "write timescales are too close ({} ppm separation, min {} ppm)",
                                separation, scenario.config.min_timescale_separation_millionths
                            ),
                        });
                        rejected_writes.extend(writes.clone());
                        logs.push(InterferenceLogEvent {
                            trace_id: scenario.trace_id.to_string(),
                            decision_id: decision_id.clone(),
                            policy_id: scenario.policy_id.to_string(),
                            component: "controller_interference_guard".to_string(),
                            event: "timescale_conflict".to_string(),
                            outcome: "fail".to_string(),
                            error_code: Some(
                                InterferenceFailureCode::TimescaleConflict.to_string(),
                            ),
                            metric: Some(metric.clone()),
                            controller_ids: vec![left_id, right_id],
                        });
                        continue;
                    }
                    ConflictResolutionMode::Serialize => {
                        let controller_ids: Vec<String> = writes
                            .iter()
                            .map(|write| write.controller_id.clone())
                            .collect();
                        resolutions.push(InterferenceResolution {
                            metric: metric.clone(),
                            controller_ids: controller_ids.clone(),
                            mode: ConflictResolutionMode::Serialize,
                            detail: format!(
                                "serialized conflicting writes due to {} ppm separation",
                                separation
                            ),
                        });
                        logs.push(InterferenceLogEvent {
                            trace_id: scenario.trace_id.to_string(),
                            decision_id: decision_id.clone(),
                            policy_id: scenario.policy_id.to_string(),
                            component: "controller_interference_guard".to_string(),
                            event: "write_conflict_serialized".to_string(),
                            outcome: "pass".to_string(),
                            error_code: None,
                            metric: Some(metric.clone()),
                            controller_ids,
                        });
                    }
                }
            }
        }

        for write in writes {
            final_metrics.insert(metric.clone(), write.value);
            applied_writes.push(write);
        }
    }

    let mut update_sequence = 0u64;
    let mut sorted_subscriptions = scenario.subscriptions.to_vec();
    sorted_subscriptions.sort_by(|left, right| {
        left.controller_id
            .cmp(&right.controller_id)
            .then(left.metric.cmp(&right.metric))
    });
    for subscription in sorted_subscriptions {
        let Some(registration) =
            lookup_registration(&registration_index, &subscription.controller_id)
        else {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnknownController,
                metric: Some(subscription.metric.clone()),
                controller_ids: vec![subscription.controller_id.clone()],
                detail: "subscription references unknown controller".to_string(),
            });
            continue;
        };
        if !(registration.read_metrics.contains(&subscription.metric)
            || registration.write_metrics.contains(&subscription.metric))
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnauthorizedRead,
                metric: Some(subscription.metric.clone()),
                controller_ids: vec![subscription.controller_id.clone()],
                detail: "subscription for unauthorized metric".to_string(),
            });
            continue;
        }

        if let Some(value) = final_metrics.get(&subscription.metric) {
            update_sequence = update_sequence.saturating_add(1);
            let update = MetricUpdate {
                sequence: update_sequence,
                metric: subscription.metric.clone(),
                value: *value,
            };
            subscription_streams
                .entry(subscription.controller_id.clone())
                .or_default()
                .push(update);
        }
    }

    let pass = findings.is_empty();
    logs.push(InterferenceLogEvent {
        trace_id: scenario.trace_id.to_string(),
        decision_id: decision_id.clone(),
        policy_id: scenario.policy_id.to_string(),
        component: "controller_interference_guard".to_string(),
        event: "interference_summary".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if pass {
            None
        } else {
            Some("controller_interference_failed".to_string())
        },
        metric: None,
        controller_ids: Vec::new(),
    });

    InterferenceEvaluation {
        decision_id,
        pass,
        rollback_required: !pass,
        read_snapshots,
        applied_writes,
        rejected_writes,
        resolutions,
        subscription_streams,
        final_metrics,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(
        id: &str,
        read_metrics: &[&str],
        write_metrics: &[&str],
        observation_interval_millionths: i64,
        write_interval_millionths: i64,
        statement: &str,
    ) -> ControllerRegistration {
        ControllerRegistration {
            controller_id: id.to_string(),
            read_metrics: read_metrics
                .iter()
                .map(|metric| (*metric).to_string())
                .collect(),
            write_metrics: write_metrics
                .iter()
                .map(|metric| (*metric).to_string())
                .collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths,
                write_interval_millionths,
                statement: statement.to_string(),
            },
        }
    }

    fn initial_metrics() -> BTreeMap<String, i64> {
        BTreeMap::from([
            ("cpu".to_string(), 10),
            ("latency".to_string(), 100),
            ("throughput".to_string(), 1_000),
        ])
    }

    fn scenario<'a>(
        trace_id: &'a str,
        policy_id: &'a str,
        config: &'a InterferenceConfig,
        registrations: &'a [ControllerRegistration],
        metric_ops: (
            &'a [MetricReadRequest],
            &'a [MetricWriteRequest],
            &'a [MetricSubscription],
        ),
        initial_metrics: &'a BTreeMap<String, i64>,
    ) -> InterferenceScenario<'a> {
        let (read_requests, write_requests, subscriptions) = metric_ops;
        InterferenceScenario {
            trace_id,
            policy_id,
            config,
            registrations,
            read_requests,
            write_requests,
            subscriptions,
            initial_metrics,
        }
    }

    #[test]
    fn concurrent_reads_observe_consistent_snapshots() {
        let registrations = vec![
            registration(
                "ctrl-a",
                &["cpu"],
                &[],
                1_000_000,
                2_000_000,
                "reads every 1s",
            ),
            registration(
                "ctrl-b",
                &["cpu"],
                &[],
                500_000,
                2_500_000,
                "reads every 500ms",
            ),
        ];

        let config = InterferenceConfig::default();
        let read_requests = [
            MetricReadRequest {
                controller_id: "ctrl-a".to_string(),
                metric: "cpu".to_string(),
            },
            MetricReadRequest {
                controller_id: "ctrl-b".to_string(),
                metric: "cpu".to_string(),
            },
        ];
        let write_requests: [MetricWriteRequest; 0] = [];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-read",
            "policy-read",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.read_snapshots.get("ctrl-a:cpu"), Some(&10));
        assert_eq!(evaluation.read_snapshots.get("ctrl-b:cpu"), Some(&10));
    }

    #[test]
    fn timescale_conflict_rejects_writes_when_policy_requires_reject() {
        let registrations = vec![
            registration(
                "writer-a",
                &["throughput"],
                &["throughput"],
                100_000,
                100_000,
                "writes every 100ms",
            ),
            registration(
                "writer-b",
                &["throughput"],
                &["throughput"],
                120_000,
                120_000,
                "writes every 120ms",
            ),
        ];

        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests = [
            MetricWriteRequest {
                controller_id: "writer-a".to_string(),
                metric: "throughput".to_string(),
                value: 900,
            },
            MetricWriteRequest {
                controller_id: "writer-b".to_string(),
                metric: "throughput".to_string(),
                value: 700,
            },
        ];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-conflict",
            "policy-conflict",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(!evaluation.pass);
        assert!(evaluation.rollback_required);
        assert_eq!(evaluation.applied_writes.len(), 0);
        assert_eq!(evaluation.rejected_writes.len(), 2);
        assert!(evaluation.findings.iter().any(|finding| {
            finding.code == InterferenceFailureCode::TimescaleConflict
                && finding.metric.as_deref() == Some("throughput")
        }));
    }

    #[test]
    fn timescale_conflict_can_serialize_writes_when_policy_allows() {
        let registrations = vec![
            registration(
                "writer-b",
                &["latency"],
                &["latency"],
                100_000,
                100_000,
                "writes every 100ms",
            ),
            registration(
                "writer-a",
                &["latency"],
                &["latency"],
                120_000,
                120_000,
                "writes every 120ms",
            ),
        ];

        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Serialize,
        };
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests = [
            MetricWriteRequest {
                controller_id: "writer-b".to_string(),
                metric: "latency".to_string(),
                value: 77,
            },
            MetricWriteRequest {
                controller_id: "writer-a".to_string(),
                metric: "latency".to_string(),
                value: 88,
            },
        ];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-serialize",
            "policy-serialize",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.rejected_writes.len(), 0);
        assert_eq!(evaluation.applied_writes.len(), 2);
        assert_eq!(evaluation.final_metrics.get("latency"), Some(&77));
        assert_eq!(evaluation.resolutions.len(), 1);
        assert_eq!(
            evaluation.resolutions[0].mode,
            ConflictResolutionMode::Serialize
        );
    }

    #[test]
    fn read_while_write_preserves_snapshot_isolation() {
        let registrations = vec![
            registration(
                "reader",
                &["cpu"],
                &[],
                200_000,
                2_000_000,
                "reads every 200ms",
            ),
            registration(
                "writer",
                &["cpu"],
                &["cpu"],
                1_000_000,
                1_000_000,
                "writes every 1s",
            ),
        ];

        let config = InterferenceConfig::default();
        let read_requests = [MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "cpu".to_string(),
        }];
        let write_requests = [MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "cpu".to_string(),
            value: 42,
        }];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-rw",
            "policy-rw",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.read_snapshots.get("reader:cpu"), Some(&10));
        assert_eq!(evaluation.final_metrics.get("cpu"), Some(&42));
    }

    #[test]
    fn subscriptions_receive_isolated_deterministic_updates() {
        let registrations = vec![
            registration(
                "sub-a",
                &["throughput"],
                &[],
                250_000,
                2_000_000,
                "subscribes every 250ms",
            ),
            registration(
                "sub-b",
                &["throughput"],
                &[],
                500_000,
                2_000_000,
                "subscribes every 500ms",
            ),
            registration(
                "writer",
                &["throughput"],
                &["throughput"],
                1_000_000,
                1_000_000,
                "writes every 1s",
            ),
        ];

        let config = InterferenceConfig::default();
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests = [MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "throughput".to_string(),
            value: 2_000,
        }];
        let subscriptions = [
            MetricSubscription {
                controller_id: "sub-b".to_string(),
                metric: "throughput".to_string(),
            },
            MetricSubscription {
                controller_id: "sub-a".to_string(),
                metric: "throughput".to_string(),
            },
        ];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-sub",
            "policy-sub",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.subscription_streams.len(), 2);
        assert_eq!(
            evaluation
                .subscription_streams
                .get("sub-a")
                .and_then(|updates| updates.first())
                .map(|update| update.value),
            Some(2_000)
        );
        assert_eq!(
            evaluation
                .subscription_streams
                .get("sub-b")
                .and_then(|updates| updates.first())
                .map(|update| update.value),
            Some(2_000)
        );
    }

    #[test]
    fn missing_timescale_statement_fails_closed() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "   ",
        )];

        let config = InterferenceConfig::default();
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests: [MetricWriteRequest; 0] = [];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "trace-invalid",
            "policy-invalid",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(!evaluation.pass);
        assert!(evaluation.rollback_required);
        assert!(
            evaluation.findings.iter().any(|finding| {
                finding.code == InterferenceFailureCode::MissingTimescaleStatement
            })
        );
    }

    // ── ConflictResolutionMode ───────────────────────────────────────

    #[test]
    fn conflict_resolution_mode_display() {
        assert_eq!(ConflictResolutionMode::Serialize.to_string(), "serialize");
        assert_eq!(ConflictResolutionMode::Reject.to_string(), "reject");
    }

    #[test]
    fn conflict_resolution_mode_serde_roundtrip() {
        for mode in [
            ConflictResolutionMode::Serialize,
            ConflictResolutionMode::Reject,
        ] {
            let json = serde_json::to_string(&mode).expect("serialize derived Serialize");
            let back: ConflictResolutionMode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, mode);
        }
    }

    // ── InterferenceConfig ───────────────────────────────────────────

    #[test]
    fn interference_config_default_values() {
        let config = InterferenceConfig::default();
        assert_eq!(config.min_timescale_separation_millionths, 100_000);
        assert_eq!(
            config.conflict_resolution_mode,
            ConflictResolutionMode::Reject
        );
    }

    #[test]
    fn interference_config_serde_roundtrip() {
        let config = InterferenceConfig::default();
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let back: InterferenceConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, config);
    }

    // ── InterferenceFailureCode ──────────────────────────────────────

    #[test]
    fn failure_code_display_all_variants() {
        assert_eq!(
            InterferenceFailureCode::DuplicateController.to_string(),
            "duplicate_controller"
        );
        assert_eq!(
            InterferenceFailureCode::MissingTimescaleStatement.to_string(),
            "missing_timescale_statement"
        );
        assert_eq!(
            InterferenceFailureCode::InvalidTimescaleInterval.to_string(),
            "invalid_timescale_interval"
        );
        assert_eq!(
            InterferenceFailureCode::UnknownController.to_string(),
            "unknown_controller"
        );
        assert_eq!(
            InterferenceFailureCode::UnauthorizedRead.to_string(),
            "unauthorized_read"
        );
        assert_eq!(
            InterferenceFailureCode::UnauthorizedWrite.to_string(),
            "unauthorized_write"
        );
        assert_eq!(
            InterferenceFailureCode::TimescaleConflict.to_string(),
            "timescale_conflict"
        );
    }

    #[test]
    fn failure_code_ordering() {
        assert!(
            InterferenceFailureCode::DuplicateController
                < InterferenceFailureCode::TimescaleConflict
        );
    }

    #[test]
    fn failure_code_serde_roundtrip() {
        for code in [
            InterferenceFailureCode::DuplicateController,
            InterferenceFailureCode::MissingTimescaleStatement,
            InterferenceFailureCode::InvalidTimescaleInterval,
            InterferenceFailureCode::UnknownController,
            InterferenceFailureCode::UnauthorizedRead,
            InterferenceFailureCode::UnauthorizedWrite,
            InterferenceFailureCode::TimescaleConflict,
        ] {
            let json = serde_json::to_string(&code).expect("serialize derived Serialize");
            let back: InterferenceFailureCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, code);
        }
    }

    // ── Duplicate controller ─────────────────────────────────────────

    #[test]
    fn duplicate_controller_registration_produces_finding() {
        let registrations = vec![
            registration("ctrl-a", &["cpu"], &[], 1_000_000, 1_000_000, "first"),
            registration("ctrl-a", &["cpu"], &[], 2_000_000, 2_000_000, "second"),
        ];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(evaluation.findings.iter().any(|f| {
            f.code == InterferenceFailureCode::DuplicateController
                && f.controller_ids.contains(&"ctrl-a".to_string())
        }));
    }

    // ── Invalid timescale intervals ──────────────────────────────────

    #[test]
    fn zero_observation_interval_produces_finding() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            0,
            1_000_000,
            "valid statement",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert!(
            evaluation
                .findings
                .iter()
                .any(|f| { f.code == InterferenceFailureCode::InvalidTimescaleInterval })
        );
    }

    #[test]
    fn negative_write_interval_produces_finding() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            -1,
            "valid statement",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert!(
            evaluation
                .findings
                .iter()
                .any(|f| { f.code == InterferenceFailureCode::InvalidTimescaleInterval })
        );
    }

    // ── Unknown controller ───────────────────────────────────────────

    #[test]
    fn unknown_controller_write_rejected() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let writes = [MetricWriteRequest {
            controller_id: "unknown".into(),
            metric: "cpu".into(),
            value: 42,
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(
            evaluation
                .rejected_writes
                .iter()
                .any(|w| w.controller_id == "unknown")
        );
        assert!(evaluation.findings.iter().any(|f| {
            f.code == InterferenceFailureCode::UnknownController && f.detail.contains("write")
        }));
    }

    #[test]
    fn unknown_controller_read_produces_finding() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let reads = [MetricReadRequest {
            controller_id: "unknown".into(),
            metric: "cpu".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &[], &[]),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(evaluation.findings.iter().any(|f| {
            f.code == InterferenceFailureCode::UnknownController && f.detail.contains("read")
        }));
    }

    #[test]
    fn unknown_controller_subscription_produces_finding() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let subs = [MetricSubscription {
            controller_id: "unknown".into(),
            metric: "cpu".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &subs),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(evaluation.findings.iter().any(|f| {
            f.code == InterferenceFailureCode::UnknownController
                && f.detail.contains("subscription")
        }));
    }

    // ── Unauthorized access ──────────────────────────────────────────

    #[test]
    fn unauthorized_write_rejected() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "read-only",
        )];
        let writes = [MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
            value: 42,
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(evaluation.rejected_writes.len() == 1);
        assert!(
            evaluation
                .findings
                .iter()
                .any(|f| { f.code == InterferenceFailureCode::UnauthorizedWrite })
        );
    }

    #[test]
    fn unauthorized_read_produces_finding() {
        let registrations = vec![registration(
            "ctrl-a",
            &[],
            &["cpu"],
            1_000_000,
            1_000_000,
            "write-only",
        )];
        let reads = [MetricReadRequest {
            controller_id: "ctrl-a".into(),
            metric: "latency".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &[], &[]),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(
            evaluation
                .findings
                .iter()
                .any(|f| { f.code == InterferenceFailureCode::UnauthorizedRead })
        );
    }

    #[test]
    fn unauthorized_subscription_produces_finding() {
        let registrations = vec![registration(
            "ctrl-a",
            &[],
            &["cpu"],
            1_000_000,
            1_000_000,
            "write-only",
        )];
        let subs = [MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "latency".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &subs),
            &metrics,
        ));
        assert!(!evaluation.pass);
        assert!(evaluation.findings.iter().any(|f| {
            f.code == InterferenceFailureCode::UnauthorizedRead && f.detail.contains("subscription")
        }));
    }

    // ── Read from write_metrics is allowed ───────────────────────────

    #[test]
    fn read_allowed_via_write_metrics() {
        let registrations = vec![registration(
            "ctrl-a",
            &[],
            &["cpu"],
            1_000_000,
            1_000_000,
            "writer reads own metric",
        )];
        let reads = [MetricReadRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &[], &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert_eq!(evaluation.read_snapshots.get("ctrl-a:cpu"), Some(&10));
    }

    // ── Decision ID ──────────────────────────────────────────────────

    #[test]
    fn decision_id_deterministic() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let a = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        let b = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert_eq!(a.decision_id, b.decision_id);
        assert!(a.decision_id.starts_with("ctrl-interference-"));
    }

    #[test]
    fn decision_id_changes_with_input() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let a = evaluate_controller_interference(&scenario(
            "trace-1",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        let b = evaluate_controller_interference(&scenario(
            "trace-2",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert_ne!(a.decision_id, b.decision_id);
    }

    // ── Logs ─────────────────────────────────────────────────────────

    #[test]
    fn logs_always_include_summary_event() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        let summary = evaluation
            .logs
            .last()
            .expect("operation should succeed for valid inputs");
        assert_eq!(summary.event, "interference_summary");
        assert_eq!(summary.outcome, "pass");
        assert!(summary.error_code.is_none());
    }

    #[test]
    fn logs_summary_fails_when_findings_present() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "  ",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        let summary = evaluation
            .logs
            .last()
            .expect("operation should succeed for valid inputs");
        assert_eq!(summary.outcome, "fail");
        assert!(summary.error_code.is_some());
    }

    #[test]
    fn logs_carry_trace_and_policy_ids() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "my-trace",
            "my-policy",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        for log in &evaluation.logs {
            assert_eq!(log.trace_id, "my-trace");
            assert_eq!(log.policy_id, "my-policy");
            assert_eq!(log.component, "controller_interference_guard");
        }
    }

    // ── Write without conflict ───────────────────────────────────────

    #[test]
    fn well_separated_writers_no_conflict() {
        let registrations = vec![
            registration("fast", &[], &["cpu"], 100_000, 100_000, "100ms"),
            registration("slow", &[], &["cpu"], 1_000_000, 1_000_000, "1s"),
        ];
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let writes = [
            MetricWriteRequest {
                controller_id: "fast".into(),
                metric: "cpu".into(),
                value: 50,
            },
            MetricWriteRequest {
                controller_id: "slow".into(),
                metric: "cpu".into(),
                value: 60,
            },
        ];
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert_eq!(evaluation.applied_writes.len(), 2);
        assert!(evaluation.rejected_writes.is_empty());
        assert!(evaluation.resolutions.is_empty());
    }

    // ── Subscription for metric not written ──────────────────────────

    #[test]
    fn subscription_for_missing_metric_no_update() {
        let registrations = vec![registration(
            "ctrl-a",
            &["nonexistent"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let subs = [MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "nonexistent".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &subs),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert!(
            evaluation
                .subscription_streams
                .get("ctrl-a")
                .is_none_or(|s| s.is_empty())
        );
    }

    // ── Empty scenario ───────────────────────────────────────────────

    #[test]
    fn empty_scenario_passes() {
        let config = InterferenceConfig::default();
        let metrics = BTreeMap::new();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &[],
            (&[], &[], &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert!(!evaluation.rollback_required);
        assert!(evaluation.findings.is_empty());
    }

    // ── pass/rollback symmetry ───────────────────────────────────────

    #[test]
    fn pass_and_rollback_are_inverse() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert_eq!(evaluation.pass, !evaluation.rollback_required);
    }

    // ── Serde roundtrips ─────────────────────────────────────────────

    #[test]
    fn evaluation_serde_roundtrip() {
        let registrations = vec![
            registration("ctrl-a", &["cpu"], &["cpu"], 1_000_000, 1_000_000, "ok"),
            registration("ctrl-b", &["cpu"], &[], 500_000, 2_000_000, "ok"),
        ];
        let reads = [MetricReadRequest {
            controller_id: "ctrl-b".into(),
            metric: "cpu".into(),
        }];
        let writes = [MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
            value: 99,
        }];
        let subs = [MetricSubscription {
            controller_id: "ctrl-b".into(),
            metric: "cpu".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &writes, &subs),
            &metrics,
        ));
        let json = serde_json::to_string(&evaluation).expect("serialize derived Serialize");
        let back: InterferenceEvaluation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.decision_id, evaluation.decision_id);
        assert_eq!(back.pass, evaluation.pass);
        assert_eq!(back.final_metrics, evaluation.final_metrics);
        assert_eq!(back.findings, evaluation.findings);
    }

    #[test]
    fn finding_serde_roundtrip() {
        let finding = InterferenceFinding {
            code: InterferenceFailureCode::UnauthorizedWrite,
            metric: Some("cpu".into()),
            controller_ids: vec!["ctrl-a".into()],
            detail: "test".into(),
        };
        let json = serde_json::to_string(&finding).expect("serialize derived Serialize");
        let back: InterferenceFinding =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, finding);
    }

    #[test]
    fn log_event_serde_roundtrip() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        for log in &evaluation.logs {
            let json = serde_json::to_string(log).expect("serialize derived Serialize");
            let back: InterferenceLogEvent =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&back, log);
        }
    }

    #[test]
    fn registration_serde_roundtrip() {
        let reg = registration(
            "ctrl-a",
            &["cpu", "mem"],
            &["disk"],
            1_000_000,
            500_000,
            "ok",
        );
        let json = serde_json::to_string(&reg).expect("serialize derived Serialize");
        let back: ControllerRegistration =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, reg);
    }

    #[test]
    fn metric_update_serde_roundtrip() {
        let update = MetricUpdate {
            sequence: 42,
            metric: "cpu".into(),
            value: 100,
        };
        let json = serde_json::to_string(&update).expect("serialize derived Serialize");
        let back: MetricUpdate = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, update);
    }

    // ── Final metrics reflect writes ─────────────────────────────────

    #[test]
    fn final_metrics_include_initial_plus_writes() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let writes = [MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
            value: 99,
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert_eq!(evaluation.final_metrics.get("cpu"), Some(&99));
        // Other initial metrics preserved
        assert_eq!(evaluation.final_metrics.get("latency"), Some(&100));
        assert_eq!(evaluation.final_metrics.get("throughput"), Some(&1_000));
    }

    // ── Subscription sequence numbering ──────────────────────────────

    #[test]
    fn subscription_updates_have_sequential_numbers() {
        let registrations = vec![
            registration(
                "sub-a",
                &["cpu", "latency"],
                &[],
                1_000_000,
                2_000_000,
                "ok",
            ),
            registration(
                "writer",
                &[],
                &["cpu", "latency"],
                1_000_000,
                1_000_000,
                "ok",
            ),
        ];
        let writes = [
            MetricWriteRequest {
                controller_id: "writer".into(),
                metric: "cpu".into(),
                value: 50,
            },
            MetricWriteRequest {
                controller_id: "writer".into(),
                metric: "latency".into(),
                value: 200,
            },
        ];
        let subs = [
            MetricSubscription {
                controller_id: "sub-a".into(),
                metric: "cpu".into(),
            },
            MetricSubscription {
                controller_id: "sub-a".into(),
                metric: "latency".into(),
            },
        ];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &subs),
            &metrics,
        ));
        let updates = evaluation
            .subscription_streams
            .get("sub-a")
            .expect("operation should succeed for valid inputs");
        assert_eq!(updates.len(), 2);
        assert!(updates[0].sequence < updates[1].sequence);
        assert_eq!(updates[0].sequence, 1);
    }

    // ── Serde roundtrips (enrichment) ─────────────────────────────

    #[test]
    fn timescale_separation_statement_serde_roundtrip_enrichment() {
        let ts = TimescaleSeparationStatement {
            observation_interval_millionths: 500_000,
            write_interval_millionths: 1_000_000,
            statement: "every 500ms observe, every 1s write".to_string(),
        };
        let json = serde_json::to_string(&ts).expect("serialize derived Serialize");
        let back: TimescaleSeparationStatement =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, ts);
    }

    #[test]
    fn metric_read_request_serde_roundtrip_enrichment() {
        let req = MetricReadRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        };
        let json = serde_json::to_string(&req).expect("serialize derived Serialize");
        let back: MetricReadRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, req);
    }

    #[test]
    fn metric_write_request_serde_roundtrip_enrichment() {
        let req = MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
            value: 42,
        };
        let json = serde_json::to_string(&req).expect("serialize derived Serialize");
        let back: MetricWriteRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, req);
    }

    #[test]
    fn metric_subscription_serde_roundtrip_enrichment() {
        let sub = MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        };
        let json = serde_json::to_string(&sub).expect("serialize derived Serialize");
        let back: MetricSubscription =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, sub);
    }

    #[test]
    fn interference_resolution_serde_roundtrip() {
        let res = InterferenceResolution {
            metric: "cpu".into(),
            controller_ids: vec!["ctrl-a".into(), "ctrl-b".into()],
            mode: ConflictResolutionMode::Serialize,
            detail: "serialized writes".into(),
        };
        let json = serde_json::to_string(&res).expect("serialize derived Serialize");
        let back: InterferenceResolution =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, res);
    }

    // ── Edge cases (enrichment) ───────────────────────────────────

    #[test]
    fn read_nonexistent_metric_returns_zero() {
        let registrations = vec![registration(
            "ctrl-a",
            &["ghost"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let reads = [MetricReadRequest {
            controller_id: "ctrl-a".into(),
            metric: "ghost".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics(); // does not contain "ghost"
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &[], &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert_eq!(evaluation.read_snapshots.get("ctrl-a:ghost"), Some(&0));
    }

    #[test]
    fn write_to_new_metric_adds_to_final_metrics() {
        let registrations = vec![registration(
            "ctrl-a",
            &[],
            &["new_metric"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let writes = [MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "new_metric".into(),
            value: 777,
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert_eq!(evaluation.final_metrics.get("new_metric"), Some(&777));
    }

    #[test]
    fn subscription_via_write_metrics_allowed() {
        let registrations = vec![registration(
            "writer",
            &[],
            &["cpu"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let writes = [MetricWriteRequest {
            controller_id: "writer".into(),
            metric: "cpu".into(),
            value: 55,
        }];
        let subs = [MetricSubscription {
            controller_id: "writer".into(),
            metric: "cpu".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &subs),
            &metrics,
        ));
        assert!(evaluation.pass);
        let updates = evaluation
            .subscription_streams
            .get("writer")
            .expect("operation should succeed for valid inputs");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].value, 55);
    }

    #[test]
    fn multiple_findings_accumulate() {
        // Duplicate + missing timescale + invalid interval all at once
        let registrations = vec![
            registration("ctrl-a", &["cpu"], &[], 0, 1_000_000, "   "),
            registration("ctrl-a", &["cpu"], &[], 1_000_000, 1_000_000, "dupe"),
        ];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert!(!evaluation.pass);
        // At least duplicate + missing timescale + invalid interval
        assert!(
            evaluation.findings.len() >= 3,
            "got {} findings",
            evaluation.findings.len()
        );
        let codes: BTreeSet<_> = evaluation.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&InterferenceFailureCode::DuplicateController));
        assert!(codes.contains(&InterferenceFailureCode::MissingTimescaleStatement));
        assert!(codes.contains(&InterferenceFailureCode::InvalidTimescaleInterval));
    }

    #[test]
    fn single_writer_no_conflict() {
        let registrations = vec![registration(
            "solo",
            &[],
            &["cpu"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let writes = [MetricWriteRequest {
            controller_id: "solo".into(),
            metric: "cpu".into(),
            value: 42,
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert_eq!(evaluation.applied_writes.len(), 1);
        assert!(evaluation.resolutions.is_empty());
    }

    #[test]
    fn interference_config_custom_serde_roundtrip() {
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 500_000,
            conflict_resolution_mode: ConflictResolutionMode::Serialize,
        };
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let back: InterferenceConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, config);
    }

    #[test]
    fn writers_on_different_metrics_no_conflict() {
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 100_000, 100_000, "fast cpu"),
            registration(
                "ctrl-b",
                &[],
                &["latency"],
                100_000,
                100_000,
                "fast latency",
            ),
        ];
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 50,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "latency".into(),
                value: 200,
            },
        ];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(evaluation.pass);
        assert_eq!(evaluation.applied_writes.len(), 2);
        assert_eq!(evaluation.final_metrics.get("cpu"), Some(&50));
        assert_eq!(evaluation.final_metrics.get("latency"), Some(&200));
    }

    // -- Enrichment: helper function coverage --

    #[test]
    fn to_hex_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_known_bytes() {
        assert_eq!(to_hex(&[0x00, 0xff, 0x0a, 0xde]), "00ff0ade");
    }

    #[test]
    fn hash_bytes_deterministic() {
        let a = hash_bytes(b"hello");
        let b = hash_bytes(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_bytes_different_inputs_differ() {
        let a = hash_bytes(b"hello");
        let b = hash_bytes(b"world");
        assert_ne!(a, b);
    }

    // -- Enrichment: ConflictResolutionMode coverage --

    #[test]
    fn conflict_resolution_mode_display_serialize() {
        assert_eq!(ConflictResolutionMode::Serialize.to_string(), "serialize");
    }

    #[test]
    fn conflict_resolution_mode_display_reject() {
        assert_eq!(ConflictResolutionMode::Reject.to_string(), "reject");
    }

    // -- Enrichment: InterferenceConfig default --

    #[test]
    fn interference_config_default_reject_mode() {
        let config = InterferenceConfig::default();
        assert_eq!(
            config.conflict_resolution_mode,
            ConflictResolutionMode::Reject
        );
    }

    #[test]
    fn interference_config_default_min_separation() {
        let config = InterferenceConfig::default();
        assert_eq!(config.min_timescale_separation_millionths, 100_000);
    }

    // -- Enrichment: InterferenceFailureCode Display all distinct --

    #[test]
    fn failure_code_display_all_distinct() {
        let codes = [
            InterferenceFailureCode::DuplicateController,
            InterferenceFailureCode::MissingTimescaleStatement,
            InterferenceFailureCode::InvalidTimescaleInterval,
            InterferenceFailureCode::UnknownController,
            InterferenceFailureCode::UnauthorizedRead,
            InterferenceFailureCode::UnauthorizedWrite,
            InterferenceFailureCode::TimescaleConflict,
        ];
        let strs: BTreeSet<String> = codes.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            strs.len(),
            codes.len(),
            "all failure codes produce distinct Display strings"
        );
    }

    // -- Enrichment: subscription ordering is deterministic --

    #[test]
    fn subscription_ordering_deterministic_across_controllers() {
        let registrations = vec![
            registration("ctrl-z", &["cpu", "mem"], &[], 1_000_000, 1_000_000, "ok"),
            registration("ctrl-a", &["cpu", "mem"], &[], 1_000_000, 1_000_000, "ok"),
        ];
        let subs = [
            MetricSubscription {
                controller_id: "ctrl-z".into(),
                metric: "cpu".into(),
            },
            MetricSubscription {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
            },
            MetricSubscription {
                controller_id: "ctrl-a".into(),
                metric: "mem".into(),
            },
        ];
        let config = InterferenceConfig::default();
        let mut metrics = initial_metrics();
        metrics.insert("mem".into(), 8192);
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &subs),
            &metrics,
        ));
        assert!(eval.pass);
        // ctrl-a comes before ctrl-z in sorted order
        let ctrl_a_updates = eval
            .subscription_streams
            .get("ctrl-a")
            .expect("operation should succeed for valid inputs");
        let ctrl_z_updates = eval
            .subscription_streams
            .get("ctrl-z")
            .expect("operation should succeed for valid inputs");
        assert_eq!(ctrl_a_updates.len(), 2);
        assert_eq!(ctrl_z_updates.len(), 1);
        // ctrl-a gets cpu (seq 1), mem (seq 2) before ctrl-z cpu (seq 3)
        assert_eq!(ctrl_a_updates[0].sequence, 1);
        assert_eq!(ctrl_a_updates[0].metric, "cpu");
        assert_eq!(ctrl_a_updates[1].sequence, 2);
        assert_eq!(ctrl_a_updates[1].metric, "mem");
        assert_eq!(ctrl_z_updates[0].sequence, 3);
    }

    // -- Enrichment: boundary timescale separation --

    #[test]
    fn timescale_exactly_at_min_separation_passes() {
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 200_000, "ok"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_000, "ok"),
        ];
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 10,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 20,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(eval.pass);
        assert_eq!(eval.applied_writes.len(), 2);
    }

    #[test]
    fn timescale_one_below_min_separation_conflicts() {
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 200_000, "ok"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_001, "ok"),
        ];
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 10,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 20,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(!eval.pass);
        assert!(
            eval.findings
                .iter()
                .any(|f| f.code == InterferenceFailureCode::TimescaleConflict)
        );
    }

    // -- Enrichment: InterferenceLogEvent --

    #[test]
    fn log_event_serde_roundtrip_with_error_code() {
        let log = InterferenceLogEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "comp".to_string(),
            event: "evt".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("err_code".to_string()),
            metric: Some("cpu".to_string()),
            controller_ids: vec!["ctrl-a".to_string()],
        };
        let json = serde_json::to_string(&log).expect("serialize derived Serialize");
        let back: InterferenceLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, log);
    }

    // -- Enrichment: InterferenceResolution serde --

    #[test]
    fn interference_resolution_serde_roundtrip_serialize_mode() {
        let resolution = InterferenceResolution {
            metric: "cpu".into(),
            controller_ids: vec!["a".into(), "b".into()],
            mode: ConflictResolutionMode::Serialize,
            detail: "serialized writes".into(),
        };
        let json = serde_json::to_string(&resolution).expect("serialize derived Serialize");
        let back: InterferenceResolution =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, resolution);
    }

    // -- Enrichment: last write wins semantics --

    #[test]
    fn last_write_wins_for_serialized_same_metric() {
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Serialize,
        };
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 100_000, "fast"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_000, "fast"),
        ];
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 10,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 20,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(eval.pass);
        assert!(!eval.resolutions.is_empty());
        // writes are sorted by controller_id, so ctrl-b writes last
        let final_cpu = eval
            .final_metrics
            .get("cpu")
            .copied()
            .expect("operation should succeed for valid inputs");
        assert_eq!(final_cpu, 20);
    }

    // -- Enrichment: TimescaleSeparationStatement serde with edge values --

    #[test]
    fn timescale_separation_zero_intervals_serde() {
        let ts = TimescaleSeparationStatement {
            observation_interval_millionths: 0,
            write_interval_millionths: 0,
            statement: "zero".to_string(),
        };
        let json = serde_json::to_string(&ts).expect("serialize derived Serialize");
        let back: TimescaleSeparationStatement =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, ts);
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn conflict_resolution_mode_display_unique_in_btreeset() {
        let displays: BTreeSet<String> = [
            ConflictResolutionMode::Serialize,
            ConflictResolutionMode::Reject,
        ]
        .iter()
        .map(|m| m.to_string())
        .collect();
        assert_eq!(displays.len(), 2);
    }

    #[test]
    fn interference_failure_code_display_all_seven_unique() {
        let codes = [
            InterferenceFailureCode::DuplicateController,
            InterferenceFailureCode::MissingTimescaleStatement,
            InterferenceFailureCode::InvalidTimescaleInterval,
            InterferenceFailureCode::UnknownController,
            InterferenceFailureCode::UnauthorizedRead,
            InterferenceFailureCode::UnauthorizedWrite,
            InterferenceFailureCode::TimescaleConflict,
        ];
        let displays: BTreeSet<String> = codes.iter().map(|c| c.to_string()).collect();
        assert_eq!(displays.len(), 7);
    }

    #[test]
    fn interference_failure_code_serde_all_variants() {
        let codes = [
            InterferenceFailureCode::DuplicateController,
            InterferenceFailureCode::MissingTimescaleStatement,
            InterferenceFailureCode::InvalidTimescaleInterval,
            InterferenceFailureCode::UnknownController,
            InterferenceFailureCode::UnauthorizedRead,
            InterferenceFailureCode::UnauthorizedWrite,
            InterferenceFailureCode::TimescaleConflict,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize derived Serialize");
            let back: InterferenceFailureCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*code, back);
        }
    }

    #[test]
    fn conflict_resolution_mode_serde_all_variants() {
        for mode in [
            ConflictResolutionMode::Serialize,
            ConflictResolutionMode::Reject,
        ] {
            let json = serde_json::to_string(&mode).expect("serialize derived Serialize");
            let back: ConflictResolutionMode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn metric_update_ordering_by_sequence() {
        let u1 = MetricUpdate {
            sequence: 1,
            metric: "cpu".into(),
            value: 10,
        };
        let u2 = MetricUpdate {
            sequence: 2,
            metric: "cpu".into(),
            value: 20,
        };
        assert_ne!(u1, u2);
    }

    #[test]
    fn controller_registration_with_empty_sets() {
        let reg = ControllerRegistration {
            controller_id: "empty".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: BTreeSet::new(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 1_000_000,
                statement: "ok".to_string(),
            },
        };
        let json = serde_json::to_string(&reg).expect("serialize derived Serialize");
        let back: ControllerRegistration =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, reg);
        assert!(back.read_metrics.is_empty());
        assert!(back.write_metrics.is_empty());
    }

    #[test]
    fn interference_evaluation_empty_scenario_serializes() {
        let config = InterferenceConfig::default();
        let metrics = BTreeMap::new();
        let evaluation = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &[],
            (&[], &[], &[]),
            &metrics,
        ));
        let json = serde_json::to_string(&evaluation).expect("serialize derived Serialize");
        let back: InterferenceEvaluation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert!(back.pass);
        assert!(back.findings.is_empty());
    }

    #[test]
    fn interference_finding_with_no_metric() {
        let finding = InterferenceFinding {
            code: InterferenceFailureCode::DuplicateController,
            metric: None,
            controller_ids: vec!["ctrl-a".into()],
            detail: "duplicate registration".into(),
        };
        let json = serde_json::to_string(&finding).expect("serialize derived Serialize");
        let back: InterferenceFinding =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.metric, None);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn decision_id_sensitive_to_policy_id() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let a = evaluate_controller_interference(&scenario(
            "t",
            "policy-1",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        let b = evaluate_controller_interference(&scenario(
            "t",
            "policy-2",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn decision_id_sensitive_to_config() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config_a = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let config_b = InterferenceConfig {
            min_timescale_separation_millionths: 200_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let metrics = initial_metrics();
        let a = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config_a,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        let b = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config_b,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn decision_id_sensitive_to_initial_metrics() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let config = InterferenceConfig::default();
        let metrics_a = initial_metrics();
        let mut metrics_b = initial_metrics();
        metrics_b.insert("cpu".into(), 999);
        let a = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics_a,
        ));
        let b = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics_b,
        ));
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn final_metrics_unchanged_when_all_writes_rejected() {
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 100_000, 100_000, "fast"),
            registration("ctrl-b", &[], &["cpu"], 100_000, 100_000, "fast"),
        ];
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 50,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 60,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(!eval.pass);
        // Final metrics should equal initial since all writes were rejected
        assert_eq!(eval.final_metrics.get("cpu"), Some(&10));
        assert_eq!(eval.final_metrics.get("latency"), Some(&100));
    }

    #[test]
    fn log_events_include_read_snapshot_entries() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu", "latency"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let reads = [
            MetricReadRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
            },
            MetricReadRequest {
                controller_id: "ctrl-a".into(),
                metric: "latency".into(),
            },
        ];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &[], &[]),
            &metrics,
        ));
        let read_logs: Vec<_> = eval
            .logs
            .iter()
            .filter(|l| l.event == "read_snapshot")
            .collect();
        assert_eq!(read_logs.len(), 2);
        assert!(read_logs.iter().all(|l| l.outcome == "pass"));
        assert!(read_logs.iter().any(|l| l.metric.as_deref() == Some("cpu")));
        assert!(
            read_logs
                .iter()
                .any(|l| l.metric.as_deref() == Some("latency"))
        );
    }

    #[test]
    fn log_events_include_write_conflict_serialized() {
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 100_000, "fast"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_000, "fast"),
        ];
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Serialize,
        };
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 10,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 20,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(eval.pass);
        let serialized_logs: Vec<_> = eval
            .logs
            .iter()
            .filter(|l| l.event == "write_conflict_serialized")
            .collect();
        assert_eq!(serialized_logs.len(), 1);
        assert_eq!(serialized_logs[0].outcome, "pass");
        assert_eq!(serialized_logs[0].metric.as_deref(), Some("cpu"));
        assert!(serialized_logs[0].error_code.is_none());
    }

    #[test]
    fn three_writers_mixed_conflict_and_independent() {
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 100_000, "fast"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_000, "fast"),
            registration("ctrl-c", &[], &["latency"], 1_000_000, 100_000, "fast"),
        ];
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 50,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 60,
            },
            MetricWriteRequest {
                controller_id: "ctrl-c".into(),
                metric: "latency".into(),
                value: 200,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        // CPU writes conflict (rejected), latency write independent (applied)
        assert!(!eval.pass);
        assert!(
            eval.findings
                .iter()
                .any(|f| f.code == InterferenceFailureCode::TimescaleConflict
                    && f.metric.as_deref() == Some("cpu"))
        );
        assert_eq!(eval.final_metrics.get("latency"), Some(&200));
        assert!(eval.applied_writes.iter().any(|w| w.metric == "latency"));
        assert_eq!(
            eval.rejected_writes
                .iter()
                .filter(|w| w.metric == "cpu")
                .count(),
            2
        );
    }

    #[test]
    fn subscription_delivers_initial_metric_without_writes() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let subs = [MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &subs),
            &metrics,
        ));
        assert!(eval.pass);
        let updates = eval
            .subscription_streams
            .get("ctrl-a")
            .expect("operation should succeed for valid inputs");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].value, 10); // initial cpu value
        assert_eq!(updates[0].metric, "cpu");
    }

    #[test]
    fn zero_min_timescale_separation_allows_same_interval_writes() {
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 100_000, "fast"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_000, "fast"),
        ];
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 0,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 50,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 60,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        assert!(eval.pass);
        assert_eq!(eval.applied_writes.len(), 2);
    }

    #[test]
    fn duplicate_controller_skips_second_registration_validation() {
        // First registration is valid, second is duplicate with blank statement.
        // Only DuplicateController should appear, not MissingTimescaleStatement for the dupe.
        let registrations = vec![
            registration("ctrl-a", &["cpu"], &[], 1_000_000, 1_000_000, "ok"),
            registration("ctrl-a", &["cpu"], &[], 1_000_000, 1_000_000, "   "),
        ];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &[]),
            &metrics,
        ));
        assert!(!eval.pass);
        assert!(
            eval.findings
                .iter()
                .any(|f| f.code == InterferenceFailureCode::DuplicateController)
        );
        assert!(
            !eval
                .findings
                .iter()
                .any(|f| f.code == InterferenceFailureCode::MissingTimescaleStatement),
            "duplicate should skip further validation"
        );
    }

    #[test]
    fn decision_id_hex_portion_is_32_chars() {
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &[],
            (&[], &[], &[]),
            &metrics,
        ));
        let hex_part = eval
            .decision_id
            .strip_prefix("ctrl-interference-")
            .expect("operation should succeed for valid inputs");
        assert_eq!(hex_part.len(), 32, "16 bytes = 32 hex chars");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn read_and_write_same_controller_same_metric() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let reads = [MetricReadRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        }];
        let writes = [MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
            value: 42,
        }];
        let config = InterferenceConfig::default();
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&reads, &writes, &[]),
            &metrics,
        ));
        assert!(eval.pass);
        // Read snapshot captures initial value (before write)
        assert_eq!(eval.read_snapshots.get("ctrl-a:cpu"), Some(&10));
        // Final metrics reflect write
        assert_eq!(eval.final_metrics.get("cpu"), Some(&42));
    }

    #[test]
    fn subscription_no_update_for_metric_absent_from_final() {
        let registrations = vec![registration(
            "ctrl-a",
            &["ghost"],
            &[],
            1_000_000,
            1_000_000,
            "ok",
        )];
        let subs = [MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "ghost".into(),
        }];
        let config = InterferenceConfig::default();
        let metrics = BTreeMap::new(); // no initial metrics at all
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &[], &subs),
            &metrics,
        ));
        assert!(eval.pass);
        assert!(
            eval.subscription_streams
                .get("ctrl-a")
                .is_none_or(|u| u.is_empty()),
            "no update for metric absent from final_metrics"
        );
    }

    #[test]
    fn timescale_conflict_log_includes_error_code_and_controller_ids() {
        let registrations = vec![
            registration("ctrl-a", &[], &["cpu"], 1_000_000, 100_000, "fast"),
            registration("ctrl-b", &[], &["cpu"], 1_000_000, 100_000, "fast"),
        ];
        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        };
        let writes = [
            MetricWriteRequest {
                controller_id: "ctrl-a".into(),
                metric: "cpu".into(),
                value: 10,
            },
            MetricWriteRequest {
                controller_id: "ctrl-b".into(),
                metric: "cpu".into(),
                value: 20,
            },
        ];
        let metrics = initial_metrics();
        let eval = evaluate_controller_interference(&scenario(
            "t",
            "p",
            &config,
            &registrations,
            (&[], &writes, &[]),
            &metrics,
        ));
        let conflict_log = eval
            .logs
            .iter()
            .find(|l| l.event == "timescale_conflict")
            .expect("conflict log event must exist");
        assert_eq!(conflict_log.outcome, "fail");
        assert_eq!(
            conflict_log.error_code.as_deref(),
            Some("timescale_conflict")
        );
        assert_eq!(conflict_log.metric.as_deref(), Some("cpu"));
        assert_eq!(conflict_log.controller_ids.len(), 2);
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn timescale_separation_statement_serde_roundtrip() {
        let tss = TimescaleSeparationStatement {
            observation_interval_millionths: 1_000_000,
            write_interval_millionths: 5_000_000,
            statement: "slow controller".to_string(),
        };
        let json = serde_json::to_string(&tss).expect("serialize derived Serialize");
        let back: TimescaleSeparationStatement =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, tss);
    }

    #[test]
    fn controller_registration_serde_roundtrip() {
        let reg = registration(
            "ctrl-a",
            &["cpu", "mem"],
            &["throttle"],
            1_000_000,
            5_000_000,
            "fast reader",
        );
        let json = serde_json::to_string(&reg).expect("serialize derived Serialize");
        let back: ControllerRegistration =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, reg);
    }

    #[test]
    fn metric_read_request_serde_roundtrip() {
        let req = MetricReadRequest {
            controller_id: "ctrl-a".to_string(),
            metric: "cpu".to_string(),
        };
        let json = serde_json::to_string(&req).expect("serialize derived Serialize");
        let back: MetricReadRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, req);
    }

    #[test]
    fn metric_write_request_serde_roundtrip() {
        let req = MetricWriteRequest {
            controller_id: "ctrl-a".to_string(),
            metric: "throttle".to_string(),
            value: 500_000,
        };
        let json = serde_json::to_string(&req).expect("serialize derived Serialize");
        let back: MetricWriteRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, req);
    }

    #[test]
    fn metric_subscription_serde_roundtrip() {
        let sub = MetricSubscription {
            controller_id: "ctrl-b".to_string(),
            metric: "latency".to_string(),
        };
        let json = serde_json::to_string(&sub).expect("serialize derived Serialize");
        let back: MetricSubscription =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, sub);
    }

    #[test]
    fn metric_update_serde_roundtrip_enrichment() {
        let upd = MetricUpdate {
            sequence: 42,
            metric: "cpu".to_string(),
            value: 750_000,
        };
        let json = serde_json::to_string(&upd).expect("serialize derived Serialize");
        let back: MetricUpdate = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, upd);
    }

    #[test]
    fn interference_finding_serde_roundtrip() {
        let finding = InterferenceFinding {
            code: InterferenceFailureCode::DuplicateController,
            metric: Some("cpu".to_string()),
            controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
            detail: "duplicate detected".to_string(),
        };
        let json = serde_json::to_string(&finding).expect("serialize derived Serialize");
        let back: InterferenceFinding =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, finding);
    }

    #[test]
    fn interference_resolution_serde_roundtrip_enrichment() {
        let res = InterferenceResolution {
            metric: "cpu".to_string(),
            controller_ids: vec!["ctrl-a".to_string()],
            mode: ConflictResolutionMode::Serialize,
            detail: "serialized access".to_string(),
        };
        let json = serde_json::to_string(&res).expect("serialize derived Serialize");
        let back: InterferenceResolution =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, res);
    }

    #[test]
    fn interference_log_event_serde_roundtrip() {
        let log = InterferenceLogEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
            component: "guard".to_string(),
            event: "check_pass".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            metric: Some("cpu".to_string()),
            controller_ids: vec!["ctrl-a".to_string()],
        };
        let json = serde_json::to_string(&log).expect("serialize derived Serialize");
        let back: InterferenceLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, log);
    }

    #[test]
    fn interference_evaluation_serde_roundtrip() {
        let eval = InterferenceEvaluation {
            decision_id: "dec-1".to_string(),
            pass: true,
            rollback_required: false,
            read_snapshots: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("cpu".to_string(), 500_000);
                m
            },
            applied_writes: vec![MetricWriteRequest {
                controller_id: "ctrl-a".to_string(),
                metric: "throttle".to_string(),
                value: 100_000,
            }],
            rejected_writes: vec![],
            resolutions: vec![],
            subscription_streams: std::collections::BTreeMap::new(),
            final_metrics: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("cpu".to_string(), 500_000);
                m.insert("throttle".to_string(), 100_000);
                m
            },
            findings: vec![],
            logs: vec![],
        };
        let json = serde_json::to_string(&eval).expect("serialize derived Serialize");
        let back: InterferenceEvaluation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, eval);
    }
}
