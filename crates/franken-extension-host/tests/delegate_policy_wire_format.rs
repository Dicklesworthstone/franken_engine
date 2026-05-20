#![forbid(unsafe_code)]

use frankenengine_extension_host::{
    ContainmentWorkflowLogEntry, DelegateCellPolicy, ExtensionState, GuardplaneDecisionLogEntry,
    GuardplanePolicyAction, LifecycleTransition,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const GOLDEN: &str = include_str!("golden_vectors/delegate_policy_wire_v1.json");
const GOLDEN_CASES: &str = include_str!("golden_vectors/delegate_policy_wire_cases_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DelegatePolicyWireFixture {
    fixture_schema_version: String,
    delegate_cell_policy: DelegateCellPolicy,
    guardplane_decision_log_entry: GuardplaneDecisionLogEntry,
    containment_workflow_log_entry: ContainmentWorkflowLogEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DelegatePolicyWireCaseSet {
    fixture_schema_version: String,
    delegate_cell_policy_cases: Vec<NamedDelegateCellPolicyCase>,
    guardplane_decision_log_cases: Vec<NamedGuardplaneDecisionLogCase>,
    containment_workflow_log_cases: Vec<NamedContainmentWorkflowLogCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamedDelegateCellPolicyCase {
    case_id: String,
    payload: DelegateCellPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamedGuardplaneDecisionLogCase {
    case_id: String,
    payload: GuardplaneDecisionLogEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamedContainmentWorkflowLogCase {
    case_id: String,
    payload: ContainmentWorkflowLogEntry,
}

fn fixture() -> DelegatePolicyWireFixture {
    DelegatePolicyWireFixture {
        fixture_schema_version: "franken-engine.extension-host.delegate-policy-wire-fixture.v1"
            .to_string(),
        delegate_cell_policy: DelegateCellPolicy::default(),
        guardplane_decision_log_entry: GuardplaneDecisionLogEntry {
            schema_version: "franken-engine.guardplane-decision-log.v1".to_string(),
            trace_id: "trace-wire-v1".to_string(),
            decision_id: "decision-wire-v1".to_string(),
            policy_id: "policy-wire-v1".to_string(),
            component: "delegate_cell_policy".to_string(),
            event: "delegate_guardplane_action".to_string(),
            outcome: "suspend".to_string(),
            error_code: None,
            source_event: "delegate_declassification".to_string(),
            delegate_id: "delegate-wire".to_string(),
            timestamp_ns: 4_242,
            posterior_micros: 550_000,
            action: GuardplanePolicyAction::Suspend,
            safe_mode_fallback: false,
            lifecycle_transition: Some(LifecycleTransition::Suspend),
            resulting_state: ExtensionState::Suspended,
        },
        containment_workflow_log_entry: ContainmentWorkflowLogEntry {
            schema_version: "franken-engine.containment-workflow-log.v1".to_string(),
            trace_id: "trace-wire-v1".to_string(),
            decision_id: "containment-wire-v1".to_string(),
            policy_id: "policy-wire-v1".to_string(),
            component: "delegate_cell_policy".to_string(),
            event: "delegate_containment_action".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            source_event: "delegate_declassification".to_string(),
            delegate_id: "delegate-wire".to_string(),
            timestamp_ns: 4_243,
            action: GuardplanePolicyAction::Suspend,
            lifecycle_transition: Some(LifecycleTransition::Suspend),
            resulting_state: ExtensionState::Suspended,
            mesh_attempted_targets: vec!["peer-a".to_string(), "peer-b".to_string()],
            mesh_targets: vec!["peer-a".to_string()],
            mesh_failed_targets: vec!["peer-b".to_string()],
            mesh_propagated: false,
        },
    }
}

fn case_set() -> DelegatePolicyWireCaseSet {
    DelegatePolicyWireCaseSet {
        fixture_schema_version: "franken-engine.extension-host.delegate-policy-wire-cases.v1"
            .to_string(),
        delegate_cell_policy_cases: vec![
            NamedDelegateCellPolicyCase {
                case_id: "delegate_policy_default".to_string(),
                payload: DelegateCellPolicy::default(),
            },
            NamedDelegateCellPolicyCase {
                case_id: "delegate_policy_high_risk_penalties".to_string(),
                payload: DelegateCellPolicy {
                    schema_version: "franken-engine.delegate-cell-policy.v1".to_string(),
                    initial_posterior_micros: 850_000,
                    capability_escalation_penalty_micros: 1_000_000,
                    flow_violation_penalty_micros: 750_000,
                    declassification_denial_penalty_micros: 650_000,
                    false_positive_cost_micros: 50_000,
                    false_negative_cost_micros: 1_000_000,
                },
            },
        ],
        guardplane_decision_log_cases: vec![
            NamedGuardplaneDecisionLogCase {
                case_id: "guardplane_allow_running".to_string(),
                payload: GuardplaneDecisionLogEntry {
                    schema_version: "franken-engine.guardplane-decision-log.v1".to_string(),
                    trace_id: "trace-allow".to_string(),
                    decision_id: "decision-allow".to_string(),
                    policy_id: "policy-wire-v1".to_string(),
                    component: "delegate_cell_policy".to_string(),
                    event: "delegate_guardplane_action".to_string(),
                    outcome: "allow".to_string(),
                    error_code: None,
                    source_event: "delegate_flow".to_string(),
                    delegate_id: "delegate-allow".to_string(),
                    timestamp_ns: 10,
                    posterior_micros: 200_000,
                    action: GuardplanePolicyAction::Allow,
                    safe_mode_fallback: false,
                    lifecycle_transition: None,
                    resulting_state: ExtensionState::Running,
                },
            },
            NamedGuardplaneDecisionLogCase {
                case_id: "guardplane_quarantine_safe_mode".to_string(),
                payload: GuardplaneDecisionLogEntry {
                    schema_version: "franken-engine.guardplane-decision-log.v1".to_string(),
                    trace_id: "trace-quarantine".to_string(),
                    decision_id: "decision-quarantine".to_string(),
                    policy_id: "policy-wire-v1".to_string(),
                    component: "delegate_cell_policy".to_string(),
                    event: "delegate_guardplane_action".to_string(),
                    outcome: "quarantine".to_string(),
                    error_code: Some("FE-DELEGATE-0008".to_string()),
                    source_event: "delegate_capability_escalation".to_string(),
                    delegate_id: "delegate-quarantine".to_string(),
                    timestamp_ns: 11,
                    posterior_micros: 950_000,
                    action: GuardplanePolicyAction::Quarantine,
                    safe_mode_fallback: true,
                    lifecycle_transition: Some(LifecycleTransition::Quarantine),
                    resulting_state: ExtensionState::Quarantined,
                },
            },
        ],
        containment_workflow_log_cases: vec![NamedContainmentWorkflowLogCase {
            case_id: "containment_mesh_degraded_quarantine".to_string(),
            payload: ContainmentWorkflowLogEntry {
                schema_version: "franken-engine.containment-workflow-log.v1".to_string(),
                trace_id: "trace-containment".to_string(),
                decision_id: "decision-containment".to_string(),
                policy_id: "policy-wire-v1".to_string(),
                component: "delegate_cell_policy".to_string(),
                event: "delegate_containment_action".to_string(),
                outcome: "degraded".to_string(),
                error_code: Some("FE-DELEGATE-0008".to_string()),
                source_event: "delegate_guardplane_action".to_string(),
                delegate_id: "delegate-quarantine".to_string(),
                timestamp_ns: 12,
                action: GuardplanePolicyAction::Quarantine,
                lifecycle_transition: Some(LifecycleTransition::Quarantine),
                resulting_state: ExtensionState::Quarantined,
                mesh_attempted_targets: vec![
                    "peer-a".to_string(),
                    "peer-b".to_string(),
                    "peer-c".to_string(),
                ],
                mesh_targets: vec!["peer-a".to_string(), "peer-c".to_string()],
                mesh_failed_targets: vec!["peer-b".to_string()],
                mesh_propagated: false,
            },
        }],
    }
}

#[test]
fn delegate_policy_wire_v1_matches_golden_snapshot() {
    let expected = fixture();
    let actual_json = serde_json::to_string_pretty(&expected).expect("serialize fixture") + "\n";

    assert_eq!(actual_json, GOLDEN);
    let decoded: DelegatePolicyWireFixture =
        serde_json::from_str(GOLDEN).expect("golden fixture should decode");
    assert_eq!(decoded, expected);
}

#[test]
fn delegate_policy_wire_case_set_matches_golden_snapshot() {
    let expected = case_set();
    let actual_json = serde_json::to_string_pretty(&expected).expect("serialize cases") + "\n";

    assert_eq!(actual_json, GOLDEN_CASES);
    let decoded: DelegatePolicyWireCaseSet =
        serde_json::from_str(GOLDEN_CASES).expect("golden case set should decode");
    assert_eq!(decoded, expected);

    let case_count = decoded.delegate_cell_policy_cases.len()
        + decoded.guardplane_decision_log_cases.len()
        + decoded.containment_workflow_log_cases.len();
    assert_eq!(case_count, 5);
}

#[test]
fn delegate_policy_deserialize_fails_closed_on_unknown_schema_version() {
    let mut value = serde_json::to_value(DelegateCellPolicy::default()).expect("policy json");
    value["schema_version"] = json!("franken-engine.delegate-cell-policy.v2");

    let err = serde_json::from_value::<DelegateCellPolicy>(value).expect_err("unknown version");
    assert!(err.to_string().contains("unsupported DelegateCellPolicy"));
}

#[test]
fn delegate_policy_deserialize_rejects_unknown_fields() {
    let mut value = serde_json::to_value(DelegateCellPolicy::default()).expect("policy json");
    value["extra_wire_field"] = json!(true);

    let err = serde_json::from_value::<DelegateCellPolicy>(value).expect_err("unknown field");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn delegate_logs_deserialize_fail_closed_on_unknown_schema_versions() {
    let fixture = fixture();

    let mut decision =
        serde_json::to_value(fixture.guardplane_decision_log_entry).expect("decision json");
    decision["schema_version"] = json!("franken-engine.guardplane-decision-log.v2");
    let decision_err = serde_json::from_value::<GuardplaneDecisionLogEntry>(decision)
        .expect_err("unknown decision version");
    assert!(
        decision_err
            .to_string()
            .contains("unsupported GuardplaneDecisionLogEntry")
    );

    let mut containment =
        serde_json::to_value(fixture.containment_workflow_log_entry).expect("containment json");
    containment["schema_version"] = json!("franken-engine.containment-workflow-log.v2");
    let containment_err = serde_json::from_value::<ContainmentWorkflowLogEntry>(containment)
        .expect_err("unknown containment version");
    assert!(
        containment_err
            .to_string()
            .contains("unsupported ContainmentWorkflowLogEntry")
    );
}
