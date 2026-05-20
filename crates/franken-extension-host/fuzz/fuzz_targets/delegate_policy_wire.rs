#![no_main]

use frankenengine_extension_host::{
    ContainmentWorkflowLogEntry, DelegateCellPolicy, GuardplaneDecisionLogEntry,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const DELEGATE_CELL_POLICY_SCHEMA_VERSION: &str = "franken-engine.delegate-cell-policy.v1";
const GUARDPLANE_DECISION_LOG_SCHEMA_VERSION: &str = "franken-engine.guardplane-decision-log.v1";
const CONTAINMENT_WORKFLOW_LOG_SCHEMA_VERSION: &str = "franken-engine.containment-workflow-log.v1";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    exercise_delegate_cell_policy(data);
    exercise_guardplane_decision_log_entry(data);
    exercise_containment_workflow_log_entry(data);
});

fn exercise_delegate_cell_policy(data: &[u8]) {
    let Ok(decoded) = serde_json::from_slice::<DelegateCellPolicy>(data) else {
        return;
    };

    assert_json_schema_version(&decoded, DELEGATE_CELL_POLICY_SCHEMA_VERSION);
    let encoded = serde_json::to_vec(&decoded).expect("delegate policy should serialize");
    let reparsed: DelegateCellPolicy =
        serde_json::from_slice(&encoded).expect("serialized delegate policy should parse");
    assert_eq!(decoded, reparsed);
}

fn exercise_guardplane_decision_log_entry(data: &[u8]) {
    let Ok(decoded) = serde_json::from_slice::<GuardplaneDecisionLogEntry>(data) else {
        return;
    };

    assert_json_schema_version(&decoded, GUARDPLANE_DECISION_LOG_SCHEMA_VERSION);
    let encoded = serde_json::to_vec(&decoded).expect("guardplane log should serialize");
    let reparsed: GuardplaneDecisionLogEntry =
        serde_json::from_slice(&encoded).expect("serialized guardplane log should parse");
    assert_eq!(decoded, reparsed);
}

fn exercise_containment_workflow_log_entry(data: &[u8]) {
    let Ok(decoded) = serde_json::from_slice::<ContainmentWorkflowLogEntry>(data) else {
        return;
    };

    assert_json_schema_version(&decoded, CONTAINMENT_WORKFLOW_LOG_SCHEMA_VERSION);
    let encoded = serde_json::to_vec(&decoded).expect("containment workflow log should serialize");
    let reparsed: ContainmentWorkflowLogEntry =
        serde_json::from_slice(&encoded).expect("serialized containment workflow log should parse");
    assert_eq!(decoded, reparsed);
}

fn assert_json_schema_version<T>(decoded: &T, expected: &str)
where
    T: serde::Serialize,
{
    let value = serde_json::to_value(decoded).expect("wire value should serialize to JSON value");
    assert_eq!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_str),
        Some(expected)
    );
}
