#![forbid(unsafe_code)]

use frankenengine_extension_host::GuardplanePolicyAction;
use serde::{Deserialize, Serialize};

const GOLDEN: &str = include_str!("golden_vectors/guardplane_policy_action_fallback_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GuardplanePolicyActionFallbackGolden {
    fixture_schema_version: String,
    action_cases: Vec<GuardplanePolicyActionFallbackCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GuardplanePolicyActionFallbackCase {
    case_id: String,
    action: GuardplanePolicyAction,
    action_display: String,
    fail_closed_fallback: GuardplanePolicyAction,
    fallback_display: String,
    is_containment_action: bool,
    fallback_is_containment_action: bool,
}

fn policy_actions() -> [GuardplanePolicyAction; 6] {
    [
        GuardplanePolicyAction::Allow,
        GuardplanePolicyAction::Challenge,
        GuardplanePolicyAction::Sandbox,
        GuardplanePolicyAction::Suspend,
        GuardplanePolicyAction::Terminate,
        GuardplanePolicyAction::Quarantine,
    ]
}

fn golden_fixture() -> GuardplanePolicyActionFallbackGolden {
    GuardplanePolicyActionFallbackGolden {
        fixture_schema_version:
            "franken-engine.extension-host.guardplane-policy-action-fallback.v1".to_string(),
        action_cases: policy_actions()
            .into_iter()
            .map(|action| {
                let fallback = action.fail_closed_fallback();
                GuardplanePolicyActionFallbackCase {
                    case_id: format!("{}_fallback", action.as_str()),
                    action,
                    action_display: action.to_string(),
                    fail_closed_fallback: fallback,
                    fallback_display: fallback.to_string(),
                    is_containment_action: action.is_containment_action(),
                    fallback_is_containment_action: fallback.is_containment_action(),
                }
            })
            .collect(),
    }
}

#[test]
fn guardplane_policy_action_fallback_mapping_matches_golden_snapshot() {
    let expected = golden_fixture();
    let actual_json = serde_json::to_string_pretty(&expected).expect("serialize golden") + "\n";

    assert_eq!(actual_json, GOLDEN);

    let decoded: GuardplanePolicyActionFallbackGolden =
        serde_json::from_str(GOLDEN).expect("golden fixture should decode");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.action_cases.len(), policy_actions().len());
}
