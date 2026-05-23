//! Integration coverage for PAC-Bayes bounds over optimization-promotion data.

#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

#[path = "../src/pac_bayes_bound.rs"]
mod pac_bayes_bound;

use pac_bayes_bound::{
    HypothesisDistribution, MILLION, PacBayesInput, PacBayesUpperBound, distribution,
};

const CONTROL_CASES: &str =
    include_str!("../../../scripts/testdata/optimization_promotion_control_contract/cases.json");
const COMPOSER_CASES: &str = include_str!(
    "../../../scripts/testdata/optimization_promotion_eligibility_composer/cases.json"
);
const OPERATOR_STATUS_CASES: &str =
    include_str!("../../../scripts/testdata/optimization_promotion_operator_status/cases.json");
const REPLAY_DRILL_CASES: &str =
    include_str!("../../../scripts/testdata/optimization_promotion_replay_drill/cases.json");
const MINER_CASES: &str =
    include_str!("../../../scripts/testdata/swarm_autopilot_promotion_candidate_miner/cases.json");

#[derive(Debug, Clone, Copy)]
struct HistoryRow {
    fixture: &'static str,
    case_id: &'static str,
    empirical_error_millionths: u64,
    posterior_primary_millionths: u64,
    sample_size: u64,
    delta_millionths: u64,
}

const HISTORY_ROWS: &[HistoryRow] = &[
    row(
        "composer",
        "promotable_current_evidence",
        40_000,
        610_000,
        12_000,
        50_000,
    ),
    row(
        "composer",
        "observe_only_low_delta",
        90_000,
        560_000,
        10_000,
        50_000,
    ),
    row(
        "composer",
        "stale_evidence_fails",
        360_000,
        820_000,
        4_000,
        20_000,
    ),
    row(
        "composer",
        "semantic_divergence_fails",
        500_000,
        900_000,
        3_000,
        20_000,
    ),
    row(
        "composer",
        "tail_regression_fails",
        420_000,
        850_000,
        3_500,
        20_000,
    ),
    row(
        "composer",
        "rollback_unready_fails",
        300_000,
        780_000,
        5_000,
        20_000,
    ),
    row(
        "composer",
        "synthetic_contamination_fails",
        600_000,
        940_000,
        2_500,
        10_000,
    ),
    row(
        "control",
        "complete_contract_passes",
        50_000,
        600_000,
        12_000,
        50_000,
    ),
    row(
        "control",
        "missing_rollback_surface_fails",
        310_000,
        770_000,
        5_000,
        20_000,
    ),
    row(
        "control",
        "stale_hot_path_evidence_fails",
        340_000,
        800_000,
        4_500,
        20_000,
    ),
    row(
        "control",
        "unsafe_mutation_policy_fails",
        470_000,
        890_000,
        3_000,
        10_000,
    ),
    row(
        "control",
        "contradictory_evidence_fails",
        520_000,
        910_000,
        3_000,
        10_000,
    ),
    row(
        "operator",
        "observe_status",
        80_000,
        570_000,
        11_000,
        50_000,
    ),
    row(
        "operator",
        "promote_status",
        45_000,
        630_000,
        12_500,
        50_000,
    ),
    row("operator", "pin_status", 60_000, 620_000, 12_000, 50_000),
    row("operator", "demote_status", 280_000, 760_000, 5_500, 20_000),
    row(
        "operator",
        "quarantine_status",
        430_000,
        860_000,
        3_500,
        20_000,
    ),
    row(
        "operator",
        "fail_closed_status",
        500_000,
        900_000,
        3_000,
        10_000,
    ),
    row(
        "replay",
        "promotable_evidence",
        55_000,
        600_000,
        12_000,
        50_000,
    ),
    row("replay", "stale_evidence", 320_000, 790_000, 4_500, 20_000),
    row(
        "replay",
        "transfer_refusal",
        350_000,
        810_000,
        4_000,
        20_000,
    ),
    row(
        "replay",
        "rollback_demotion",
        530_000,
        920_000,
        3_000,
        10_000,
    ),
    row(
        "replay",
        "missing_artifact_fail_closed",
        410_000,
        850_000,
        3_500,
        20_000,
    ),
    row(
        "miner",
        "promotable_repeated_success",
        45_000,
        620_000,
        12_000,
        50_000,
    ),
    row(
        "miner",
        "stable_non_promotion_recommendation",
        160_000,
        650_000,
        8_000,
        50_000,
    ),
    row(
        "miner",
        "contamination_refusal",
        560_000,
        930_000,
        3_000,
        10_000,
    ),
    row(
        "miner",
        "insufficient_evidence_degradation",
        380_000,
        830_000,
        4_000,
        20_000,
    ),
    row(
        "miner",
        "contradictory_hindsight_block",
        520_000,
        910_000,
        3_000,
        10_000,
    ),
    row(
        "control",
        "complete_contract_passes",
        35_000,
        550_000,
        20_000,
        100_000,
    ),
    row(
        "operator",
        "promote_status",
        30_000,
        580_000,
        20_000,
        100_000,
    ),
];

const fn row(
    fixture: &'static str,
    case_id: &'static str,
    empirical_error_millionths: u64,
    posterior_primary_millionths: u64,
    sample_size: u64,
    delta_millionths: u64,
) -> HistoryRow {
    HistoryRow {
        fixture,
        case_id,
        empirical_error_millionths,
        posterior_primary_millionths,
        sample_size,
        delta_millionths,
    }
}

fn fixture_ids() -> BTreeSet<String> {
    [
        ("control", CONTROL_CASES),
        ("composer", COMPOSER_CASES),
        ("operator", OPERATOR_STATUS_CASES),
        ("replay", REPLAY_DRILL_CASES),
        ("miner", MINER_CASES),
    ]
    .into_iter()
    .flat_map(|(fixture, body)| {
        let parsed: Value = serde_json::from_str(body).expect("fixture JSON parses");
        parsed["cases"]
            .as_array()
            .expect("cases array exists")
            .iter()
            .map(move |case| {
                format!(
                    "{}:{}",
                    fixture,
                    case["case_id"].as_str().expect("case_id is a string")
                )
            })
            .collect::<Vec<_>>()
    })
    .collect()
}

fn prior() -> HypothesisDistribution {
    distribution(&[
        ("hostcall_elision", 500_000),
        ("typed_slot_fastpath", 300_000),
        ("rollback_guard", 200_000),
    ])
}

fn posterior(primary_mass: u64) -> HypothesisDistribution {
    let remaining = MILLION - primary_mass;
    let rollback_mass = remaining / 2;
    let typed_slot_mass = remaining - rollback_mass;
    distribution(&[
        ("hostcall_elision", primary_mass),
        ("typed_slot_fastpath", typed_slot_mass),
        ("rollback_guard", rollback_mass),
    ])
}

fn bound_for(row: HistoryRow) -> PacBayesUpperBound {
    let input = PacBayesInput::new(
        row.empirical_error_millionths,
        prior(),
        posterior(row.posterior_primary_millionths),
        row.sample_size,
        row.delta_millionths,
    );
    PacBayesUpperBound::compute(&input).expect("history row is valid")
}

fn assert_history_row(index: usize) {
    let row = HISTORY_ROWS[index];
    assert!(
        fixture_ids().contains(&format!("{}:{}", row.fixture, row.case_id)),
        "history row must be backed by checked-in optimization-promotion fixture data"
    );
    let bound = bound_for(row);
    assert_eq!(
        bound.schema_version,
        pac_bayes_bound::PAC_BAYES_SCHEMA_VERSION
    );
    assert!(bound.bound_millionths >= row.empirical_error_millionths);
    assert!(bound.bound_millionths <= MILLION);
    assert_eq!(bound.hypothesis_count, 3);
}

macro_rules! history_case {
    ($name:ident, $index:expr) => {
        #[test]
        fn $name() {
            assert_history_row($index);
        }
    };
}

history_case!(history_case_00_composer_promotable_current_evidence, 0);
history_case!(history_case_01_composer_observe_only_low_delta, 1);
history_case!(history_case_02_composer_stale_evidence_fails, 2);
history_case!(history_case_03_composer_semantic_divergence_fails, 3);
history_case!(history_case_04_composer_tail_regression_fails, 4);
history_case!(history_case_05_composer_rollback_unready_fails, 5);
history_case!(history_case_06_composer_synthetic_contamination_fails, 6);
history_case!(history_case_07_control_complete_contract_passes, 7);
history_case!(history_case_08_control_missing_rollback_surface_fails, 8);
history_case!(history_case_09_control_stale_hot_path_evidence_fails, 9);
history_case!(history_case_10_control_unsafe_mutation_policy_fails, 10);
history_case!(history_case_11_control_contradictory_evidence_fails, 11);
history_case!(history_case_12_operator_observe_status, 12);
history_case!(history_case_13_operator_promote_status, 13);
history_case!(history_case_14_operator_pin_status, 14);
history_case!(history_case_15_operator_demote_status, 15);
history_case!(history_case_16_operator_quarantine_status, 16);
history_case!(history_case_17_operator_fail_closed_status, 17);
history_case!(history_case_18_replay_promotable_evidence, 18);
history_case!(history_case_19_replay_stale_evidence, 19);
history_case!(history_case_20_replay_transfer_refusal, 20);
history_case!(history_case_21_replay_rollback_demotion, 21);
history_case!(history_case_22_replay_missing_artifact_fail_closed, 22);
history_case!(history_case_23_miner_promotable_repeated_success, 23);
history_case!(
    history_case_24_miner_stable_non_promotion_recommendation,
    24
);
history_case!(history_case_25_miner_contamination_refusal, 25);
history_case!(history_case_26_miner_insufficient_evidence_degradation, 26);
history_case!(history_case_27_miner_contradictory_hindsight_block, 27);
history_case!(history_case_28_control_complete_contract_low_error, 28);
history_case!(history_case_29_operator_promote_status_low_error, 29);

#[test]
fn checked_in_history_has_enough_distinct_cases() {
    assert!(fixture_ids().len() >= 30);
}

#[test]
fn bounds_are_monotone_across_history_kl_shift() {
    let low = bound_for(HistoryRow {
        posterior_primary_millionths: 550_000,
        ..HISTORY_ROWS[0]
    });
    let high = bound_for(HistoryRow {
        posterior_primary_millionths: 900_000,
        ..HISTORY_ROWS[0]
    });
    assert!(high.kl_divergence_millionths > low.kl_divergence_millionths);
    assert!(high.bound_millionths >= low.bound_millionths);
}

#[test]
fn bounds_are_deterministic_for_history_rows() {
    let first: BTreeMap<&'static str, u64> = HISTORY_ROWS
        .iter()
        .map(|row| (row.case_id, bound_for(*row).bound_millionths))
        .collect();
    let second: BTreeMap<&'static str, u64> = HISTORY_ROWS
        .iter()
        .map(|row| (row.case_id, bound_for(*row).bound_millionths))
        .collect();
    assert_eq!(first, second);
}
