#![forbid(unsafe_code)]
//! Enrichment integration tests for `attack_surface_game_model`.
//!
//! Adds Display exactness, Debug distinctness, serde exact tags,
//! JSON field-name stability, serde roundtrips, builder pattern,
//! and factory function validation beyond the existing 30 integration tests.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::attack_surface_game_model::{
    ActionId, ActionSpace, AdmissibleActionAutomaton, GameModel, GameModelBuilder, GameModelReport,
    HardConstraint, LossDimension, LossEntry, LossTensor, Player, SCHEMA_VERSION, StrategicAction,
    Subsystem, generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(5)
}

fn simple_game_model() -> GameModel {
    GameModelBuilder::new(Subsystem::Runtime, test_epoch())
        .attacker_action(StrategicAction {
            action_id: ActionId("atk-1".into()),
            player: Player::Attacker,
            subsystem: Subsystem::Runtime,
            description: "exploit memory bug".into(),
            admissible: true,
            constraints: vec![],
        })
        .defender_action(StrategicAction {
            action_id: ActionId("def-1".into()),
            player: Player::Defender,
            subsystem: Subsystem::Runtime,
            description: "enable ASLR".into(),
            admissible: true,
            constraints: vec![],
        })
        .loss(LossEntry {
            attacker_action: ActionId("atk-1".into()),
            defender_action: ActionId("def-1".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 500_000,
        })
        .build()
}

// ===========================================================================
// 1) SCHEMA_VERSION constant
// ===========================================================================

#[test]
fn schema_version_exact_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.attack-surface-game.v1");
}

// ===========================================================================
// 2) Subsystem — Display exact values
// ===========================================================================

#[test]
fn subsystem_display_compiler() {
    assert_eq!(Subsystem::Compiler.to_string(), "compiler");
}

#[test]
fn subsystem_display_runtime() {
    assert_eq!(Subsystem::Runtime.to_string(), "runtime");
}

#[test]
fn subsystem_display_control_plane() {
    assert_eq!(Subsystem::ControlPlane.to_string(), "control_plane");
}

#[test]
fn subsystem_display_extension_host() {
    assert_eq!(Subsystem::ExtensionHost.to_string(), "extension_host");
}

#[test]
fn subsystem_display_evidence_pipeline() {
    assert_eq!(Subsystem::EvidencePipeline.to_string(), "evidence_pipeline");
}

// ===========================================================================
// 3) Subsystem — serde exact tags (snake_case)
// ===========================================================================

#[test]
fn serde_exact_tags_subsystem() {
    let subsystems = [
        Subsystem::Compiler,
        Subsystem::Runtime,
        Subsystem::ControlPlane,
        Subsystem::ExtensionHost,
        Subsystem::EvidencePipeline,
    ];
    let expected = [
        "\"compiler\"",
        "\"runtime\"",
        "\"control_plane\"",
        "\"extension_host\"",
        "\"evidence_pipeline\"",
    ];
    for (s, exp) in subsystems.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(json, *exp, "Subsystem tag mismatch for {s:?}");
    }
}

// ===========================================================================
// 4) Subsystem — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_subsystem() {
    let variants = [
        format!("{:?}", Subsystem::Compiler),
        format!("{:?}", Subsystem::Runtime),
        format!("{:?}", Subsystem::ControlPlane),
        format!("{:?}", Subsystem::ExtensionHost),
        format!("{:?}", Subsystem::EvidencePipeline),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 5) Player — Display exact values
// ===========================================================================

#[test]
fn player_display_attacker() {
    assert_eq!(Player::Attacker.to_string(), "attacker");
}

#[test]
fn player_display_defender() {
    assert_eq!(Player::Defender.to_string(), "defender");
}

// ===========================================================================
// 6) Player — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_tags_player() {
    assert_eq!(
        serde_json::to_string(&Player::Attacker).unwrap(),
        "\"attacker\""
    );
    assert_eq!(
        serde_json::to_string(&Player::Defender).unwrap(),
        "\"defender\""
    );
}

// ===========================================================================
// 7) Player — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_player() {
    let variants = [
        format!("{:?}", Player::Attacker),
        format!("{:?}", Player::Defender),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 2);
}

// ===========================================================================
// 8) LossDimension — Display exact values
// ===========================================================================

#[test]
fn loss_dimension_display_user_harm() {
    assert_eq!(LossDimension::UserHarm.to_string(), "user_harm");
}

#[test]
fn loss_dimension_display_performance_cost() {
    assert_eq!(
        LossDimension::PerformanceCost.to_string(),
        "performance_cost"
    );
}

#[test]
fn loss_dimension_display_false_positive_cost() {
    assert_eq!(
        LossDimension::FalsePositiveCost.to_string(),
        "false_positive_cost"
    );
}

#[test]
fn loss_dimension_display_availability_cost() {
    assert_eq!(
        LossDimension::AvailabilityCost.to_string(),
        "availability_cost"
    );
}

#[test]
fn loss_dimension_display_evidence_integrity_cost() {
    assert_eq!(
        LossDimension::EvidenceIntegrityCost.to_string(),
        "evidence_integrity_cost"
    );
}

// ===========================================================================
// 9) LossDimension — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_tags_loss_dimension() {
    let dims = [
        LossDimension::UserHarm,
        LossDimension::PerformanceCost,
        LossDimension::FalsePositiveCost,
        LossDimension::AvailabilityCost,
        LossDimension::EvidenceIntegrityCost,
    ];
    let expected = [
        "\"user_harm\"",
        "\"performance_cost\"",
        "\"false_positive_cost\"",
        "\"availability_cost\"",
        "\"evidence_integrity_cost\"",
    ];
    for (d, exp) in dims.iter().zip(expected.iter()) {
        let json = serde_json::to_string(d).unwrap();
        assert_eq!(json, *exp, "LossDimension tag mismatch for {d:?}");
    }
}

// ===========================================================================
// 10) LossDimension — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_loss_dimension() {
    let variants = [
        format!("{:?}", LossDimension::UserHarm),
        format!("{:?}", LossDimension::PerformanceCost),
        format!("{:?}", LossDimension::FalsePositiveCost),
        format!("{:?}", LossDimension::AvailabilityCost),
        format!("{:?}", LossDimension::EvidenceIntegrityCost),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 11) ActionId — Display forwards inner string
// ===========================================================================

#[test]
fn action_id_display_forwards() {
    let id = ActionId("my-action".into());
    assert_eq!(id.to_string(), "my-action");
}

// ===========================================================================
// 12) GameModel::compute_model_id — starts with "game-"
// ===========================================================================

#[test]
fn model_id_starts_with_game() {
    let id = GameModel::compute_model_id(&Subsystem::Compiler, &test_epoch());
    assert!(id.starts_with("game-"), "model_id: {id}");
}

#[test]
fn model_id_deterministic() {
    let id1 = GameModel::compute_model_id(&Subsystem::Runtime, &test_epoch());
    let id2 = GameModel::compute_model_id(&Subsystem::Runtime, &test_epoch());
    assert_eq!(id1, id2);
}

#[test]
fn model_id_differs_by_subsystem() {
    let id1 = GameModel::compute_model_id(&Subsystem::Runtime, &test_epoch());
    let id2 = GameModel::compute_model_id(&Subsystem::Compiler, &test_epoch());
    assert_ne!(id1, id2);
}

// ===========================================================================
// 13) LossTensor::from_entries — deterministic hash
// ===========================================================================

#[test]
fn loss_tensor_from_entries_deterministic_hash() {
    let entries = vec![LossEntry {
        attacker_action: ActionId("a".into()),
        defender_action: ActionId("d".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 1_000_000,
    }];
    let t1 = LossTensor::from_entries(Subsystem::Runtime, entries.clone());
    let t2 = LossTensor::from_entries(Subsystem::Runtime, entries);
    assert_eq!(t1.content_hash, t2.content_hash);
}

// ===========================================================================
// 14) LossTensor — lookup
// ===========================================================================

#[test]
fn loss_tensor_lookup_found() {
    let entries = vec![LossEntry {
        attacker_action: ActionId("a".into()),
        defender_action: ActionId("d".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 500_000,
    }];
    let t = LossTensor::from_entries(Subsystem::Runtime, entries);
    assert_eq!(
        t.lookup(
            &ActionId("a".into()),
            &ActionId("d".into()),
            LossDimension::UserHarm
        ),
        Some(500_000)
    );
}

#[test]
fn loss_tensor_lookup_not_found() {
    let entries = vec![LossEntry {
        attacker_action: ActionId("a".into()),
        defender_action: ActionId("d".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 500_000,
    }];
    let t = LossTensor::from_entries(Subsystem::Runtime, entries);
    assert_eq!(
        t.lookup(
            &ActionId("x".into()),
            &ActionId("d".into()),
            LossDimension::UserHarm
        ),
        None
    );
}

// ===========================================================================
// 15) AdmissibleActionAutomaton — is_admissible
// ===========================================================================

#[test]
fn automaton_is_admissible_without_constraints() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::Runtime,
        constraints: vec![],
        all_defender_actions: BTreeSet::from([ActionId("d1".into())]),
    };
    assert!(auto.is_admissible(&ActionId("d1".into())));
}

#[test]
fn automaton_is_not_admissible_when_forbidden() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::Runtime,
        constraints: vec![HardConstraint {
            constraint_id: "c1".into(),
            description: "no d1".into(),
            forbidden_actions: BTreeSet::from([ActionId("d1".into())]),
            active_conditions: vec![],
        }],
        all_defender_actions: BTreeSet::from([ActionId("d1".into()), ActionId("d2".into())]),
    };
    assert!(!auto.is_admissible(&ActionId("d1".into())));
    assert!(auto.is_admissible(&ActionId("d2".into())));
}

// ===========================================================================
// 16) JSON field-name stability — StrategicAction
// ===========================================================================

#[test]
fn json_fields_strategic_action() {
    let a = StrategicAction {
        action_id: ActionId("a".into()),
        player: Player::Attacker,
        subsystem: Subsystem::Runtime,
        description: "d".into(),
        admissible: true,
        constraints: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "action_id",
        "player",
        "subsystem",
        "description",
        "admissible",
        "constraints",
    ] {
        assert!(
            obj.contains_key(key),
            "StrategicAction missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) JSON field-name stability — LossEntry
// ===========================================================================

#[test]
fn json_fields_loss_entry() {
    let le = LossEntry {
        attacker_action: ActionId("a".into()),
        defender_action: ActionId("d".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 100_000,
    };
    let v: serde_json::Value = serde_json::to_value(&le).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "attacker_action",
        "defender_action",
        "dimension",
        "loss_millionths",
    ] {
        assert!(obj.contains_key(key), "LossEntry missing field: {key}");
    }
}

// ===========================================================================
// 18) JSON field-name stability — GameModelReport
// ===========================================================================

#[test]
fn json_fields_game_model_report() {
    let model = simple_game_model();
    let report = generate_report(&[model], &test_epoch());
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "epoch",
        "subsystem_summaries",
        "total_models",
        "total_attacker_actions",
        "total_defender_actions",
        "total_constraints",
        "report_hash",
    ] {
        assert!(
            obj.contains_key(key),
            "GameModelReport missing field: {key}"
        );
    }
}

// ===========================================================================
// 19) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_action_id() {
    let id = ActionId("test-action".into());
    let json = serde_json::to_string(&id).unwrap();
    let rt: ActionId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, rt);
}

#[test]
fn serde_roundtrip_strategic_action() {
    let a = StrategicAction {
        action_id: ActionId("a".into()),
        player: Player::Defender,
        subsystem: Subsystem::Compiler,
        description: "d".into(),
        admissible: false,
        constraints: vec!["c1".into()],
    };
    let json = serde_json::to_string(&a).unwrap();
    let rt: StrategicAction = serde_json::from_str(&json).unwrap();
    assert_eq!(a, rt);
}

#[test]
fn serde_roundtrip_loss_entry() {
    let le = LossEntry {
        attacker_action: ActionId("a".into()),
        defender_action: ActionId("d".into()),
        dimension: LossDimension::AvailabilityCost,
        loss_millionths: -200_000,
    };
    let json = serde_json::to_string(&le).unwrap();
    let rt: LossEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(le, rt);
}

#[test]
fn serde_roundtrip_hard_constraint() {
    let hc = HardConstraint {
        constraint_id: "c1".into(),
        description: "d".into(),
        forbidden_actions: BTreeSet::from([ActionId("a1".into())]),
        active_conditions: vec!["cond".into()],
    };
    let json = serde_json::to_string(&hc).unwrap();
    let rt: HardConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(hc, rt);
}

#[test]
fn serde_roundtrip_game_model_report() {
    let model = simple_game_model();
    let report = generate_report(&[model], &test_epoch());
    let json = serde_json::to_string(&report).unwrap();
    let rt: GameModelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, rt);
}

// ===========================================================================
// 20) GameModelBuilder — basic construction
// ===========================================================================

#[test]
fn game_model_builder_produces_valid_model() {
    let model = simple_game_model();
    assert_eq!(model.attacker_action_count(), 1);
    assert_eq!(model.defender_action_count(), 1);
    assert!(model.model_id.starts_with("game-"));
}

// ===========================================================================
// 21) generate_report — counts correct
// ===========================================================================

#[test]
fn generate_report_counts_correct() {
    let model = simple_game_model();
    let report = generate_report(&[model], &test_epoch());
    assert_eq!(report.total_models, 1);
    assert_eq!(report.total_attacker_actions, 1);
    assert_eq!(report.total_defender_actions, 1);
}

#[test]
fn generate_report_schema_version() {
    let model = simple_game_model();
    let report = generate_report(&[model], &test_epoch());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

// ===========================================================================
// 22) ActionSpace — action_count / admissible_actions
// ===========================================================================

#[test]
fn action_space_action_count() {
    let space = ActionSpace {
        player: Player::Defender,
        subsystem: Subsystem::Runtime,
        actions: vec![
            StrategicAction {
                action_id: ActionId("d1".into()),
                player: Player::Defender,
                subsystem: Subsystem::Runtime,
                description: "a".into(),
                admissible: true,
                constraints: vec![],
            },
            StrategicAction {
                action_id: ActionId("d2".into()),
                player: Player::Defender,
                subsystem: Subsystem::Runtime,
                description: "b".into(),
                admissible: false,
                constraints: vec![],
            },
        ],
    };
    assert_eq!(space.action_count(), 2);
    assert_eq!(space.admissible_actions().len(), 1);
}

// ===========================================================================
// 23) LossTensor::total_loss — sums across all dimensions
// ===========================================================================

#[test]
fn test_loss_tensor_total_loss_sums_dimensions() {
    let entries = vec![
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 300_000,
        },
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def".into()),
            dimension: LossDimension::PerformanceCost,
            loss_millionths: 200_000,
        },
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def".into()),
            dimension: LossDimension::AvailabilityCost,
            loss_millionths: 100_000,
        },
    ];
    let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
    assert_eq!(
        tensor.total_loss(&ActionId("atk".into()), &ActionId("def".into())),
        600_000
    );
}

// ===========================================================================
// 24) LossTensor::total_loss — returns zero for unknown pair
// ===========================================================================

#[test]
fn test_loss_tensor_total_loss_unknown_pair_is_zero() {
    let entries = vec![LossEntry {
        attacker_action: ActionId("atk".into()),
        defender_action: ActionId("def".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 500_000,
    }];
    let tensor = LossTensor::from_entries(Subsystem::Compiler, entries);
    assert_eq!(
        tensor.total_loss(&ActionId("unknown".into()), &ActionId("def".into())),
        0
    );
}

// ===========================================================================
// 25) LossTensor::total_loss — handles negative loss entries (benefit)
// ===========================================================================

#[test]
fn test_loss_tensor_total_loss_negative_entries() {
    let entries = vec![
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def".into()),
            dimension: LossDimension::FalsePositiveCost,
            loss_millionths: 500_000,
        },
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def".into()),
            dimension: LossDimension::EvidenceIntegrityCost,
            loss_millionths: -200_000,
        },
    ];
    let tensor = LossTensor::from_entries(Subsystem::EvidencePipeline, entries);
    assert_eq!(
        tensor.total_loss(&ActionId("atk".into()), &ActionId("def".into())),
        300_000
    );
}

// ===========================================================================
// 26) LossTensor::minimax_defender — single pair returns that defender
// ===========================================================================

#[test]
fn test_loss_tensor_minimax_defender_single_pair() {
    let entries = vec![LossEntry {
        attacker_action: ActionId("atk".into()),
        defender_action: ActionId("def".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 400_000,
    }];
    let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
    let result = tensor.minimax_defender();
    assert_eq!(result, Some(ActionId("def".into())));
}

// ===========================================================================
// 27) LossTensor::minimax_defender — empty tensor returns None
// ===========================================================================

#[test]
fn test_loss_tensor_minimax_defender_empty_returns_none() {
    let tensor = LossTensor::from_entries(Subsystem::Runtime, vec![]);
    assert!(tensor.minimax_defender().is_none());
}

// ===========================================================================
// 28) LossTensor::minimax_defender — picks defender with lower max loss
// ===========================================================================

#[test]
fn test_loss_tensor_minimax_defender_picks_lower_max_loss() {
    // def-A: max attacker loss = 900_000
    // def-B: max attacker loss = 300_000  ← minimax chooses this
    let entries = vec![
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def-A".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 900_000,
        },
        LossEntry {
            attacker_action: ActionId("atk".into()),
            defender_action: ActionId("def-B".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 300_000,
        },
    ];
    let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
    assert_eq!(tensor.minimax_defender(), Some(ActionId("def-B".into())));
}

// ===========================================================================
// 29) AdmissibleActionAutomaton::admissible_actions — excludes forbidden
// ===========================================================================

#[test]
fn test_automaton_admissible_actions_excludes_forbidden() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::ControlPlane,
        constraints: vec![HardConstraint {
            constraint_id: "c1".into(),
            description: "forbid d1".into(),
            forbidden_actions: BTreeSet::from([ActionId("d1".into())]),
            active_conditions: vec![],
        }],
        all_defender_actions: BTreeSet::from([
            ActionId("d1".into()),
            ActionId("d2".into()),
            ActionId("d3".into()),
        ]),
    };
    let admissible = auto.admissible_actions();
    assert!(!admissible.contains(&ActionId("d1".into())));
    assert!(admissible.contains(&ActionId("d2".into())));
    assert!(admissible.contains(&ActionId("d3".into())));
    assert_eq!(admissible.len(), 2);
}

// ===========================================================================
// 30) AdmissibleActionAutomaton::constraint_count — counts constraints
// ===========================================================================

#[test]
fn test_automaton_constraint_count_matches_vec_len() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::ExtensionHost,
        constraints: vec![
            HardConstraint {
                constraint_id: "c1".into(),
                description: "d".into(),
                forbidden_actions: BTreeSet::new(),
                active_conditions: vec![],
            },
            HardConstraint {
                constraint_id: "c2".into(),
                description: "e".into(),
                forbidden_actions: BTreeSet::new(),
                active_conditions: vec![],
            },
        ],
        all_defender_actions: BTreeSet::new(),
    };
    assert_eq!(auto.constraint_count(), 2);
}

// ===========================================================================
// 31) AdmissibleActionAutomaton::is_admissible — not in set returns false
// ===========================================================================

#[test]
fn test_automaton_is_admissible_action_not_in_set() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::Compiler,
        constraints: vec![],
        all_defender_actions: BTreeSet::from([ActionId("d1".into())]),
    };
    assert!(!auto.is_admissible(&ActionId("nonexistent".into())));
}

// ===========================================================================
// 32) GameModel::admissible_count — correct count with constraint
// ===========================================================================

#[test]
fn test_game_model_admissible_count_with_constraint() {
    let model = GameModelBuilder::new(Subsystem::Runtime, test_epoch())
        .attacker_action(StrategicAction {
            action_id: ActionId("atk-1".into()),
            player: Player::Attacker,
            subsystem: Subsystem::Runtime,
            description: "attack".into(),
            admissible: true,
            constraints: vec![],
        })
        .defender_action(StrategicAction {
            action_id: ActionId("def-1".into()),
            player: Player::Defender,
            subsystem: Subsystem::Runtime,
            description: "defend-1".into(),
            admissible: true,
            constraints: vec![],
        })
        .defender_action(StrategicAction {
            action_id: ActionId("def-2".into()),
            player: Player::Defender,
            subsystem: Subsystem::Runtime,
            description: "defend-2".into(),
            admissible: true,
            constraints: vec![],
        })
        .constraint(HardConstraint {
            constraint_id: "c1".into(),
            description: "forbid def-1".into(),
            forbidden_actions: BTreeSet::from([ActionId("def-1".into())]),
            active_conditions: vec![],
        })
        .build();
    // def-2 is admissible, def-1 is forbidden
    assert_eq!(model.admissible_count(), 1);
}

// ===========================================================================
// 33) GameModel::minimax_recommendation — returns Some for model with entries
// ===========================================================================

#[test]
fn test_game_model_minimax_recommendation_present() {
    let model = simple_game_model();
    // simple_game_model has one attacker/defender pair with a loss entry
    let rec = model.minimax_recommendation();
    assert!(rec.is_some());
}

// ===========================================================================
// 34) GameModel serde roundtrip — full model serializes and deserializes
// ===========================================================================

#[test]
fn test_serde_roundtrip_game_model() {
    let model = simple_game_model();
    let json = serde_json::to_string(&model).unwrap();
    let rt: GameModel = serde_json::from_str(&json).unwrap();
    assert_eq!(model, rt);
}

// ===========================================================================
// 35) GameModel::clone — clone is equal to original
// ===========================================================================

#[test]
fn test_game_model_clone_equals_original() {
    let model = simple_game_model();
    let cloned = model.clone();
    assert_eq!(model, cloned);
}

// ===========================================================================
// 36) generate_report — empty models slice produces zero counts
// ===========================================================================

#[test]
fn test_generate_report_empty_models() {
    let report = generate_report(&[], &test_epoch());
    assert_eq!(report.total_models, 0);
    assert_eq!(report.total_attacker_actions, 0);
    assert_eq!(report.total_defender_actions, 0);
    assert_eq!(report.total_constraints, 0);
    assert!(report.subsystem_summaries.is_empty());
}

// ===========================================================================
// 37) generate_report — multiple models aggregate correctly
// ===========================================================================

#[test]
fn test_generate_report_multiple_models_aggregate() {
    let m1 = GameModelBuilder::new(Subsystem::Runtime, test_epoch())
        .attacker_action(StrategicAction {
            action_id: ActionId("atk-r1".into()),
            player: Player::Attacker,
            subsystem: Subsystem::Runtime,
            description: "r-attack".into(),
            admissible: true,
            constraints: vec![],
        })
        .build();
    let m2 = GameModelBuilder::new(Subsystem::Compiler, test_epoch())
        .attacker_action(StrategicAction {
            action_id: ActionId("atk-c1".into()),
            player: Player::Attacker,
            subsystem: Subsystem::Compiler,
            description: "c-attack".into(),
            admissible: true,
            constraints: vec![],
        })
        .attacker_action(StrategicAction {
            action_id: ActionId("atk-c2".into()),
            player: Player::Attacker,
            subsystem: Subsystem::Compiler,
            description: "c-attack-2".into(),
            admissible: true,
            constraints: vec![],
        })
        .build();
    let report = generate_report(&[m1, m2], &test_epoch());
    assert_eq!(report.total_models, 2);
    assert_eq!(report.total_attacker_actions, 3);
    assert_eq!(report.total_defender_actions, 0);
}

// ===========================================================================
// 38) generate_report — subsystem_summaries keyed by subsystem name
// ===========================================================================

#[test]
fn test_generate_report_subsystem_summary_keys() {
    let model = simple_game_model();
    let report = generate_report(&[model], &test_epoch());
    assert!(report.subsystem_summaries.contains_key("runtime"));
}

// ===========================================================================
// 39) SubsystemSummary — serde roundtrip
// ===========================================================================

#[test]
fn test_serde_roundtrip_subsystem_summary() {
    use frankenengine_engine::attack_surface_game_model::SubsystemSummary;
    let summary = SubsystemSummary {
        subsystem: "runtime".into(),
        attacker_actions: 3,
        defender_actions: 2,
        admissible_actions: 1,
        constraints: 1,
        minimax_recommendation: Some("def-B".into()),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let rt: SubsystemSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, rt);
}

// ===========================================================================
// 40) LossTensor — content_hash differs across subsystems
// ===========================================================================

#[test]
fn test_loss_tensor_hash_differs_by_subsystem() {
    let entries = vec![LossEntry {
        attacker_action: ActionId("atk".into()),
        defender_action: ActionId("def".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 1_000_000,
    }];
    let t1 = LossTensor::from_entries(Subsystem::Runtime, entries.clone());
    let t2 = LossTensor::from_entries(Subsystem::Compiler, entries);
    assert_ne!(t1.content_hash, t2.content_hash);
}

// ===========================================================================
// 41) LossTensor — lookup across multiple entries picks correct one
// ===========================================================================

#[test]
fn test_loss_tensor_lookup_multiple_entries_correct_match() {
    let entries = vec![
        LossEntry {
            attacker_action: ActionId("atk-1".into()),
            defender_action: ActionId("def-1".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 100_000,
        },
        LossEntry {
            attacker_action: ActionId("atk-2".into()),
            defender_action: ActionId("def-1".into()),
            dimension: LossDimension::UserHarm,
            loss_millionths: 700_000,
        },
        LossEntry {
            attacker_action: ActionId("atk-1".into()),
            defender_action: ActionId("def-2".into()),
            dimension: LossDimension::PerformanceCost,
            loss_millionths: 50_000,
        },
    ];
    let tensor = LossTensor::from_entries(Subsystem::ControlPlane, entries);
    assert_eq!(
        tensor.lookup(
            &ActionId("atk-2".into()),
            &ActionId("def-1".into()),
            LossDimension::UserHarm
        ),
        Some(700_000)
    );
    assert_eq!(
        tensor.lookup(
            &ActionId("atk-1".into()),
            &ActionId("def-2".into()),
            LossDimension::PerformanceCost
        ),
        Some(50_000)
    );
    // wrong dimension → None
    assert!(
        tensor
            .lookup(
                &ActionId("atk-1".into()),
                &ActionId("def-1".into()),
                LossDimension::AvailabilityCost
            )
            .is_none()
    );
}

// ===========================================================================
// 42) GameModel — content_hash non-empty
// ===========================================================================

#[test]
fn test_game_model_content_hash_non_empty() {
    let model = simple_game_model();
    assert!(!model.content_hash.is_empty());
}

// ===========================================================================
// 43) GameModelBuilder — with constraint increases constraint_count
// ===========================================================================

#[test]
fn test_builder_with_constraint_increases_constraint_count() {
    let model = GameModelBuilder::new(Subsystem::Compiler, test_epoch())
        .constraint(HardConstraint {
            constraint_id: "c1".into(),
            description: "first".into(),
            forbidden_actions: BTreeSet::new(),
            active_conditions: vec!["cond-a".into()],
        })
        .constraint(HardConstraint {
            constraint_id: "c2".into(),
            description: "second".into(),
            forbidden_actions: BTreeSet::new(),
            active_conditions: vec![],
        })
        .build();
    assert_eq!(model.automaton.constraint_count(), 2);
}

// ===========================================================================
// 44) model_id differs by epoch
// ===========================================================================

#[test]
fn test_model_id_differs_by_epoch() {
    let id1 = GameModel::compute_model_id(&Subsystem::Runtime, &SecurityEpoch::from_raw(1));
    let id2 = GameModel::compute_model_id(&Subsystem::Runtime, &SecurityEpoch::from_raw(2));
    assert_ne!(id1, id2);
}

// ===========================================================================
// 45) generate_report — report_hash non-empty and stable
// ===========================================================================

#[test]
fn test_generate_report_hash_non_empty_and_stable() {
    let model = simple_game_model();
    let r1 = generate_report(std::slice::from_ref(&model), &test_epoch());
    let r2 = generate_report(std::slice::from_ref(&model), &test_epoch());
    assert!(!r1.report_hash.is_empty());
    assert_eq!(r1.report_hash, r2.report_hash);
}

// ===========================================================================
// 46) ActionId PartialEq / Ord
// ===========================================================================

#[test]
fn test_action_id_partial_eq_and_ord() {
    let a = ActionId("alpha".into());
    let b = ActionId("beta".into());
    let a2 = ActionId("alpha".into());
    assert_eq!(a, a2);
    assert_ne!(a, b);
    assert!(a < b);
}

// ===========================================================================
// 47) HardConstraint — multiple forbidden actions all checked
// ===========================================================================

#[test]
fn test_hard_constraint_multiple_forbidden() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::EvidencePipeline,
        constraints: vec![HardConstraint {
            constraint_id: "c1".into(),
            description: "forbid several".into(),
            forbidden_actions: BTreeSet::from([
                ActionId("d1".into()),
                ActionId("d2".into()),
                ActionId("d3".into()),
            ]),
            active_conditions: vec!["epoch-high".into()],
        }],
        all_defender_actions: BTreeSet::from([
            ActionId("d1".into()),
            ActionId("d2".into()),
            ActionId("d3".into()),
            ActionId("d4".into()),
        ]),
    };
    assert!(!auto.is_admissible(&ActionId("d1".into())));
    assert!(!auto.is_admissible(&ActionId("d2".into())));
    assert!(!auto.is_admissible(&ActionId("d3".into())));
    assert!(auto.is_admissible(&ActionId("d4".into())));
    assert_eq!(auto.admissible_actions().len(), 1);
}

// ===========================================================================
// 48) Subsystem ordering is deterministic (Ord)
// ===========================================================================

#[test]
fn test_subsystem_ord_deterministic() {
    let mut subsystems = vec![
        Subsystem::Runtime,
        Subsystem::Compiler,
        Subsystem::EvidencePipeline,
        Subsystem::ControlPlane,
        Subsystem::ExtensionHost,
    ];
    subsystems.sort();
    // After sort, the vec should equal itself sorted again
    let sorted_again = {
        let mut v = subsystems.clone();
        v.sort();
        v
    };
    assert_eq!(subsystems, sorted_again);
}

// ===========================================================================
// 49) ActionSpace serde roundtrip
// ===========================================================================

#[test]
fn test_serde_roundtrip_action_space() {
    let space = ActionSpace {
        player: Player::Attacker,
        subsystem: Subsystem::ControlPlane,
        actions: vec![StrategicAction {
            action_id: ActionId("exploit-policy".into()),
            player: Player::Attacker,
            subsystem: Subsystem::ControlPlane,
            description: "policy bypass".into(),
            admissible: true,
            constraints: vec!["no-epoch-rollback".into()],
        }],
    };
    let json = serde_json::to_string(&space).unwrap();
    let rt: ActionSpace = serde_json::from_str(&json).unwrap();
    assert_eq!(space, rt);
}

// ===========================================================================
// 50) AdmissibleActionAutomaton serde roundtrip
// ===========================================================================

#[test]
fn test_serde_roundtrip_admissible_action_automaton() {
    let auto = AdmissibleActionAutomaton {
        subsystem: Subsystem::ExtensionHost,
        constraints: vec![HardConstraint {
            constraint_id: "c1".into(),
            description: "no unload during exec".into(),
            forbidden_actions: BTreeSet::from([ActionId("unload".into())]),
            active_conditions: vec!["executing".into()],
        }],
        all_defender_actions: BTreeSet::from([ActionId("pause".into()), ActionId("unload".into())]),
    };
    let json = serde_json::to_string(&auto).unwrap();
    let rt: AdmissibleActionAutomaton = serde_json::from_str(&json).unwrap();
    assert_eq!(auto, rt);
}
