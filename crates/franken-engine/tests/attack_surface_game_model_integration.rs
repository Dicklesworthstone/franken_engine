//! Integration tests for `frankenengine_engine::attack_surface_game_model`.
//!
//! Exercises the attack-surface game model from the public crate boundary:
//! Subsystem, Player, ActionId, StrategicAction, ActionSpace, LossDimension,
//! LossEntry, LossTensor, HardConstraint, AdmissibleActionAutomaton,
//! GameModel, GameModelBuilder, GameModelReport, generate_report.

use std::collections::BTreeSet;

use frankenengine_engine::attack_surface_game_model::{
    ActionId, ActionSpace, AdmissibleActionAutomaton, GameModel, GameModelBuilder, HardConstraint,
    LossDimension, LossEntry, LossTensor, Player, SCHEMA_VERSION, StrategicAction, Subsystem,
    generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(7)
}

fn aid(name: &str) -> ActionId {
    ActionId(name.to_string())
}

fn attacker_action(name: &str, sub: Subsystem) -> StrategicAction {
    StrategicAction {
        action_id: aid(name),
        player: Player::Attacker,
        subsystem: sub,
        description: format!("Attacker: {name}"),
        admissible: true,
        constraints: Vec::new(),
    }
}

fn defender_action(name: &str, sub: Subsystem, admissible: bool) -> StrategicAction {
    StrategicAction {
        action_id: aid(name),
        player: Player::Defender,
        subsystem: sub,
        description: format!("Defender: {name}"),
        admissible,
        constraints: if admissible {
            Vec::new()
        } else {
            vec!["forbidden-by-test".to_string()]
        },
    }
}

fn loss(atk: &str, def: &str, dim: LossDimension, value: i64) -> LossEntry {
    LossEntry {
        attacker_action: aid(atk),
        defender_action: aid(def),
        dimension: dim,
        loss_millionths: value,
    }
}

fn build_simple_model() -> GameModel {
    GameModelBuilder::new(Subsystem::Compiler, epoch())
        .attacker_action(attacker_action("inject-malicious-ast", Subsystem::Compiler))
        .attacker_action(attacker_action("overflow-stack", Subsystem::Compiler))
        .defender_action(defender_action("quarantine", Subsystem::Compiler, true))
        .defender_action(defender_action("allow-through", Subsystem::Compiler, true))
        .defender_action(defender_action(
            "nuke-everything",
            Subsystem::Compiler,
            false,
        ))
        .loss(loss(
            "inject-malicious-ast",
            "quarantine",
            LossDimension::UserHarm,
            100_000,
        ))
        .loss(loss(
            "inject-malicious-ast",
            "allow-through",
            LossDimension::UserHarm,
            900_000,
        ))
        .loss(loss(
            "overflow-stack",
            "quarantine",
            LossDimension::UserHarm,
            50_000,
        ))
        .loss(loss(
            "overflow-stack",
            "allow-through",
            LossDimension::UserHarm,
            700_000,
        ))
        .loss(loss(
            "inject-malicious-ast",
            "quarantine",
            LossDimension::PerformanceCost,
            200_000,
        ))
        .loss(loss(
            "inject-malicious-ast",
            "allow-through",
            LossDimension::PerformanceCost,
            0,
        ))
        .constraint(HardConstraint {
            constraint_id: "no-nuke".to_string(),
            description: "Cannot nuke everything".to_string(),
            forbidden_actions: {
                let mut s = BTreeSet::new();
                s.insert(aid("nuke-everything"));
                s
            },
            active_conditions: vec!["always".to_string()],
        })
        .build()
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn schema_version_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

// ── Subsystem ──────────────────────────────────────────────────────────

#[test]
fn subsystem_display() {
    assert_eq!(Subsystem::Compiler.to_string(), "compiler");
    assert_eq!(Subsystem::Runtime.to_string(), "runtime");
    assert_eq!(Subsystem::ControlPlane.to_string(), "control_plane");
    assert_eq!(Subsystem::ExtensionHost.to_string(), "extension_host");
    assert_eq!(Subsystem::EvidencePipeline.to_string(), "evidence_pipeline");
}

#[test]
fn subsystem_serde_roundtrip() {
    for sub in [
        Subsystem::Compiler,
        Subsystem::Runtime,
        Subsystem::ControlPlane,
        Subsystem::ExtensionHost,
        Subsystem::EvidencePipeline,
    ] {
        let json = serde_json::to_string(&sub).unwrap();
        let back: Subsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sub);
    }
}

// ── Player ──────────────────────────────────────────────────────────────

#[test]
fn player_display() {
    assert_eq!(Player::Attacker.to_string(), "attacker");
    assert_eq!(Player::Defender.to_string(), "defender");
}

#[test]
fn player_serde_roundtrip() {
    for player in [Player::Attacker, Player::Defender] {
        let json = serde_json::to_string(&player).unwrap();
        let back: Player = serde_json::from_str(&json).unwrap();
        assert_eq!(back, player);
    }
}

// ── ActionId ────────────────────────────────────────────────────────────

#[test]
fn action_id_display() {
    let id = aid("quarantine");
    assert_eq!(id.to_string(), "quarantine");
}

#[test]
fn action_id_serde_roundtrip() {
    let id = aid("test-action");
    let json = serde_json::to_string(&id).unwrap();
    let back: ActionId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, id);
}

// ── LossDimension ──────────────────────────────────────────────────────

#[test]
fn loss_dimension_display() {
    assert_eq!(LossDimension::UserHarm.to_string(), "user_harm");
    assert_eq!(
        LossDimension::PerformanceCost.to_string(),
        "performance_cost"
    );
    assert_eq!(
        LossDimension::FalsePositiveCost.to_string(),
        "false_positive_cost"
    );
    assert_eq!(
        LossDimension::AvailabilityCost.to_string(),
        "availability_cost"
    );
    assert_eq!(
        LossDimension::EvidenceIntegrityCost.to_string(),
        "evidence_integrity_cost"
    );
}

#[test]
fn loss_dimension_serde_roundtrip() {
    for dim in [
        LossDimension::UserHarm,
        LossDimension::PerformanceCost,
        LossDimension::FalsePositiveCost,
        LossDimension::AvailabilityCost,
        LossDimension::EvidenceIntegrityCost,
    ] {
        let json = serde_json::to_string(&dim).unwrap();
        let back: LossDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dim);
    }
}

// ── ActionSpace ─────────────────────────────────────────────────────────

#[test]
fn action_space_counts() {
    let space = ActionSpace {
        player: Player::Defender,
        subsystem: Subsystem::Runtime,
        actions: vec![
            defender_action("d1", Subsystem::Runtime, true),
            defender_action("d2", Subsystem::Runtime, false),
            defender_action("d3", Subsystem::Runtime, true),
        ],
    };
    assert_eq!(space.action_count(), 3);
    assert_eq!(space.admissible_actions().len(), 2);
}

#[test]
fn action_space_serde_roundtrip() {
    let space = ActionSpace {
        player: Player::Attacker,
        subsystem: Subsystem::Compiler,
        actions: vec![attacker_action("a1", Subsystem::Compiler)],
    };
    let json = serde_json::to_string(&space).unwrap();
    let back: ActionSpace = serde_json::from_str(&json).unwrap();
    assert_eq!(back, space);
}

// ── LossTensor ──────────────────────────────────────────────────────────

#[test]
fn loss_tensor_from_entries_sorts_and_hashes() {
    let entries = vec![
        loss("a2", "d1", LossDimension::UserHarm, 200_000),
        loss("a1", "d1", LossDimension::UserHarm, 100_000),
    ];
    let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
    // Entries should be sorted by attacker action.
    assert_eq!(tensor.entries[0].attacker_action, aid("a1"));
    assert_eq!(tensor.entries[1].attacker_action, aid("a2"));
    assert!(!tensor.content_hash.is_empty());
}

#[test]
fn loss_tensor_lookup() {
    let tensor = LossTensor::from_entries(
        Subsystem::Compiler,
        vec![loss("a1", "d1", LossDimension::UserHarm, 500_000)],
    );
    assert_eq!(
        tensor.lookup(&aid("a1"), &aid("d1"), LossDimension::UserHarm),
        Some(500_000)
    );
    assert_eq!(
        tensor.lookup(&aid("a1"), &aid("d1"), LossDimension::PerformanceCost),
        None
    );
    assert_eq!(
        tensor.lookup(&aid("a1"), &aid("d2"), LossDimension::UserHarm),
        None
    );
}

#[test]
fn loss_tensor_total_loss() {
    let tensor = LossTensor::from_entries(
        Subsystem::Compiler,
        vec![
            loss("a1", "d1", LossDimension::UserHarm, 300_000),
            loss("a1", "d1", LossDimension::PerformanceCost, 100_000),
        ],
    );
    assert_eq!(tensor.total_loss(&aid("a1"), &aid("d1")), 400_000);
    assert_eq!(tensor.total_loss(&aid("a1"), &aid("d2")), 0);
}

#[test]
fn loss_tensor_minimax_defender() {
    let tensor = LossTensor::from_entries(
        Subsystem::Compiler,
        vec![
            loss("a1", "d-safe", LossDimension::UserHarm, 100_000),
            loss("a1", "d-risky", LossDimension::UserHarm, 900_000),
        ],
    );
    // d-safe has max loss of 100k across all attackers, d-risky has 900k.
    // Minimax picks d-safe.
    let mm = tensor.minimax_defender().unwrap();
    assert_eq!(mm, aid("d-safe"));
}

#[test]
fn loss_tensor_deterministic() {
    let entries = vec![
        loss("a1", "d1", LossDimension::UserHarm, 100_000),
        loss("a2", "d1", LossDimension::UserHarm, 200_000),
    ];
    let t1 = LossTensor::from_entries(Subsystem::Compiler, entries.clone());
    let t2 = LossTensor::from_entries(Subsystem::Compiler, entries);
    assert_eq!(t1.content_hash, t2.content_hash);
}

#[test]
fn loss_tensor_serde_roundtrip() {
    let tensor = LossTensor::from_entries(
        Subsystem::Runtime,
        vec![loss("a1", "d1", LossDimension::UserHarm, 500_000)],
    );
    let json = serde_json::to_string(&tensor).unwrap();
    let back: LossTensor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tensor);
}

// ── AdmissibleActionAutomaton ──────────────────────────────────────────

#[test]
fn automaton_admissible_actions() {
    let mut all = BTreeSet::new();
    all.insert(aid("d1"));
    all.insert(aid("d2"));
    all.insert(aid("d3"));
    let automaton = AdmissibleActionAutomaton {
        subsystem: Subsystem::Compiler,
        constraints: vec![HardConstraint {
            constraint_id: "c1".to_string(),
            description: "test".to_string(),
            forbidden_actions: {
                let mut s = BTreeSet::new();
                s.insert(aid("d2"));
                s
            },
            active_conditions: vec![],
        }],
        all_defender_actions: all,
    };
    let admissible = automaton.admissible_actions();
    assert_eq!(admissible.len(), 2);
    assert!(admissible.contains(&aid("d1")));
    assert!(admissible.contains(&aid("d3")));
    assert!(!admissible.contains(&aid("d2")));
}

#[test]
fn automaton_is_admissible() {
    let mut all = BTreeSet::new();
    all.insert(aid("d1"));
    all.insert(aid("d2"));
    let automaton = AdmissibleActionAutomaton {
        subsystem: Subsystem::Runtime,
        constraints: vec![HardConstraint {
            constraint_id: "c1".to_string(),
            description: "test".to_string(),
            forbidden_actions: {
                let mut s = BTreeSet::new();
                s.insert(aid("d2"));
                s
            },
            active_conditions: vec![],
        }],
        all_defender_actions: all,
    };
    assert!(automaton.is_admissible(&aid("d1")));
    assert!(!automaton.is_admissible(&aid("d2")));
    // Not in all_defender_actions at all.
    assert!(!automaton.is_admissible(&aid("d99")));
}

#[test]
fn automaton_constraint_count() {
    let automaton = AdmissibleActionAutomaton {
        subsystem: Subsystem::Compiler,
        constraints: vec![
            HardConstraint {
                constraint_id: "c1".to_string(),
                description: "".to_string(),
                forbidden_actions: BTreeSet::new(),
                active_conditions: vec![],
            },
            HardConstraint {
                constraint_id: "c2".to_string(),
                description: "".to_string(),
                forbidden_actions: BTreeSet::new(),
                active_conditions: vec![],
            },
        ],
        all_defender_actions: BTreeSet::new(),
    };
    assert_eq!(automaton.constraint_count(), 2);
}

// ── GameModel ──────────────────────────────────────────────────────────

#[test]
fn game_model_compute_model_id_deterministic() {
    let id1 = GameModel::compute_model_id(&Subsystem::Compiler, &epoch());
    let id2 = GameModel::compute_model_id(&Subsystem::Compiler, &epoch());
    assert_eq!(id1, id2);
    assert!(id1.starts_with("game-"));
}

#[test]
fn game_model_compute_model_id_differs_by_subsystem() {
    let id1 = GameModel::compute_model_id(&Subsystem::Compiler, &epoch());
    let id2 = GameModel::compute_model_id(&Subsystem::Runtime, &epoch());
    assert_ne!(id1, id2);
}

#[test]
fn game_model_builder_produces_valid_model() {
    let model = build_simple_model();
    assert!(model.model_id.starts_with("game-"));
    assert_eq!(model.schema_version, SCHEMA_VERSION);
    assert_eq!(model.subsystem, Subsystem::Compiler);
    assert_eq!(model.attacker_action_count(), 2);
    assert_eq!(model.defender_action_count(), 3);
    // "nuke-everything" is forbidden.
    assert_eq!(model.admissible_count(), 2);
}

#[test]
fn game_model_minimax_recommendation() {
    let model = build_simple_model();
    let rec = model.minimax_recommendation();
    assert!(rec.is_some());
    // "quarantine" has lower max loss than "allow-through".
    assert_eq!(rec.unwrap(), aid("quarantine"));
}

#[test]
fn game_model_serde_roundtrip() {
    let model = build_simple_model();
    let json = serde_json::to_string(&model).unwrap();
    let back: GameModel = serde_json::from_str(&json).unwrap();
    assert_eq!(back.model_id, model.model_id);
    assert_eq!(back.content_hash, model.content_hash);
    assert_eq!(back.subsystem, model.subsystem);
}

// ── generate_report ────────────────────────────────────────────────────

#[test]
fn generate_report_single_model() {
    let model = build_simple_model();
    let report = generate_report(&[model], &epoch());
    assert_eq!(report.total_models, 1);
    assert_eq!(report.total_attacker_actions, 2);
    assert_eq!(report.total_defender_actions, 3);
    assert_eq!(report.total_constraints, 1);
    assert!(!report.report_hash.is_empty());
    assert!(report.subsystem_summaries.contains_key("compiler"));
}

#[test]
fn generate_report_empty() {
    let report = generate_report(&[], &epoch());
    assert_eq!(report.total_models, 0);
    assert!(report.subsystem_summaries.is_empty());
}

#[test]
fn generate_report_deterministic() {
    let model = build_simple_model();
    let r1 = generate_report(std::slice::from_ref(&model), &epoch());
    let r2 = generate_report(std::slice::from_ref(&model), &epoch());
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn generate_report_serde_roundtrip() {
    let model = build_simple_model();
    let report = generate_report(&[model], &epoch());
    let json = serde_json::to_string(&report).unwrap();
    let back = serde_json::from_str::<
        frankenengine_engine::attack_surface_game_model::GameModelReport,
    >(&json)
    .unwrap();
    assert_eq!(back, report);
}

// ── Full lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_build_analyze_report() {
    let compiler_model = build_simple_model();
    let runtime_model = GameModelBuilder::new(Subsystem::Runtime, epoch())
        .attacker_action(attacker_action("timing-side-channel", Subsystem::Runtime))
        .defender_action(defender_action("rate-limit", Subsystem::Runtime, true))
        .loss(loss(
            "timing-side-channel",
            "rate-limit",
            LossDimension::PerformanceCost,
            150_000,
        ))
        .build();

    let report = generate_report(&[compiler_model, runtime_model], &epoch());
    assert_eq!(report.total_models, 2);
    assert!(report.subsystem_summaries.contains_key("compiler"));
    assert!(report.subsystem_summaries.contains_key("runtime"));
    assert_eq!(report.epoch, epoch());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn loss_dimension_debug_is_nonempty() {
    let dim = LossDimension::PerformanceCost;
    assert!(!format!("{dim:?}").is_empty());
}

#[test]
fn subsystem_debug_is_nonempty() {
    let s = Subsystem::Compiler;
    assert!(!format!("{s:?}").is_empty());
}

#[test]
fn player_debug_is_nonempty() {
    let p = Player::Attacker;
    assert!(!format!("{p:?}").is_empty());
}
