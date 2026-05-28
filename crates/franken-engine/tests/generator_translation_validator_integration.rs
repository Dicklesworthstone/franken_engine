// Integration tests for Track G.6.C (bd-cixqu.7.9.3): generator +
// async-generator translation validation. Drives the public checker as an
// external consumer over the full corpus and confirms broken lowerings are
// rejected.

use frankenengine_engine::generator_translation_validator::{
    GeneratorKind, GeneratorSource, GeneratorStateMachine, GeneratorStep, LoweringMutation,
    TraceDivergence, apply_mutation, generate_generator_corpus, lower_to_state_machine,
    replay_state_machine, source_trace, validate_corpus, validate_generator, validate_lowering,
};

#[test]
fn full_corpus_validates_equivalent_with_one_event_each() {
    let corpus = generate_generator_corpus();
    assert!(corpus.len() >= 50, "G.6.C requires >=50 programs");
    let report = validate_corpus(&corpus).unwrap();
    assert!(
        report.all_equivalent(),
        "{} of {} programs validated",
        report.equivalent,
        report.total
    );
    assert_eq!(report.events.len(), corpus.len());
}

#[test]
fn corpus_covers_all_four_feature_areas() {
    let corpus = generate_generator_corpus();
    let has = |p: &str| corpus.iter().any(|s| s.program_id.starts_with(p));
    assert!(has("sync-multiyield-"), "multi-yield sync generators");
    assert!(has("sync-return-"), "generators with return value");
    assert!(has("async-await-yield-"), "async gen await+yield");
    assert!(has("yield-delegate-"), "yield* delegation");
    assert!(corpus.iter().any(|s| s.kind == GeneratorKind::Async));
}

#[test]
fn canonical_lowering_replays_to_source_trace_for_every_program() {
    for src in generate_generator_corpus() {
        let sm = lower_to_state_machine(&src);
        let replayed = replay_state_machine(&sm).unwrap();
        assert_eq!(
            replayed,
            source_trace(&src),
            "lowering of {} must replay to source trace",
            src.program_id
        );
    }
}

#[test]
fn every_canonical_program_is_equivalent_with_matching_digests() {
    for src in generate_generator_corpus() {
        let w = validate_generator(&src).unwrap();
        assert!(w.equivalent, "{}", src.program_id);
        assert_eq!(w.source_digest, w.machine_digest);
    }
}

#[test]
fn dropping_any_yield_state_is_caught_for_every_program() {
    // For each program with >1 effect, dropping the first state must diverge.
    for src in generate_generator_corpus() {
        let sm = lower_to_state_machine(&src);
        if sm.states.len() < 2 {
            continue;
        }
        let broken = apply_mutation(&sm, &LoweringMutation::DropState(0));
        let w = validate_lowering(&src, &broken).unwrap();
        assert!(
            !w.equivalent,
            "dropping a state in {} must be caught",
            src.program_id
        );
        assert!(w.divergence.is_some());
    }
}

#[test]
fn async_await_yield_interleaving_is_order_significant() {
    // An async generator: await, yield, await, yield. Swapping the first two
    // effects (await<->yield) must be detected — checkpoints are observable.
    let src = GeneratorSource::new(
        "async-order",
        GeneratorKind::Async,
        vec![
            GeneratorStep::Await,
            GeneratorStep::Yield(1),
            GeneratorStep::Await,
            GeneratorStep::Yield(2),
        ],
        None,
    );
    assert!(validate_generator(&src).unwrap().equivalent);

    let sm = lower_to_state_machine(&src);
    let broken = apply_mutation(&sm, &LoweringMutation::SwapEffects(0, 1));
    let w = validate_lowering(&src, &broken).unwrap();
    assert!(!w.equivalent);
    assert_eq!(
        w.divergence,
        Some(TraceDivergence::EffectMismatch { index: 0 })
    );
}

#[test]
fn yield_delegation_flattens_and_is_validated() {
    let src = GeneratorSource::new(
        "deleg",
        GeneratorKind::Sync,
        vec![
            GeneratorStep::Yield(0),
            GeneratorStep::YieldDelegate(vec![1, 2, 3, 4]),
            GeneratorStep::Yield(5),
        ],
        Some(7),
    );
    let w = validate_generator(&src).unwrap();
    assert!(w.equivalent);
    // 1 + 4 delegated + 1 + return = 7 effects.
    assert_eq!(w.source_effects, 7);
}

#[test]
fn externally_supplied_correct_machine_validates() {
    // A consumer can validate a state machine it produced itself.
    let src = GeneratorSource::new(
        "ext",
        GeneratorKind::Sync,
        vec![GeneratorStep::Yield(1), GeneratorStep::Yield(2)],
        Some(9),
    );
    let sm = lower_to_state_machine(&src);
    let _: &GeneratorStateMachine = &sm;
    assert!(validate_lowering(&src, &sm).unwrap().equivalent);
}
