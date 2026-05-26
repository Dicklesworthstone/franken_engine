//! Integration tests for G.6.B async/await + microtask translation validation
//! (`bd-cixqu.7.9.2`).
//!
//! Exercises the public API end-to-end against the full generated corpus: every
//! program's lowering must validate, every semantics-breaking mutation must be
//! rejected, category breadth must meet the acceptance criteria, and the
//! `bd-cixqu.45` event log must round-trip through a real file sink.

use frankenengine_engine::async_translation_validation::{
    AsyncFeatureCategory, AsyncProgram, AsyncSourceOp, AsyncTranslationEvent, Completion,
    EquivalenceViolation, LoweringMutation, append_event_line, break_lowering,
    generate_async_programs, lower, source_semantics, verify_async_translation, verify_program,
};

#[test]
fn corpus_covers_all_five_categories_with_minimum_size() {
    let programs = generate_async_programs();
    assert!(
        programs.len() >= 50,
        "G.6.B requires >=50 generated programs, got {}",
        programs.len()
    );
    for category in AsyncFeatureCategory::ALL {
        let count = programs.iter().filter(|p| p.category == category).count();
        assert!(
            count >= 5,
            "category {category:?} under-covered ({count}); G.6.B requires breadth across all 5"
        );
    }
}

#[test]
fn every_program_in_corpus_validates() {
    for program in generate_async_programs() {
        let proof = verify_program(&program)
            .unwrap_or_else(|e| panic!("{} failed translation validation: {e:?}", program.name));
        assert_eq!(proof.program_name, program.name);
        assert_eq!(proof.category, program.category);
        assert_eq!(proof.source_op_count, program.source.len());
    }
}

#[test]
fn every_mutation_of_every_program_is_rejected() {
    // The core G.11 negative-test composition: a preserving-looking but broken
    // lowering must be REJECTED, not merely flagged.
    for program in generate_async_programs() {
        let lowered = lower(&program.source);
        for mutation in LoweringMutation::ALL {
            // If the mutation actually changed the lowering, validation must fail.
            if let Some(broken) = break_lowering(&lowered, mutation)
                && broken != lowered
            {
                let result = verify_async_translation(
                    &program.name,
                    program.category,
                    &program.source,
                    &broken,
                );
                assert!(
                    result.is_err(),
                    "{}: mutation {mutation:?} produced a broken lowering that was NOT rejected",
                    program.name
                );
            }
        }
    }
}

#[test]
fn ifc_downgrade_across_suspension_is_always_rejected() {
    // For every program with a non-trivial suspend label, downgrading the resume
    // is classified as an IFC downgrade — the security-critical rejection.
    let mut exercised = 0usize;
    for program in generate_async_programs() {
        let lowered = lower(&program.source);
        if let Some(broken) = break_lowering(&lowered, LoweringMutation::DowngradeResumeLabel) {
            let err =
                verify_async_translation(&program.name, program.category, &program.source, &broken)
                    .expect_err("downgraded resume must be rejected");
            assert!(
                matches!(err, EquivalenceViolation::IfcLabelDowngraded { .. }),
                "{}: expected IfcLabelDowngraded, got {err:?}",
                program.name
            );
            exercised += 1;
        }
    }
    assert!(
        exercised > 0,
        "no program exercised the IFC-downgrade rejection path"
    );
}

#[test]
fn simple_await_has_exactly_one_microtask_checkpoint() {
    let program = generate_async_programs()
        .into_iter()
        .find(|p| p.category == AsyncFeatureCategory::SimpleAwait)
        .unwrap();
    let proof = verify_program(&program).unwrap();
    assert_eq!(proof.microtask_checkpoints, 1);
}

#[test]
fn await_in_loop_checkpoint_count_matches_iterations() {
    let program = AsyncProgram {
        name: "loop5".into(),
        category: AsyncFeatureCategory::AwaitInLoop,
        source: vec![
            AsyncSourceOp::AwaitInLoop {
                iterations: 5,
                label: 1,
            },
            AsyncSourceOp::Return { label: 0 },
        ],
    };
    let proof = verify_program(&program).unwrap();
    assert_eq!(proof.microtask_checkpoints, 5);
}

#[test]
fn promise_all_schedules_branch_plus_join_checkpoints() {
    let program = AsyncProgram {
        name: "all3".into(),
        category: AsyncFeatureCategory::ParallelAwait,
        source: vec![
            AsyncSourceOp::ParallelAwait {
                branch_labels: vec![2, 0, 3],
            },
            AsyncSourceOp::Return { label: 0 },
        ],
    };
    let proof = verify_program(&program).unwrap();
    assert_eq!(proof.microtask_checkpoints, 4, "3 branches + 1 join");
    assert_eq!(proof.max_ifc_label, 3, "join lifts pc to lattice join");
}

#[test]
fn error_propagation_through_awaits_rejects_the_function() {
    let program = AsyncProgram {
        name: "throws".into(),
        category: AsyncFeatureCategory::ErrorPropagation,
        source: vec![
            AsyncSourceOp::Await { label: 1 },
            AsyncSourceOp::Await { label: 2 },
            AsyncSourceOp::Throw,
        ],
    };
    let proof = verify_program(&program).unwrap();
    assert_eq!(proof.completion, Completion::Rejected);
    assert_eq!(proof.microtask_checkpoints, 2);
}

#[test]
fn await_in_try_catch_caught_rejection_resolves() {
    let program = AsyncProgram {
        name: "caught".into(),
        category: AsyncFeatureCategory::AwaitTryCatch,
        source: vec![
            AsyncSourceOp::TryAwait {
                body_label: 2,
                rejects: true,
                handler_label: 1,
            },
            AsyncSourceOp::Return { label: 0 },
        ],
    };
    let proof = verify_program(&program).unwrap();
    // A caught rejection does not reject the function; pc joins to max(body, handler).
    assert_eq!(proof.completion, Completion::Resolved { label: 2 });
}

#[test]
fn proof_hashes_are_deterministic_across_runs() {
    let first: Vec<String> = generate_async_programs()
        .iter()
        .map(|p| verify_program(p).unwrap().proof_hash.to_hex())
        .collect();
    let second: Vec<String> = generate_async_programs()
        .iter()
        .map(|p| verify_program(p).unwrap().proof_hash.to_hex())
        .collect();
    assert_eq!(first, second);
}

#[test]
fn event_log_round_trips_through_a_real_file() {
    let dir = std::env::temp_dir().join(format!("g6b_integ_events_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let _ = std::fs::remove_file(&path);

    let programs = generate_async_programs();
    let mut validated = 0usize;
    let mut rejected = 0usize;

    for program in &programs {
        // Log the validated outcome.
        let proof = verify_program(program).unwrap();
        append_event_line(&path, &AsyncTranslationEvent::validated(&proof)).unwrap();
        validated += 1;

        // Log a rejected outcome for a broken lowering.
        let lowered = lower(&program.source);
        if let Some(broken) = break_lowering(&lowered, LoweringMutation::SwapCompletion)
            && let Err(err) =
                verify_async_translation(&program.name, program.category, &program.source, &broken)
        {
            append_event_line(
                &path,
                &AsyncTranslationEvent::rejected(
                    &program.name,
                    program.category,
                    program.source.len(),
                    &err,
                ),
            )
            .unwrap();
            rejected += 1;
        }
    }

    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), validated + rejected);

    let mut parsed_validated = 0usize;
    let mut parsed_rejected = 0usize;
    for line in lines {
        let event: AsyncTranslationEvent = serde_json::from_str(line).unwrap();
        if event.validated {
            assert_eq!(event.event, "async_translation_validated");
            assert!(!event.proof_hash.is_empty());
            parsed_validated += 1;
        } else {
            assert_eq!(event.event, "async_translation_rejected");
            assert!(event.proof_hash.is_empty());
            parsed_rejected += 1;
        }
    }
    assert_eq!(parsed_validated, validated);
    assert_eq!(parsed_rejected, rejected);
    assert!(rejected > 0, "expected at least one rejected program");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn source_and_lowered_schedules_agree_for_whole_corpus() {
    for program in generate_async_programs() {
        let src = source_semantics(&program.source);
        let low = frankenengine_engine::async_translation_validation::ir3_semantics(&lower(
            &program.source,
        ));
        assert_eq!(src, low, "schedule divergence for {}", program.name);
    }
}
