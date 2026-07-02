#![forbid(unsafe_code)]
//! E2.T5 — divergence-preserving case minimization, end-to-end (bd-fqlfw.2.5).
//!
//! These tests drive the *real* differential oracle as the divergence predicate
//! (no synthetic classifier, no mocks). To stay hermetic and deterministic they
//! restrict the lane selection to the internal twin — franken-engine vs
//! franken-core — so no external `node`/`bun` process is spawned and the
//! classification is a pure function of the two in-process interpreters.
//!
//! The unit-level coverage of the `ddmin` reduction logic lives next to the
//! implementation in `src/differential_oracle.rs`; here we prove that the
//! oracle-backed wrapper (`minimize_oracle_divergence`) actually reduces a real
//! diverging program while reproducing the original classification, and that it
//! refuses a program that does not diverge.

use frankenengine_engine::differential_oracle::{
    DifferentialBackend, DifferentialMinimizationError, DifferentialOracleInput,
    DivergenceSignature, minimize_oracle_divergence, run_differential_oracle,
};

/// Build an oracle input restricted to the internal franken-engine ↔ franken-core
/// twin. The external runtime specs are pointed at deliberately-missing binaries
/// as a belt-and-suspenders guard so the test can never spawn a real node/bun
/// even if the selection logic changed.
fn engine_core_input(case_id: &str, source: &str) -> DifferentialOracleInput {
    let mut input = DifferentialOracleInput::new(case_id, source)
        .with_selected_backends([
            DifferentialBackend::FrankenEngine,
            DifferentialBackend::FrankenCore,
        ])
        // The engine lane's containment budget is far below benchmark sizes; the
        // probe programs are tiny, but raise it so a divergence is never an
        // artifact of one lane hitting the instruction ceiling first.
        .with_engine_instruction_budget(64_000_000);
    input.node.program = "frankenengine-missing-node-runtime".to_string();
    input.bun.program = "frankenengine-missing-bun-runtime".to_string();
    input
}

fn signature_of(input: &DifferentialOracleInput) -> DivergenceSignature {
    DivergenceSignature::from_report(&run_differential_oracle(input))
}

#[test]
fn consensus_program_is_not_minimizable() {
    // engine and franken-core both evaluate the bare expression `1 + 1` to the
    // completion value `2`; there is no classified (semantic) divergence, so the
    // minimizer must refuse rather than invent one. (A bare expression is used
    // deliberately: a `console.log` program would diverge because the engine lane
    // renders the console stream while the core lane reports the statement's
    // `undefined` completion value — a lane asymmetry the semantic-only signature
    // is designed to surface, not suppress.)
    let input = engine_core_input("consensus-arith", "1 + 1;");
    assert!(
        !signature_of(&input).has_classified_divergence(),
        "engine and franken-core should agree on the value of `1 + 1`"
    );

    let err = minimize_oracle_divergence(&input, 256)
        .expect_err("a consensus program has nothing to minimize");
    assert_eq!(err, DifferentialMinimizationError::NoDivergenceInOriginal);
}

#[test]
fn minimizes_a_real_engine_core_divergence_preserving_classification() {
    // Candidate one-liner *bare expressions* (no `console.log`: the core lane has
    // no console builtin and faults on it, which the oracle reports as
    // InsufficientData rather than a comparable divergence). A clean classified
    // divergence needs BOTH lanes to complete with different structured values,
    // so we target the value-producing constructs where the two interpreters are
    // most likely to disagree (function calls / returns / loop accumulation —
    // historically the register-allocation and return-convention divergence
    // areas). We do NOT assume which one currently diverges; we pick the first the
    // *real* oracle classifies as a divergence and minimize THAT one.
    let candidates = [
        // A stable architectural divergence: `typeof console` is "object" in the
        // engine (runtime globals injected) but "undefined" in franken-core (no
        // runtime globals). This leads the list because the consumed-postfix
        // (bd-xi3bk) and array/object (bd-rkmpj) candidates below have reached
        // parity. If franken-core ever injects console, replace with another
        // genuine divergence.
        "typeof console;",
        "(function () { var i = 5; var x = i++; return x; })();",
        "[1, 2, 3];",
        "({a: 1, b: 2});",
        "(function () { return [1, 2, 3]; })();",
        "(function () { return {x: 1}; })();",
        "[1, 2, 3].length === 3 ? [1, 2] : [3];",
        "(function (a, b) { return a + b; })(3, 4);",
        "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();",
        "(function (a, b, c) { return a + b + c; })(1, 2, 3);",
        "(function () { function inner(n) { return n * n; } return inner(6); })();",
        "(function () { var a = [10, 20, 30]; return a[0] + a[2]; })();",
    ];

    let mut probe_report: Vec<String> = Vec::new();
    let mut chosen: Option<&str> = None;
    for snippet in candidates {
        let input = engine_core_input("probe", snippet);
        let started = std::time::Instant::now();
        let signature = signature_of(&input);
        let elapsed_ms = started.elapsed().as_millis();
        probe_report.push(format!(
            "{snippet:?} -> divergence={} verdict={:?} semantic_findings={} ({elapsed_ms}ms)",
            signature.has_classified_divergence(),
            signature.verdict,
            signature.findings.len(),
        ));
        if signature.has_classified_divergence() {
            chosen = Some(snippet);
            break;
        }
    }

    eprintln!("[bd-fqlfw.2.5] probe results:\n{}", probe_report.join("\n"));
    let snippet = chosen.unwrap_or_else(|| {
        panic!(
            "expected at least one engine<->franken-core divergence among the probe \
             candidates; if the internal twin has reached full parity on this set, \
             extend the candidate list. Per-candidate results:\n{}",
            probe_report.join("\n")
        )
    });
    eprintln!("[bd-fqlfw.2.5] minimizing real divergence from: {snippet:?}");

    // Wrap the diverging line in inert comment/blank filler that both lanes treat
    // identically. A faithful minimizer must strip all of it while keeping the
    // one line that carries the divergence.
    let program = format!(
        "// preamble comment 1\n\
         // preamble comment 2\n\
         \n\
         {snippet}\n\
         \n\
         // trailing comment 1\n\
         // trailing comment 2\n\
         // trailing comment 3\n"
    );

    let input = engine_core_input("real-divergence", &program);
    let original_signature = signature_of(&input);
    assert!(
        original_signature.has_classified_divergence(),
        "filler must not erase the divergence carried by `{snippet}`"
    );

    let outcome = minimize_oracle_divergence(&input, 256).expect("the wrapped program diverges");
    eprintln!(
        "[bd-fqlfw.2.5] {} -> {} line(s) in {} oracle calls; minimized = {:?}",
        outcome.original_line_count,
        outcome.minimized_line_count,
        outcome.oracle_invocations,
        outcome.minimized_source,
    );

    // The minimizer claims the classification is preserved...
    assert!(outcome.classification_preserved);
    assert!(outcome.signature.has_classified_divergence());
    assert_eq!(outcome.signature, original_signature);

    // ...and it actually reduced the program (filler removed).
    assert!(
        outcome.minimized_line_count < outcome.original_line_count,
        "expected filler to be removed: {} -> {} lines",
        outcome.original_line_count,
        outcome.minimized_line_count
    );
    assert!(outcome.minimized_len_bytes < outcome.original_len_bytes);
    assert!(outcome.reached_fixed_point);

    // Independent re-verification of the ACCEPTANCE criterion: re-running the real
    // oracle on the minimized source must reproduce the *same* taxonomy
    // classification as the original. This does not trust the minimizer's own
    // bookkeeping — it recomputes the signature from scratch.
    let reverify = engine_core_input("real-divergence-reverify", &outcome.minimized_source);
    assert_eq!(
        signature_of(&reverify),
        original_signature,
        "minimized case must reproduce the original classified divergence"
    );
}
