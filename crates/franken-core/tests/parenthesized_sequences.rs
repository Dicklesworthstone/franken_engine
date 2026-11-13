#![forbid(unsafe_code)]

//! Parenthesized comma operands execute in the caller's scope and yield the
//! final value, including in parameter defaults and across bounded call chunks.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

fn assert_output(source: &str, expected: &[&str]) {
    assert_output_with_register_budget(source, expected, None);
}

fn assert_output_with_register_budget(
    source: &str,
    expected: &[&str],
    register_budget: Option<u32>,
) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("sequence fixture must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "parenthesized-sequences.js"),
        &LoweringContext::new("sequence-trace", "sequence-decision", "sequence-policy"),
    )
    .expect("sequence fixture must lower")
    .ir3;
    if register_budget.is_some() {
        assert!(
            module
                .function_table
                .iter()
                .all(|function| function.arity <= 64),
            "the unrolled fixture must keep every generated call within the sequence chunk bound"
        );
        assert!(
            module
                .function_table
                .iter()
                .filter(|function| function.name.as_deref() != Some("main"))
                .all(|function| function.frame_size <= 256),
            "synthetic callees must still fit the default QuickJS register budget"
        );
    }
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        if let Some(register_budget) = register_budget {
            config.max_registers = config.max_registers.max(register_budget);
        }
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "parenthesized-sequences");
        let result = core
            .execute(&module)
            .expect("sequence fixture must execute");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn operands_execute_left_to_right_and_yield_the_last_value() {
    assert_output(
        r#"
        let trace = '';
        function mark(value) { trace += value; return value; }
        const last = (mark('a'), mark('b'), mark('c'));
        console.log(trace, last);
        function pair(left, right) { return left * 10 + right; }
        console.log(pair(1, 2), pair((1, 2), 3), ((a, b) => a + b)(6, 7));
        "#,
        &["abc c", "12 23 13"],
    );
}

#[test]
fn parameter_defaults_keep_sequence_updates_and_skip_explicit_arguments() {
    assert_output(
        r#"
        let defaults = 0;
        function choose(value = (++defaults, 4)) { return value + 1; }
        console.log(defaults);
        console.log(choose(), defaults);
        console.log(choose(8), defaults);
        "#,
        &["0", "5 1", "9 1"],
    );
}

#[test]
fn operands_keep_caller_this_and_cannot_be_shadowed_by_generated_parameters() {
    assert_output(
        r#"
        const __seq_0 = 40, __seq_1 = 2;
        const receiver = {
            base: 7,
            read() { return (this.base += 1, this.base + __seq_0 + __seq_1); }
        };
        console.log(receiver.read(), receiver.base, __seq_0, __seq_1);
        "#,
        &["50 8 40 2"],
    );
}

#[test]
fn a_throw_preserves_identity_and_skips_later_operands() {
    assert_output(
        r#"
        const failure = {code: 7};
        let trace = '';
        function first() { trace += 'a'; return 1; }
        function fail() { trace += 'b'; throw failure; }
        function skipped() { trace += 'c'; return 3; }
        let same = false;
        try { (first(), fail(), skipped()); }
        catch (error) { same = error === failure; }
        console.log(trace, same);
        "#,
        &["ab true"],
    );
}

#[test]
fn chunk_boundaries_preserve_every_operand_with_bounded_call_arity() {
    // Core's current allocator retains every caller temporary: these unrolled
    // 64/65/300-call fixtures need 337/345/1529 caller registers respectively.
    // Give only this fixture a finite larger caller budget; generated function
    // arities and callee frames remain bounded by their original limits.
    for count in [64, 65, 300] {
        let operands = (1..=count)
            .map(|value| format!("step({value})"))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!(
            "let count=0; let total=0; let ordered=true; \
             function step(value){{count++; total+=value; ordered=ordered&&value===count; return value;}} \
             const result=({operands}); console.log(result,count,total,ordered);"
        );
        let expected = format!("{count} {count} {} true", count * (count + 1) / 2);
        assert_output_with_register_budget(&source, &[&expected], Some(2048));
    }
}

#[test]
fn sequences_reject_missing_trailing_and_spread_operands() {
    for source in [
        "(1,);",
        "(,1);",
        "(1,,2);",
        "(1, /* missing */);",
        "(...values,1);",
        "(/* before spread */ ...values,1);",
        "(1,...values);",
    ] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect_err("a sequence requires an expression at every operand");
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
    }
}
