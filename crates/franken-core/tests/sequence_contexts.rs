#![forbid(unsafe_code)]

//! Full Expression contexts accept comma operators, while AssignmentExpression
//! contexts retain their separators and reject an unparenthesized sequence.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn assert_output(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|error| panic!("sequence context must parse: {error:?}\n{source}"));
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "sequence-contexts.js"),
        &LoweringContext::new("sequence-trace", "sequence-decision", "sequence-policy"),
    )
    .expect("sequence context must lower")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "sequence-contexts");
        let result = core
            .execute(&module)
            .expect("sequence context must execute");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected, "{source}");
    }
}

#[test]
fn expression_statements_and_assignments_execute_in_source_order() {
    assert_output(
        r#"
        let trace = '', first = 0, last = 0;
        function mark(value) { trace += value; return value; }
        mark('a'), mark('b'), first = 3, last = first + 4;
        false ? mark('x') : mark('c'), mark('d');
        console.log(trace, first, last);
        "#,
        &["abcd 3 7"],
    );
}

#[test]
fn conditions_use_the_final_operand_on_every_evaluation() {
    assert_output(
        r#"
        let trace = '', index = 0;
        if (trace += 'a', false) { trace += 'x'; } else { trace += 'e'; }
        while (trace += 'w', index < 2) { index++; }
        do { trace += 'd'; } while (trace += 't', false);
        console.log(trace, index);
        "#,
        &["aewwwdt 2"],
    );
}

#[test]
fn all_three_for_clauses_preserve_sequence_effects() {
    assert_output(
        r#"
        let i = 0, j = 0, sum = 0;
        for (i = 0, j = 0; false, j < 3; i++, j++) { sum += i + j; }
        console.log(i, j, sum);
        let declarationSum = 0;
        for (let left = 0, right = 0; left < 2; left++, right += 2) {
            declarationSum += left + right;
        }
        console.log(declarationSum);
        "#,
        &["3 3 6", "3"],
    );
}

#[test]
fn return_sequences_yield_the_last_value_and_respect_line_terminators() {
    assert_output(
        r#"
        let trace = '';
        function read() { return trace += 'r', trace += 's', 42; }
        function automatic() {
            return
            trace += 'x', trace += 'y';
        }
        console.log(read(), trace);
        console.log(automatic(), trace);
        "#,
        &["42 rs", "undefined rs"],
    );
}

#[test]
fn throw_sequences_keep_object_identity_and_stop_at_a_failing_operand() {
    assert_output(
        r#"
        const failure = {code: 7};
        let trace = '', same = false;
        try { throw trace += 't', failure; }
        catch (error) { same = error === failure; }
        console.log(trace, same);
        function fail() { throw failure; }
        try { trace += 'a', fail(), trace += 'x'; }
        catch (error) { same = error === failure; }
        console.log(trace, same);
        "#,
        &["t true", "ta true"],
    );
}

#[test]
fn switch_discriminants_and_case_expressions_keep_conditional_colons() {
    assert_output(
        r#"
        let trace = '';
        switch (trace += 'd', 2) {
            case trace += 'x', 1: trace += 'bad'; break;
            case trace += 'y', true ? 2 : 3: trace += 'm'; break;
            default: trace += 'bad';
        }
        console.log(trace);
        "#,
        &["dxym"],
    );
}

#[test]
fn for_in_accepts_a_sequence_and_for_of_accepts_a_grouped_sequence() {
    assert_output(
        r#"
        let trace = '', keys = '', total = 0;
        const fields = {a: 1, b: 2};
        for (const key in trace += 'i', fields) { keys += key; }
        for (const value of (trace += 'o', [3, 4])) { total += value; }
        console.log(trace, keys, total);
        "#,
        &["io ab 7"],
    );
}

#[test]
fn template_substitutions_and_member_keys_evaluate_each_operand() {
    assert_output(
        r#"
        let count = 0;
        const object = {value: 9};
        console.log(object[count++, 'value'], count);
        object[count++, 'value'] += 3;
        console.log(`value:${count++, object.value} end`, count);
        "#,
        &["9 1", "value:12 end 3"],
    );
}

#[test]
fn list_separators_and_arrow_parameters_keep_their_original_meaning() {
    assert_output(
        r#"
        const left = 1, right = 2;
        const array = [left, right], object = {left: left, right: right};
        function pair(a, b) { return a * 10 + b; }
        function invoke(fn, value) { return fn(0) + value; }
        console.log(pair(left, right), array[0], array[1], object.left, object.right);
        console.log(((a, b) => a + b)(3, 4), invoke(x => 1, 2));
        "#,
        &["12 1 2 1 2", "7 3"],
    );
}

#[test]
fn assignment_expression_contexts_require_parentheses_around_a_sequence() {
    for source in [
        "for (const value of first, second) {}",
        "const object = {[first, second]: 1};",
        "class C { [first, second]() {} }",
        "const {[first, second]: value} = object;",
        "const value = true ? first, second : third;",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .is_err(),
            "AssignmentExpression must reject a bare sequence: {source}"
        );
    }
    assert!(
        CanonicalEs2020Parser
            .parse("export default first, second;", ParseGoal::Module)
            .is_err(),
        "the export-default expression must remain an AssignmentExpression"
    );
    for source in [
        "for (const value of (first, second)) {}",
        "const object = {[(first, second)]: 1};",
        "const value = true ? (first, second) : third;",
    ] {
        CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("grouped sequence must parse: {source}: {error:?}"));
    }
    CanonicalEs2020Parser
        .parse("export default (first, second);", ParseGoal::Module)
        .expect("grouping permits a sequence in an export-default operand");
}

#[test]
fn bare_sequences_require_every_operand_and_cannot_contain_spread() {
    for source in [
        "1,;",
        ",1;",
        "1,,2;",
        "1, /* missing */;",
        "...values,1;",
        "1,...values;",
        "if (1,) {}",
        "while (,true) {}",
        "function f() { return 1,; }",
        "throw 1,;",
        "object[1,];",
        "`value:${1,}`;",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .is_err(),
            "a sequence requires an expression at every operand: {source}"
        );
    }
}
