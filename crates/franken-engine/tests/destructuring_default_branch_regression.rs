//! Default-pattern control flow and binding-semantics regressions.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::lower_ir0_to_ir1;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn assert_eval(source: &str, expected: &str) {
    let mut router = HybridRouter::default();
    let outcome = router
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"));
    assert_eq!(outcome.value, expected, "source: {source}");
}

#[test]
fn defaults_only_replace_undefined() {
    assert_eval(
        r#"let calls = 0; let [a = (calls += 1), b = (calls += 1), c = (calls += 1), d = (calls += 1)] = [null, 0, false, void 0]; (a === null) + ":" + b + ":" + (c === false) + ":" + d + ":" + calls;"#,
        "true:0:true:1:1",
    );
}

#[test]
fn nested_defaults_run_outside_in_once() {
    assert_eval(
        r#"let trace = ""; let [[[x = (trace += "x", 7)] = (trace += "i", [])] = (trace += "o", [])] = []; trace + ":" + x;"#,
        "oix:7",
    );
}

#[test]
fn provided_nested_values_skip_all_defaults() {
    assert_eval(
        r#"let calls = 0; let [[[x = (calls += 100)] = (calls += 10, [])] = (calls += 1, [])] = [[[8]]]; x + ":" + calls;"#,
        "8:0",
    );
}

#[test]
fn nested_object_defaults_share_one_initialization_path() {
    assert_eval(r#"let {a: {b: {c = 7} = {}} = {}} = {}; c;"#, "7");
}

#[test]
fn default_observes_prior_binding() {
    assert_eval(r#"let [a = 3, b = a + 4, c = b + 5] = []; c;"#, "12");
}

#[test]
fn loop_defaults_observe_current_iteration_not_outer_binding() {
    assert_eval(
        r#"let a = 99; let total = 0; for (let [a, b = a] of [[1], [2]]) { total += b; } total + ":" + a;"#,
        "3:99",
    );
}

#[test]
fn default_closure_retains_each_iteration_cell() {
    assert_eval(
        r#"let fns = []; for (let [a, g = () => a] of [[1], [2], [3]]) { fns.push(g); } fns[0]() + fns[1]() + fns[2]();"#,
        "6",
    );
}

#[test]
fn nested_defaults_in_function_parameters() {
    assert_eval(
        r#"function f([[x = 7] = []] = []) { return x; } f() + f([[9]]);"#,
        "16",
    );
}

#[test]
fn nested_defaults_in_arrow_parameters() {
    assert_eval(
        r#"let f = ([[x = 7] = []] = []) => x; f() + f([[9]]);"#,
        "16",
    );
}

#[test]
fn assignment_defaults_preserve_sequential_writes() {
    assert_eval(
        r#"let a = 0, b = 0; [a = 3, b = a + 2] = []; a + ":" + b;"#,
        "3:5",
    );
}

#[test]
fn default_assignment_still_rejects_const_write() {
    assert_eval(
        r#"let name = ""; const a = 1; try { [a = 3] = []; } catch (error) { name = error.name; } name;"#,
        "TypeError",
    );
}

#[test]
fn throwing_default_prevents_later_initializer() {
    assert_eval(
        r#"let trace = ""; function boom() { trace += "a"; throw 7; } try { let [[x = boom()] = [], y = (trace += "b")] = []; } catch (error) { trace += "c"; } trace;"#,
        "ac",
    );
}

#[test]
fn forward_binding_remains_in_tdz() {
    assert_eval(
        r#"let name = ""; try { for (let [a = b, b = 2] of [[]]) {} } catch (error) { name = error.name; } name;"#,
        "ReferenceError",
    );
}

#[test]
fn deeply_nested_defaults_do_not_duplicate_the_target_subtree() {
    for depth in [1, 4, 8, 12] {
        let mut pattern = "value = 7".to_string();
        for _ in 0..depth {
            pattern = format!("[{pattern}] = []");
        }
        let source = format!("let [{pattern}] = []; value;");
        assert_eval(&source, "7");
    }
}

fn lowered_default_ops(depth: usize) -> usize {
    let mut pattern = "value = 7".to_string();
    for _ in 0..depth {
        pattern = format!("[{pattern}] = []");
    }
    let source = format!("let [{pattern}] = []; value;");
    let tree = CanonicalEs2020Parser
        .parse(source.as_str(), ParseGoal::Script)
        .expect("nested default source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "nested-default-branch-regression");
    lower_ir0_to_ir1(&ir0)
        .expect("nested defaults should lower")
        .module
        .ops
        .len()
}

#[test]
fn nested_default_ir_size_grows_linearly() {
    let counts = [
        lowered_default_ops(3),
        lowered_default_ops(6),
        lowered_default_ops(9),
    ];
    assert!(
        counts[1] <= counts[0] * 2 + 32 && counts[2] <= counts[1] * 2 + 32,
        "nested-default IR is growing superlinearly: {counts:?}"
    );
}
