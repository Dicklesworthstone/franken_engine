//! Recursive array-rest binding-pattern regressions.

use frankenengine_engine::HybridRouter;

fn assert_eval(source: &str, expected: &str) {
    let mut router = HybridRouter::default();
    let outcome = router
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"));
    assert_eq!(outcome.value, expected, "source: {source}");
}

#[test]
fn rest_array_pattern_binds_every_target() {
    assert_eval(r#"let [...[a, b]] = [1, 2, 3]; a + ":" + b;"#, "1:2");
}

#[test]
fn rest_array_pattern_uses_tail_not_whole_source() {
    assert_eval(
        r#"let [first, ...[second, third]] = [1, 2, 3]; first + second + third;"#,
        "6",
    );
}

#[test]
fn rest_object_pattern_observes_collected_array() {
    assert_eval(
        r#"let [first, ...{length: n}] = [1, 2, 3, 4]; first + ":" + n;"#,
        "1:3",
    );
}

#[test]
fn empty_rest_array_runs_sequential_defaults() {
    assert_eval(r#"let [...[a = 3, b = a + 2]] = []; a + ":" + b;"#, "3:5");
}

#[test]
fn rest_defaults_observe_prior_outer_pattern_binding() {
    assert_eval(
        r#"let [head, ...[a = head, b = a + 1]] = [7]; a + ":" + b;"#,
        "7:8",
    );
}

#[test]
fn rest_patterns_can_contain_another_rest() {
    assert_eval(
        r#"let [...[a, ...tail]] = [1, 2, 3]; a + ":" + tail.length + ":" + tail[0] + ":" + tail[1];"#,
        "1:2:2:3",
    );
}

#[test]
fn rest_patterns_preserve_elisions() {
    assert_eval(r#"let [...[, b]] = [1, 2]; b;"#, "2");
}

#[test]
fn rest_patterns_recurse_into_object_elements() {
    assert_eval(r#"let [...[{x}, y]] = [{x: 4}, 5]; x + y;"#, "9");
}

#[test]
fn const_loop_rest_patterns_initialize_each_binding() {
    assert_eval(
        r#"let total = 0; for (const [head, ...[a, b = a + 1]] of [[1, 2], [3, 4]]) { total += head + a + b; } total;"#,
        "18",
    );
}

#[test]
fn var_loop_rest_patterns_keep_shared_bindings() {
    assert_eval(
        r#"let total = 0; for (var [...[a, b]] of [[1, 2], [3, 4]]) { total += a + b; } total + ":" + a + ":" + b;"#,
        "10:3:4",
    );
}

#[test]
fn rest_assignment_pattern_writes_all_existing_bindings() {
    assert_eval(r#"let a = 0, b = 0; [...[a, b]] = [4, 5]; a + b;"#, "9");
}

#[test]
fn rest_patterns_work_in_function_parameters() {
    assert_eval(
        r#"function f([head, ...[a, b = a + 1]]) { return head + a + b; } f([1, 2]);"#,
        "6",
    );
}

#[test]
fn rest_patterns_work_in_arrow_parameters() {
    assert_eval(
        r#"let f = ([head, ...[a, b = a + 1]]) => head + a + b; f([1, 2]);"#,
        "6",
    );
}

#[test]
fn nested_empty_rest_target_does_not_clobber_head() {
    assert_eval(r#"let [head, ...[]] = [9, 8]; head;"#, "9");
}

#[test]
fn rest_pattern_does_not_mutate_source_array() {
    assert_eval(
        r#"let source = [1, 2, 3]; let [a, ...[b, c]] = source; source.join(":") + ":" + a + ":" + b + ":" + c;"#,
        "1:2:3:1:2:3",
    );
}

#[test]
fn simple_identifier_rest_remains_supported() {
    assert_eval(
        r#"let [head, ...tail] = [1, 2, 3]; head + ":" + tail.join(":");"#,
        "1:2:3",
    );
}
