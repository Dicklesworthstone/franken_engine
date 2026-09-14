//! End-to-end iterator destructuring: lazy consumption, references and completions.

use frankenengine_engine::HybridRouter;

fn assert_eval(source: &str, expected: &str) {
    let mut router = HybridRouter::default();
    let outcome = router
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"));
    assert_eq!(outcome.value, expected, "source: {source}");
}

#[test]
fn custom_iterator_overrides_indexed_properties() {
    assert_eval(
        r#"let xs = {0: 99, length: 1, [Symbol.iterator]: function() { return {next: function() { return {value: 7, done: false}; }}; }}; let [a] = xs; a;"#,
        "7",
    );
}

#[test]
fn empty_binding_acquires_and_closes_without_stepping() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { trace += 'i'; return {next: function() { trace += 'n'; return {done: false}; }, return: function() { trace += 'r'; return {}; }}; }}; let [] = xs; trace;"#,
        "ir",
    );
}

#[test]
fn empty_assignment_acquires_and_closes_without_stepping() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { trace += 'i'; return {next: function() { trace += 'n'; return {done: false}; }, return: function() { trace += 'r'; return {}; }}; }}; [] = xs; trace;"#,
        "ir",
    );
}

#[test]
fn generator_prefix_is_lazy_and_finalized() {
    assert_eval(
        r#"let trace = ''; function* values() { try { trace += 'a'; yield 3; trace += 'b'; yield 4; } finally { trace += 'f'; } } let [a] = values(); a + ':' + trace;"#,
        "3:af",
    );
}

#[test]
fn infinite_generator_only_produces_requested_prefix() {
    assert_eval(
        r#"let n = 0; function* values() { while (true) { n += 1; yield n; } } let [a, b] = values(); a + ':' + b + ':' + n;"#,
        "1:2:2",
    );
}

#[test]
fn elisions_advance_but_do_not_read_result_value() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { return {next: function() { trace += 'n'; return {get done() { trace += 'd'; return false; }, get value() { trace += 'v'; return 8; }}; }, return: function() { trace += 'r'; return {}; }}; }}; let [, a] = xs; a + ':' + trace;"#,
        "8:ndndvr",
    );
}

#[test]
fn elision_skips_throwing_custom_value_getter() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, get value() { throw 9; }}; }, return: function() { trace += 'r'; return {}; }}; }}; let [,] = xs; trace;"#,
        "r",
    );
}

#[test]
fn exhaustion_is_sticky_and_ignores_terminal_value() {
    assert_eval(
        r#"let n = 0; let closed = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {done: true, get value() { throw 9; }}; }, return: function() { closed += 1; return {}; }}; }}; let [a = 3, , b = a + 1, ...rest] = xs; a + ':' + b + ':' + n + ':' + closed + ':' + rest.length;"#,
        "3:4:1:0:0",
    );
}

#[test]
fn done_coercion_uses_truthiness() {
    assert_eval(
        r#"let n = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {done: 'finished', get value() { throw 1; }}; }}; }}; let [a = 6, b = 7] = xs; a + b + n;"#,
        "14",
    );
}

#[test]
fn defaults_are_interleaved_with_steps() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { return {next: function() { trace += 'n'; return {done: false, value: undefined}; }, return: function() { trace += 'r'; return {}; }}; }}; let [a = (trace += 'a', 2), b = (trace += 'b', a + 1)] = xs; a + ':' + b + ':' + trace;"#,
        "2:3:nanbr",
    );
}

#[test]
fn null_does_not_trigger_a_default() {
    assert_eval(
        r#"let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: null}; }}; }}; let [a = 9] = xs; a === null;"#,
        "true",
    );
}

#[test]
fn captured_next_method_survives_mutation() {
    assert_eval(
        r#"let n = 0; let it = {next: function() { n += 1; it.next = function() { throw 9; }; return {done: false, value: n}; }}; let xs = {[Symbol.iterator]: function() { return it; }}; let [a, b] = xs; a + ':' + b + ':' + n;"#,
        "1:2:2",
    );
}

#[test]
fn rest_collects_only_remaining_iterator_values() {
    assert_eval(
        r#"let n = 0; let c = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {done: n > 4, value: n}; }, return: function() { c += 1; return {}; }}; }}; let [a, , ...rest] = xs; a + ':' + rest.length + ':' + rest[0] + ':' + rest[1] + ':' + c;"#,
        "1:2:3:4:0",
    );
}

#[test]
fn rest_supports_nested_binding_patterns() {
    assert_eval(
        r#"let n = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {done: n > 3, value: n * 2}; }}; }}; let [a, ...[b, c, d = 9]] = xs; a + b + c + d;"#,
        "21",
    );
}

#[test]
fn string_destructuring_uses_unicode_code_points() {
    assert_eval(
        r#"let [a, b, ...rest] = 'A💩B'; a + ':' + b + ':' + b.length + ':' + rest.length + ':' + rest[0];"#,
        "A:💩:2:1:B",
    );
}

#[test]
fn array_iterator_observes_default_mutation() {
    assert_eval(
        r#"let xs = [undefined, 2]; let [a = (xs[1] = 8, 3), b] = xs; a + b;"#,
        "11",
    );
}

#[test]
fn sparse_array_rest_materializes_undefined() {
    assert_eval(
        r#"let [a, ...rest] = [1, , 3]; a + ':' + rest.length + ':' + (0 in rest) + ':' + (rest[0] === undefined) + ':' + rest[1];"#,
        "1:2:true:true:3",
    );
}

#[test]
fn custom_iterators_work_in_parameters_and_arrow_bodies() {
    assert_eval(
        r#"let xs = {[Symbol.iterator]: function() { let n = 0; return {next: function() { n += 1; return {done: n > 2, value: n}; }}; }}; function f([a, ...rest]) { return a + rest[0]; } let g = ([a, b]) => a * b; f(xs) + g(xs);"#,
        "5",
    );
}

#[test]
fn custom_iterator_patterns_work_in_for_of_heads() {
    assert_eval(
        r#"let xs = {[Symbol.iterator]: function() { let n = 0; return {next: function() { n += 1; return {done: n > 2, value: n}; }}; }}; let total = 0; for (const [a, b] of [xs, xs]) { total += a + b; } total;"#,
        "6",
    );
}

#[test]
fn nested_empty_patterns_still_acquire_and_close() {
    assert_eval(
        r#"let trace = ''; let inner = {[Symbol.iterator]: function() { trace += 'i'; return {next: function() { trace += 'n'; return {done: false}; }, return: function() { trace += 'r'; return {}; }}; }}; let [[]] = [inner]; trace;"#,
        "ir",
    );
}

#[test]
fn assignment_returns_original_iterable_identity() {
    assert_eval(
        r#"let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: 4}; }}; }}; let a = 0; let result = ([a] = xs); (result === xs) + ':' + a;"#,
        "true:4",
    );
}

#[test]
fn assignment_reference_is_evaluated_before_next() {
    assert_eval(
        r#"let trace = ''; let target = {}; function base() { trace += 'b'; return target; } function key() { trace += 'k'; return 'x'; } let xs = {[Symbol.iterator]: function() { trace += 'i'; return {next: function() { trace += 'n'; return {done: false, value: 7}; }, return: function() { trace += 'r'; return {}; }}; }}; [base()[key()]] = xs; target.x + ':' + trace;"#,
        "7:ibknr",
    );
}

#[test]
fn rest_assignment_reference_precedes_consumption() {
    assert_eval(
        r#"let trace = ''; let n = 0; let target = {}; function base() { trace += 'b'; return target; } let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; trace += 'n'; return {done: n > 2, value: n}; }}; }}; [...base().tail] = xs; trace + ':' + target.tail.length;"#,
        "bnnn:2",
    );
}

#[test]
fn assignment_reference_throw_closes_before_catch() {
    assert_eval(
        r#"let trace = ''; function base() { trace += 'b'; throw 7; } let xs = {[Symbol.iterator]: function() { return {next: function() { trace += 'n'; return {done: false}; }, return: function() { trace += 'r'; return {}; }}; }}; try { [base().x] = xs; } catch (e) { trace += e; } trace;"#,
        "br7",
    );
}

#[test]
fn default_throw_closes_once_and_preserves_identity() {
    assert_eval(
        r#"let token = {}; let closed = 0; let caught = false; function fail() { throw token; } let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: undefined}; }, return: function() { closed += 1; throw 9; }}; }}; try { let [a = fail()] = xs; } catch (e) { caught = e === token; } caught + ':' + closed;"#,
        "true:1",
    );
}

#[test]
fn normal_close_failure_replaces_normal_completion() {
    assert_eval(
        r#"let caught = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: 2}; }, return: function() { throw 8; }}; }}; try { let [a] = xs; } catch (e) { caught = e; } caught;"#,
        "8",
    );
}

#[test]
fn empty_pattern_close_failure_is_observable() {
    assert_eval(
        r#"let caught = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { throw 99; }, return: function() { throw 8; }}; }}; try { let [] = xs; } catch (e) { caught = e; } caught;"#,
        "8",
    );
}

#[test]
fn non_object_normal_close_result_is_rejected() {
    assert_eval(
        r#"let caught = false; let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false}; }, return: function() { return 1; }}; }}; try { let [] = xs; } catch (e) { caught = true; } caught;"#,
        "true",
    );
}

#[test]
fn acquisition_failure_does_not_close() {
    assert_eval(
        r#"let trace = ''; let xs = {get [Symbol.iterator]() { trace += 'i'; throw 4; }, return: function() { trace += 'r'; return {}; }}; try { let [] = xs; } catch (e) { trace += e; } trace;"#,
        "i4",
    );
}

#[test]
fn next_failure_does_not_close() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { return {next: function() { trace += 'n'; throw 5; }, return: function() { trace += 'r'; return {}; }}; }}; try { let [a] = xs; } catch (e) { trace += e; } trace;"#,
        "n5",
    );
}

#[test]
fn done_getter_failure_does_not_close() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { return {next: function() { return {get done() { trace += 'd'; throw 5; }}; }, return: function() { trace += 'r'; return {}; }}; }}; try { let [a] = xs; } catch (e) { trace += e; } trace;"#,
        "d5",
    );
}

#[test]
fn value_getter_failure_does_not_close() {
    assert_eval(
        r#"let trace = ''; let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, get value() { trace += 'v'; throw 5; }}; }, return: function() { trace += 'r'; return {}; }}; }}; try { let [a] = xs; } catch (e) { trace += e; } trace;"#,
        "v5",
    );
}

#[test]
fn default_after_exhaustion_does_not_close() {
    assert_eval(
        r#"let trace = ''; function fail() { throw 6; } let xs = {[Symbol.iterator]: function() { return {next: function() { trace += 'n'; return {done: true}; }, return: function() { trace += 'r'; return {}; }}; }}; try { let [a = fail()] = xs; } catch (e) { trace += e; } trace;"#,
        "n6",
    );
}

#[test]
fn rest_failure_does_not_assign_or_close() {
    assert_eval(
        r#"let trace = ''; let rest = 42; let xs = {[Symbol.iterator]: function() { return {next: function() { trace += 'n'; throw 6; }, return: function() { trace += 'r'; return {}; }}; }}; try { [...rest] = xs; } catch (e) { trace += e; } trace + ':' + rest;"#,
        "n6:42",
    );
}

#[test]
fn earlier_assignments_survive_later_default_failure() {
    assert_eval(
        r#"let a = 0; let b = 0; let closed = 0; let n = 0; function fail() { throw 6; } let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {done: false, value: n === 1 ? 3 : undefined}; }, return: function() { closed += 1; return {}; }}; }}; try { [a, b = fail()] = xs; } catch (e) { } a + ':' + b + ':' + closed;"#,
        "3:0:1",
    );
}

#[test]
fn nested_binding_failure_closes_inner_before_outer() {
    assert_eval(
        r#"let trace = ''; function fail() { throw 7; } let inner = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: undefined}; }, return: function() { trace += 'i'; return {}; }}; }}; let outer = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: inner}; }, return: function() { trace += 'o'; return {}; }}; }}; try { let [[a = fail()]] = outer; } catch (e) { trace += e; } trace;"#,
        "io7",
    );
}

#[test]
fn inner_step_failure_closes_outer_but_not_inner() {
    assert_eval(
        r#"let trace = ''; let inner = {[Symbol.iterator]: function() { return {next: function() { throw 7; }, return: function() { trace += 'i'; return {}; }}; }}; let outer = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: inner}; }, return: function() { trace += 'o'; return {}; }}; }}; try { let [[a]] = outer; } catch (e) { trace += e; } trace;"#,
        "o7",
    );
}

#[test]
fn close_getter_error_does_not_replace_original_throw() {
    assert_eval(
        r#"let token = {}; let closed = 0; let caught = false; function fail() { throw token; } let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false}; }, get return() { closed += 1; throw 5; }}; }}; try { let [a = fail()] = xs; } catch (e) { caught = e === token; } caught + ':' + closed;"#,
        "true:1",
    );
}

#[test]
fn noniterable_array_like_is_rejected() {
    assert_eval(
        r#"let caught = false; try { let [a] = {0: 7, length: 1}; } catch (e) { caught = true; } caught;"#,
        "true",
    );
}

#[test]
fn var_patterns_in_function_scope_use_iterators() {
    assert_eval(
        r#"function f() { let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: 6}; }}; }}; var [a] = xs; return a; } f();"#,
        "6",
    );
}

#[test]
fn rest_assignment_patterns_can_be_nested() {
    assert_eval(
        r#"let n = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {done: n > 3, value: n}; }}; }}; let a = 0, b = 0, c = 0; [a, ...[b, c]] = xs; a + b + c;"#,
        "6",
    );
}

#[test]
fn next_method_is_called_with_iterator_receiver() {
    assert_eval(
        r#"let it = {n: 0, next: function() { this.n += 1; return {done: false, value: this.n}; }}; let xs = {[Symbol.iterator]: function() { return it; }}; let [a, b] = xs; a + ':' + b + ':' + it.n;"#,
        "1:2:2",
    );
}

#[test]
fn normal_close_occurs_after_target_store() {
    assert_eval(
        r#"let a = 0; let observed = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: 4}; }, return: function() { observed = a; return {}; }}; }}; [a] = xs; a + observed;"#,
        "8",
    );
}

#[test]
fn pattern_close_error_does_not_leak_exception_frame() {
    assert_eval(
        r#"let seen = 0; let xs = {[Symbol.iterator]: function() { return {next: function() { return {done: false, value: 1}; }, return: function() { throw 3; }}; }}; try { let [a] = xs; } catch (e) { seen += e; } try { throw 5; } catch (e) { seen += e; } seen;"#,
        "8",
    );
}

#[test]
fn native_array_iterator_can_be_reused_after_prefix_binding() {
    assert_eval(
        r#"let it=[1,2,3].values();let [a]=it;let [b]=it;let n=it.next();a+':'+b+':'+n.value+':'+n.done;"#,
        "1:2:3:false",
    );
}

#[test]
fn native_array_iterator_survives_empty_binding() {
    assert_eval(r#"let it=[4,5].values();let []=it;it.next().value;"#, "4");
}

#[test]
fn native_array_iterator_can_be_reused_after_assignment() {
    assert_eval(
        r#"let it=[4,5].values();let a=0;[a]=it;a+':'+it.next().value;"#,
        "4:5",
    );
}

#[test]
fn native_array_iterator_survives_for_of_break() {
    assert_eval(
        r#"let it=[4,5].values();for(let x of it){break;}it.next().value;"#,
        "5",
    );
}

#[test]
fn native_array_iterator_observes_index_getters_for_elisions() {
    assert_eval(
        r#"let trace='';let xs=[1,2];Object.defineProperty(xs,'0',{get:function(){trace+='g';return 8;}});let [,b]=xs;b+':'+trace;"#,
        "2:g",
    );
}

#[test]
fn nullish_iterator_method_rejects_without_a_has_trap() {
    assert_eval(
        r#"let trace='';let xs=new Proxy({0:7,length:1},{get:function(t,k){trace+='g';return undefined;},has:function(t,k){trace+='h';return true;}});let caught=false;try{let []=xs;}catch(e){caught=true;}caught+':'+trace;"#,
        "true:g",
    );
}

#[test]
fn generator_for_of_break_runs_finally() {
    assert_eval(
        r#"let trace='';function* g(){try{yield 1;yield 2;}finally{trace+='f';}}for(let v of g()){break;}trace;"#,
        "f",
    );
}

#[test]
fn generator_return_from_iterator_factory_is_supported() {
    assert_eval(
        r#"let n=0;function* g(){try{yield 7;}finally{n+=1;}}let xs={[Symbol.iterator]:function(){return g();}};let [a]=xs;a+':'+n;"#,
        "7:1",
    );
}

#[test]
fn generator_close_may_yield_without_being_resumed_again() {
    assert_eval(
        r#"let trace='';function* g(){try{yield 1;}finally{trace+='a';yield 2;trace+='b';}}let it=g();let [a]=it;let before=trace;let r=it.next();a+':'+before+':'+trace+':'+r.done;"#,
        "1:a:ab:true",
    );
}

#[test]
fn generator_close_failure_does_not_replace_pattern_throw() {
    assert_eval(
        r#"let token={};function* g(){try{yield undefined;}finally{throw 9;}}let same=false;try{let [a=(()=>{throw token;})()]=g();}catch(e){same=e===token;}same;"#,
        "true",
    );
}

#[test]
fn native_iterator_records_do_not_rewind_each_other() {
    assert_eval(
        r#"let it=[1,2,3,4].values();let [a,b=(it.next().value)]=it;let [c]=it;a+':'+b+':'+c;"#,
        "1:2:3",
    );
}

#[test]
fn empty_pattern_does_not_require_callable_next() {
    assert_eval(
        r#"let trace='';let xs={[Symbol.iterator]:function(){trace+='i';return {get next(){trace+='n';return 42;},return:function(){trace+='r';return {};}};}};let []=xs;trace;"#,
        "inr",
    );
}

#[test]
fn empty_assignment_can_close_iterator_with_missing_next() {
    assert_eval(
        r#"let trace='';let xs={[Symbol.iterator]:function(){return {return:function(){trace+='r';return {};}};}};[] = xs;trace;"#,
        "r",
    );
}

#[test]
fn empty_pattern_accepts_iterator_without_next_or_return() {
    assert_eval(
        r#"let xs={[Symbol.iterator]:function(){return {};}};let []=xs;7;"#,
        "7",
    );
}

#[test]
fn noncallable_next_fails_at_step_without_closing() {
    assert_eval(
        r#"let trace='';let xs={[Symbol.iterator]:function(){return {get next(){trace+='n';return 42;},return:function(){trace+='r';return {};}};}};let caught=false;try{let [a]=xs;}catch(e){caught=e instanceof TypeError;}caught+':'+trace;"#,
        "true:n",
    );
}

#[test]
fn assignment_reference_precedes_noncallable_next_failure() {
    assert_eval(
        r#"let trace='';let target={};function key(){trace+='k';return 'x';}let xs={[Symbol.iterator]:function(){return {get next(){trace+='n';return null;},return:function(){trace+='r';return {};}};}};let caught=false;try{[target[key()]]=xs;}catch(e){caught=e instanceof TypeError;}caught+':'+trace;"#,
        "true:nk",
    );
}

#[test]
fn failing_reference_closes_even_when_cached_next_is_noncallable() {
    assert_eval(
        r#"let trace='';let token={};let target={};function key(){trace+='k';throw token;}let xs={[Symbol.iterator]:function(){return {next:42,return:function(){trace+='r';return {};}};}};let same=false;try{[target[key()]]=xs;}catch(e){same=e===token;}same+':'+trace;"#,
        "true:kr",
    );
}

#[test]
fn next_getter_failure_is_acquisition_failure_without_close() {
    assert_eval(
        r#"let trace='';let token={};let xs={[Symbol.iterator]:function(){return {get next(){trace+='n';throw token;},return:function(){trace+='r';return {};}};}};let same=false;try{let []=xs;}catch(e){same=e===token;}same+':'+trace;"#,
        "true:n",
    );
}

#[test]
fn empty_pattern_preserves_close_failure_with_noncallable_next() {
    assert_eval(
        r#"let token={};let xs={[Symbol.iterator]:function(){return {next:42,return:function(){throw token;}};}};let same=false;try{let []=xs;}catch(e){same=e===token;}same;"#,
        "true",
    );
}
