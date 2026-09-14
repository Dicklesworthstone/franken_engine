//! End-to-end synchronous generator protocol: next, return, throw, and isolated completions.
use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => o.value.to_string(),
        Err(err) => format!("ERR={}", err.to_string().lines().next().unwrap_or("")),
    }
}

#[test]
fn generator_next_value() {
    assert_eq!(
        eval("function* g(){ yield 1; yield 2; } let it = g(); it.next().value;"),
        "1"
    );
}

#[test]
fn generator_sequential_next() {
    assert_eq!(
        eval("function* g(){ yield 1; yield 2; } let it = g(); it.next(); it.next().value;"),
        "2"
    );
}

#[test]
fn generator_done_flag_before_exhaustion() {
    // Not yet exhausted → done is false. (The post-exhaustion `done:true`
    // transition is a deeper generator-engine bug — see bd-hoplz.)
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next().done;"),
        "false"
    );
}

// bd-hoplz bug #1 (completion-via-return) — FIXED: `generator_next` now reads a
// `generator_yielded` marker set by the `Yield` handler, so a `run_loop` exit
// that was a function `Return` (not a yield) is wrapped as
// `{value:<ret>, done:true}` and marks the generator Completed.
#[test]
fn generator_done_after_exhaustion() {
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next(); it.next().done;"),
        "true"
    );
}

#[test]
fn generator_value_undefined_after_exhaustion() {
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next(); it.next().value;"),
        "undefined"
    );
}

// bd-hoplz bug #2 — FIXED: the symptom looked like a bad resume, but the IR3
// dump showed `yield 1+1` was mis-parsed as `(yield 1) + 1` (binary scanning ran
// before the yield arm). `parse_expression` now routes yield/await-prefixed
// expressions to the yield/await arm before binary scanning, so the operand is a
// full AssignmentExpression and the body yields 2 then 10.
#[test]
fn generator_yields_computed_values() {
    assert_eq!(
        eval("function* g(){ yield 1+1; yield 2*5; } let it = g(); it.next(); it.next().value;"),
        "10"
    );
}

#[test]
fn generator_methods_are_real_callable_values() {
    assert_eq!(
        eval(
            r#"function* g(){yield 1;} let it=g(); typeof it.next+':'+typeof it.return+':'+typeof it.throw;"#
        ),
        "function:function:function"
    );
}

#[test]
fn generator_return_skips_an_unstarted_body() {
    assert_eq!(
        eval(
            r#"let trace=''; function* g(){try{trace+='b';yield 1;}finally{trace+='f';}} let it=g(); let r=it.return(9); r.value+':'+r.done+':'+it.next().done+':'+trace;"#
        ),
        "9:true:true:"
    );
}

#[test]
fn generator_throw_skips_an_unstarted_body() {
    assert_eq!(
        eval(
            r#"let trace=''; let token={}; function* g(){try{trace+='b';yield 1;}finally{trace+='f';}} let it=g(); let same=false; try{it.throw(token);}catch(e){same=e===token;} same+':'+it.next().done+':'+trace;"#
        ),
        "true:true:"
    );
}

#[test]
fn generator_return_executes_finally_and_stops_body() {
    assert_eq!(
        eval(
            r#"let trace=''; function* g(){try{yield 1;trace+='b';yield 2;}finally{trace+='f';}} let it=g(); it.next(); let r=it.return(8); r.value+':'+r.done+':'+it.next().done+':'+trace;"#
        ),
        "8:true:true:f"
    );
}

#[test]
fn generator_return_suspends_through_a_finally_yield() {
    assert_eq!(
        eval(
            r#"function* g(){try{yield 1;}finally{yield 2;}} let it=g();it.next();let a=it.return(7);let b=it.next();a.value+':'+a.done+':'+b.value+':'+b.done;"#
        ),
        "2:false:7:true"
    );
}

#[test]
fn generator_new_return_overrides_suspended_return() {
    assert_eq!(
        eval(
            r#"function* g(){try{yield 1;}finally{yield 2;}} let it=g();it.next();it.return(7);let r=it.return(9);r.value+':'+r.done+':'+it.next().done;"#
        ),
        "9:true:true"
    );
}

#[test]
fn generator_finally_return_overrides_injected_return() {
    assert_eq!(
        eval(
            r#"function* g(){try{yield 1;}finally{return 11;}}let it=g();it.next();let r=it.return(7);r.value+':'+r.done;"#
        ),
        "11:true"
    );
}

#[test]
fn generator_throw_is_caught_at_the_suspension_point() {
    assert_eq!(
        eval(
            r#"function* g(){try{yield 1;}catch(e){yield e+2;}return 9;}let it=g();it.next();let a=it.throw(5);let b=it.next();a.value+':'+a.done+':'+b.value+':'+b.done;"#
        ),
        "7:false:9:true"
    );
}

#[test]
fn generator_throw_preserves_object_identity_through_finally() {
    assert_eq!(
        eval(
            r#"let token={};let trace='';function* g(){try{yield 1;}finally{trace+='f';}}let it=g();it.next();let same=false;try{it.throw(token);}catch(e){same=e===token;}same+':'+trace+':'+it.next().done;"#
        ),
        "true:f:true"
    );
}

#[test]
fn generator_throw_survives_finally_yield() {
    assert_eq!(
        eval(
            r#"let token={};function* g(){try{yield 1;}finally{yield 2;}}let it=g();it.next();let a=it.throw(token);let same=false;try{it.next();}catch(e){same=e===token;}a.value+':'+a.done+':'+same+':'+it.next().done;"#
        ),
        "2:false:true:true"
    );
}

#[test]
fn generator_finally_throw_overrides_injected_return() {
    assert_eq!(
        eval(
            r#"function* g(){try{yield 1;}finally{throw 12;}}let it=g();it.next();let got=0;try{it.return(7);}catch(e){got=e;}got+':'+it.next().done;"#
        ),
        "12:true"
    );
}

#[test]
fn generator_return_unwinds_nested_finally_in_order() {
    assert_eq!(
        eval(
            r#"let trace='';function* g(){try{try{yield 1;}finally{trace+='i';}}finally{trace+='o';}}let it=g();it.next();let r=it.return(7);r.value+':'+trace;"#
        ),
        "7:io"
    );
}

#[test]
fn generator_completed_return_and_throw_use_supplied_value() {
    assert_eq!(
        eval(
            r#"function* g(){return 3;}let it=g();it.next();let r=it.return(8);let got=0;try{it.throw(6);}catch(e){got=e;}r.value+':'+r.done+':'+got+':'+it.next().done;"#
        ),
        "8:true:6:true"
    );
}

#[test]
fn generator_next_method_uses_its_call_receiver() {
    assert_eq!(
        eval(
            r#"function* g(){yield 1;yield 2;}let a=g(),b=g();a.next();let next=a.next;next.call(b).value+':'+a.next().value;"#
        ),
        "1:2"
    );
}

#[test]
fn generator_return_method_uses_its_call_receiver() {
    assert_eq!(
        eval(
            r#"function* g(){yield 1;yield 2;}let a=g(),b=g();a.next();b.next();let close=a.return;let r=close.call(b,7);r.value+':'+b.next().done+':'+a.next().value;"#
        ),
        "7:true:2"
    );
}

#[test]
fn generator_methods_reject_non_generator_receivers() {
    assert_eq!(
        eval(
            r#"function* g(){yield 1;}let it=g();let count=0;try{it.next.call({});}catch(e){count+=1;}try{it.return.call({});}catch(e){count+=1;}try{it.throw.call({});}catch(e){count+=1;}count+':'+it.next().value;"#
        ),
        "3:1"
    );
}

#[test]
fn generator_return_reentry_is_rejected_without_corrupting_state() {
    assert_eq!(
        eval(
            r#"let it;function* g(){try{it.return(9);}catch(e){yield 4;}yield 5;}it=g();it.next().value+':'+it.next().value;"#
        ),
        "4:5"
    );
}

#[test]
fn generator_bare_return_passes_undefined() {
    assert_eq!(
        eval(
            r#"function* g(){yield 1;}let it=g();it.next();let r=it.return();r.value+':'+r.done;"#
        ),
        "undefined:true"
    );
}

#[test]
fn generator_caller_finally_survives_generator_throw() {
    assert_eq!(
        eval(
            r#"let trace='';function* g(){try{yield 1;}finally{trace+='g';}}let it=g();it.next();try{try{it.throw(6);}finally{trace+='c';}}catch(e){trace+=e;}trace;"#
        ),
        "gc6"
    );
}

#[test]
fn generator_next_after_return_has_no_suspended_completion_leak() {
    assert_eq!(
        eval(
            r#"function* g(){yield 1;}let it=g();it.next();it.return(7);let got=0;try{throw 5;}catch(e){got=e;}got+':'+it.next().value;"#
        ),
        "5:undefined"
    );
}

#[test]
fn generator_object_is_not_callable_and_does_not_start() {
    assert_eq!(
        eval(
            r#"let n=0;function* g(){n+=1;yield 7;}let it=g();let caught=false;try{it();}catch(e){caught=e instanceof TypeError;}let before=n;let r=it.next();caught+':'+before+':'+r.value+':'+n;"#
        ),
        "true:0:7:1"
    );
}

#[test]
fn generator_object_as_method_is_not_callable() {
    assert_eq!(
        eval(
            r#"let n=0;function* g(){n+=1;yield 8;}let it=g();let obj={run:it};let caught=false;try{obj.run();}catch(e){caught=e instanceof TypeError;}let before=n;caught+':'+before+':'+it.next().value;"#
        ),
        "true:0:8"
    );
}

#[test]
fn extracted_generator_method_requires_its_receiver() {
    assert_eq!(
        eval(
            r#"let n=0;function* g(){n+=1;yield 9;}let it=g();let step=it.next;let caught=false;try{step();}catch(e){caught=e instanceof TypeError;}let before=n;caught+':'+before+':'+step.call(it).value;"#
        ),
        "true:0:9"
    );
}

// Synchronous yield* executes the iterator protocol, rather than yielding its
// operand as a single value. Every case exercises the public parser-to-runtime
// entrypoint, including abrupt completion and observable protocol callbacks.
macro_rules! delegation_case {
    ($name:ident, $source:literal, $expected:literal) => {
        #[test]
        fn $name() {
            assert_eq!(eval($source), $expected, "source: {}", $source);
        }
    };
}

delegation_case!(
    delegate_array_and_expression_result,
    r#"function* g() { let x = yield* [2, 3]; return x === undefined ? 7 : 0; } let it = g(); let a = it.next(); let b = it.next(); let c = it.next(); a.value + ':' + b.value + ':' + c.value + ':' + c.done;"#,
    "2:3:7:true"
);
delegation_case!(
    delegate_nested_generator_terminal_value,
    r#"function* a() { yield 1; return 9; } function* b() { return (yield* a()) + 1; } let it = b(); let x = it.next(); let y = it.next(); x.value + ':' + y.value + ':' + y.done;"#,
    "1:10:true"
);
delegation_case!(
    delegate_infinite_generator_is_lazy_and_closes,
    r#"let n = 0; let trace = ''; function* a() { try { while (true) { n += 1; yield n; } } finally { trace += 'a'; } } function* b() { try { yield* a(); } finally { trace += 'b'; } } let it = b(); let x = it.next(); let y = it.return(8); x.value + ':' + n + ':' + y.value + ':' + y.done + ':' + trace;"#,
    "1:1:8:true:ab"
);
delegation_case!(
    delegate_caches_next_once,
    r#"let gets = 0; let n = 0; let source = {get next() { gets += 1; return function() { n += 1; return {done: n > 2, value: n}; }; }, [Symbol.iterator]: function() { return this; }}; function* g() { return yield* source; } let it = g(); let a = it.next(); Object.defineProperty(source, 'next', {value: function() { throw 77; }}); let b = it.next(); let c = it.next(); a.value + ':' + b.value + ':' + c.value + ':' + gets;"#,
    "1:2:3:1"
);
delegation_case!(
    delegate_preserves_result_identity_and_lazy_value,
    r#"let trace = ''; let result = {get done() { trace += 'd'; return false; }, get value() { trace += 'v'; return 7; }}; let source = {[Symbol.iterator]: function() { return {next: function() { return result; }}; }}; function* g() { yield* source; } let r = g().next(); (r === result) + ':' + trace;"#,
    "true:d"
);
delegation_case!(
    delegate_terminal_getters_are_ordered,
    r#"let trace = ''; let source = {[Symbol.iterator]: function() { return {next: function() { return {get done() { trace += 'd'; return 'yes'; }, get value() { trace += 'v'; return 6; }}; }}; }}; function* g() { return (yield* source) + 1; } let r = g().next(); r.value + ':' + r.done + ':' + trace;"#,
    "7:true:dv"
);
delegation_case!(
    delegate_forwards_sent_value_and_ignores_first_outer_argument,
    r#"let first = false; let n = 0; let source = {[Symbol.iterator]: function() { return {next: function(x) { n += 1; if (n === 1) { first = x === undefined; return {value: 1, done: false}; } return {value: x * 2, done: true}; }}; }}; function* g() { return (yield* source) + 1; } let it = g(); it.next(500); let r = it.next(7); first + ':' + r.value + ':' + r.done;"#,
    "true:15:true"
);
delegation_case!(
    delegate_instances_do_not_share_state,
    r#"function* g() { yield* [1, 2]; } let a = g(); let b = g(); a.next().value + ':' + b.next().value + ':' + a.next().value + ':' + b.next().value;"#,
    "1:1:2:2"
);
delegation_case!(
    delegate_evaluates_iterable_once,
    r#"let n = 0; function source() { n += 1; return [4, 5]; } function* g() { yield* source(); } let it = g(); it.next(); it.next(); it.next(); n;"#,
    "1"
);
delegation_case!(
    delegate_after_plain_yield_accepts_sent_iterable,
    r#"function* g() { let xs = yield 'ready'; return yield* xs; } let it = g(); let a = it.next(); let b = it.next([1, 2]); let c = it.next(); let d = it.next(); a.value + ':' + b.value + ':' + c.value + ':' + d.done;"#,
    "ready:1:2:true"
);
delegation_case!(
    delegate_can_be_followed_by_plain_and_delegated_yields,
    r#"function* g() { yield* [1]; yield 2; yield* [3]; return 4; } let it = g(); it.next().value + ':' + it.next().value + ':' + it.next().value + ':' + it.next().value;"#,
    "1:2:3:4"
);
delegation_case!(
    delegate_empty_completes_in_same_resume,
    r#"function* g() { yield* []; return 7; } let r = g().next(); r.value + ':' + r.done;"#,
    "7:true"
);
delegation_case!(
    delegate_string_uses_code_points,
    r#"function* g() { yield* 'A\u{1F680}B'; } let it = g(); it.next().value + ':' + it.next().value + ':' + it.next().value + ':' + it.next().done;"#,
    "A:🚀:B:true"
);
delegation_case!(
    delegate_for_of_break_unwinds_both_generators,
    r#"let trace = ''; function* a() { try { yield 1; yield 2; } finally { trace += 'a'; } } function* b() { try { yield* a(); } finally { trace += 'b'; } } let sum = 0; for (let x of b()) { sum += x; break; } sum + ':' + trace;"#,
    "1:ab"
);
delegation_case!(
    delegate_destructuring_closes_nested_generator,
    r#"let trace = ''; function* a() { try { yield 1; yield 2; yield 3; } finally { trace += 'a'; } } function* b() { try { yield* a(); } finally { trace += 'b'; } } let [x, y] = b(); x + ':' + y + ':' + trace;"#,
    "1:2:ab"
);
delegation_case!(
    delegate_throw_can_yield_and_then_resume_normally,
    r#"let seen = 0; let n = 0; let source = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {value: n === 1 ? 1 : 9, done: n > 1}; }, throw: function(x) { seen = x; return {value: 44, done: false}; }}; }}; function* g() { return (yield* source) + 1; } let it = g(); it.next(); let a = it.throw(7); let b = it.next(); a.value + ':' + a.done + ':' + b.value + ':' + b.done + ':' + seen;"#,
    "44:false:10:true:7"
);
delegation_case!(
    delegate_throw_done_value_completes_expression,
    r#"let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, throw: function(x) { return {value: x + 1, done: true}; }}; }}; function* g() { return (yield* source) + 2; } let it = g(); it.next(); let r = it.throw(6); r.value + ':' + r.done;"#,
    "9:true"
);
delegation_case!(
    delegate_missing_throw_closes_without_observing_result_properties,
    r#"let trace = ''; let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, return: function() { trace += arguments.length; return {get done() { throw 1; }, get value() { throw 2; }}; }}; }}; function* g() { try { yield* source; } catch (e) { yield e.name; } finally { trace += 'f'; } } let it = g(); it.next(); let r = it.throw(7); it.next(); r.value + ':' + trace;"#,
    "TypeError:0f"
);
delegation_case!(
    delegate_missing_throw_close_error_replaces_type_error,
    r#"let failure = {}; let trace = ''; let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, return: function() { trace += 'r'; throw failure; }}; }}; function* g() { try { yield* source; } finally { trace += 'f'; } } let it = g(); it.next(); let same = false; try { it.throw(7); } catch (e) { same = e === failure; } same + ':' + trace;"#,
    "true:rf"
);
delegation_case!(
    delegate_noncallable_throw_does_not_close,
    r#"let closed = 0; let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, throw: 3, return: function() { closed += 1; return {}; }}; }}; function* g() { yield* source; } let it = g(); it.next(); let name = ''; try { it.throw(7); } catch (e) { name = e.name; } name + ':' + closed;"#,
    "TypeError:0"
);
delegation_case!(
    delegate_missing_return_preserves_requested_value,
    r#"let trace = ''; let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }}; }}; function* g() { try { yield* source; trace += 'p'; } finally { trace += 'f'; } } let it = g(); it.next(); let r = it.return(8); r.value + ':' + r.done + ':' + trace;"#,
    "8:true:f"
);
delegation_case!(
    delegate_return_done_value_unwinds_outer_finally,
    r#"let trace = ''; let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, return: function(x) { trace += 'r'; return {value: x + 2, done: true}; }}; }}; function* g() { try { yield* source; trace += 'p'; } finally { trace += 'f'; } } let it = g(); it.next(); let r = it.return(8); r.value + ':' + r.done + ':' + trace;"#,
    "10:true:rf"
);
delegation_case!(
    delegate_return_false_keeps_result_identity_and_allows_next,
    r#"let n = 0; let returned = {value: 33, done: false}; let source = {[Symbol.iterator]: function() { return {next: function() { n += 1; return {value: n === 1 ? 1 : 9, done: n > 1}; }, return: function() { return returned; }}; }}; function* g() { return (yield* source) + 1; } let it = g(); it.next(); let a = it.return(8); let b = it.next(); (a === returned) + ':' + b.value + ':' + b.done;"#,
    "true:10:true"
);
delegation_case!(
    delegate_nested_return_survives_finally_yields,
    r#"function* a() { try { yield 1; } finally { yield 2; } } function* b() { try { return yield* a(); } finally { yield 3; } } let it = b(); let a1 = it.next(); let a2 = it.return(8); let a3 = it.next(); let a4 = it.next(); a1.value + ':' + a2.value + ':' + a3.value + ':' + a4.value + ':' + a4.done;"#,
    "1:2:3:8:true"
);
delegation_case!(
    delegate_unhandled_throw_retains_identity_and_unwinds_inner_first,
    r#"let failure = {}; let trace = ''; function* a() { try { yield 1; } finally { trace += 'a'; } } function* b() { try { yield* a(); } finally { trace += 'b'; } } let it = b(); it.next(); let same = false; try { it.throw(failure); } catch (e) { same = e === failure; } same + ':' + trace;"#,
    "true:ab"
);
delegation_case!(
    delegate_failure_clears_state_before_catch_yields,
    r#"let bad = {[Symbol.iterator]: function() { return {next: function() { return 3; }}; }}; function* g() { try { yield* bad; } catch (e) { yield e.name; } yield* [6]; } let it = g(); it.next().value + ':' + it.next().value + ':' + it.next().done;"#,
    "TypeError:6:true"
);
delegation_case!(
    delegate_done_getter_failure_does_not_close,
    r#"let failure = {}; let closed = 0; let source = {[Symbol.iterator]: function() { return {next: function() { return {get done() { throw failure; }}; }, return: function() { closed += 1; return {}; }}; }}; function* g() { yield* source; } let same = false; try { g().next(); } catch (e) { same = e === failure; } same + ':' + closed;"#,
    "true:0"
);
delegation_case!(
    delegate_terminal_value_getter_failure_does_not_close,
    r#"let failure = {}; let closed = 0; let source = {[Symbol.iterator]: function() { return {next: function() { return {done: true, get value() { throw failure; }}; }, return: function() { closed += 1; return {}; }}; }}; function* g() { yield* source; } let same = false; try { g().next(); } catch (e) { same = e === failure; } same + ':' + closed;"#,
    "true:0"
);
delegation_case!(
    delegate_primitive_return_result_is_rejected,
    r#"let trace = ''; let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, return: function() { trace += 'r'; return 3; }}; }}; function* g() { try { yield* source; } finally { trace += 'f'; } } let it = g(); it.next(); let name = ''; try { it.return(8); } catch (e) { name = e.name; } name + ':' + trace;"#,
    "TypeError:rf"
);
delegation_case!(
    delegate_return_method_is_looked_up_on_each_request,
    r#"let reads = 0; let iterator = {next: function() { return {value: 1, done: false}; }, get return() { reads += 1; return function(x) { return {value: x, done: reads > 1}; }; }}; let source = {[Symbol.iterator]: function() { return iterator; }}; function* g() { yield* source; } let it = g(); it.next(); let a = it.return(7); let b = it.return(8); a.value + ':' + a.done + ':' + b.value + ':' + b.done + ':' + reads;"#,
    "7:false:8:true:2"
);
delegation_case!(
    delegate_reentry_is_rejected_without_losing_state,
    r#"let it; let n = 0; let name = ''; let source = {[Symbol.iterator]: function() { return {next: function() { n += 1; try { it.next(); } catch (e) { name = e.name; } return {value: n, done: n > 1}; }}; }}; function* g() { return yield* source; } it = g(); let a = it.next(); let b = it.next(); a.value + ':' + b.value + ':' + b.done + ':' + name;"#,
    "1:2:true:TypeError"
);
delegation_case!(
    delegate_noniterable_operand_is_rejected,
    r#"function* g() { try { yield* {0: 1, length: 1}; } catch (e) { return e.name; } } let r = g().next(); r.value + ':' + r.done;"#,
    "TypeError:true"
);
delegation_case!(
    delegate_first_next_receives_exactly_one_argument,
    r#"let source = {[Symbol.iterator]: function() { return {next: function() { return {value: arguments.length, done: true}; }}; }}; function* g() { return yield* source; } g().next(99).value;"#,
    "1"
);
delegation_case!(
    delegate_return_receives_exactly_one_argument,
    r#"let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, return: function() { return {value: arguments.length, done: true}; }}; }}; function* g() { yield* source; } let it = g(); it.next(); it.return().value;"#,
    "1"
);
delegation_case!(
    delegate_throw_receives_exactly_one_argument,
    r#"let source = {[Symbol.iterator]: function() { return {next: function() { return {value: 1, done: false}; }, throw: function() { return {value: arguments.length, done: true}; }}; }}; function* g() { return yield* source; } let it = g(); it.next(); it.throw().value;"#,
    "1"
);
