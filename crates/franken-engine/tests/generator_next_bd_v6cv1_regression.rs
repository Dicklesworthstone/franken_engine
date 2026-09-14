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
