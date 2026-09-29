//! bd-9vouw.23: program size no longer runs a frame out of registers.
//!
//! IR2->IR3 lowering gave every temporary a fresh register and never reused
//! one, and every binding held a register for the whole body, so 300
//! expression statements or ~200 top-level `let`s failed at runtime with
//! "register 256 out of bounds (max 256)". Temporaries are now reused at
//! statement boundaries. Root-scope bindings (functions included) and
//! function-body locals beyond a budget live in the runtime scope. Name-status
//! slots are released by their put. Expected strings are what Node v22.2.0
//! prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path, plus
//! the real lowering pipeline for the register high-water assertion.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, QuickJsLane};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(name: &str, source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "{name} must match Node v22.2.0"
    );
}

/// The fixed-width lane (256 registers, as `frankenctl run` executes):
/// `HybridRouter::eval` sizes its frame to the program, so only this path
/// proves register reuse and binding spill actually keep programs in bounds.
fn fixed_lane_value(source: &str) -> String {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse_bd_9vouw_23.js");
    let context = LoweringContext::new("rr-trace", "rr-decision", "rr-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    // The programs call builtins (`Object.keys`, for-of over arrays), which
    // QuickJsLane::new()'s VM/heap-only grant refuses; the frame is what is
    // under test, so grant the builtins too.
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    match QuickJsLane::with_config(config).execute(&module, "rr-trace") {
        Ok(result) => result.value.to_string(),
        Err(err) => format!("ERROR: {err}"),
    }
}

fn main_frame_size(source: &str) -> u32 {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse_bd_9vouw_23.js");
    let context = LoweringContext::new("rr-trace", "rr-decision", "rr-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    module.function_table[0].frame_size
}

#[test]
fn many_expression_statements_run() {
    let source = format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(300));
    check("300 top-level statements", &source, "300");
    let source = format!(
        "function f() {{ let t = 0;\n{}return t; }} f();",
        "t = t + 1;\n".repeat(400)
    );
    check("400 statements in a function body", &source, "400");
}

#[test]
fn many_top_level_lets_run() {
    let lets: String = (0..5000).map(|i| format!("let v{i} = {i};\n")).collect();
    check("5000 top-level lets", &format!("{lets}v0 + v4999;"), "4999");
}

#[test]
fn many_top_level_vars_run_and_stay_hoisted() {
    let vars: String = (0..300).map(|i| format!("var w{i} = {i};\n")).collect();
    check("300 top-level vars", &format!("{vars}w0 + w299;"), "299");
    // A `var` past the register budget is still hoisted: read before its
    // declaration it is undefined, not a ReferenceError.
    let vars: String = (0..200).map(|i| format!("var w{i} = {i};\n")).collect();
    check(
        "hoisted spilled var",
        &format!("{vars}var r = typeof late; var late = 5; r + ':' + late;"),
        "undefined:5",
    );
}

#[test]
fn many_try_catch_statements_run() {
    let source = format!(
        "let r;\n{}r;",
        "try { r = typeof X; } catch (e) { r = 'THROW'; }\n".repeat(1000)
    );
    check("1000 try/catch statements", &source, "undefined");
}

#[test]
fn spilled_lexical_bindings_keep_their_semantics() {
    let lets: String = (0..200).map(|i| format!("let v{i} = {i};\n")).collect();
    // A closure over a binding past the register budget sees later writes.
    check(
        "closure over spilled let",
        &format!("{lets}let cap = 5; const g = () => cap; cap = 6; g() + ':' + v199;"),
        "6:199",
    );
    // A spilled binding read before its declaration is still in its TDZ.
    check(
        "TDZ of spilled let",
        &format!(
            "{lets}let r = 'none'; try {{ late; }} catch (e) {{ r = e.name; }} let late = 1; r + ':' + late;"
        ),
        "ReferenceError:1",
    );
}

#[test]
fn register_high_water_does_not_grow_with_statement_count() {
    let small = main_frame_size(&format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(10)));
    let large = main_frame_size(&format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(1000)));
    assert_eq!(
        small, large,
        "independent statements must reuse temporaries (frame {small} vs {large})"
    );
}

#[test]
fn large_programs_fit_the_fixed_256_register_lane() {
    let statements = format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(300));
    assert_eq!(fixed_lane_value(&statements), "300");
    let lets: String = (0..300).map(|i| format!("let v{i} = {i};\n")).collect();
    assert_eq!(fixed_lane_value(&format!("{lets}v0 + v299;")), "299");
    let vars: String = (0..300).map(|i| format!("var w{i} = {i};\n")).collect();
    assert_eq!(fixed_lane_value(&format!("{vars}w0 + w299;")), "299");
}

#[test]
fn bindings_read_before_their_first_write_never_see_stale_temporaries() {
    // A binding register must not have held an earlier statement's rewound
    // temporary: a hoisted `var` read before assignment is undefined.
    check(
        "hoisted var after rewound temporaries",
        "function f() { var a = [1, 2, 3].map(x => x * 2).join(); \
         var r = typeof late; var late = 5; return r + ':' + a; } f();",
        "undefined:2,4,6",
    );
    check(
        "hoisted var after a block temporary",
        "function g() { var s = 'x' + 'y'; { let inner = s + 'z'; } \
         var r = typeof later; var later = 1; return r; } g();",
        "undefined",
    );
}

fn top_level_vars(count: usize) -> String {
    (0..count).map(|i| format!("var w{i} = {i};\n")).collect()
}

#[test]
fn function_declarations_past_the_root_budget_are_callable() {
    // A function declared after the register-resident root budget used to
    // pin a register and never reach its runtime-scope binding, so `typeof
    // add` was "undefined" and every call threw.
    let source = format!(
        "{}function add(a, b) {{ return a + b; }}\n\
         typeof add + ':' + add(2, 3) + ':' + w0 + ':' + w199;",
        top_level_vars(200)
    );
    assert_eq!(fixed_lane_value(&source), "function:5:0:199");
    // Each such declaration also cost a whole register: 300 top-level
    // functions overflowed the 256-register frame.
    let functions: String = (0..300)
        .map(|i| format!("function f{i}() {{ return {i}; }}\n"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!("{functions}f0() + f299();")),
        "299"
    );
}

#[test]
fn large_function_bodies_fit_the_fixed_256_register_lane() {
    // Bundler output wraps a whole program in one function. Its locals used
    // to pin one register each for the whole body.
    let vars = top_level_vars(300);
    assert_eq!(
        fixed_lane_value(&format!("(function () {{\n{vars}return w0 + w299; }})();")),
        "299"
    );
    // Each function captures its predecessor, so all 300 declarations are
    // scope-routed; each used to pin a register too. (No deep recursion: the
    // lane's call depth is capped at 256.)
    let chain: String = (1..300)
        .map(|i| {
            format!(
                "function f{i}() {{ return typeof f{} === 'function' ? {i} : -1; }}\n",
                i - 1
            )
        })
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\nfunction f0() {{ return 0; }}\n{chain}return f1() + f299(); }})();"
        )),
        "300"
    );
}

#[test]
fn spilled_function_locals_keep_their_semantics() {
    let vars = top_level_vars(200);
    // Still hoisted: read before its declaration a spilled `var` is undefined.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var r = typeof late;\n{vars}var late = 5; return r + ':' + late; }})();"
        )),
        "undefined:5"
    );
    // Loop counters and compound assignment past the budget.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{vars}var acc = 0; for (var i = 0; i < 10; i++) acc += i; return acc; }})();"
        )),
        "45"
    );
    // A closure over a local past the budget sees later writes.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{vars}var cap = 1; var g = function () {{ return cap; }}; cap = 2; return g(); }})();"
        )),
        "2"
    );
    // A spilled function declaration is hoisted above its first call.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{vars}return late(); function late() {{ return 'hoisted'; }} }})();"
        )),
        "hoisted"
    );
}

#[test]
fn assignments_to_undeclared_names_release_their_status_registers() {
    // The pre-RHS resolution status of `name = value` for an undeclared name
    // used to hold a register for the rest of the body.
    let globals: String = (0..300).map(|i| format!("ig{i} = {i};\n")).collect();
    assert_eq!(fixed_lane_value(&format!("{globals}ig0 + ig299;")), "299");
    let globals: String = (0..300).map(|i| format!("jg{i} = {i};\n")).collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{globals}return jg0 + jg299; }})();"
        )),
        "299"
    );
    // A statement boundary inside the RHS (a comma expression) must not
    // reclaim the live status register.
    assert_eq!(
        fixed_lane_value("var side = 0; zz = (side++, side++, side + 40); zz + side;"),
        "44"
    );
}

fn array_literal(count: usize) -> String {
    let elements: Vec<String> = (0..count).map(|i| i.to_string()).collect();
    format!("[{}]", elements.join(", "))
}

fn object_literal(count: usize) -> String {
    let entries: Vec<String> = (0..count).map(|i| format!("k{i}: {i}")).collect();
    format!("{{{}}}", entries.join(", "))
}

#[test]
fn large_literals_fit_the_fixed_256_register_lane() {
    // A literal held one register per element (two per object entry) until
    // it was built, so data tables with hundreds of entries overflowed the
    // frame. Test262's generated RegExp property-escape tests hit this too.
    // Past 64 entries, literals build one entry at a time and reuse each
    // entry's registers.
    assert_eq!(
        fixed_lane_value(&format!(
            "var a = {}; a.length + a[299];",
            array_literal(300)
        )),
        "599"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "var o = {}; var n = 0, first, last; \
             for (var k in o) {{ if (n === 0) first = k; last = k; n++; }} \
             n + o.k299 + ':' + first + ':' + last;",
            object_literal(300)
        )),
        "599:k0:k299"
    );
    let rows: Vec<String> = (0..100)
        .map(|i| format!("{{a: {i}, b: [{i}, {i}], c: 'x'}}"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "var rows = [{}]; var t = 0; for (var i = 0; i < rows.length; i++) \
             t += rows[i].a + rows[i].b[1]; t + ':' + rows.length;",
            rows.join(", ")
        )),
        "9900:100"
    );
    let calls: Vec<String> = (0..300).map(|i| format!("f({i})")).collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "function f(x) {{ return x * 2; }} var a = [{}]; a[299] + a[0] + a.length;",
            calls.join(", ")
        )),
        "898"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "function sum(xs) {{ var t = 0; for (var i = 0; i < xs.length; i++) t += xs[i]; \
             return t; }} sum({});",
            array_literal(300)
        )),
        "44850"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var a = {}; var o = {}; return a[150] + o.k150; }})();",
            array_literal(300),
            object_literal(300)
        )),
        "300"
    );
    // A literal `__proto__:` entry sets the prototype; such literals stay on
    // the batch path, which implements that.
    let entries: Vec<String> = (0..100).map(|i| format!("k{i}: {i}")).collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "var p = {{ z: 1 }}; var o = {{__proto__: p, {}}}; \
             var n = 0; for (var k in o) n++; o.z + ':' + n + ':' + o.k99;",
            entries.join(", ")
        )),
        "1:101:99"
    );
}

fn max_function_frame_size(source: &str) -> u32 {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse_bd_9vouw_23.js");
    let context = LoweringContext::new("rr-trace", "rr-decision", "rr-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    module
        .function_table
        .iter()
        .map(|function| function.frame_size)
        .max()
        .expect("at least the main function")
}

fn chained_calls(statements: usize) -> String {
    let body =
        "[].concat(xs).filter(Boolean).map(id).filter(Boolean).forEach(add);\n".repeat(statements);
    format!(
        "(function (xs) {{ var total = 0; function id(x) {{ return x; }} \
         function add(x) {{ total += x; }}\n{body}return total; }})([1, 0, 2]);"
    )
}

#[test]
fn expression_temporaries_release_their_registers_in_function_bodies() {
    // Method-call receivers, `?:` results and `&&`/`||`/switch operands live
    // in internal bindings. Each one pinned a register for the rest of its
    // function body, so ten statements of five-link call chains overflowed
    // the frame, and minimist 1.2.8's parseArgs needed 589 registers.
    assert_eq!(fixed_lane_value(&chained_calls(10)), "30");
    assert_eq!(fixed_lane_value(&chained_calls(15)), "45");
    assert_eq!(
        max_function_frame_size(&chained_calls(5)),
        max_function_frame_size(&chained_calls(15)),
        "a statement's temporaries are free once it ends"
    );
    let ternaries: String = (0..300)
        .map(|i| format!("t = (t > {i} ? t - 1 : t + 2) || (t && 7);\n"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var t = 0;\n{ternaries}return t; }})();"
        )),
        "300"
    );
    let cases: String = (0..200)
        .map(|i| format!("case {i}: out.push([{i}].concat([0]).length); break;\n"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var out = [];\n\
             for (var i = 0; i < 5; i++) {{ switch (i * 3) {{\n{cases}default: out.push('d'); }} }}\n\
             return out.join(','); }})();"
        )),
        "2,2,2,2,2"
    );
}

#[test]
fn reused_local_registers_keep_values_across_loops_handlers_and_finally() {
    // Filler statements allocate and free many registers inside each block,
    // so a local whose register were released too early would be clobbered.
    let filler = |prefix: &str, suffix: &str| -> String {
        (0..120)
            .map(|i| format!("var {prefix}{i} = [{i}].concat([1]){suffix};\n"))
            .collect()
    };
    // `base` is written before the loop and read inside it on every
    // iteration; `prev` is read one iteration after its write (not assigned
    // on the first pass), so it keeps a register for the whole body.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var base = 10; var out = [];\n\
             for (var k = 0; k < 3; k++) {{\n  if (k > 0) out.push(prev);\n{}  var prev = base + k;\n}}\n\
             return out.join(',') + ':' + base; }})();",
            filler("f", ".length + (base ? 1 : 0)")
        )),
        "10,11:10"
    );
    // `continue` leaves the try through its finally block.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var seen = 0; var log = [];\n\
             for (var i = 0; i < 4; i++) {{\n  try {{ if (i % 2) continue; log.push('b' + i); }}\n\
             finally {{ {} seen = seen + 1; }}\n}}\n\
             return log.join(',') + ':' + seen; }})();",
            filler("g", ".join('-')")
        )),
        "b0,b2:4"
    );
    // A catch handler reads a local written before the try.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var before = 'kept'; var r = '';\n{}\
             try {{ null.x; }} catch (e) {{ r = before + ':' + e.name; }}\n\
             return r; }})();",
            filler("h", ".length")
        )),
        "kept:TypeError"
    );
}

#[test]
fn statements_after_a_switch_still_reuse_registers() {
    // A switch stored its discriminant and left the value on the lowering
    // stack, so statement-boundary reuse stayed off for the rest of the body:
    // every statement after one `switch` kept all its temporaries.
    let tail: String = (0..300)
        .map(|i| format!("out.push([{i}].concat([0]).length);\n"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "var out = []; switch (out.length) {{ case 0: out.push(1); }}\n{tail}out.length;"
        )),
        "301"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var out = []; switch (out.length) {{ case 0: out.push(1); }}\n\
             {tail}return out.length; }})();"
        )),
        "301"
    );
}

#[test]
fn return_and_throw_statements_release_their_temporaries() {
    // Test262's S11.7.3_A4_T4 is 500 top-level `if (c) { throw new
    // Test262Error(...) }` statements: a throw (like a return) consumed its
    // operand without ending the statement, so every one kept its
    // temporaries and the main frame needed 4226 registers.
    let checks: String = (0..500)
        .map(|i| format!("if ({i} >>> 16 !== 0) {{ throw new Error('#{i}: ' + ({i} >>> 16)); }}\n"))
        .collect();
    assert_eq!(fixed_lane_value(&format!("{checks}'ok';")), "ok");
    assert_eq!(
        fixed_lane_value(&format!("(function () {{\n{checks}return 'ok'; }})();")),
        "ok"
    );
    let returns: String = (0..300)
        .map(|i| format!("if (n === {i}) {{ return 'r' + ({i} * 2); }}\n"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function (n) {{\n{returns}return 'none'; }})(299);"
        )),
        "r598"
    );
    // The returned value is captured before the finally block reuses the
    // return statement's registers.
    assert_eq!(
        fixed_lane_value(
            "(function () { try { return [1, 2].concat([3]).join('-'); } \
             finally { var t = [9].concat([8]).join('+'); } })();"
        ),
        "1-2-3"
    );
}

#[test]
fn nested_batch_literals_release_their_element_registers() {
    // Test262's harness/byteConversionValues.js is one statement holding an
    // object of eleven ~58-element arrays. Each array (under the 64-entry
    // batch threshold) kept its element and key registers until the
    // statement ended, so the main frame needed 1295 registers.
    let array = |step: usize| -> String {
        let elements: Vec<String> = (0..58).map(|i| (i * step).to_string()).collect();
        format!("[{}]", elements.join(", "))
    };
    let expected: Vec<String> = "abcdefghijk"
        .chars()
        .enumerate()
        .map(|(i, name)| format!("{name}: {}", array(i + 1)))
        .collect();
    let table = format!(
        "{{ values: {}, expected: {{ {} }} }}",
        array(1),
        expected.join(", ")
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "var table = {table};\n\
             table.expected.k.length + ':' + table.expected.k[57] + ':' + table.values[57];"
        )),
        "58:627:57"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var table = {table}; \
             var n = 0; for (var k in table.expected) n++; return table.expected.j[10] + ':' + n; }})();"
        )),
        "100:11"
    );
}

fn loop_filler(target: &str) -> String {
    (0..60)
        .map(|i| format!("{target}.push([{i}].concat([0]).length);\n"))
        .collect()
}

#[test]
fn for_in_and_for_of_bodies_reuse_registers() {
    // A for-in/for-of loop keeps its iterator on the lowering value stack for
    // the whole body, so no statement in the body ever emptied the stack and
    // none of them released its temporaries: 60 statements in one loop body
    // failed with "register 256 out of bounds". Plain for/while bodies were
    // fine. Expected strings are Node v22.2.0's.
    let fill = loop_filler("out");
    assert_eq!(
        fixed_lane_value(&format!(
            "var out = []; for (const x of [1, 2]) {{\n{fill}}}\nout.length;"
        )),
        "120"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var out = []; for (const x of [1, 2]) {{\n{fill}}}\n\
             return out.length; }})();"
        )),
        "120"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var out = []; for (const k in {{a: 1, b: 2}}) {{\n{fill}}}\n\
             return out.length; }})();"
        )),
        "120"
    );
    let scratch = loop_filler("[]");
    // Loop-carried locals and a destructured loop variable keep their values.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var acc = 0; var last = ''; \
             for (const [k, v] of [['a', 1], ['b', 2], ['c', 3]]) {{\n{scratch}\
             acc = acc + v; last = k + last; }}\nreturn acc + ':' + last; }})();"
        )),
        "6:cba"
    );
    // Nested loops with break, continue and a labeled continue.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var log = []; outer: for (const a of [1, 2, 3]) {{ \
             for (const b of ['x', 'y', 'z']) {{\n{scratch}\
             if (b === 'y' && a === 2) continue outer; if (a === 3) break outer; \
             log.push(a + b); }} log.push('|'); }}\nreturn log.join(','); }})();"
        )),
        "1x,1y,1z,|,2x"
    );
    // A return inside the body still closes the iterator.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var closed = false; var it = {{ [Symbol.iterator]() {{ var n = 0; \
             return {{ next() {{ n++; return {{ value: n, done: n > 5 }}; }}, \
             return() {{ closed = true; return {{}}; }} }}; }} }};\n\
             var found = (function () {{ for (const v of it) {{\n{scratch}\
             if (v === 3) return v * 10; }} return -1; }})(); return found + ':' + closed; }})();"
        )),
        "30:true"
    );
    // A generator suspended inside a long loop body resumes with its state.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ function* g(xs) {{ for (const x of xs) {{\n{scratch}\
             yield x * 2; }} }} return [...g([1, 2, 3])].join(','); }})();"
        )),
        "2,4,6"
    );
}

fn repeated(item: &str, count: usize) -> String {
    vec![item; count].join(", ")
}

#[test]
fn calls_inside_one_expression_release_their_temporaries() {
    // A call's callee, receiver and argument registers (and the contiguous
    // copies it passes) stayed allocated until its statement ended, about six
    // registers per `f(1, 2)`, so an array literal, object literal or argument
    // list of ~40 calls overflowed the 256-register frame. Node values.
    let calls = repeated("f(1, 2)", 60);
    let prelude = "function f(a, b) { return a + b; } \
                   function g() { return arguments.length; } \
                   var o = { m(a) { return a * 2; } }; \
                   function P(a) { this.a = a; }";
    let object_entries = (0..60)
        .map(|i| format!("k{i}: f(1, 2)"))
        .collect::<Vec<_>>()
        .join(", ");
    for (name, expression, node) in [
        (
            "array_of_calls",
            format!("((r) => r.length + r[59])([{calls}])"),
            "63",
        ),
        ("call_arguments", format!("g({calls})"), "60"),
        (
            "object_of_calls",
            format!("Object.keys({{{object_entries}}}).length"),
            "60",
        ),
        (
            "method_calls",
            format!("[{}].reduce((s, x) => s + x, 0)", repeated("o.m(1)", 60)),
            "120",
        ),
        (
            "constructions",
            format!("[{}].length", repeated("new P(1)", 60)),
            "60",
        ),
        (
            "builtin_calls",
            format!("[{}].length", repeated("Math.max(1, 2)", 60)),
            "60",
        ),
    ] {
        let top_level = fixed_lane_value(&format!("{prelude} {expression};"));
        if matches!(name, "method_calls" | "builtin_calls") {
            // Ratchet, known limit (bd-9vouw.86): at top level each member
            // call's receiver (`o` in `o.m(1)`, `Math` in `Math.max(1, 2)`)
            // is a synthetic binding in a pinned register until the
            // statement ends, so 60 of them in one top-level expression
            // still overflow. The function-body case below reuses one
            // register per call. Promote to `node` when fixed.
            assert_eq!(
                top_level, "ERROR: register 256 out of bounds (max 256)",
                "{name} at top level: promote the bd-9vouw.86 ratchet to Node's value"
            );
        } else {
            assert_eq!(top_level, node, "{name} at top level");
        }
        assert_eq!(
            fixed_lane_value(&format!(
                "{prelude} (function () {{ return {expression}; }})();"
            )),
            node,
            "{name} in a function body"
        );
    }
}

fn operator_chain(item: &str, count: usize) -> String {
    vec![item; count].join(" + ")
}

#[test]
fn binary_operators_release_their_operand_registers() {
    // A binary operator's result took a fresh register and its operands stayed
    // allocated until the statement ended, two registers per operator, so a
    // 128-term `1 + 1 + ... + 1` overflowed the 256-register frame. Chains
    // longer than 255 terms also need bd-9vouw.85 to parse. Node values.
    let prelude = "function f(a, b) { return a + b; } var log = []; var i; \
                   function o(n) { return { valueOf() { log.push(n); return n; } }; } \
                   function inOrder(count) { for (var k = 0; k < count; k++) { \
                   if (log[k] !== k + 1) return false; } return log.length === count; }";
    let strings = (0..600)
        .map(|index| format!("'{}'", index % 10))
        .collect::<Vec<_>>()
        .join(" + ");
    let value_of_calls = (1..=150)
        .map(|n| format!("o({n})"))
        .collect::<Vec<_>>()
        .join(" + ");
    for (name, expression, node) in [
        ("literals", operator_chain("1", 600), "600"),
        ("strings", format!("({strings}).length"), "600"),
        ("products", operator_chain("3 * 3", 200), "1800"),
        ("calls", operator_chain("f(1, 2)", 150), "450"),
        ("comparisons", operator_chain("(1 < 2)", 200), "200"),
        (
            "updates",
            format!("(i = 0, {})", operator_chain("i++", 150)),
            "11175",
        ),
        (
            // ToPrimitive still runs left to right, one operand at a time.
            "value_of_order",
            format!("(log = [], ({value_of_calls}) * (inOrder(150) ? 1 : -1))"),
            "11325",
        ),
    ] {
        assert_eq!(
            fixed_lane_value(&format!("{prelude} {expression};")),
            node,
            "{name} at top level"
        );
        assert_eq!(
            fixed_lane_value(&format!(
                "{prelude} (function () {{ return {expression}; }})();"
            )),
            node,
            "{name} in a function body"
        );
    }
    // The chain's length no longer shows in the frame width.
    assert_eq!(
        main_frame_size(&format!("var x = {};", operator_chain("1", 100))),
        main_frame_size("var x = 1 + 1;"),
        "top-level chain frame"
    );
    assert_eq!(
        max_function_frame_size(&format!(
            "function g() {{ return {}; }}",
            operator_chain("1", 100)
        )),
        max_function_frame_size("function g() { return 1 + 1; }"),
        "function-body chain frame"
    );
}
