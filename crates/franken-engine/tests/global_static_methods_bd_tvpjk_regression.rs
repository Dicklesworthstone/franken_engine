//! Regression for bd-tvpjk: Object/Array/String STATIC methods unresolved via
//! member access. Their execution handlers + id-registry entries already existed
//! in dispatch_builtin_hostcall_inner, but the lowering interception only wired
//! Object.keys/values/entries + JSON.parse/stringify — so Object.assign,
//! Array.isArray, String.fromCharCode, etc. faulted ("expected function/object,
//! got undefined") because the bare `Object`/`Array`/`String` globals have no
//! eval-scope binding. Fix extends the static-member interception (cf. bd-6kkg6).
//!
//! bd-cue2u extends the same narrow surface for VALUE reads of
//! `Array.isArray`: a dedicated zero-argument factory materializes a
//! first-class builtin without creating a synthetic `Array` global or widening
//! arbitrary hostcall capabilities into guest-callable values.
use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir1Op};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, lower_ir0_to_ir1, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => o.value.to_string(),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn object_assign() {
    assert_eq!(
        eval("let o = Object.assign({}, {a:1}, {b:2}); o.a + o.b;"),
        "3"
    );
    assert_eq!(eval("Object.assign({x:1}, {x:9}).x;"), "9"); // later sources win
}

#[test]
fn object_is() {
    // Object.is uses the receiver-placeholder calling convention — these caught
    // a real wiring bug (slot-0 routing returned "false" for Object.is(1,1)).
    assert_eq!(eval("Object.is(1, 1);"), "true");
    assert_eq!(eval("Object.is(1, 2);"), "false");
    assert_eq!(eval("Object.is(\"x\", \"x\");"), "true");
}

#[test]
fn object_is_extensible() {
    // Receiver-placeholder convention. This validates the WIRING: a fresh object
    // literal is extensible. (Note: the engine's Object.freeze does not yet mark
    // the object non-extensible, so `isExtensible` of a frozen object still
    // reports true — that is a separate handler-semantics gap, not a wiring bug;
    // tracked under bd-tvpjk's comments.)
    assert_eq!(eval("Object.isExtensible({});"), "true");
}

#[test]
fn object_get_own_property_names() {
    // Another slot-0 static, confirming the wiring delivers the receiver object
    // at slot 0.
    assert_eq!(eval("Object.getOwnPropertyNames({a:1,b:2}).length;"), "2");
}

#[test]
fn object_freeze_and_is_frozen() {
    assert_eq!(
        eval("let o = {a:1}; Object.freeze(o); Object.isFrozen(o);"),
        "true"
    );
    assert_eq!(eval("Object.isFrozen({});"), "false");
}

#[test]
fn object_create_and_keys() {
    // Object.create(null) yields an object with no inherited keys.
    assert_eq!(
        eval("Object.keys(Object.assign(Object.create(null), {a:1,b:2})).length;"),
        "2"
    );
}

#[test]
fn array_is_array() {
    assert_eq!(eval("Array.isArray([1,2,3]);"), "true");
    assert_eq!(eval("Array.isArray({});"), "false");
    assert_eq!(eval("Array.isArray(5);"), "false");
}

#[test]
fn array_is_array_member_reads_are_first_class() {
    assert_eq!(
        eval("let predicate = Array.isArray; predicate([1,2,3]);"),
        "true"
    );
    assert_eq!(
        eval("let predicate = Array[\"isArray\"]; predicate({0:1});"),
        "false"
    );
    assert_eq!(eval("typeof Array.isArray;"), "function");
    assert_eq!(eval("Array.isArray === Array.isArray;"), "true");
    assert_eq!(eval("Array.isArray === Array[\"isArray\"];"), "true");
    assert_eq!(eval("Array[\"isArray\"]([]);"), "true");
    assert_eq!(eval("Array.isArray();"), "false");
    assert_eq!(eval("let predicate = Array.isArray; predicate();"), "false");
}

#[test]
fn array_is_array_value_works_as_array_callback() {
    assert_eq!(eval("[[1], [2,3], []].every(Array.isArray);"), "true");
    assert_eq!(eval("[[1], {0:2}, []].every(Array.isArray);"), "false");
    assert_eq!(eval("[{}, [1]].some(Array.isArray);"), "true");
    assert_eq!(
        eval("(function (predicate) { return predicate([1]); })(Array.isArray);"),
        "true"
    );
}

#[test]
fn array_is_array_value_respects_lexical_shadowing() {
    assert_eq!(
        eval(
            "let Array = {isArray: function(value) { return value === 42; }}; \
             let predicate = Array.isArray; predicate(42);"
        ),
        "true"
    );
    assert_eq!(
        eval(
            "(function(Array) { let predicate = Array.isArray; return predicate(42); }) \
             ({isArray: function(value) { return value === 42; }});"
        ),
        "true"
    );
    assert_eq!(
        eval(
            "let Array = {isArray: function(value) { return value === 42; }}; \
             let outer = function() { \
               return function() { let predicate = Array.isArray; return predicate(42); }; \
             }; outer()();"
        ),
        "true"
    );
}

#[test]
fn array_is_array_factory_lowering_is_narrow() {
    fn collect_hostcalls<'a>(ops: &'a [Ir1Op], out: &mut Vec<(&'a str, u32)>) {
        for op in ops {
            match op {
                Ir1Op::HostCall {
                    capability,
                    arg_count,
                } => out.push((capability.as_str(), *arg_count)),
                Ir1Op::DeclareFunction { body_ops, .. }
                | Ir1Op::CreateFunction { body_ops, .. } => collect_hostcalls(body_ops, out),
                _ => {}
            }
        }
    }

    let source = "let first = Array.isArray; let second = Array[\"isArray\"]; \
                  Array.isArray([]); Array[\"isArray\"]([]); first === second;";
    let lower = || {
        let tree = CanonicalEs2020Parser
            .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
            .expect("source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd-cue2u-array-is-array-factory.js");
        let context =
            LoweringContext::new("bd-cue2u-trace", "bd-cue2u-decision", "bd-cue2u-policy");
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("source should lower to IR1")
            .module;
        let lowered = lower_ir0_to_ir3(&ir0, &context).expect("source should lower to IR3");
        (ir1, lowered)
    };

    let (ir1, first) = lower();
    let (_, second) = lower();
    let mut hostcalls = Vec::new();
    collect_hostcalls(&ir1.ops, &mut hostcalls);
    assert_eq!(
        hostcalls
            .iter()
            .filter(|(capability, _)| *capability == "builtin:ArrayIsArrayFunction")
            .copied()
            .collect::<Vec<_>>(),
        vec![
            ("builtin:ArrayIsArrayFunction", 0),
            ("builtin:ArrayIsArrayFunction", 0),
        ]
    );
    assert_eq!(
        hostcalls
            .iter()
            .filter(|(capability, _)| *capability == "builtin:ArrayIsArray")
            .copied()
            .collect::<Vec<_>>(),
        vec![("builtin:ArrayIsArray", 1), ("builtin:ArrayIsArray", 1),],
        "dot and literal-computed direct calls must retain the dedicated hostcall"
    );
    assert!(
        !hostcalls
            .iter()
            .any(|(capability, _)| *capability == "hostcall.invoke")
    );
    assert!(
        first
            .ir3
            .required_capabilities
            .iter()
            .any(|capability| capability.0 == "builtin:ArrayIsArrayFunction")
    );
    assert_eq!(
        first.ir3.required_capabilities, second.ir3.required_capabilities,
        "factory capability accounting must be deterministic"
    );

    let shadowed = "let Array = {isArray: function(value) { return value; }}; \
                    let predicate = Array.isArray; predicate(true);";
    let tree = CanonicalEs2020Parser
        .parse_with_options(shadowed, ParseGoal::Script, &ParserOptions::default())
        .expect("shadowing source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd-cue2u-array-shadow.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("shadowing source should lower")
        .module;
    let mut shadowed_hostcalls = Vec::new();
    collect_hostcalls(&ir1.ops, &mut shadowed_hostcalls);
    assert!(
        !shadowed_hostcalls
            .iter()
            .any(|(capability, _)| *capability == "builtin:ArrayIsArrayFunction")
    );

    let unrelated = "let key = \"isArray\"; let dynamic = Array[key]; \
                     let other = Array.from; dynamic === other;";
    let tree = CanonicalEs2020Parser
        .parse_with_options(unrelated, ParseGoal::Script, &ParserOptions::default())
        .expect("unrelated member source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd-cue2u-array-unrelated-members.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("unrelated member source should lower")
        .module;
    let mut unrelated_hostcalls = Vec::new();
    collect_hostcalls(&ir1.ops, &mut unrelated_hostcalls);
    assert!(
        !unrelated_hostcalls
            .iter()
            .any(|(capability, _)| *capability == "builtin:ArrayIsArrayFunction"),
        "dynamic and unrelated member reads must not use the narrow factory"
    );
}

#[test]
fn array_from() {
    assert_eq!(eval("Array.from([1,2,3]).length;"), "3");
    assert_eq!(eval("Array.from([1,2,3], x => x * 2)[2];"), "6");
}

#[test]
fn string_from_char_code() {
    assert_eq!(eval("String.fromCharCode(65);"), "A");
    assert_eq!(eval("String.fromCharCode(72, 105);"), "Hi");
}

#[test]
fn string_from_code_point_invalid_values_throw_range_error_bd_xulus() {
    assert_eq!(eval("String.fromCodePoint(65, 66);"), "AB");

    for source in [
        "String.fromCodePoint(65, 0x110000);",
        "String.fromCodePoint(-1);",
        "String.fromCodePoint(1.5);",
        "String.fromCodePoint(undefined);",
    ] {
        let out = eval(source);
        assert!(
            out.contains("range error") && out.contains("String.fromCodePoint"),
            "{source} should throw RangeError instead of returning a partial string, got {out:?}"
        );
    }
}

#[test]
fn math_and_string_builtins_use_modular_float_coercion() {
    // ECMA `Math.imul`/`Math.clz32`/`String.fromCharCode` apply modular
    // ToInt32/ToUint32/ToUint16 to their operands. Rust's `f64 as i32`/`as u32`
    // *saturates*, so before the fix any float operand outside the 32-bit range
    // clamped instead of wrapping. These cases all exercise the float branch.

    // Math.imul: ToUint32(2**31)=2147483648 -> int32 -2147483648; *2 wraps to 0
    // (saturating gave i32::MAX*2 wrapping = -2).
    assert_eq!(eval("Math.imul(2147483648.5, 2);"), "0");

    // Math.clz32: ToUint32(2**32)=0 -> clz32(0)=32 (saturating gave clz32(MAX)=0).
    assert_eq!(eval("Math.clz32(4294967296.5);"), "32");
    // Math.clz32(-1.5): ToUint32=0xFFFFFFFF -> clz32=0 (saturating gave 0->32).
    assert_eq!(eval("Math.clz32(-1.5);"), "0");

    // String.fromCharCode: ToUint16(-1.5)=0xFFFF (saturating gave 0x0000).
    assert_eq!(eval("String.fromCharCode(-1.5).charCodeAt(0);"), "65535");
}

#[test]
fn static_globals_are_shadowable() {
    // A user binding named `Object` must NOT be reinterpreted as the global.
    assert_eq!(
        eval("let Object = { assign: () => 42 }; Object.assign({}, {});"),
        "42"
    );
}

#[test]
fn statics_compose_in_expressions() {
    assert_eq!(eval("Array.isArray([1]) && Object.is(2, 2);"), "true");
}
