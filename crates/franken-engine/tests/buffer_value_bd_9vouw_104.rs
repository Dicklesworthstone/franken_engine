//! bd-9vouw.104: `Buffer` is a first-class constructor value.
//!
//! The global existed only as a lowering rewrite of `Buffer.from(...)` and the
//! other static member calls: `typeof Buffer` was 'undefined', `x instanceof
//! Buffer` threw ReferenceError, and Buffer instances had no prototype, so
//! `buf instanceof Uint8Array` was false and `buf.constructor` was Object.
//! Now `Buffer` is a global constructor whose statics route to the same
//! builtins, `Buffer.prototype` inherits from `Uint8Array.prototype` and
//! serves Buffer's methods ahead of the typed array ones, and every Buffer is
//! linked to it. Expected strings are Node v22.2.0's output for the same
//! programs.
//!
//! No-claim: `buf.map(...)` and the other species-creating methods return a
//! Uint8Array, not a Buffer (Node: Buffer); `Buffer.isEncoding`,
//! `Buffer.allocUnsafeSlow` and `class X extends Buffer` are not covered;
//! `Object.getPrototypeOf(Buffer)` is not `Uint8Array`. The alias regressions
//! also cover source-eval authority admission (bd-9vouw.166); they do not grant
//! filesystem, network, environment, or process authority.

use frankenengine_engine::{
    HybridRouter, JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine,
};

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

#[test]
fn ordinary_buffer_import_lowers_without_process_authority_bd_h8s4j() {
    use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};

    for specifier in ["buffer", "node:buffer"] {
        let source = format!("const {{ Blob, File }} = require('{specifier}'); [Blob, File];");
        let tree = frankenengine_engine::parser_api_stability::parse_script(&source)
            .expect("parse the ordinary Buffer import");
        let context = LoweringContext::new("buffer-import", "source-metadata", "builtin-only")
            .with_authenticated_commonjs_runtime_bindings();
        let ir0 = Ir0Module::from_syntax_tree(tree, "buffer-import.cjs");
        let module = lower_ir0_to_ir3(&ir0, &context)
            .expect("the engine-owned File factory must not require guest process authority")
            .ir3;
        assert!(module.instructions.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::HostCall { capability, .. } if capability.0 == "builtin:OsPlatform"
        )));
    }
}

#[test]
fn buffer_import_does_not_authorize_guest_process_reads_bd_h8s4j() {
    use frankenengine_engine::effect_set::EffectKind;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{
        LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
    };

    for source in [
        "process.platform;",
        "require('node:buffer'); process.platform;",
        "require('node:buffer'); process.env.SECRET;",
    ] {
        let tree = frankenengine_engine::parser_api_stability::parse_script(source).unwrap();
        let context = LoweringContext::new("guest-process", "source-metadata", "builtin-only")
            .with_authenticated_commonjs_runtime_bindings();
        let error = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "guest-process.cjs"),
            &context,
        )
        .expect_err("importing Buffer never grants guest process authority");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { required_effect, .. }
                    if required_effect == if source.ends_with("process.env.SECRET;") {
                        EffectKind::EnvRead
                    } else {
                        EffectKind::ProcessShapeRead
                    }
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn buffer_import_preserves_local_process_binding_bd_h8s4j() {
    assert_eq!(
        eval(
            "const process = { platform: 'guest-local' }; const { Blob } = require('node:buffer'); [process.platform, new Blob(['ok']).size].join(':');"
        ),
        "guest-local:2"
    );
}

/// `Buffer` is a value: typeof, name, length, poolSize, an alias, and the global object's property.
#[test]
fn buffer_global_value() {
    let source = "const B = Buffer;\n\
         [typeof Buffer, Buffer.name, Buffer.length, Buffer.poolSize, B === Buffer, globalThis.Buffer === Buffer,\n\
          typeof B.from, B.from === Buffer.from].join(' ');";
    assert_eq!(
        eval(source),
        "function Buffer 3 8192 true true function true"
    );
}

/// No direct static builtin call may accidentally grant the capability needed
/// by these aliases. Expected values are independently checked in Node/Bun.
#[test]
fn canonical_builtin_aliases_work_without_a_direct_static_call() {
    for (source, expected) in [
        ("const B = Buffer; B.from('hi').toString('hex');", "6869"),
        ("const O = Object; O.keys({a: 1})[0];", "a"),
        ("const O = Object; O.keys({a: 1}).join();", "a"),
        ("const R = Reflect; R.get({answer: 42}, 'answer');", "42"),
        ("const M = Math; M.abs(-7);", "7"),
        (
            "const G = globalThis; G.Buffer.from('hi').toString('hex');",
            "6869",
        ),
        (
            "function hex(s) { const B = Buffer; return B.from(s).toString('hex'); } hex('hi');",
            "6869",
        ),
    ] {
        assert_eq!(eval(source), expected, "HybridRouter: {source}");
        assert_eq!(
            QuickJsInspiredNativeEngine
                .eval(source)
                .expect("baseline lane")
                .value,
            expected,
            "baseline lane: {source}"
        );
        assert_eq!(
            V8InspiredNativeEngine
                .eval(source)
                .expect("throughput lane")
                .value,
            expected,
            "throughput lane: {source}"
        );
        let prepared = HybridRouter::prepare_eval(source).expect("prepare alias source");
        for _ in 0..2 {
            assert_eq!(
                HybridRouter::default()
                    .eval_prepared(&prepared)
                    .expect("fresh prepared execution")
                    .value,
                expected,
                "prepared execution: {source}"
            );
        }
    }
}

/// A builtin reached through an implicit constructor is outside source eval's
/// canonical-name admission rule. A shadowed name must not grant authority.
#[test]
fn implicit_constructor_does_not_declare_builtin_authority() {
    for source in [
        "({}).constructor.keys({a: 1})[0];",
        "const Object = 0; ({}).constructor.keys({a: 1})[0];",
        "const Object = 0; Object; ({}).constructor.keys({a: 1})[0];",
        "const Buffer = 0; Buffer; ({}).constructor.keys({a: 1})[0];",
        "const Object = 0; function read() { return Object; } read(); ({}).constructor.keys({a: 1})[0];",
        "const Buffer = 0; function read() { return Buffer; } read(); ({}).constructor.keys({a: 1})[0];",
    ] {
        let error = HybridRouter::default()
            .eval(source)
            .expect_err("no canonical builtin global was referenced");
        assert_eq!(
            error.stable_namespace(),
            "eval.capability.denied",
            "{source}"
        );
        assert!(error.to_string().contains("builtin:ObjectKeys"), "{error}");
    }
}

/// Statics read as values keep their behavior, names and lengths.
#[test]
fn buffer_statics_as_values() {
    let source = "const { from, alloc, concat, isBuffer, byteLength, compare } = Buffer;\n\
         [from('ab').toString(), alloc(2, 7).toString('hex'), concat([from('a'), from('b')]).toString(),\n\
          isBuffer(from('x')), isBuffer(new Uint8Array(1)), byteLength('h\\u00e9'), compare(from('a'), from('b')),\n\
          [Buffer.from, Buffer.alloc, Buffer.allocUnsafe, Buffer.byteLength, Buffer.concat, Buffer.compare, Buffer.isBuffer]\n\
            .map(f => f.name + '/' + f.length).join(',')].join(' ');";
    assert_eq!(
        eval(source),
        "ab 0707 ab true false 3 -1 from/3,alloc/3,allocUnsafe/1,byteLength/2,concat/2,compare/2,isBuffer/1"
    );
}

/// Instances inherit from Buffer.prototype, which inherits from Uint8Array.prototype.
#[test]
fn buffer_instances_link_to_buffer_prototype() {
    let source = "const b = Buffer.from('hi');\n\
         [b instanceof Buffer, b instanceof Uint8Array, Object.getPrototypeOf(b) === Buffer.prototype,\n\
          Object.getPrototypeOf(Buffer.prototype) === Uint8Array.prototype, b.constructor === Buffer, b.constructor.name,\n\
          b.buffer instanceof ArrayBuffer, new Uint8Array(2) instanceof Buffer, Buffer.alloc(1) instanceof Buffer,\n\
          b.subarray(1) instanceof Buffer, b.slice(0, 1) instanceof Uint8Array].join(' ');";
    assert_eq!(
        eval(source),
        "true true true true true Buffer true false true true true"
    );
}

/// Buffer's own methods shadow %TypedArray.prototype%'s, and the inherited ones still work.
#[test]
fn buffer_buffer_methods_win() {
    let source = "const b = Buffer.from('hi');\n\
         [b.toString(), String(b), b.subarray(1).toString(), b.slice(0, 1).toString(), JSON.stringify(b),\n\
          b.toString === Buffer.prototype.toString, typeof Buffer.prototype.readUInt8, typeof Buffer.prototype.map,\n\
          b.includes(105), b.indexOf('i'), Array.from(b.map(x => x + 1)).join(), b.reduce((a, x) => a + x, 0),\n\
          require('util').inspect(b), Object.prototype.toString.call(b)].join(' ');";
    assert_eq!(
        eval(source),
        "hi hi i h {\"type\":\"Buffer\",\"data\":[104,105]} true function function true 1 105,106 209 <Buffer 68 69> [object Uint8Array]"
    );
}

/// The is-buffer package's duck check and instanceof without a typeof guard.
#[test]
fn buffer_is_buffer_package_check() {
    let source = "function isBuffer(obj) {\n\
           return obj != null && obj.constructor != null && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj);\n\
         }\n\
         function bytes(x) { if (x instanceof Buffer) return 'buffer'; if (x instanceof Uint8Array) return 'u8'; return typeof x; }\n\
         [isBuffer(Buffer.from('a')), isBuffer(new Uint8Array(1)), isBuffer({}), isBuffer(null),\n\
          bytes(Buffer.from('a')), bytes(new Uint8Array(1)), bytes('s')].join(' ');";
    assert_eq!(eval(source), "true false false false buffer u8 string");
}

/// The deprecated Buffer(arg) and new Buffer(arg) forms.
#[test]
fn buffer_call_and_construct() {
    let source = "[new Buffer('ab').toString(), Buffer('cd').toString(), new Buffer(3).length, Buffer(2).toString('hex'),\n\
          new Buffer([1, 2]) instanceof Buffer].join(' ');";
    assert_eq!(eval(source), "ab cd 3 0000 true");
}
