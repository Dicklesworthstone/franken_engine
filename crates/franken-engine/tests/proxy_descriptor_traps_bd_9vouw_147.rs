//! bd-9vouw.147: Proxy [[GetOwnProperty]] and [[DefineOwnProperty]]
//! (ES2020 9.5.5, 9.5.6).
//!
//! `Object.getOwnPropertyDescriptor(proxy, k)` answered undefined even
//! without a trap, and `Object.defineProperty(proxy, ...)` neither called the
//! `defineProperty` trap nor reached the target. Expected strings are Node
//! v22.2.0's output for the same programs.
//!
//! Covers `Object/Reflect.getOwnPropertyDescriptor`, `Object/Reflect.defineProperty`,
//! `Object.getOwnPropertyDescriptors`, `Object.defineProperties`, and
//! `Object.create`'s second argument through Proxy traps and forwarding.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// Without traps, getOwnPropertyDescriptor and defineProperty reach the target.
#[test]
fn proxy_descriptor_forwarding() {
    let source = "var t = { a: 1 }; var p = new Proxy(t, {});\n\
         Object.defineProperty(p, 'x', { value: 2, enumerable: true });\n\
         [JSON.stringify(Object.getOwnPropertyDescriptor(p, 'a')), t.x, JSON.stringify(Object.getOwnPropertyDescriptor(t, 'x')), String(Object.getOwnPropertyDescriptor(p, 'zz')), Reflect.defineProperty(p, 'y', { value: 3 }), t.y].join(' ');";
    assert_eq!(
        eval(source),
        "{\"value\":1,\"writable\":true,\"enumerable\":true,\"configurable\":true} 2 {\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false} undefined true 3"
    );
}

/// The traps receive (target, key) and (target, key, descriptor); the trap's descriptor is completed.
#[test]
fn proxy_descriptor_traps() {
    let source = "var log = []; var t = {};\n\
         var p = new Proxy(t, {\n\
           getOwnPropertyDescriptor(target, k) { log.push('gopd:' + String(k) + ':' + (target === t)); return { value: 7, configurable: true }; },\n\
           defineProperty(target, k, d) { log.push('def:' + k + ':' + JSON.stringify(d)); return Reflect.defineProperty(target, k, d); }\n\
         });\n\
         var d = Object.getOwnPropertyDescriptor(p, 'q');\n\
         Object.defineProperty(p, 'w', { value: 3, writable: true });\n\
         [JSON.stringify(d), t.w, log.join('|')].join(' ');";
    assert_eq!(
        eval(source),
        "{\"value\":7,\"writable\":false,\"enumerable\":false,\"configurable\":true} 3 gopd:q:true|def:w:{\"value\":3,\"writable\":true}"
    );
}

/// Invariant violations are TypeErrors (ES2020 9.5.5, 9.5.6); a false defineProperty result throws in Object.defineProperty and is false in Reflect.defineProperty.
#[test]
fn proxy_descriptor_invariants() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var locked = {}; Object.defineProperty(locked, 'k', { value: 1, configurable: false });\n\
         var hides = new Proxy(locked, { getOwnPropertyDescriptor() { return undefined; } });\n\
         var invents = new Proxy({}, { getOwnPropertyDescriptor() { return { value: 1, configurable: false }; } });\n\
         var refuses = new Proxy({}, { defineProperty() { return false; } });\n\
         var lies = new Proxy({}, { defineProperty() { return true; } });\n\
         [attempt(() => Object.getOwnPropertyDescriptor(hides, 'k')), attempt(() => Object.getOwnPropertyDescriptor(invents, 'k')),\n\
          attempt(() => Object.defineProperty(refuses, 'a', { value: 1 })), attempt(() => Reflect.defineProperty(refuses, 'a', { value: 1 })),\n\
          attempt(() => Object.defineProperty(lies, 'b', { value: 1, configurable: false })), attempt(() => Reflect.defineProperty({}, 'c', { get: 1 }))].join(' ');";
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError false TypeError TypeError"
    );
}

/// A callable proxy (bd-9vouw.132) takes the same path.
#[test]
fn proxy_descriptor_callable() {
    let source = "function f(a, b) {} var p = new Proxy(f, {});\n\
         Object.defineProperty(p, 'tag', { value: 't', enumerable: true });\n\
         [JSON.stringify(Object.getOwnPropertyDescriptor(p, 'length')), f.tag, JSON.stringify(Object.getOwnPropertyDescriptor(p, 'tag'))].join(' ');";
    assert_eq!(
        eval(source),
        "{\"value\":2,\"writable\":false,\"enumerable\":false,\"configurable\":true} t {\"value\":\"t\",\"writable\":false,\"enumerable\":true,\"configurable\":false}"
    );
}

/// bd-9vouw.236: HasOwnProperty of a Proxy is its [[GetOwnProperty]]: the
/// getOwnPropertyDescriptor trap, else the target's own property (string or
/// symbol key), and a revoked Proxy throws. Every key read false, so mobx's
/// `hasOwnProperty.call(proxy, $mobx)` made a second administration and
/// recursed until the stack overflowed on `observable({ a: 1 })`. Node v22.2.0
/// gives this value; Bun 1.4.2 agrees.
#[test]
fn has_own_property_of_a_proxy_asks_its_target_or_trap() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar sym = Symbol('adm');\nvar target = {};\nObject.defineProperty(target, sym, { value: 1, enumerable: false, writable: true, configurable: true });\ntarget.s = 2;\nvar plain = new Proxy(target, {});\nvar virtual = new Proxy({}, { getOwnPropertyDescriptor(t, k) { return k === 'virt' ? { value: 1, configurable: true } : undefined; } });\nvar revocable = Proxy.revocable({ a: 1 }, {}); revocable.revoke();\nvar hop = Object.prototype.hasOwnProperty;\n[hop.call(plain, sym), hop.call(plain, 's'), hop.call(plain, 'missing'), plain.hasOwnProperty(sym), Object.hasOwn(plain, 's'),\n hop.call(virtual, 'virt'), hop.call(virtual, 'other'), attempt(() => hop.call(revocable.proxy, 'a'))].join(' ');\n";
    assert_eq!(
        eval(source),
        "true true false true true true false TypeError"
    );
}

/// bd-9vouw.236: propertyIsEnumerable of a Proxy is its [[GetOwnProperty]]'s
/// enumerability (the getOwnPropertyDescriptor trap, else the target's own
/// property); every key read false, as hasOwnProperty did. Node v22.2.0
/// gives this value.
#[test]
fn property_is_enumerable_of_a_proxy_asks_its_target_or_trap() {
    let source = "var t = { a: 1 }; Object.defineProperty(t, 'h', { value: 2, enumerable: false });\nvar p = new Proxy(t, {}); var v = new Proxy({}, { getOwnPropertyDescriptor(o, k) { return k === 'x' ? { value: 1, enumerable: true, configurable: true } : undefined; } });\nvar pe = Object.prototype.propertyIsEnumerable;\n[pe.call(p, 'a'), pe.call(p, 'h'), pe.call(p, 'zz'), pe.call(v, 'x'), pe.call(v, 'y'), p.propertyIsEnumerable('a'), Object.keys(p).join(), JSON.stringify(Object.entries(v))].join(' ');\n";
    assert_eq!(eval(source), "true false false true false true a []");
}

/// Array iteration is inherited through the actual prototype chain. Removing
/// that chain must agree across ordinary, Reflect and transparent Proxy reads.
#[test]
fn array_iterator_get_and_has_follow_explicit_prototypes() {
    let source = r#"
        const key = Symbol.iterator;
        function inspect(value) {
            const proxy = new Proxy(value, {});
            return [typeof value[key], key in value,
                    typeof Reflect.get(value, key), Reflect.has(value, key),
                    typeof proxy[key], key in proxy].join(':');
        }
        const missing = Object.setPrototypeOf([1], null);
        const plain = Object.setPrototypeOf([2], Object.prototype);
        const custom = Object.setPrototypeOf([3], {});
        const inherited = Object.setPrototypeOf([4], Object.create(Array.prototype));
        const before = [inspect(missing), inspect(plain), inspect(custom)];
        missing[key] = Array.prototype[key];
        before.push(inspect(missing), inspect(inherited), inspect([5]));
        before.join('|');
    "#;
    assert_eq!(
        eval(source),
        [
            "undefined:false:undefined:false:undefined:false",
            "undefined:false:undefined:false:undefined:false",
            "undefined:false:undefined:false:undefined:false",
            "function:true:function:true:function:true",
            "function:true:function:true:function:true",
            "function:true:function:true:function:true",
        ]
        .join("|")
    );
}

/// Prototype replacement must not depend on whether Array.prototype has
/// already been observed. Non-extensible arrays may keep their actual parent,
/// but cannot replace it with the non-allocating lookup's temporary fallback.
#[test]
fn array_prototype_changes_respect_intrinsic_materialization_and_extensibility() {
    let source = r#"
        const objectPrototype = Object.prototype;
        const locked = Object.preventExtensions([0]);
        const refused = Reflect.setPrototypeOf(locked, objectPrototype);
        let thrown = 'none';
        try { Object.setPrototypeOf(locked, objectPrototype); }
        catch (error) { thrown = error.name; }
        const early = [1];
        const earlyChanged = Reflect.setPrototypeOf(early, objectPrototype);
        const arrayPrototype = Array.prototype;
        const late = [2];
        const lateChanged = Reflect.setPrototypeOf(late, objectPrototype);
        Object.preventExtensions(late);
        [refused, thrown, earlyChanged, lateChanged,
         Object.getPrototypeOf(early) === objectPrototype,
         Object.getPrototypeOf(late) === objectPrototype,
         typeof early[Symbol.iterator], typeof late[Symbol.iterator],
         Object.getPrototypeOf(locked) === arrayPrototype,
         Reflect.setPrototypeOf(locked, arrayPrototype),
         Object.setPrototypeOf(locked, arrayPrototype) === locked,
         Reflect.setPrototypeOf(late, objectPrototype)].join(':');
    "#;
    assert_eq!(
        eval(source),
        "false:TypeError:true:true:true:true:undefined:undefined:true:true:true:true"
    );
}

/// bd-9vouw.306: frozen data properties use SameValue, including Symbol
/// keys, NaN, signed zero and object identity. Configurable or writable
/// properties remain virtualizable, even on a non-extensible target.
#[test]
fn proxy_get_preserves_locked_values_and_allows_legal_virtual_values() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const key = Symbol('locked');
        const item = {};
        const target = { n: NaN, z: -0, item: item };
        target[key] = 7;
        Object.freeze(target);
        const wrong = new Proxy(target, { get() { return 9; } });
        const signed = new Proxy(target, { get() { return 0; } });
        const correct = new Proxy(target, { get(t, k) { return t[k]; } });
        const movable = { x: 1 };
        Object.preventExtensions(movable);
        const virtual = new Proxy(movable, { get() { return 11; } });
        const writable = {};
        Object.defineProperty(writable, 'x', { value: 1, writable: true });
        const writableProxy = new Proxy(writable, { get() { return 12; } });
        [attempt(() => wrong[key]), attempt(() => wrong.item), attempt(() => signed.z),
         Object.is(correct.n, NaN), Object.is(correct.z, -0), correct.item === item,
         correct[key], virtual.x, writableProxy.x].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError true true true 7 11 12"
    );
}

#[test]
fn proxy_get_and_set_enforce_accessor_endpoint_invariants_without_calling_them() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const key = Symbol('accessor');
        let calls = 0;
        const target = {};
        Object.defineProperty(target, 'noGetter', { set(v) { calls++; } });
        Object.defineProperty(target, key, { get() { calls++; return 3; } });
        const present = new Proxy(target, { get() { return 8; }, set() { return true; } });
        const absent = new Proxy(target, { get() { return undefined; } });
        const configurable = {};
        Object.defineProperty(configurable, 'x', { get: undefined, set: undefined, configurable: true });
        const virtual = new Proxy(configurable, { get() { return 5; }, set() { return true; } });
        [attempt(() => present.noGetter), absent.noGetter, present[key],
         attempt(() => Reflect.set(present, key, 4)), Reflect.set(present, 'noGetter', 4),
         virtual.x, Reflect.set(virtual, 'x', 4), calls].join(' ');
    "#;
    assert_eq!(eval(source), "TypeError  8 TypeError true 5 true 0");
}

#[test]
fn proxy_set_preserves_locked_data_and_keeps_false_results_as_refusals() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const key = Symbol('locked');
        const item = {};
        const target = { n: NaN, z: -0, item: item };
        target[key] = 7;
        Object.freeze(target);
        const accepts = new Proxy(target, { set() { return true; } });
        const refuses = new Proxy(target, { set() { return false; } });
        const movable = { x: 1 };
        Object.preventExtensions(movable);
        const virtual = new Proxy(movable, { set() { return true; } });
        [attempt(() => Reflect.set(accepts, key, 8)), attempt(() => Reflect.set(accepts, 'z', 0)),
         attempt(() => Reflect.set(accepts, 'item', {})), Reflect.set(accepts, key, 7),
         Reflect.set(accepts, 'n', NaN), Reflect.set(accepts, 'z', -0),
         Reflect.set(accepts, 'item', item), Reflect.set(refuses, key, 8),
         Reflect.set(virtual, 'x', 2), Reflect.set(virtual, 'newKey', 3), movable.x].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError true true true true false true true 1"
    );
}

#[test]
fn proxy_has_and_delete_preserve_nonconfigurable_and_nonextensible_own_properties() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const key = Symbol('locked');
        const fixed = {};
        Object.defineProperty(fixed, key, { value: 1 });
        const closed = { x: 1 };
        Object.preventExtensions(closed);
        const inherited = Object.create({ x: 1 });
        Object.preventExtensions(inherited);
        function hide(t) { return new Proxy(t, { has() { return false; }, deleteProperty() { return true; } }); }
        const p = hide(fixed), q = hide(closed), r = hide({ x: 1 }), s = hide(inherited);
        [attempt(() => key in p), attempt(() => Reflect.deleteProperty(p, key)),
         attempt(() => Reflect.has(q, 'x')), attempt(() => delete q.x),
         Reflect.has(r, 'x'), Reflect.deleteProperty(r, 'x'),
         Reflect.has(s, 'x'), Reflect.deleteProperty(s, 'x'),
         Reflect.has(q, 'absent'), Reflect.deleteProperty(q, 'absent')].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError TypeError false true false true false true"
    );
}

#[test]
fn proxy_own_keys_preserves_locked_keys_and_closed_target_key_sets() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const key = Symbol('locked');
        const twin = Symbol('locked');
        const target = { open: 1 };
        Object.defineProperty(target, key, { value: 2 });
        function keys(t, list) { return Reflect.ownKeys(new Proxy(t, { ownKeys() { return list; } })); }
        const configurable = { a: 1, b: 2 };
        Object.preventExtensions(configurable);
        [attempt(() => keys(target, ['open'])), attempt(() => keys(target, ['open', twin])),
         keys(target, [key, 'virtual']).map(String).join(','),
         attempt(() => keys(configurable, ['a'])), attempt(() => keys(configurable, ['a', 'b', 'extra'])),
         keys(configurable, ['b', 'a']).join(','),
         attempt(() => keys(Object.freeze([1]), ['0'])),
         keys(Object.preventExtensions({}), []).length].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "TypeError TypeError Symbol(locked),virtual TypeError TypeError b,a TypeError 0"
    );
}

#[test]
fn proxy_invariants_use_the_target_state_after_the_trap_and_list_conversion() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const read = new Proxy({ x: 1 }, { get(t, k) { Object.freeze(t); return 2; } });
        const write = new Proxy({ x: 1 }, { set(t, k, v) { Object.freeze(t); return true; } });
        const readOk = new Proxy({ x: 1 }, { get(t, k) { t[k] = 2; Object.freeze(t); return 2; } });
        const writeOk = new Proxy({ x: 1 }, { set(t, k, v) { t[k] = v; Object.freeze(t); return true; } });
        const gone = new Proxy({ x: 1 }, { deleteProperty(t, k) { delete t[k]; Object.preventExtensions(t); return true; } });
        const hidden = new Proxy({ x: 1 }, { has(t, k) { delete t[k]; Object.preventExtensions(t); return false; } });
        const listedTarget = {};
        const listed = new Proxy(listedTarget, { ownKeys() {
            return { get length() { Object.defineProperty(listedTarget, 'late', { value: 1 }); return 0; } };
        } });
        [attempt(() => read.x), attempt(() => Reflect.set(write, 'x', 2)), readOk.x,
         Reflect.set(writeOk, 'x', 2), Reflect.deleteProperty(gone, 'x'),
         Reflect.has(hidden, 'x'), attempt(() => Reflect.ownKeys(listed))].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "TypeError TypeError 2 true true false TypeError"
    );
}

#[test]
fn proxy_own_keys_finishes_ordered_descriptor_queries_before_reporting_missing_keys() {
    let source = r#"
        const log = [];
        const marker = {};
        const base = { later: 2 };
        Object.defineProperty(base, 'locked', { value: 1 });
        const target = new Proxy(base, {
            isExtensible(t) { log.push('extensible'); return Reflect.isExtensible(t); },
            ownKeys(t) { log.push('keys'); return ['locked', 'later']; },
            getOwnPropertyDescriptor(t, k) {
                log.push('desc:' + k);
                if (k === 'later') throw marker;
                return Reflect.getOwnPropertyDescriptor(t, k);
            }
        });
        const outer = new Proxy(target, { ownKeys() {
            log.push('trap');
            return { get length() { log.push('length'); return 1; }, get 0() { log.push('item'); return 'extra'; } };
        } });
        let exact = false;
        try { Reflect.ownKeys(outer); } catch (e) { exact = e === marker; }
        [exact, log.join('|')].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "true trap|length|item|extensible|keys|desc:locked|desc:later"
    );
}

#[test]
fn proxy_invariant_short_circuits_do_not_invoke_unneeded_target_traps() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const log = [];
        const target = new Proxy({}, {
            getOwnPropertyDescriptor() { log.push('descriptor'); throw 1; },
            isExtensible() { log.push('extensible'); throw 2; }
        });
        const p = new Proxy(target, {
            set() { log.push('set'); return false; },
            has() { log.push('has'); return true; },
            deleteProperty() { log.push('delete'); return false; },
            ownKeys() { log.push('keys'); return ['x', 'x']; }
        });
        [Reflect.set(p, 'x', 1), Reflect.has(p, 'x'), Reflect.deleteProperty(p, 'x'),
         attempt(() => Reflect.ownKeys(p)), log.join('|')].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "false true false TypeError set|has|delete|keys"
    );
}

#[test]
fn proxy_invariants_apply_to_nested_callable_targets_and_symbol_keys() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const key = Symbol('callable');
        function target() { return 5; }
        Object.defineProperty(target, key, { value: 7 });
        const inner = new Proxy(target, {});
        const wrong = new Proxy(inner, {
            get() { return 8; }, set() { return true; }, has() { return false; },
            deleteProperty() { return true; }, ownKeys() { return []; }
        });
        const correct = new Proxy(inner, {
            get(t, k) { return Reflect.get(t, k); }, set() { return true; },
            has(t, k) { return Reflect.has(t, k); }, ownKeys(t) { return Reflect.ownKeys(t); }
        });
        [attempt(() => wrong[key]), attempt(() => Reflect.set(wrong, key, 8)),
         attempt(() => Reflect.has(wrong, key)), attempt(() => Reflect.deleteProperty(wrong, key)),
         attempt(() => Reflect.ownKeys(wrong)), correct[key], correct(),
         Reflect.set(correct, key, 7), Reflect.has(correct, key),
         Reflect.ownKeys(correct).includes(key)].join(' ');
    "#;
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError TypeError TypeError 7 5 true true true"
    );
}

#[test]
fn proxy_invariant_internal_descriptors_ignore_inherited_descriptor_fields() {
    let source = r#"
        const target = Object.freeze({ x: 1 });
        const p = new Proxy(target, { get(t, k) { return t[k]; } });
        let calls = 0;
        Object.defineProperty(Object.prototype, 'get', { get() { calls++; throw 9; }, configurable: true });
        const value = p.x;
        const descriptor = Object.getOwnPropertyDescriptor(new Proxy(target, {}), 'x');
        delete Object.prototype.get;
        [value, descriptor.value, calls].join(' ');
    "#;
    assert_eq!(eval(source), "1 1 0");
}

#[test]
fn with_binding_lookup_preserves_proxy_has_invariants() {
    let source = r#"
        const locked = Object.freeze({ x: 1 });
        const closed = Object.preventExtensions({ x: 1 });
        const first = new Proxy(locked, { has() { return false; } });
        const second = new Proxy(closed, { has() { return false; } });
        let a = '', b = '';
        try { with (first) { x; } } catch (e) { a = e.name; }
        try { with (second) { x; } } catch (e) { b = e.name; }
        [a, b].join(' ');
    "#;
    assert_eq!(eval(source), "TypeError TypeError");
}

/// Invariant checks inspect internal descriptors; they must not consume a
/// guest heap object on every property read. Exercise the full source pipeline
/// on both native profiles with their ordinary budgets and memory oracle.
#[test]
fn repeated_proxy_reads_do_not_allocate_internal_descriptor_objects() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"
        const target = Object.freeze({ value: 7 });
        const proxy = new Proxy(target, { get(t, key) { return t[key]; } });
        let sum = 0;
        for (let i = 0; i < 1000; i++) { sum += proxy.value; }
        sum === 7000;
    "#;
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "proxy-allocation.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("proxy allocation source must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "proxy-allocation.js"),
        &LoweringContext::new("proxy-trace", "proxy-decision", "proxy-policy"),
    )
    .expect("proxy allocation source must lower")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "proxy-allocation");
        let result = core.execute(&module).expect("proxy reads must execute");
        assert_eq!(result.value, Value::Bool(true));
        assert!(
            core.heap_size() <= 256,
            "1,000 proxy reads must not allocate 1,000 descriptor objects: {} allocations",
            core.heap_size()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "internal descriptors must preserve memory accounting"
        );
    }
}

/// A constant public trap result still reveals whether it equals a locked
/// target value. Both the successful read and a caught invariant failure must
/// retain that property's label, including through a pre-existing public alias.
#[test]
fn proxy_get_invariant_observations_label_success_and_caught_errors() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{
        CapabilityTag, Ir0Module, Ir3FunctionDesc, Ir3Instruction, RegRange,
    };
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "proxy-invariant-labels.js".into(),
                text: "0;".into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .unwrap();
    let template = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "proxy-invariant-labels.js"),
        &LoweringContext::new("proxy-trace", "proxy-decision", "proxy-policy"),
    )
    .unwrap()
    .ir3;
    for reflect in [false, true] {
        for (property_label, key_label) in [
            (Label::Public, Label::Public),
            (Label::Secret, Label::Public),
            (Label::Public, Label::Secret),
        ] {
            for guess in [7, 8] {
                for mut config in [
                    InterpreterConfig::quickjs_defaults(),
                    InterpreterConfig::v8_defaults(),
                ] {
                    config.granted_capabilities = [
                        RuntimeCapability::VmDispatch,
                        RuntimeCapability::HeapAllocate,
                        RuntimeCapability::Builtin,
                    ]
                    .into_iter()
                    .collect();
                    let mut core = InterpreterCore::new(config, "proxy-invariant-labels");
                    let target = core.alloc_object_with_prototype(None).unwrap();
                    let handler = core.alloc_object_with_prototype(None).unwrap();
                    core.set_object_property(handler, "get".into(), Value::Function(0))
                        .unwrap();
                    for (register, value) in [
                        (0, Value::Object(target)),
                        (1, Value::Object(handler)),
                        (2, Value::Int(7)),
                        (3, Value::str("value")),
                        (6, Value::str("value")),
                        (9, Value::str("name")),
                    ] {
                        core.seed_register(register, value).unwrap();
                    }
                    core.set_register_label(2, property_label.clone()).unwrap();
                    core.set_register_label(6, key_label.clone()).unwrap();
                    let mut module = template.clone();
                    module.instructions = vec![
                        Ir3Instruction::HostCall {
                            capability: CapabilityTag("builtin:Proxy".into()),
                            args: RegRange { start: 0, count: 2 },
                            dst: 5,
                        },
                        Ir3Instruction::SetProperty {
                            obj: 0,
                            key: 3,
                            val: 2,
                        },
                        Ir3Instruction::HostCall {
                            capability: CapabilityTag("builtin:ObjectFreeze".into()),
                            args: RegRange { start: 0, count: 1 },
                            dst: 4,
                        },
                        Ir3Instruction::BeginTry {
                            catch_target: 7,
                            finally_target: None,
                        },
                        if reflect {
                            Ir3Instruction::HostCall {
                                capability: CapabilityTag("builtin:ReflectGet".into()),
                                args: RegRange { start: 5, count: 2 },
                                dst: 8,
                            }
                        } else {
                            Ir3Instruction::GetProperty {
                                obj: 5,
                                key: 6,
                                dst: 8,
                            }
                        },
                        Ir3Instruction::EndTry,
                        Ir3Instruction::Return { value: 8 },
                        Ir3Instruction::EnterCatch { dst: 8 },
                        Ir3Instruction::GetProperty {
                            obj: 8,
                            key: 9,
                            dst: 10,
                        },
                        Ir3Instruction::Return { value: 10 },
                        Ir3Instruction::LoadInt {
                            dst: 0,
                            value: guess,
                        },
                        Ir3Instruction::Return { value: 0 },
                    ];
                    module.function_table = vec![Ir3FunctionDesc {
                        entry: 10,
                        arity: 0,
                        frame_size: 1,
                        name: Some("public_guess".into()),
                        is_generator: false,
                        rest_param_index: None,
                    }];
                    let result = core.execute(&module).unwrap();
                    let expected = if guess == 7 {
                        Value::Int(7)
                    } else {
                        Value::str("TypeError")
                    };
                    assert_eq!(result.value, expected, "reflect={reflect}, guess={guess}");
                    assert_eq!(
                        result.completion_label,
                        property_label.join(&key_label),
                        "reflect={reflect}, guess={guess}, property_label={property_label:?}, key_label={key_label:?}"
                    );
                    assert_eq!(core.get_register_label(5).unwrap(), &Label::Public);
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes()
                    );
                }
            }
        }
    }
}

/// bd-9vouw.147: `Object.defineProperties`, `Object.create`'s second argument,
/// and `Object.getOwnPropertyDescriptors` route through Proxy `ownKeys`,
/// `getOwnPropertyDescriptor`, `get`, and `defineProperty` traps in ES2020
/// 19.1.2.3.1 / 19.1.2.9 order, including Symbol keys, revoked proxies, and
/// non-enumerable filtering. Expected strings match Node v22.
#[test]
fn proxy_define_properties_create_and_get_own_property_descriptors() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
        const log = [];
        const sym = Symbol('s');
        const target = {};
        const targetProxy = new Proxy(target, {
            defineProperty(t, k, d) {
                log.push('def:' + String(k) + ':' + JSON.stringify(d));
                return Reflect.defineProperty(t, k, d);
            }
        });
        const propsSource = { a: { value: 1, enumerable: true }, [sym]: { value: 2, enumerable: true } };
        Object.defineProperty(propsSource, 'hidden', { value: { value: 3 }, enumerable: false });
        const propsProxy = new Proxy(propsSource, {
            ownKeys(t) { log.push('ownKeys'); return Reflect.ownKeys(t); },
            getOwnPropertyDescriptor(t, k) { log.push('gopd:' + String(k)); return Reflect.getOwnPropertyDescriptor(t, k); },
            get(t, k, r) { log.push('get:' + String(k)); return Reflect.get(t, k, r); }
        });
        const dpResult = Object.defineProperties(targetProxy, propsProxy);
        const dpTrace = [dpResult === targetProxy, target.a, target[sym], 'hidden' in target, log.join('|')].join(' ');

        log.length = 0;
        const created = Object.create(null, propsProxy);
        const createTrace = [String(Object.getPrototypeOf(created)), created.a, created[sym], 'hidden' in created, log.join('|')].join(' ');

        log.length = 0;
        const descs = Object.getOwnPropertyDescriptors(propsProxy);
        const gopdsTrace = [descs.a.value.value, descs[sym].value.value, descs.hidden.enumerable, log.join('|')].join(' ');

        const rev = Proxy.revocable({}, {});
        rev.revoke();
        const refusedProxy = new Proxy({}, { defineProperty() { return false; } });
        const arrDefined = Object.defineProperties({}, [{ value: 42, enumerable: true }]);
        const fnProps = function () {};
        fnProps.x = { value: 9, enumerable: true };
        const fnDefined = Object.defineProperties({}, fnProps);
        const edges = [
            Object.defineProperties(rev.proxy, {}) === rev.proxy,
            attempt(() => Object.defineProperties(rev.proxy, { x: { value: 1 } })),
            attempt(() => Object.defineProperties({}, rev.proxy)),
            attempt(() => Object.defineProperties(refusedProxy, { k: { value: 1 } })),
            arrDefined[0],
            fnDefined.x,
        ].join(' ');

        [dpTrace, createTrace, gopdsTrace, edges].join('\n');
    "#;
    let expected = [
        "true 1 2 false ownKeys|gopd:a|get:a|gopd:hidden|gopd:Symbol(s)|get:Symbol(s)|def:a:{\"value\":1,\"enumerable\":true}|def:Symbol(s):{\"value\":2,\"enumerable\":true}",
        "null 1 2 false ownKeys|gopd:a|get:a|gopd:hidden|gopd:Symbol(s)|get:Symbol(s)",
        "1 2 false ownKeys|gopd:a|gopd:hidden|gopd:Symbol(s)",
        "true TypeError TypeError TypeError 42 9",
    ]
    .join("\n");
    assert_eq!(eval(source), expected);
}

/// ArraySetLength belongs to the actual array's [[DefineOwnProperty]], so
/// transparent proxies and every caller of [[Set]] observe the same two
/// numeric conversions. A public Object.defineProperty-only conversion misses
/// both proxy forwarding and Reflect/Object.assign writes.
#[test]
fn array_length_coercion_reaches_the_array_through_every_property_entry() {
    let source = r#"
        const out = [];
        const calls = [];
        function run(name, write) {
            const target = [0, 1, 2, 3];
            const proxy = new Proxy(new Proxy(target, {}), {});
            const length = { [Symbol.toPrimitive](hint) { calls.push(name + ':' + hint); return 2; } };
            write(proxy, length);
            out.push(target.length + ':' + target.join());
        }
        run('define', (p, n) => Object.defineProperty(p, 'length', { value: n }));
        run('reflectDefine', (p, n) => Reflect.defineProperty(p, 'length', { value: n }));
        run('defineMany', (p, n) => Object.defineProperties(p, { length: { value: n } }));
        run('assign', (p, n) => { p.length = n; });
        run('reflectSet', (p, n) => Reflect.set(p, 'length', n));
        run('objectAssign', (p, n) => Object.assign(p, { length: n }));
        const bare = [0, 1, 2];
        Reflect.set(bare, 'length', { valueOf() { calls.push('bare'); return 1; } });
        out.push(bare.length + ':' + bare.join());
        out.join('|') + ';' + calls.join(',');
    "#;
    assert_eq!(
        eval(source),
        "2:0,1|2:0,1|2:0,1|2:0,1|2:0,1|2:0,1|1:0;\
         define:number,define:number,reflectDefine:number,reflectDefine:number,\
         defineMany:number,defineMany:number,assign:number,assign:number,\
         reflectSet:number,reflectSet:number,objectAssign:number,objectAssign:number,bare,bare"
    );
}

#[test]
fn array_length_traps_receive_the_original_value_before_any_coercion() {
    let source = r#"
        const log = [];
        const target = [0, 1, 2];
        const value = { valueOf() { log.push('number'); return 1; } };
        const intercepted = new Proxy(target, {
            defineProperty(t, k, d) { log.push('trap:' + (d.value === value)); return true; }
        });
        Object.defineProperty(intercepted, 'length', { value });
        log.push('length:' + target.length);
        const forwarded = new Proxy(target, {
            defineProperty(t, k, d) {
                log.push('forward:' + (d.value === value));
                return Reflect.defineProperty(t, k, d);
            }
        });
        Object.defineProperties(forwarded, { length: { value } });
        log.push('length:' + target.length);
        const receiver = {};
        Reflect.set(target, 'length', value, receiver);
        log.push('receiver:' + (receiver.length === value));
        const setter = { set length(v) { log.push('setter:' + (v === value)); } };
        Reflect.set(setter, 'length', value);
        log.join(',');
    "#;
    assert_eq!(
        eval(source),
        "trap:true,length:3,forward:true,number,number,length:1,receiver:true,setter:true"
    );
}

#[test]
fn array_length_definition_rechecks_attributes_after_reentrant_coercion() {
    let source = r#"
        const out = [];
        function run(proxy) {
            const target = [0, 1, 2];
            const receiver = proxy ? new Proxy(target, {}) : target;
            let calls = 0;
            const value = { valueOf() {
                calls++;
                if (calls === 1) Object.defineProperty(target, 'length', { writable: false });
                return 1;
            } };
            out.push(Reflect.set(receiver, 'length', value), calls, target.length);
        }
        run(false);
        run(true);
        const receiver = [0, 1, 2];
        let calls = 0;
        out.push(Reflect.set({ length: 0 }, 'length', {
            valueOf() { calls++; return 1; }
        }, receiver), calls, receiver.length);
        out.join('|');
    "#;
    assert_eq!(eval(source), "false|2|3|false|2|3|true|2|1");
}

#[test]
fn array_length_forwarding_keeps_abrupt_completions_and_integrity_rules() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (error) { return error.name || error; } }
        const out = [];
        const frozen = Object.freeze([0, 1, 2]);
        const frozenProxy = new Proxy(frozen, {});
        let calls = 0;
        const length = { valueOf() { calls++; return 1; } };
        out.push(Reflect.set(frozenProxy, 'length', length), calls);
        out.push(Reflect.defineProperty(frozenProxy, 'length', { value: length }), calls);
        out.push(attempt(() => Object.defineProperty(frozenProxy, 'length', { value: length })), calls);
        const target = [0, 1, 2];
        const proxy = new Proxy(target, {});
        let flip = 0;
        out.push(attempt(() => Reflect.defineProperty(proxy, 'length', {
            value: { valueOf() { return ++flip; } }
        })), flip, target.length);
        out.push(attempt(() => Reflect.set(proxy, 'length', {
            valueOf() { throw 'original'; }
        })), target.length);
        out.push(attempt(() => Reflect.defineProperty(proxy, 'length', { value: Symbol() })),
                 attempt(() => Reflect.defineProperty(proxy, 'length', { value: 1n })));
        Object.defineProperty(target, '1', { configurable: false });
        out.push(Reflect.defineProperty(proxy, 'length', {
            value: { valueOf() { return 0; } }, writable: false
        }), target.length, 2 in target, Object.getOwnPropertyDescriptor(target, 'length').writable);
        out.join('|');
    "#;
    assert_eq!(
        eval(source),
        "false|0|false|2|TypeError|4|RangeError|2|3|original|3|TypeError|TypeError|false|2|false|false"
    );
}

/// ToPropertyDescriptor accepts every ECMAScript object, including carriers
/// with native internal slots; a getOwnPropertyDescriptor trap has that same
/// object-type boundary before descriptor completion and invariant checks.
#[test]
fn exotic_objects_are_valid_descriptors_and_proxy_descriptor_results() {
    let source = r#"
        function* generate() { yield 1; }
        async function* generateAsync() { yield 1; }
        const descriptors = [Promise.resolve(0), generate(), [1].values(), generateAsync(), function () {}];
        const out = [];
        let index = 0;
        for (const descriptor of descriptors) {
            descriptor.value = ++index;
            descriptor.enumerable = true;
            descriptor.configurable = true;
            const direct = {};
            Object.defineProperty(direct, 'x', descriptor);
            const reflected = {};
            const accepted = Reflect.defineProperty(reflected, 'x', descriptor);
            const many = Object.defineProperties({}, { x: descriptor });
            const created = Object.create(null, { x: descriptor });
            const proxy = new Proxy({}, { getOwnPropertyDescriptor() { return descriptor; } });
            const reported = Object.getOwnPropertyDescriptor(proxy, 'x');
            out.push([direct.x, reflected.x, many.x, created.x, reported.value,
                      reported.writable, reported.enumerable, accepted].join(':'));
        }
        out.join('|');
    "#;
    assert_eq!(
        eval(source),
        "1:1:1:1:1:false:true:true|2:2:2:2:2:false:true:true|3:3:3:3:3:false:true:true|\
         4:4:4:4:4:false:true:true|5:5:5:5:5:false:true:true"
    );
}

#[test]
fn exotic_descriptor_fields_use_has_then_get_with_the_original_receiver() {
    let source = r#"
        const log = [];
        const descriptor = Promise.resolve(0);
        const fields = {
            get enumerable() { log.push('enumerable:' + (this === descriptor)); return true; },
            get configurable() { log.push('configurable:' + (this === descriptor)); return true; },
            get value() { log.push('value:' + (this === descriptor)); return 9; },
            get writable() { log.push('writable:' + (this === descriptor)); return false; }
        };
        Object.setPrototypeOf(descriptor, new Proxy(fields, {
            has(t, k) { log.push('has:' + k); return Reflect.has(t, k); }
        }));
        const target = Object.create(null, { x: descriptor });
        const trace = log.join(',');
        const mixed = [1].values();
        mixed.value = 1;
        mixed.get = function () { return 2; };
        let invalid = '';
        try { Object.defineProperty({}, 'x', mixed); } catch (error) { invalid = error.name; }
        const locked = Object.freeze({ x: 1 });
        const fake = Promise.resolve(0);
        fake.value = 2;
        let invariant = '';
        try { Object.getOwnPropertyDescriptor(new Proxy(locked, {
            getOwnPropertyDescriptor() { return fake; }
        }), 'x'); } catch (error) { invariant = error.name; }
        target.x + ';' + trace + ';' + invalid + ';' + invariant;
    "#;
    assert_eq!(
        eval(source),
        "9;has:enumerable,enumerable:true,has:configurable,configurable:true,\
         has:value,value:true,has:writable,writable:true,has:get,has:set;TypeError;TypeError"
    );
}

#[test]
fn descriptor_entry_points_preserve_omitted_keys_and_conversion_order() {
    let source = r#"
        function attempt(f) { try { return String(f()); } catch (error) { return error.name; } }
        const target = { undefined: 7 };
        const log = [];
        const key = { toString() { log.push('key'); return 'x'; } };
        const invalidDescriptor = attempt(() => Reflect.defineProperty({}, key, 1));
        const invalidTarget = attempt(() => Reflect.defineProperty(null, key, {}));
        [Object.getOwnPropertyDescriptor(target).value,
         Reflect.getOwnPropertyDescriptor(target).value,
         attempt(() => Object.getOwnPropertyDescriptor()),
         attempt(() => Object.getOwnPropertyDescriptor(null)),
         invalidDescriptor, invalidTarget, log.join(',')].join('|');
    "#;
    assert_eq!(eval(source), "7|7|TypeError|TypeError|TypeError|TypeError|key");
}
