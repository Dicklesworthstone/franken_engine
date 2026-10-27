//! bd-9vouw.347: Object.getOwnPropertyDescriptors applies ToObject and
//! reads [[OwnPropertyKeys]] and each key's [[GetOwnProperty]] (ES2020
//! 19.1.2.9), so a Proxy's ownKeys and getOwnPropertyDescriptor traps run
//! in key order and the `Object.create(proto,
//! Object.getOwnPropertyDescriptors(p))` clone keeps a proxied object's
//! properties; it gave {} for a Proxy and refused primitives. Object.entries
//! and Object.values of a Proxy read each key's descriptor and then its
//! value before the next key (7.3.22); they read every descriptor first.
//! Node v22.2.0 gives this line.

use frankenengine_engine::{
    HybridRouter, JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine,
};

// Each consumer must use the same checked [[GetOwnProperty]] operation.
const ENUMERATION_CONSUMERS: [(&str, &str, &str); 7] = [
    ("JSON.stringify(Object.keys(proxy))", r#"["x"]"#, "[]"),
    ("JSON.stringify(Object.values(proxy))", "[7]", "[]"),
    (
        "JSON.stringify(Object.entries(proxy))",
        r#"[["x",7]]"#,
        "[]",
    ),
    ("JSON.stringify(proxy)", r#"{"x":7}"#, "{}"),
    (
        "JSON.stringify(Object.assign({}, proxy))",
        r#"{"x":7}"#,
        "{}",
    ),
    ("JSON.stringify({...proxy})", r#"{"x":7}"#, "{}"),
    (
        "(function () { var keys = []; for (var key in proxy) keys.push(key); return keys.join(','); })()",
        "x",
        "",
    ),
];

fn assert_native_enumeration(source: &str, expected: &str) {
    // These public engines are both Rust-native execution profiles. Retain
    // their ordinary containment budgets, including the smaller baseline one.
    for (profile, outcome) in [
        ("baseline", QuickJsInspiredNativeEngine.eval(source)),
        ("adaptive", V8InspiredNativeEngine.eval(source)),
    ] {
        let outcome =
            outcome.unwrap_or_else(|error| panic!("{profile} failed: {error}\nsource: {source}"));
        assert_eq!(outcome.value, expected, "{profile}\nsource: {source}");
    }
}

#[test]
fn enumeration_rejects_invalid_proxy_descriptors() {
    let cases = [
        r#"var target = Object.freeze({x: 1});
var proxy = new Proxy(target, {getOwnPropertyDescriptor() {return undefined;}});"#,
        r#"var target = Object.freeze({x: 1});
var proxy = new Proxy(target, {getOwnPropertyDescriptor() {
  return {value: 1, writable: false, enumerable: false, configurable: false};
}});"#,
        r#"var target = Object.preventExtensions({x: 1});
var proxy = new Proxy(target, {getOwnPropertyDescriptor() {return undefined;}});"#,
        r#"var proxy = new Proxy({}, {
  ownKeys() {return ['x'];},
  getOwnPropertyDescriptor() {return {enumerable: true, configurable: false};}
});"#,
        r#"var proxy = new Proxy({x: 1}, {getOwnPropertyDescriptor() {
  return {value: 1, get() {return 1;}, enumerable: true, configurable: true};
}});"#,
        r#"var proxy = new Proxy({x: 1}, {getOwnPropertyDescriptor() {
  return {get: 1, enumerable: true, configurable: true};
}});"#,
        r#"var target = Object.freeze({x: 1});
var inner = new Proxy(target, {getOwnPropertyDescriptor() {return undefined;}});
var proxy = new Proxy(inner, {});"#,
        r#"var target = {};
Object.defineProperty(target, 'x', {value: 1, writable: true, enumerable: true});
var proxy = new Proxy(target, {getOwnPropertyDescriptor() {
  return {value: 1, enumerable: true};
}});"#,
        r#"var target = Object.freeze({x: 1});
var proxy = new Proxy(target, {getOwnPropertyDescriptor() {
  return {writable: false, enumerable: true, configurable: false};
}});"#,
        r#"var target = {};
Object.defineProperty(target, 'x', {get() {return 1;}, enumerable: true});
var proxy = new Proxy(target, {getOwnPropertyDescriptor() {
  return {enumerable: true, configurable: false};
}});"#,
        r#"function descriptor() {}
descriptor.get = 1; descriptor.enumerable = true; descriptor.configurable = true;
var proxy = new Proxy({x: 7}, {getOwnPropertyDescriptor() {return descriptor;}});"#,
    ];
    for setup in cases {
        for operation in ENUMERATION_CONSUMERS
            .into_iter()
            .map(|(operation, _, _)| operation)
            .chain([
                "Object.getOwnPropertyDescriptor(proxy, 'x')",
                "Reflect.getOwnPropertyDescriptor(proxy, 'x')",
            ])
        {
            let source = format!(
                "{setup}\nvar result;\ntry {{ {operation}; result = 'accepted'; }} \
                 catch (error) {{ result = error.name; }}\nresult;"
            );
            assert_native_enumeration(&source, "TypeError");
        }
    }
}

#[test]
fn enumeration_preserves_legal_virtual_forwarded_and_missing_properties() {
    for (operation, present, missing) in ENUMERATION_CONSUMERS {
        for setup in [
            r#"var proxy = new Proxy({}, {
  ownKeys() {return ['x'];},
  getOwnPropertyDescriptor() {return {value: 99, enumerable: true, configurable: true};},
  get() {return 7;}
});"#,
            r#"var target = Object.freeze({x: 7});
var proxy = new Proxy(new Proxy(target, {}), {});"#,
            r#"function descriptor() {}
descriptor.value = 99; descriptor.enumerable = true; descriptor.configurable = true;
var proxy = new Proxy({x: 7}, {getOwnPropertyDescriptor() {return descriptor;}});"#,
        ] {
            assert_native_enumeration(&format!("{setup}\n{operation};"), present);
        }
        let callable = "function target() {} target.x = 7; \
                        var proxy = new Proxy(target, {});";
        let callable_result = if operation == "JSON.stringify(proxy)" {
            "undefined" // A callable itself is omitted by JSON serialization.
        } else {
            present
        };
        assert_native_enumeration(&format!("{callable}\n{operation};"), callable_result);
        for setup in [
            r#"var proxy = new Proxy({x: 7}, {getOwnPropertyDescriptor() {return undefined;}});"#,
            r#"var proxy = new Proxy({x: 7}, {getOwnPropertyDescriptor() {
  return {value: 99, enumerable: false, configurable: true};
}});"#,
        ] {
            assert_native_enumeration(&format!("{setup}\n{operation};"), missing);
        }
    }
}

#[test]
fn enumeration_reads_the_whole_descriptor_before_the_property_value() {
    let setup = r#"var log = [];
var fields = {enumerable: true, configurable: true, value: 9};
var proxy = new Proxy({x: 7}, {
  ownKeys() {log.push('ownKeys'); return ['x'];},
  getOwnPropertyDescriptor() {
    log.push('descriptor');
    return new Proxy(fields, {
      has(t, k) {log.push('has:' + k); return k in t;},
      get(t, k) {log.push('read:' + k); return t[k];}
    });
  },
  get(t, k) {log.push('value:' + k); return t[k];}
});"#;
    let descriptor_reads = "ownKeys|descriptor|has:enumerable|read:enumerable|\
                            has:configurable|read:configurable|has:value|read:value|\
                            has:writable|has:get|has:set";
    for (operation, result, value_read) in [
        ("Object.keys(proxy)", r#"["x"]"#, ""),
        ("Object.values(proxy)", "[7]", "|value:x"),
    ] {
        let source = format!(
            "{setup}\nvar result = {operation};\n\
             [JSON.stringify(result), log.join('|')].join(' ');"
        );
        assert_native_enumeration(&source, &format!("{result} {descriptor_reads}{value_read}"));
    }
}

#[test]
fn enumeration_propagates_descriptor_getter_failure_before_reading_a_value() {
    let setup = r#"var failure = {};
var reads = 0;
var proxy = new Proxy({x: 7}, {
  getOwnPropertyDescriptor() {
    return {enumerable: true, configurable: true, get value() {throw failure;}};
  },
  get(t, k) {if (k === 'x') reads++; return t[k];}
});"#;
    for (operation, _, _) in ENUMERATION_CONSUMERS {
        let source = format!(
            "{setup}\nvar result = 'missed';\ntry {{ {operation}; }} \
             catch (error) {{ result = error === failure ? 'same' : 'wrong'; }}\n\
             [result, reads].join(':');"
        );
        assert_native_enumeration(&source, "same:0");
    }
}

#[test]
fn enumeration_observes_descriptor_getter_effects_before_value_reads() {
    let setup = r#"var target = {x: 1};
var log = [];
var proxy = new Proxy(target, {
  getOwnPropertyDescriptor() {
    return {
      get enumerable() {log.push('enumerable'); return true;},
      get configurable() {log.push('configurable'); return true;},
      get value() {log.push('value'); target.x = 7; return 99;},
      get writable() {log.push('writable'); return true;}
    };
  },
  get(t, k) {if (k === 'x') log.push('read:x'); return t[k];}
});"#;
    for (index, (operation, present, _)) in ENUMERATION_CONSUMERS.into_iter().enumerate() {
        let source = format!(
            "{setup}\nvar result = {operation};\n\
             [result, target.x, log.join('|')].join('::');"
        );
        let value_read = if (1..=5).contains(&index) {
            "|read:x"
        } else {
            ""
        };
        assert_native_enumeration(
            &source,
            &format!("{present}::7::enumerable|configurable|value|writable{value_read}"),
        );
    }
}

#[test]
fn callable_proxy_enumeration_preserves_target_and_receiver() {
    let source = r#"var out = [];
var log = [];
function target() {} target.x = 7;
var handler = {
  ownKeys(t) {
    if (this !== handler || t !== target) throw new Error('wrong ownKeys target');
    log.push('keys'); return Reflect.ownKeys(t);
  },
  getOwnPropertyDescriptor(t, k) {
    if (this !== handler || t !== target) throw new Error('wrong descriptor target');
    log.push('descriptor:' + String(k)); return Reflect.getOwnPropertyDescriptor(t, k);
  },
  get(t, k, r) {
    if (this !== handler || t !== target || r !== proxy) throw new Error('wrong get receiver');
    log.push('get:' + String(k)); return Reflect.get(t, k, r);
  }
};
var proxy = new Proxy(target, handler);
function record(run) {
  log = [];
  out.push(JSON.stringify(run()), log.indexOf('keys') >= 0,
    log.indexOf('descriptor:x') >= 0, log.indexOf('get:x') >= 0);
}
record(function () {return Object.keys(proxy);});
record(function () {return Object.values(proxy);});
record(function () {return Object.entries(proxy);});
record(function () {return Object.assign({}, proxy);});
out.join(' ');"#;
    assert_native_enumeration(
        source,
        r#"["x"] true true false [7] true true true [["x",7]] true true true {"x":7} true true true"#,
    );
}

#[test]
fn callable_proxy_intrinsic_prototype_descriptors_are_checked() {
    for (source, expected) in [
        (
            r#"var out = []; var keys = 0;
function target() {}
var original = target.prototype;
var proxy = new Proxy(target, {
  ownKeys(t) {keys++; return Reflect.ownKeys(t);},
  getOwnPropertyDescriptor(t, k) {return Reflect.getOwnPropertyDescriptor(t, k);}
});
function record() {
  var d = Object.getOwnPropertyDescriptor(proxy, 'prototype');
  out.push([d.value === original, d.writable, d.enumerable, d.configurable].join(':'));
  out.push(JSON.stringify(Object.keys(proxy)));
}
record(); Object.freeze(target); record(); out.push(keys); out.join('|');"#,
            "true:true:false:false|[]|true:false:false:false|[]|2",
        ),
        (
            r#"var out = [];
function target() {} target.prototype = 7; Object.freeze(target);
for (var guess of [7, 8]) {
  var proxy = new Proxy(target, {
    ownKeys(t) {return Reflect.ownKeys(t);},
    getOwnPropertyDescriptor(t, k) {
      if (k === 'prototype') {
        return {value: guess, writable: false, enumerable: false, configurable: false};
      }
      return Reflect.getOwnPropertyDescriptor(t, k);
    }
  });
  try {Object.keys(proxy); out.push(Object.getOwnPropertyDescriptor(proxy, 'prototype').value);}
  catch (error) {out.push(error.name);}
}
out.join('|');"#,
            "7|TypeError",
        ),
    ] {
        assert_native_enumeration(source, expected);
    }
}

/// A public descriptor guess against a frozen Secret value must retain that
/// provenance both when enumeration succeeds and when its TypeError is caught.
#[test]
fn enumeration_invariant_checks_preserve_labels_and_memory_accounting() {
    assert_descriptor_invariant_labels(false);
}

#[test]
fn callable_prototype_invariants_preserve_labels_and_memory_accounting() {
    assert_descriptor_invariant_labels(true);
}

fn assert_descriptor_invariant_labels(callable_target: bool) {
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
                label: "enumeration-labels.js".into(),
                text: "0;".into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .unwrap();
    let template = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "enumeration-labels.js"),
        &LoweringContext::new(
            "enumeration-trace",
            "enumeration-decision",
            "enumeration-policy",
        ),
    )
    .unwrap()
    .ir3;
    for property_label in [Label::Public, Label::Secret] {
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
                let mut core = InterpreterCore::new(config, "enumeration-labels");
                let target = if callable_target {
                    Value::Function(1)
                } else {
                    Value::Object(core.alloc_object_with_prototype(None).unwrap())
                };
                let handler = core.alloc_object_with_prototype(None).unwrap();
                let descriptor = core.alloc_object_with_prototype(None).unwrap();
                for (name, value) in [
                    ("value", Value::Int(guess)),
                    ("writable", Value::Bool(false)),
                    ("enumerable", Value::Bool(!callable_target)),
                    ("configurable", Value::Bool(false)),
                ] {
                    core.set_object_property(descriptor, name.into(), value)
                        .unwrap();
                }
                core.set_object_property(handler, "0".into(), Value::Object(descriptor))
                    .unwrap();
                core.set_object_property(
                    handler,
                    "getOwnPropertyDescriptor".into(),
                    Value::Function(0),
                )
                .unwrap();
                for (register, value) in [
                    (0, target),
                    (1, Value::Object(handler)),
                    (2, Value::Int(7)),
                    (
                        3,
                        Value::str(if callable_target { "prototype" } else { "x" }),
                    ),
                    (9, Value::str("name")),
                ] {
                    core.seed_register(register, value).unwrap();
                }
                core.set_register_label(2, property_label.clone()).unwrap();
                if callable_target {
                    core.seed_register(6, Value::str("prototype")).unwrap();
                    core.seed_register(7, Value::str("value")).unwrap();
                }
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
                        catch_target: 9,
                        finally_target: None,
                    },
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ObjectKeys".into()),
                        args: RegRange { start: 5, count: 1 },
                        dst: 8,
                    },
                    Ir3Instruction::EndTry,
                    Ir3Instruction::LoadInt { dst: 6, value: 0 },
                    Ir3Instruction::GetProperty {
                        obj: 8,
                        key: 6,
                        dst: 10,
                    },
                    Ir3Instruction::Return { value: 10 },
                    Ir3Instruction::EnterCatch { dst: 8 },
                    Ir3Instruction::GetProperty {
                        obj: 8,
                        key: 9,
                        dst: 10,
                    },
                    Ir3Instruction::Return { value: 10 },
                    // The trap's public descriptor is stored on its receiver.
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::LoadInt { dst: 1, value: 0 },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 2,
                    },
                    Ir3Instruction::Return { value: 2 },
                ];
                module.function_table = vec![Ir3FunctionDesc {
                    entry: 12,
                    arity: 2,
                    frame_size: 3,
                    name: Some("public_descriptor".into()),
                    is_generator: false,
                    rest_param_index: None,
                }];
                if callable_target {
                    module.instructions[4] = Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ObjectGetOwnPropertyDescriptor".into()),
                        args: RegRange { start: 5, count: 2 },
                        dst: 8,
                    };
                    module.instructions[6] = Ir3Instruction::LoadInt { dst: 11, value: 0 };
                    module.instructions[7] = Ir3Instruction::GetProperty {
                        obj: 8,
                        key: 7,
                        dst: 10,
                    };
                    module.function_table.push(Ir3FunctionDesc {
                        entry: 16,
                        arity: 0,
                        frame_size: 1,
                        name: Some("target".into()),
                        is_generator: false,
                        rest_param_index: None,
                    });
                    module.instructions.extend([
                        Ir3Instruction::LoadInt { dst: 0, value: 0 },
                        Ir3Instruction::Return { value: 0 },
                    ]);
                }
                let result = core.execute(&module).unwrap();
                let expected = if guess != 7 {
                    Value::str("TypeError")
                } else if callable_target {
                    Value::Int(7)
                } else {
                    Value::str("x")
                };
                assert_eq!(result.value, expected, "guess={guess}");
                assert_eq!(result.completion_label, property_label, "guess={guess}");
                assert_eq!(core.get_register_label(5).unwrap(), &Label::Public);
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "guess={guess}"
                );
            }
        }
    }
}

#[test]
fn own_property_descriptors_and_entries_follow_proxy_traps() {
    let source = r#"
var out = [];
var log = [];
var target = { a: 1, b: 2 };
Object.defineProperty(target, 'h', { value: 3, enumerable: false });
var proxy = new Proxy(target, {
  ownKeys: function (t) { log.push('ownKeys'); return Reflect.ownKeys(t); },
  getOwnPropertyDescriptor: function (t, k) { log.push('gopd:' + String(k)); return Reflect.getOwnPropertyDescriptor(t, k); },
  get: function (t, k, r) { log.push('get:' + String(k)); return Reflect.get(t, k, r); }
});
var descs = Object.getOwnPropertyDescriptors(proxy);
out.push(log.join('|'), Object.keys(descs).join(','), descs.h.enumerable);
log.length = 0;
out.push(JSON.stringify(Object.entries(proxy)), log.join('|'));
log.length = 0;
out.push(JSON.stringify(Object.values(proxy)), log.join('|'));
out.push(JSON.stringify(Object.getOwnPropertyDescriptors(true)), JSON.stringify(Object.getOwnPropertyDescriptors(3)));
var sd = Object.getOwnPropertyDescriptors('ab');
out.push(Object.keys(sd).join(','), sd[0].value, sd[0].writable, sd.length.value, sd.length.enumerable);
out.push(Object.getOwnPropertySymbols(Object.getOwnPropertyDescriptors(Symbol('s'))).length);
try { Object.getOwnPropertyDescriptors(null); out.push('no'); } catch (e) { out.push(e.constructor.name); }
var clone = Object.create(Object.getPrototypeOf(proxy), Object.getOwnPropertyDescriptors(proxy));
out.push(clone.a + clone.b + clone.h);
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "ownKeys|gopd:a|gopd:b|gopd:h a,b,h false [[\"a\",1],[\"b\",2]] \
             ownKeys|gopd:a|get:a|gopd:b|get:b|gopd:h [1,2] \
             ownKeys|gopd:a|get:a|gopd:b|get:b|gopd:h {} {} 0,1,length a false 2 false 0 TypeError 6"
        ]
    );
}
