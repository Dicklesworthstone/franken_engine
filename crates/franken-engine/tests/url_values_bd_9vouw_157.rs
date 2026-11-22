//! bd-9vouw.157: `URL` and `URLSearchParams` are global constructor values.
//!
//! Both existed only as lowering's rewrite of `new URL(...)` (bd-8y0gs kept
//! them lowering-only on purpose), so a bare reference threw "URL is not
//! defined": superjson's `value instanceof URL`, aliases and subclasses
//! failed. They are now standard constructors that build the same
//! engine-owned objects, instances inherit from URL.prototype /
//! URLSearchParams.prototype, and both prototypes carry Node's
//! @@toStringTag. Expected strings are Node v22.2.0's output for the same
//! programs.
//!
//! URL.prototype.toString and toJSON (the href) are added, so `String(url)`
//! and `JSON.stringify` no longer give "[object Object]" and `{}`.
//!
//! No-claim: `URL(...)` without `new` constructs instead of throwing a
//! TypeError; URL.prototype has no accessors of its own (instances answer
//! href, host, ...); URL.createObjectURL and revokeObjectURL are not covered.
//! bd-9vouw.168: URL arguments and setters now perform observable USVString
//! conversion, including user hooks, exact order and abrupt completions.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

fn lower_source(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "url-conversion.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("URL conversion source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "url-conversion.js"),
        &LoweringContext::new("url-trace", "url-decision", "url-policy"),
    )
    .expect("URL conversion source lowers")
    .ir3
}

fn configure_native(mut config: InterpreterConfig) -> InterpreterConfig {
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    config
}

fn native_result(
    source: &str,
    config: InterpreterConfig,
    stress: Option<u64>,
) -> Result<Value, String> {
    let module = lower_source(source);
    let mut core = InterpreterCore::new(configure_native(config), "url-conversion");
    core.set_gc_stress_interval(stress);
    let outcome = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "URL accounting drift with GC={stress:?}: {source}"
    );
    outcome
        .map(|execution| execution.value)
        .map_err(|error| format!("{error:?}"))
}

fn assert_native_output(source: &str, expected: &str) {
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for stress in [None, Some(1), Some(7)] {
            assert_eq!(
                native_result(source, config.clone(), stress),
                Ok(Value::str(expected)),
                "GC={stress:?}: {source}"
            );
        }
    }
}

/// `URL` and `URLSearchParams` are values: typeof, name, length, the global object's properties.
#[test]
fn url_global_values() {
    let source = "[typeof URL, typeof URLSearchParams, URL.name, URL.length, URLSearchParams.name, URLSearchParams.length,\n\
          globalThis.URL === URL, globalThis.URLSearchParams === URLSearchParams].join(' ');";
    assert_eq!(
        eval(source),
        "function function URL 1 URLSearchParams 0 true true"
    );
}

/// An alias constructs the same objects, which inherit from URL.prototype and carry its tag.
#[test]
fn url_instances_and_aliases() {
    let source = "const U = URL, P = URLSearchParams;\n\
         const u = new U('http://a.example:8080/p/q?x=1&y=2#h');\n\
         const p = new P({ a: '1', b: 'two words' });\n\
         [u.host, u.pathname, u.searchParams.get('y'), u.hash, u instanceof URL, u.searchParams instanceof URLSearchParams,\n\
          Object.getPrototypeOf(u) === URL.prototype, u.constructor === URL, Object.prototype.toString.call(u),\n\
          Object.prototype.toString.call(p), p.toString(), URLSearchParams.prototype.toString.call(p),\n\
          URLSearchParams.prototype.append.length, p instanceof URLSearchParams, new URL('http://x') instanceof URL].join(' ');";
    assert_eq!(
        eval(source),
        "a.example:8080 /p/q 2 #h true true true true [object URL] [object URLSearchParams] a=1&b=two+words a=1&b=two+words 2 true true"
    );
}

/// superjson-style `instanceof URL` checks and destructuring from globalThis.
#[test]
fn url_type_checks() {
    let source = "const { URL: GlobalURL } = globalThis;\n\
         function isURL(value) { return value instanceof URL; }\n\
         [isURL(new GlobalURL('https://b.example/')), isURL({ href: 'https://b.example/' }), isURL('https://b.example/'),\n\
          new URL('../c', 'https://b.example/a/b').href, String(new URL('https://b.example/?q=1')),\n\
          JSON.stringify({ u: new URL('https://b.example/x') })].join(' ');";
    assert_eq!(
        eval(source),
        "true false false https://b.example/c https://b.example/?q=1 {\"u\":\"https://b.example/x\"}"
    );
}

/// URL.canParse and URL.parse: whether the constructor would succeed, and the URL or null.
#[test]
fn url_statics() {
    let source = "[URL.canParse('https://a.example/'), URL.canParse('/x'), URL.canParse('/x', 'https://a.example/c'), URL.parse('nope'),\n\
          URL.parse('/p?q=1', 'https://a.example').href, URL.parse('https://a.example/') instanceof URL, URL.canParse.length,\n\
          URL.parse.name, typeof URL.canParse, URL.canParse(new URL('https://x.example'))].join(' ');";
    assert_eq!(
        eval(source),
        "true false true  https://a.example/p?q=1 true 1 parse function true"
    );
}

/// A URL object as the input or base converts to its href (it was "[object URL]", an Invalid URL).
#[test]
fn url_object_arguments() {
    let source = "[new URL(new URL('https://y.example/a')).href, new URL('b', new URL('https://y.example/a/')).href,\n\
          URL.canParse('/q', new URL('https://z.example')), URL.parse(new URL('https://x.example/q')).pathname,\n\
          new URLSearchParams(new URL('https://w.example/?k=v').search).get('k')].join(' ');";
    assert_eq!(
        eval(source),
        "https://y.example/a https://y.example/a/b true /q v"
    );
}

/// A subclass keeps the URL state and adds its own members.
#[test]
fn url_subclass() {
    let source = "class Tagged extends URL { get tag() { return 'tagged:' + this.hostname; } }\n\
         const t = new Tagged('https://sub.example/path');\n\
         [t.tag, t.pathname, t instanceof Tagged, t instanceof URL, Object.getPrototypeOf(Tagged.prototype) === URL.prototype].join(' ');";
    assert_eq!(eval(source), "tagged:sub.example /path true true true");
}

/// Expected outputs in the conversion tests were observed on Node 24.22.3.
/// Both global URL and the node:url export must reach the same native path.
#[test]
fn url_conversion_runs_input_then_base_once_for_constructor_and_statics() {
    let source = r#"
const out = [];
for (const U of [URL, require('node:url').URL]) {
    for (const method of ['new', 'parse', 'canParse']) {
        const log = [];
        const input = {
            get [Symbol.toPrimitive]() {
                log.push('input:get');
                return function(hint) {
                    log.push('input:' + hint + ':' + (this === input));
                    return '../p?x=1';
                };
            }
        };
        const base = {
            toString() { log.push('base:string'); return {}; },
            valueOf() { log.push('base:value'); return 'https://host/a/b/'; }
        };
        const result = method === 'new' ? new U(input, base) : U[method](input, base);
        out.push(method + ':' + (typeof result === 'boolean' ? result : result.href)
            + ':' + log.join(','));
    }
}
out.join('\n');
"#;
    let once = "new:https://host/a/p?x=1:input:get,input:string:true,base:string,base:value\n\
parse:https://host/a/p?x=1:input:get,input:string:true,base:string,base:value\n\
canParse:true:input:get,input:string:true,base:string,base:value";
    assert_native_output(source, &format!("{once}\n{once}"));
}

#[test]
fn url_conversion_observes_url_overrides_callable_values_and_proxy_receivers() {
    let source = r#"
const original = new URL('https://original/');
original.toString = function() { return 'https://override/'; };
const out = [new URL(original).href, URL.parse(original).href];
original[Symbol.toPrimitive] = function(hint) {
    return hint === 'string' ? 'https://symbol/' : 'bad';
};
out.push(new URL(original).href);
function callable() {}
callable.toString = function() { return 'https://callable/'; };
out.push(new URL(callable).href);
const log = [];
const target = { toString() { log.push(this === proxy); return 'https://proxy/'; } };
const proxy = new Proxy(target, {
    get(t, k, r) {
        log.push(typeof k === 'symbol' ? 'symbol' : k);
        return Reflect.get(t, k, r);
    }
});
out.push(new URL(proxy).href, log.join(','));
const base = { toString() { return 'https://old/'; } };
out.push(new URL({ toString() {
    base.toString = () => 'https://new/';
    return 'x';
} }, base).href);
out.join('\n');
"#;
    assert_native_output(
        source,
        "https://override/\nhttps://override/\nhttps://symbol/\nhttps://callable/\n\
https://proxy/\nsymbol,toString,true\nhttps://new/x",
    );
}

#[test]
fn url_conversion_preserves_thrown_identity_and_rejects_symbols_and_invalid_hooks() {
    let source = r#"
const out = [];
for (const method of ['new', 'parse', 'canParse']) {
    const invoke = (...args) => method === 'new' ? new URL(...args) : URL[method](...args);
    const token = {};
    let baseReads = 0;
    try {
        invoke({ toString() { throw token; } }, {
            toString() { baseReads++; return 'https://base/'; }
        });
    } catch(error) { out.push(method + ':' + (error === token) + ':' + baseReads); }
    for (const args of [
        [], [Symbol('input')], ['https://x/', Symbol('base')],
        [{ [Symbol.toPrimitive]() { return Symbol('result'); } }],
        [{ [Symbol.toPrimitive]: 1 }],
        [{ toString() { return {}; }, valueOf() { return {}; } }]
    ]) {
        try { invoke(...args); out.push('unexpected'); }
        catch(error) { out.push(error.name); }
    }
    try { out.push(String(invoke(undefined))); }
    catch(error) { out.push(error.name); }
}
out.join('|');
"#;
    assert_native_output(
        source,
        "new:true:0|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|\
parse:true:0|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|null|\
canParse:true:0|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|false",
    );
}

#[test]
fn every_url_setter_uses_string_hint_and_keeps_linked_query_state() {
    let source = r#"
const out = [];
const u = new URL('https://initial/');
for (const [key, text] of [
    ['href', 'http://start/a?x=1'], ['protocol', 'https:'],
    ['username', 'user name'], ['password', 'p@ss'], ['host', 'other:8443'],
    ['hostname', 'final'], ['port', '8080'], ['pathname', '/a b'],
    ['search', '?q=two words'], ['hash', '#frag ment']
]) {
    const log = [];
    u[key] = { [Symbol.toPrimitive](hint) { log.push(hint); return text; } };
    out.push(key + ':' + log.join(',') + ':' + u.href);
}
out.push(u.searchParams.get('q'));
const token = {};
try { u.href = { toString() { u.hash = 'changed'; throw token; } }; }
catch(error) { out.push(String(error === token)); }
out.push(u.hash);
const unchanged = u.href;
for (const key of [
    'href', 'protocol', 'username', 'password', 'host', 'hostname',
    'port', 'pathname', 'search', 'hash'
]) {
    try { u[key] = Symbol(); out.push('bad'); }
    catch(error) { out.push(error.name + ':' + (u.href === unchanged)); }
}
out.join('\n');
"#;
    let expected = "href:string:http://start/a?x=1\n\
protocol:string:https://start/a?x=1\n\
username:string:https://user%20name@start/a?x=1\n\
password:string:https://user%20name:p%40ss@start/a?x=1\n\
host:string:https://user%20name:p%40ss@other:8443/a?x=1\n\
hostname:string:https://user%20name:p%40ss@final:8443/a?x=1\n\
port:string:https://user%20name:p%40ss@final:8080/a?x=1\n\
pathname:string:https://user%20name:p%40ss@final:8080/a%20b?x=1\n\
search:string:https://user%20name:p%40ss@final:8080/a%20b?q=two%20words\n\
hash:string:https://user%20name:p%40ss@final:8080/a%20b?q=two%20words#frag%20ment\n\
two words\ntrue\n#changed";
    assert_native_output(
        source,
        &format!("{expected}{}", "\nTypeError:true".repeat(10)),
    );
}

#[test]
fn url_usvstring_conversion_replaces_lone_surrogates_after_guest_hooks() {
    let source = r#"
const out = [];
out.push(new URL({ toString() { return 'https://x/\ud800'; } }).href);
out.push(URL.parse({ [Symbol.toPrimitive]() { return '\udc00'; } }, 'https://x/').href);
out.push(URL.canParse({ toString() { return 'https://x/\ud800'; } }));
const u = new URL('https://x/');
u.pathname = { toString() { return '/\ud800'; } };
u.search = { toString() { return '?q=\udc00'; } };
out.push(u.href, u.searchParams.get('q').charCodeAt(0));
out.join('\n');
"#;
    assert_native_output(
        source,
        "https://x/%EF%BF%BD\nhttps://x/%EF%BF%BD\ntrue\n\
https://x/%EF%BF%BD?q=%EF%BF%BD\n65533",
    );
}

#[test]
fn url_setters_read_live_state_after_reentrant_conversion() {
    // Web IDL converts an attribute's USVString before running its setter
    // algorithm (https://webidl.spec.whatwg.org/#es-attributes). Node 24.22.3
    // snapshots URL state earlier for some setters; this regression follows
    // the specification and deliberately does not use that Node result.
    let source = r#"
const u = new URL('https://old/a?x=1');
const params = u.searchParams;
u.pathname = { toString() {
    u.hostname = 'new';
    params.set('x', '2');
    u.hash = '#inner';
    return '/outer';
} };
const first = [u.href, params === u.searchParams, params.get('x')].join('|');
u.search = { toString() {
    u.pathname = '/retained';
    params.append('temporary', 'yes');
    return '?final=1';
} };
[first, u.href, params.toString()].join('\n');
"#;
    assert_native_output(
        source,
        "https://new/outer?x=2#inner|true|2\nhttps://new/retained?final=1#inner\nfinal=1",
    );
}

#[test]
fn url_conversions_charge_native_work_and_encoded_output_to_runtime_budgets() {
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 128;
        assert_eq!(
            native_result("URL.canParse('https://x/');", config.clone(), None),
            Ok(Value::Bool(true)),
            "the instruction budget must admit the same short operation"
        );
        let source = format!(
            "try {{ URL.canParse('https://x/{}'); }} catch(error) {{ 'caught'; }}",
            "a".repeat(65_536)
        );
        let error = native_result(&source, config.clone(), None).expect_err("native work bound");
        assert!(error.contains("BudgetExhausted"), "{error}");

        config.instruction_budget = 1_000_000;
        config.max_string_size = 1024;
        for source in [
            "new URL({toString() {return 'https://x/' + '\\ud800'.repeat(200);}});",
            "URL.parse({toString() {return 'https://x/' + '\\ud800'.repeat(200);}});",
            "const u = new URL('https://x/'); u.pathname = {toString() {return '/'+ '\\ud800'.repeat(200);}};",
        ] {
            let error = native_result(source, config.clone(), None).expect_err("URL string bound");
            assert!(error.contains("StringLimitExceeded"), "{source}: {error}");
        }
    }
}

#[test]
fn url_conversions_retain_secret_observations_across_hooks_setters_and_catch() {
    let cases = [
        (
            "const secret = 'label-marker'; new URL({toString() {return secret;}}, {toString() {return 'https://x/';}}).href;",
            "https://x/secret",
            Value::str("https://x/secret"),
        ),
        (
            "const secret = 'label-marker'; URL.canParse({toString() {return secret;}}, {toString() {return 'bad-base';}});",
            "https://x/secret",
            Value::Bool(false),
        ),
        (
            "const secret = 'label-marker'; URL.parse({toString() {return secret;}}, {toString() {return 'bad-base';}});",
            "https://x/secret",
            Value::Null,
        ),
        (
            "const secret = 'label-marker'; const u = new URL('https://x/'); u.search = {toString() {return secret;}}; u.searchParams.get('q');",
            "?q=secret",
            Value::str("secret"),
        ),
        (
            "const secret = 'label-marker'; let caught = ''; try {URL.parse({toString() {return secret;}}, {toString() {throw 'public';}});} catch(error) {caught = error;} caught;",
            "https://x/secret",
            Value::str("public"),
        ),
    ];
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        let config = configure_native(config);
        for (source, input, expected) in &cases {
            let input_register = config.max_registers - 1;
            let mut module = lower_source(source);
            let pool_index = module
                .constant_pool
                .iter()
                .position(|text| text == "label-marker")
                .expect("one labelled input") as u32;
            let mut replacements = 0;
            for instruction in &mut module.instructions {
                if let Ir3Instruction::LoadStr {
                    dst,
                    pool_index: index,
                } = instruction
                    && *index == pool_index
                {
                    *instruction = Ir3Instruction::Move {
                        dst: *dst,
                        src: input_register,
                    };
                    replacements += 1;
                }
            }
            assert_eq!(replacements, 1);
            for stress in [None, Some(1), Some(7)] {
                let mut core = InterpreterCore::new(config.clone(), "url-conversion-label");
                core.seed_register(input_register, Value::str(*input))
                    .unwrap();
                core.set_register_label(input_register, Label::Secret)
                    .unwrap();
                core.set_gc_stress_interval(stress);
                let execution = core.execute(&module).expect("URL label execution");
                assert_eq!(&execution.value, expected, "{source}");
                assert_eq!(execution.completion_label, Label::Secret, "{source}");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}
