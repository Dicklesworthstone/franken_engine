//! Request construction and body consumption run through the parser and native
//! interpreter. No network authority is granted to these pure object fixtures.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_script(source: &str) {
    let source = format!(
        "function check(value, message) {{ if (!value) throw new Error(message); }}\n{source}"
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "fetch-request.js".into(),
                text: source.clone(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("Request fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "fetch-request.js"),
        &LoweringContext::new("fetch-request", "decision", "policy"),
    )
    .expect("Request fixture lowers")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 1_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "fetch-request");
        let execution = core.execute(&module).expect("native Request execution");
        let output: Vec<_> = execution
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(output, ["ok"], "source:\n{source}");
    }
}

#[test]
fn request_constructor_is_first_class_subclassable_and_branded() {
    assert_script(
        r#"
        check(globalThis.Request === Request && Request.length === 1, "global Request");
        check(Request.prototype.constructor === Request, "constructor identity");
        class Outgoing extends Request {}
        const request = new Outgoing("https://EXAMPLE.com:443/a#fragment", {
            method: "post", body: "payload", headers: {"X-Test": " one "}, redirect: "manual"
        });
        check(request instanceof Outgoing && request instanceof Request, "subclass identity");
        check(Object.getPrototypeOf(request) === Outgoing.prototype, "newTarget prototype");
        check(request.url === "https://example.com/a#fragment" && request.method === "POST", "native metadata");
        check(request.redirect === "manual" && request.headers.get("x-test") === "one", "init metadata");
        check(request.headers === request.headers && request.signal === request.signal, "stable associated objects");
        check(request.headers.get("content-type") === "text/plain;charset=UTF-8", "inferred content type");
        check(Object.prototype.toString.call(request) === "[object Request]", "native toStringTag");
        check(request.mode === "cors" && request.credentials === "same-origin" && request.cache === "default", "default policy metadata");
        check(request.referrer === "about:client" && request.referrerPolicy === "" && request.integrity === "", "default source metadata");
        check(request.destination === "" && request.keepalive === false && request.duplex === "half", "default fetch metadata");
        const getter = Object.getOwnPropertyDescriptor(Request.prototype, "url");
        check(getter.enumerable && getter.configurable && getter.set === undefined, "Web IDL accessor");
        check(getter.get.call(request) === request.url, "borrowed getter");
        check(Object.getOwnPropertyDescriptor(Request.prototype, "clone").enumerable, "Web IDL method");
        function Alternative() {}
        const alternate = Reflect.construct(Request, ["data:text/plain,hello"], Alternative);
        check(Object.getPrototypeOf(alternate) === Alternative.prototype, "Reflect newTarget");
        check(getter.get.call(alternate) === "data:text/plain,hello", "native non-network construction");
        let rejected = 0;
        for (const run of [
            () => Request("https://example.com"), () => new Request(),
            () => getter.get.call({}), () => Request.prototype.clone.call(Object.create(Request.prototype))
        ]) {
            try { run(); } catch (error) { if (error.name === "TypeError") rejected++; }
        }
        check(rejected === 4, "constructor and native receiver guards");
        check((() => { const Request = () => 42; return Request(); })() === 42, "lexical shadowing");
        console.log("ok");
        "#,
    );
}

#[test]
fn request_body_consumption_snapshots_ranges_and_keeps_clones_independent() {
    assert_script(
        r#"
        async function run() {
            const backing = new Uint8Array([99, 65, 66, 100]);
            const request = new Request("https://example.com", {
                method: "post", body: new DataView(backing.buffer, 1, 2)
            });
            backing[1] = 88;
            const copy = request.clone();
            check(copy !== request && copy.headers !== request.headers && copy.signal !== request.signal, "clone isolation");
            copy.headers.set("x-copy", "yes");
            check(!request.headers.has("x-copy"), "header clone isolation");
            check(!request.bodyUsed && !copy.bodyUsed, "clone does not consume");
            const bytes = await request.bytes();
            check(bytes instanceof Uint8Array && bytes.length === 2 && bytes[0] === 65 && bytes[1] === 66, "DataView snapshot");
            check(request.bodyUsed && !copy.bodyUsed, "independent disturbance");
            check(await copy.text() === "AB", "independent cloned body");
            let second = false;
            try { await request.arrayBuffer(); } catch (error) { second = error.name === "TypeError"; }
            check(second, "second body read rejects");
            let cloneUsed = false;
            try { request.clone(); } catch (error) { cloneUsed = error.name === "TypeError"; }
            check(cloneUsed, "used clone rejects synchronously");
            console.log("ok");
        }
        run().catch(error => console.log("failed: " + error.message));
        "#,
    );
}

#[test]
fn request_copy_transfers_native_body_only_after_successful_validation() {
    assert_script(
        r#"
        async function run() {
            const original = new Request("https://example.com/path", {
                method: "POST", headers: {"x-original": "yes"}, body: "original", redirect: "error"
            });
            original.toString = () => { throw new Error("must not stringify native Request"); };
            Object.defineProperty(original, "url", {get() { throw new Error("must not read public url"); }});
            let failed = false;
            try { new Request(original, {method: "GET"}); } catch (error) { failed = error.name === "TypeError"; }
            check(failed && !original.bodyUsed, "failed validation does not consume source");
            const copied = new Request(original, {body: null, headers: {"x-new": "yes"}});
            check(original.bodyUsed && !copied.bodyUsed, "copy transfers source body");
            check(copied.url === "https://example.com/path" && copied.method === "POST" && copied.redirect === "error", "native inherited metadata");
            check(copied.headers.get("x-new") === "yes" && !copied.headers.has("x-original"), "replacement headers");
            check(await copied.text() === "original", "null body preserves inherited bytes");
            const replaced = new Request(original, {body: "replacement"});
            check(await replaced.text() === "replacement", "explicit replacement permits consumed source");
            let consumed = false;
            try { new Request(original); } catch (error) { consumed = error.name === "TypeError"; }
            check(consumed, "consumed inherited body rejected");
            console.log("ok");
        }
        run().catch(error => console.log("failed: " + error.message));
        "#,
    );
}

#[test]
fn null_and_empty_request_bodies_have_distinct_consumption_states() {
    assert_script(
        r#"
        async function run() {
            const empty = new Request("https://example.com", {method: "POST", body: ""});
            check(await empty.text() === "" && empty.bodyUsed, "empty non-null consumed");
            const absent = new Request("https://example.com");
            check(await absent.text() === "" && !absent.bodyUsed, "null text is reusable");
            const buffer = await absent.arrayBuffer();
            check(buffer.byteLength === 0 && !absent.bodyUsed, "null arrayBuffer is reusable");
            const copy = new Request(absent);
            check(!absent.bodyUsed && !copy.bodyUsed && copy.method === "GET", "copy of null body");
            const json = new Request("https://example.com", {method: "PUT", body: '{"answer":42}'});
            check((await json.json()).answer === 42 && json.bodyUsed, "JSON consumes native bytes");
            const invalid = new Request("https://example.com", {method: "PUT", body: "{"});
            let syntax = false;
            try { await invalid.json(); } catch (error) { syntax = error.name === "SyntaxError"; }
            check(syntax && invalid.bodyUsed, "failed JSON still consumes body");
            let receiver = false;
            try { await Request.prototype.text.call({}); } catch (error) { receiver = error.name === "TypeError"; }
            check(receiver, "borrowed body read rejects invalid receiver");
            console.log("ok");
        }
        run().catch(error => console.log("failed: " + error.message));
        "#,
    );
}

#[test]
fn request_dictionary_conversion_is_ordered_and_snapshots_after_getters() {
    assert_script(
        r#"
        async function run() {
            const seen = [];
            const bytes = new Uint8Array([65]);
            const init = {
                get body() { seen.push("body"); return bytes; },
                get cache() { seen.push("cache"); return "default"; },
                get credentials() { seen.push("credentials"); return "same-origin"; },
                get duplex() { seen.push("duplex"); return "half"; },
                get headers() { seen.push("headers"); return new Headers([["x", "one"]]); },
                get integrity() { seen.push("integrity"); return ""; },
                get keepalive() { seen.push("keepalive"); return false; },
                get method() { seen.push("method"); return {toString() { seen.push("method-string"); return "pOsT"; }}; },
                get mode() { seen.push("mode"); return "cors"; },
                get priority() { seen.push("priority"); return "auto"; },
                get redirect() { seen.push("redirect"); return "manual"; },
                get referrer() { seen.push("referrer"); return "about:client"; },
                get referrerPolicy() { seen.push("referrerPolicy"); return ""; },
                get signal() { seen.push("signal"); return null; },
                get window() { seen.push("window"); bytes[0] = 66; return null; }
            };
            const request = new Request({toString() { seen.push("input"); return "https://example.com"; }}, init);
            check(seen.join(",") === "input,body,cache,credentials,duplex,headers,integrity,keepalive,method,method-string,mode,priority,redirect,referrer,referrerPolicy,signal,window", "dictionary order");
            check(request.method === "POST" && await request.text() === "B", "native body extracted after dictionary");
            let later = false;
            let abrupt = false;
            try {
                new Request("https://example.com", {get method() { return Symbol(); }, get mode() { later = true; return "cors"; }});
            } catch (error) { abrupt = error.name === "TypeError"; }
            check(abrupt && !later, "abrupt conversion stops later getters");
            console.log("ok");
        }
        run().catch(error => console.log("failed: " + error.message));
        "#,
    );
}

#[test]
fn request_signals_follow_native_dependencies_and_can_be_detached() {
    assert_script(
        r#"
        const controller = new AbortController();
        const first = new Request("https://example.com", {signal: controller.signal});
        const copied = new Request(first);
        const cloned = first.clone();
        const detached = new Request(first, {signal: null});
        check(first.signal !== controller.signal && copied.signal !== first.signal && cloned.signal !== first.signal, "dependent signal identities");
        controller.signal.addEventListener("abort", event => event.stopImmediatePropagation());
        let events = 0;
        first.signal.addEventListener("abort", () => events++);
        copied.signal.addEventListener("abort", () => events++);
        cloned.signal.addEventListener("abort", () => events++);
        const reason = {why: "cancel"};
        controller.abort(reason);
        check(first.signal.aborted && copied.signal.aborted && cloned.signal.aborted, "native abort propagation");
        check(events === 3 && first.signal.reason === reason && cloned.signal.reason === reason, "reason identity and events");
        check(!detached.signal.aborted, "null detaches inherited signal");
        const already = new Request("https://example.com", {signal: controller.signal});
        check(already.signal.aborted && already.signal.reason === reason, "already aborted source");
        console.log("ok");
        "#,
    );
}

#[test]
fn request_rejects_malformed_inputs_and_explicitly_unsupported_policy_options() {
    assert_script(
        r#"
        let rejected = 0;
        const invalid = [
            () => new Request("relative/path"),
            () => new Request("https://user:pass@example.com"),
            () => new Request("https://example.com", {method: "TRACE"}),
            () => new Request("https://example.com", {method: "space method"}),
            () => new Request("https://example.com", {body: "not for GET"}),
            () => new Request("https://example.com", {method: "HEAD", body: ""}),
            () => new Request("https://example.com", {redirect: "invalid"}),
            () => new Request("https://example.com", {signal: {aborted: false}}),
            () => new Request("https://example.com", {window: {}}),
            () => new Request("https://example.com", {duplex: "full"}),
            () => new Request("https://example.com", {integrity: "sha256-unchecked"}),
            () => new Request("https://example.com", {mode: "no-cors"}),
            () => new Request("https://example.com", {credentials: "include"}),
            () => new Request("https://example.com", {cache: "only-if-cached"}),
            () => new Request("https://example.com", {keepalive: true}),
            () => new Request("https://example.com", {referrer: "https://other.example"})
        ];
        for (const make of invalid) {
            try { make(); } catch (error) { if (error.name === "TypeError") rejected++; }
        }
        check(rejected === invalid.length, "invalid or unsupported policy cannot disappear");
        const custom = new Request("https://example.com", {method: "patch", headers: {"x-latin": "\u00e9"}});
        check(custom.method === "patch" && custom.headers.get("x-latin") === "\u00e9", "pure object keeps custom method and Latin-1");
        console.log("ok");
        "#,
    );
}
