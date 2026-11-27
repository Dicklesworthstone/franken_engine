//! Public buffered Fetch objects execute through the parser and native VM in
//! both supported profiles. Pure construction has no network capability grant.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let source = format!(
        "function check(value, message) {{ if (!value) throw new Error(message); }}\n{source}"
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "fetch-objects.js".into(),
                text: source,
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("Fetch objects fixture parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "fetch-objects.js"),
        &LoweringContext::new("fetch-objects", "decision", "policy"),
    )
    .expect("Fetch objects fixture lowers")
    .ir3
}

fn assert_script(source: &str) {
    assert_script_with_network_gate(source, false);
}

fn assert_script_with_network_gate(source: &str, network_gate: bool) {
    let module = lower(source);
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
        if network_gate {
            config
                .granted_capabilities
                .insert(RuntimeCapability::NetworkEgress);
        }
        let mut core = InterpreterCore::new(config, "fetch-objects");
        let result = core
            .execute(&module)
            .expect("native Fetch objects execution");
        let output: Vec<_> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(output, ["ok"], "source:\n{source}");
    }
}

#[test]
fn constructors_are_first_class_branded_subclassable_and_require_new() {
    assert_script(
        r#"
        check(globalThis.Headers === Headers, "Headers global identity");
        check(globalThis.Response === Response, "Response global identity");
        check(Headers.length === 0 && Response.length === 0, "constructor lengths");
        check(Response.json.length === 1 && Response.redirect.length === 1, "factory lengths");
        check(Response.error.length === 0, "error factory length");
        check((() => { const Headers = () => "shadow"; return Headers(); })() === "shadow",
              "lexical shadowing");

        class CustomHeaders extends Headers {}
        const headers = new CustomHeaders([["X-Test", "value"]]);
        check(headers instanceof CustomHeaders && headers instanceof Headers, "Headers subclass");
        check(headers.get("x-test") === "value", "subclass brand");
        check(Object.getPrototypeOf(headers) === CustomHeaders.prototype, "subclass prototype");
        class CustomResponse extends Response {}
        const response = new CustomResponse(null, {status: 201});
        check(response instanceof CustomResponse && response instanceof Response, "Response subclass");
        check(response.status === 201, "Response subclass slots");
        const statusDescriptor = Object.getOwnPropertyDescriptor(Response.prototype, "status");
        check(statusDescriptor.enumerable && statusDescriptor.configurable &&
              typeof statusDescriptor.get === "function" && statusDescriptor.set === undefined,
              "Web IDL Response accessor descriptor");
        check(statusDescriptor.get.call(response) === 201, "borrowed native Response getter");
        let getterRejected = false;
        try { statusDescriptor.get.call({}); } catch (error) {
            getterRejected = error.name === "TypeError";
        }
        check(getterRejected, "Response getter receiver brand");
        class OverrideResponse extends Response { get status() { return 299; } }
        check(new OverrideResponse().status === 299, "inherited Response accessor override");
        Object.defineProperty(response, "status", {value: 298});
        check(response.status === 298, "own Response metadata override");
        function Alternative() {}
        const alternate = Reflect.construct(Headers, [[["x", "a"]]], Alternative);
        check(Object.getPrototypeOf(alternate) === Alternative.prototype, "Reflect newTarget");
        check(Headers.prototype.get.call(alternate, "x") === "a", "Reflect native brand");
        check(Headers.prototype.constructor === Headers, "Headers constructor link");
        check(Response.prototype.constructor === Response, "Response constructor link");
        check(Object.getOwnPropertyDescriptor(Headers.prototype, "append").enumerable,
              "Web IDL prototype operation descriptor");
        check(Object.getOwnPropertyDescriptor(Response, "json").enumerable,
              "Web IDL static operation descriptor");
        check(Object.getOwnPropertyDescriptor(Object.getPrototypeOf(headers.entries()), "next").enumerable,
              "Web IDL iterator next descriptor");
        check(!Object.getOwnPropertyDescriptor(Headers.prototype, Symbol.iterator).enumerable,
              "iterator symbol is non-enumerable");
        check(Object.prototype.toString.call(headers) === "[object Headers]", "Headers tag");
        check(Object.prototype.toString.call(response) === "[object Response]", "Response tag");

        let rejected = 0;
        for (const make of [
            () => Headers(), () => Response(), () => Headers.prototype.get.call({}, "x"),
            () => Headers.prototype.append.call(Object.create(Headers.prototype), "x", "y"),
            () => Object.getPrototypeOf(headers.entries()).next.call({})
        ]) {
            try { make(); } catch (error) { if (error.name === "TypeError") rejected++; }
        }
        check(rejected === 5, "constructor and receiver guards");
        console.log("ok");
    "#,
    );
}

#[test]
fn headers_accept_real_iterables_records_and_overridden_headers_iterators() {
    assert_script(
        r#"
        function* pairs() {
            yield ["B", " two\t"];
            yield new Set(["a", "one"]);
            yield ["Set-Cookie", "a=1"];
            yield ["set-cookie", "b=2"];
            yield ["Cookie", "a=1"];
            yield ["cookie", "b=2"];
            yield ["a", "three"];
            yield ["x-latin", "\u00e9"];
        }
        const headers = new Headers(pairs());
        check(headers.get("A") === "one, three", "combined case-insensitive fields");
        check(headers.get("b") === "two", "HTTP whitespace trimming");
        check(headers.get("cookie") === "a=1; b=2", "server cookie combination");
        check(headers.getSetCookie().join("|") === "a=1|b=2", "separate cookies");
        check(headers.get("x-latin") === "\u00e9", "Latin-1 ByteString");
        check(Array.from(headers.keys()).join("|") === "a|b|cookie|set-cookie|set-cookie|x-latin",
              "sorted names with separate Set-Cookie entries");
        check(Array.from(headers.values()).slice(3, 5).join("|") === "a=1|b=2",
              "cookie iteration order");
        check(headers[Symbol.iterator] === headers.entries, "iterator alias");
        let reads = 0;
        const record = Object.create({"ignored": "inherited"});
        Object.defineProperty(record, "X-Record", {enumerable: true, get() {
            reads++; return {toString() { reads++; return "record"; }};
        }});
        const fromRecord = new Headers(record);
        check(reads === 2 && fromRecord.get("x-record") === "record", "record conversions once");
        check(!fromRecord.has("ignored"), "own enumerable record properties");

        headers[Symbol.iterator] = function*() { yield ["replaced", "iterator"]; };
        const replaced = new Headers(headers);
        check(replaced.get("replaced") === "iterator" && !replaced.has("a"),
              "branded Headers must honor overridden iterator");
        console.log("ok");
    "#,
    );
}

#[test]
fn header_conversion_order_and_iterator_cleanup_precede_semantic_fill() {
    assert_script(
        r#"
        const order = [];
        const record = {};
        Object.defineProperty(record, "bad name", {enumerable: true, get() {
            order.push("bad"); return "value";
        }});
        Object.defineProperty(record, "later", {enumerable: true, get() {
            order.push("later"); return {toString() { order.push("string"); return "value"; }};
        }});
        try { new Headers(record); } catch (error) {
            check(error.name === "TypeError", "invalid name rejection");
        }
        check(order.join("|") === "bad|later|string", "complete record conversion before fill");

        const closed = [];
        const pair = {
            [Symbol.iterator]() {
                let index = 0;
                return {
                    next() { return index++ === 0 ? {value: "x", done: false}
                                                 : {value: Symbol("invalid"), done: false}; },
                    return() { closed.push("inner"); return {done: true}; }
                };
            }
        };
        const outer = {
            [Symbol.iterator]() {
                return {
                    next() { return {value: pair, done: false}; },
                    return() { closed.push("outer"); return {done: true}; }
                };
            }
        };
        let failed = false;
        try { new Headers(outer); } catch (error) { failed = error.name === "TypeError"; }
        check(failed && closed.join("|") === "inner|outer", "nested iterator cleanup");

        const later = [];
        function* wrongLength() {
            yield ["x", "one", "extra"];
            yield ["y", {toString() { later.push("converted"); return "two"; }}];
        }
        try { new Headers(wrongLength()); } catch (error) {
            check(error.name === "TypeError", "wrong sequence length");
        }
        check(later.join("|") === "converted", "nested sequences convert before fill");
        console.log("ok");
    "#,
    );
}

#[test]
fn header_iterators_and_for_each_observe_live_mutations() {
    assert_script(
        r#"
        const headers = new Headers([["a", "1"], ["c", "3"]]);
        const iterator = headers.entries();
        check(iterator[Symbol.iterator]() === iterator, "self-iterable iterator");
        check(iterator.next().value.join("=") === "a=1", "first entry");
        headers.delete("a");
        headers.append("b", "2");
        headers.set("c", "4");
        check(iterator.next().value.join("=") === "c=4", "current sorted index after mutation");
        headers.append("d", "5");
        check(iterator.next().value.join("=") === "d=5", "new appended entry");
        check(iterator.next().done, "exhausted current list");
        headers.append("e", "6");
        check(iterator.next().value.join("=") === "e=6", "Web IDL iteration can resume after done");

        const visited = [];
        const mutable = new Headers([["a", "1"], ["c", "3"]]);
        const context = {prefix: "seen:"};
        mutable.forEach(function(value, key, owner) {
            check(this === context && owner === mutable, "forEach arguments");
            visited.push(this.prefix + key + "=" + value);
            if (key === "a") { owner.append("b", "2"); owner.set("c", "4"); }
        }, context);
        check(visited.join("|") === "seen:a=1|seen:b=2|seen:c=4", "live forEach");
        mutable.set("set-cookie", "one");
        mutable.append("set-cookie", "two");
        mutable.set("set-cookie", "only");
        check(mutable.getSetCookie().join("|") === "only", "set replaces every cookie field");
        mutable.delete("missing");
        console.log("ok");
    "#,
    );
}

#[test]
fn header_validation_and_required_arguments_do_not_mutate_existing_fields() {
    assert_script(
        r#"
        const headers = new Headers([["safe", "kept"]]);
        let errors = 0;
        for (const invalid of [
            () => new Headers(null), () => new Headers(42),
            () => new Headers([["x"]]), () => new Headers([["x", "\u0100"]]),
            () => new Headers([["x", "\ud800"]]),
            () => headers.append("x", "bad\r\nvalue"),
            () => headers.set("bad name", "value"),
            () => headers.delete(""), () => headers.get(), () => headers.has(),
            () => headers.append("x"), () => headers.set("x"), () => headers.forEach(),
            () => headers.forEach(1)
        ]) {
            try { invalid(); } catch (error) { if (error.name === "TypeError") errors++; }
        }
        check(errors === 14, "invalid inputs and required method arguments");
        check(Array.from(headers).map(pair => pair.join("=")).join("|") === "safe=kept",
              "failed mutations are atomic");
        const symbolRecord = {[Symbol("x")]: "value"};
        let symbolRejected = false;
        try { new Headers(symbolRecord); } catch (error) { symbolRejected = error.name === "TypeError"; }
        check(symbolRejected, "enumerable symbols cannot convert to ByteString keys");
        console.log("ok");
    "#,
    );
}

#[test]
fn response_buffers_native_views_after_dictionary_conversion_and_clones_independently() {
    assert_script(
        r#"
        (async () => {
            const bytes = new Uint8Array([65, 66, 67, 68]);
            const view = new Uint8Array(bytes.buffer, 1, 2);
            const trace = [];
            const response = new Response(view, {
                get headers() { trace.push("headers"); return {"x-test": "yes"}; },
                get status() { trace.push("status"); bytes[1] = 90; return 201; },
                get statusText() { trace.push("statusText"); return "Created"; }
            });
            check(trace.join("|") === "headers|status|statusText", "dictionary order");
            bytes[1] = 88;
            check(response.status === 201 && response.statusText === "Created", "response metadata");
            check(response.ok && response.type === "default", "constructed response type");
            check(response.url === "" && !response.redirected, "constructed response routing");
            check(!response.bodyUsed && response.headers.get("x-test") === "yes", "unconsumed body");
            response.headers.set("x-test", "changed");
            const clone = response.clone();
            response.headers.set("x-test", "original");
            check(clone.headers.get("x-test") === "changed", "independent cloned headers");
            const read = response.arrayBuffer();
            check(response.bodyUsed, "consumption starts synchronously");
            const result = new Uint8Array(await read);
            check(Array.from(result).join(",") === "90,67", "view offset and post-init snapshot");
            check(await clone.text() === "ZC", "clone retains independent bytes");
            let rejected = false;
            try { await response.text(); } catch (error) { rejected = error.name === "TypeError"; }
            check(rejected, "body cannot be consumed twice");
            let cloneRejected = false;
            try { response.clone(); } catch (error) { cloneRejected = error.name === "TypeError"; }
            check(cloneRejected, "used body cannot be cloned");
            console.log("ok");
        })().catch(error => console.log("failed: " + error.name + ": " + error.message));
    "#,
    );
}

#[test]
fn response_body_types_use_native_bytes_usv_strings_and_null_body_rules() {
    assert_script(
        r#"
        (async () => {
            const form = new URLSearchParams([["a b", "x+y"]]);
            form.toString = () => { throw new Error("public stringifier must not run"); };
            const formResponse = new Response(form);
            check(formResponse.headers.get("content-type") ===
                  "application/x-www-form-urlencoded;charset=UTF-8", "form content type");
            check(await formResponse.text() === "a+b=x%2By", "native form serialization");
            const blob = new Blob([new Uint8Array([0, 255, 65])], {type: "application/octet-stream"});
            const blobResponse = new Response(blob);
            check(blobResponse.headers.get("content-type") === "application/octet-stream", "Blob MIME");
            check(Array.from(await blobResponse.bytes()).join(",") === "0,255,65", "Blob byte snapshot");
            const stringResponse = new Response("\ud800");
            check(stringResponse.headers.get("content-type") === "text/plain;charset=UTF-8", "string MIME");
            check(await stringResponse.text() === "\ufffd", "USVString replacement");
            const empty = new Response(null, {status: 204});
            check(await empty.text() === "" && !empty.bodyUsed, "null body does not become disturbed");
            check(await empty.text() === "" && !empty.clone().bodyUsed, "null body is reusable");
            const zero = new Response("");
            check(await zero.text() === "" && zero.bodyUsed, "empty string is a consumable body");
            let invalid = 0;
            for (const status of [204, 205, 304]) {
                try { new Response("", {status}); } catch (error) {
                    if (error.name === "TypeError") invalid++;
                }
            }
            check(invalid === 3, "null-body status rejects even empty non-null bodies");
            console.log("ok");
        })().catch(error => console.log("failed: " + error.name + ": " + error.message));
    "#,
    );
}

#[test]
fn response_init_conversion_observes_webidl_order_range_and_byte_strings() {
    assert_script(
        r#"
        const trace = [];
        const body = {toString() { trace.push("body"); return "text"; }};
        const response = new Response(body, {
            get headers() {
                trace.push("headers");
                return {x: {toString() { trace.push("header-value"); return "value"; }}};
            },
            get status() {
                trace.push("status");
                return {valueOf() { trace.push("status-number"); return 65737.9; }};
            },
            get statusText() {
                trace.push("statusText");
                return {toString() { trace.push("status-string"); return "OK\t\u00e9"; }};
            }
        });
        check(trace.join("|") === "body|headers|header-value|status|status-number|statusText|status-string",
              "BodyInit then lexicographic dictionary conversion");
        check(response.status === 201 && response.statusText === "OK\t\u00e9", "converted init");
        // ResponseInit.status is an unsigned short without EnforceRange. Negative
        // modulo conversion follows Web IDL even where a Node release diverges.
        check(new Response(null, {status: -65335}).status === 201, "unsigned short modulo");
        check(new Response(null, {status: 200.9}).status === 200, "integer truncation");
        let rangeErrors = 0;
        for (const status of [0, 199, 600, NaN, Infinity]) {
            try { new Response(null, {status}); } catch (error) {
                if (error.name === "RangeError") rangeErrors++;
            }
        }
        check(rangeErrors === 5, "status range after conversion");
        let textErrors = 0;
        for (const statusText of ["bad\r", "bad\n", "\0", "\u007f", "\u0100", "\ud800"]) {
            try { new Response(null, {statusText}); } catch (error) {
                if (error.name === "TypeError") textErrors++;
            }
        }
        check(textErrors === 6, "ByteString and reason-phrase validation");
        console.log("ok");
    "#,
    );
}

#[test]
fn response_factories_use_intrinsic_json_and_preserve_mutable_or_immutable_guards() {
    assert_script(
        r#"
        (async () => {
            const trace = [];
            const data = {toJSON() { trace.push("json"); return {answer: 42}; }};
            const original = JSON.stringify;
            JSON.stringify = () => { throw new Error("public JSON.stringify must not run"); };
            const response = Response.json(data, {
                get headers() { trace.push("headers"); return {"x-factory": "yes"}; },
                get status() { trace.push("status"); return 202; },
                get statusText() { trace.push("statusText"); return "Accepted"; }
            });
            JSON.stringify = original;
            check(trace.join("|") === "headers|status|statusText|json", "init converts before JSON algorithm");
            check(response.status === 202 && response.headers.get("content-type") === "application/json",
                  "JSON factory metadata");
            response.headers.append("x-factory", "mutable");
            check((await response.json()).answer === 42, "intrinsic JSON body");
            const custom = Response.json("value", {headers: {"content-type": "custom/type"}});
            check(custom.headers.get("content-type") === "custom/type", "explicit content type preserved");
            let jsonRejected = 0;
            const cycle = {}; cycle.self = cycle;
            for (const value of [undefined, cycle, {toJSON() { return undefined; }}]) {
                try { Response.json(value); } catch (error) {
                    if (error.name === "TypeError") jsonRejected++;
                }
            }
            check(jsonRejected === 3, "unserializable factory values");

            const failed = Response.error();
            check(failed.status === 0 && failed.type === "error" && !failed.ok, "network-error response");
            check(failed.url === "" && !failed.redirected && await failed.text() === "", "error body");
            const redirect = Response.redirect("https://example.test/path#fragment", 307);
            check(redirect.status === 307 && redirect.type === "default", "redirect factory metadata");
            check(redirect.headers.get("location") === "https://example.test/path#fragment",
                  "redirect factory retains fragment");
            let immutable = 0;
            for (const headers of [failed.headers, failed.clone().headers,
                                   redirect.headers, redirect.clone().headers]) {
                try { headers.set("x-test", "no"); } catch (error) {
                    if (error.name === "TypeError") immutable++;
                }
            }
            check(immutable === 4, "factory and clone immutable guards");
            let invalidRedirects = 0;
            for (const make of [
                () => Response.redirect(), () => Response.redirect("relative/path"),
                () => Response.redirect("https://example.test", 200), () => Response.json()
            ]) {
                try { make(); } catch (error) { invalidRedirects++; }
            }
            check(invalidRedirects === 4, "factory required arguments and redirect validation");
            console.log("ok");
        })().catch(error => console.log("failed: " + error.name + ": " + error.message));
    "#,
    );
}

#[test]
fn known_streams_reject_after_init_conversion_without_exposing_private_brand_or_using_prototypes() {
    assert_script(
        r#"
        (async () => {
            const web = require("node:stream/web");
            check(Object.getOwnPropertyNames(web).every(name => name.charCodeAt(0) !== 0),
                  "engine-private stream predicate is not exported");
            const ReadableStream = web.ReadableStream;
            const stream = new ReadableStream();
            const trace = [];
            stream.toString = () => { trace.push("stringified"); return "wrong"; };
            Object.setPrototypeOf(stream, Object.prototype);
            web.ReadableStream = function Fake() {};
            let rejected = false;
            try {
                new Response(stream, {
                    get headers() { trace.push("headers"); return {}; },
                    get status() { trace.push("status"); return 200; },
                    get statusText() { trace.push("statusText"); return ""; }
                });
            } catch (error) { rejected = error.name === "TypeError"; }
            check(rejected && trace.join("|") === "headers|status|statusText",
                  "native stream brand survives prototype/export changes and waits for init");
            const spoof = Object.create(ReadableStream.prototype);
            Object.defineProperty(spoof, Symbol.toStringTag, {value: "ReadableStream"});
            spoof.toString = () => "ordinary buffered object";
            check(await new Response(spoof).text() === "ordinary buffered object",
                  "a spoofed stream prototype and tag confer no stream brand");
            console.log("ok");
        })().catch(error => console.log("failed: " + error.name + ": " + error.message));
    "#,
    );
}

#[test]
fn fetch_reuses_iterable_headers_conversion_before_request_validation() {
    // The initial net:fetch capability gate is satisfied, but the deliberately
    // invalid GET body fails before any provider can perform I/O.
    assert_script_with_network_gate(
        r#"
        (async () => {
            const trace = [];
            const headers = new Headers([["unused", "ignored"]]);
            headers[Symbol.iterator] = function*() {
                trace.push("iterator");
                yield ["x-shared", {toString() { trace.push("value"); return "converted"; }}];
            };
            let rejected = false;
            try {
                await fetch("http://example.test/no-io", {
                    body: "forbidden GET body",
                    headers,
                    get method() { trace.push("method"); return "GET"; }
                });
            } catch (error) { rejected = error.name === "TypeError"; }
            check(rejected && trace.join("|") === "iterator|value|method",
                  "fetch shares iterable conversion and honors overridden Headers iterator");
            console.log("ok");
        })().catch(error => console.log("failed: " + error.name + ": " + error.message));
    "#,
        true,
    );
}
