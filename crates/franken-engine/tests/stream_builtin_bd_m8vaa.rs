//! bd-fw7zd / bd-m8vaa: focused Node `stream` acceptance through
//! `HybridRouter::eval`.
//!
//! The reference contract is the Bun 1.3.14 lockstep corpus in sibling
//! `franken_node/crates/franken-node/tests/fixtures/compat_corpus/{stream_ext,stream}`.
//! This suite records the deliberate 52/65 (80%) target slice. The thirteen
//! deferred cases are async-iterable/async-iterator consumption (0003, 0024,
//! 0048), byte-HWM backpressure (0027, 0028, 0053, 0059), Duplex (0031),
//! post-terminal misuse errors (0040, 0041), buffer surgery (0042, 0043), and
//! asynchronous Transform callbacks (0065).
//! Acceptance clusters are unignored only when their lowering/runtime slice
//! lands, so ordinary package test runs remain a truthful green checkpoint
//! throughout the staged implementation.
//!
//! These tests exercise only engine-contained computation and deterministic
//! scheduling. Recognizing a supported static `stream` import must not grant a
//! materialized module object or general-purpose module-loading authority.

use std::collections::BTreeSet;

use frankenengine_engine::HybridRouter;

#[derive(Clone, Copy)]
struct EvalCase {
    ids: &'static [&'static str],
    description: &'static str,
    source: &'static str,
    expected: &'static str,
}

fn eval_console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("stream eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => panic!("expected stream source to be refused: {source:?}; got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

fn assert_cases(cases: &[EvalCase]) {
    for case in cases {
        assert_eq!(
            eval_console(case.source),
            case.expected,
            "stream conformance mismatch for {} ({})",
            case.ids.join(", "),
            case.description,
        );
    }
}

const TARGET_FIXTURE_IDS: &[&str] = &[
    "tc::stream::0001",
    "tc::stream::0002",
    "tc::stream::0004",
    "tc::stream::0005",
    "tc::stream::0006",
    "tc::stream::0007",
    "tc::stream::0008",
    "tc::stream::0009",
    "tc::stream::0010",
    "tc::stream::0011",
    "tc::stream::0012",
    "tc::stream::0013",
    "tc::stream::0014",
    "tc::stream::0015",
    "tc::stream::0016",
    "tc::stream::0017",
    "tc::stream::0018",
    "tc::stream::0019",
    "tc::stream::0020",
    "tc::stream::0021",
    "tc::stream::0022",
    "tc::stream::0023",
    "tc::stream::0025",
    "tc::stream::0026",
    "tc::stream::0029",
    "tc::stream::0030",
    "tc::stream::0032",
    "tc::stream::0033",
    "tc::stream::0034",
    "tc::stream::0035",
    "tc::stream::0036",
    "tc::stream::0037",
    "tc::stream::0038",
    "tc::stream::0039",
    "tc::stream::0044",
    "tc::stream::0045",
    "tc::stream::0046",
    "tc::stream::0047",
    "tc::stream::0049",
    "tc::stream::0050",
    "tc::stream::0051",
    "tc::stream::0052",
    "tc::stream::0054",
    "tc::stream::0055",
    "tc::stream::0056",
    "tc::stream::0057",
    "tc::stream::0058",
    "tc::stream::0060",
    "tc::stream::0061",
    "tc::stream::0062",
    "tc::stream::0063",
    "tc::stream::0064",
];

const IMPLEMENTED_FIXTURE_IDS: &[&str] = &[
    "tc::stream::0001",
    "tc::stream::0002",
    "tc::stream::0004",
    "tc::stream::0005",
    "tc::stream::0006",
    "tc::stream::0007",
    "tc::stream::0008",
    "tc::stream::0009",
    "tc::stream::0010",
    "tc::stream::0011",
    "tc::stream::0012",
    "tc::stream::0022",
    "tc::stream::0023",
    "tc::stream::0029",
    "tc::stream::0030",
    "tc::stream::0032",
    "tc::stream::0033",
    "tc::stream::0034",
    "tc::stream::0035",
    "tc::stream::0036",
    "tc::stream::0037",
    "tc::stream::0044",
    "tc::stream::0046",
    "tc::stream::0047",
    "tc::stream::0049",
    "tc::stream::0050",
    "tc::stream::0051",
    "tc::stream::0052",
    "tc::stream::0054",
    "tc::stream::0055",
];

#[test]
fn target_and_implemented_inventories_are_explicit() {
    let unique = TARGET_FIXTURE_IDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(TARGET_FIXTURE_IDS.len(), 52);
    assert_eq!(unique.len(), TARGET_FIXTURE_IDS.len());
    assert!(TARGET_FIXTURE_IDS.windows(2).all(|pair| pair[0] < pair[1]));

    let implemented = IMPLEMENTED_FIXTURE_IDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(IMPLEMENTED_FIXTURE_IDS.len(), 30);
    assert_eq!(implemented.len(), IMPLEMENTED_FIXTURE_IDS.len());
    assert!(IMPLEMENTED_FIXTURE_IDS.iter().all(|id| unique.contains(id)));
}

#[test]
fn readable_from_sync_iterables_and_static_module_forms() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0001", "tc::stream::0002"],
            description: "CJS Readable.from preserves arrays and treats a string as one chunk",
            source: r#"
                const { Readable } = require('stream');
                const first = Readable.from(['a', 'b', 'c']);
                const a = [];
                first.on('data', (chunk) => a.push(String(chunk)));
                first.on('end', () => {
                  console.log(a.join(',') + '|end');
                  const second = Readable.from('hello');
                  const b = [];
                  second.on('data', (chunk) => b.push(String(chunk)));
                  second.on('end', () => console.log(b.length + ':' + b.join('')));
                });
            "#,
            expected: "a,b,c|end\n1:hello",
        },
        EvalCase {
            ids: &["tc::stream::0004", "tc::stream::0037"],
            description: "finite and empty Readables order data, end, and close",
            source: r#"
                const { Readable } = require('node:stream');
                const one = Readable.from(['one']);
                one.on('data', (chunk) => console.log('data:' + chunk));
                one.on('end', () => console.log('end'));
                one.on('close', () => {
                  console.log('close');
                  const empty = Readable.from([]);
                  let count = 0;
                  empty.on('data', () => count++);
                  empty.on('end', () => console.log('empty-end:' + count));
                  empty.on('close', () => console.log('empty-close'));
                });
            "#,
            expected: "data:one\nend\nclose\nempty-end:0\nempty-close",
        },
        EvalCase {
            ids: &["tc::stream::0007"],
            description: "object-mode Readable preserves object chunks",
            source: r#"
                const { Readable } = require('stream');
                const readable = Readable.from([{ id: 1 }, { id: 2 }], { objectMode: true });
                readable.on('data', (value) => console.log('id:' + value.id + ':' + typeof value));
                readable.on('end', () => console.log('end'));
            "#,
            expected: "id:1:object\nid:2:object\nend",
        },
        EvalCase {
            ids: &["tc::stream::0046"],
            description: "ESM node:stream and node:events named imports are statically recognized",
            source: r#"
                import { once } from 'node:events';
                import { Readable } from 'node:stream';
                const events = [];
                const chunks = [];
                const readable = Readable.from(['alpha', 'beta']);
                readable.on('data', (chunk) => { events.push('data'); chunks.push(String(chunk)); });
                readable.on('end', () => events.push('end'));
                readable.on('close', () => events.push('close'));
                await once(readable, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "data,data,end,close\nalpha,beta",
        },
        EvalCase {
            ids: &["tc::stream::0049"],
            description: "ESM object-mode Readable preserves values and lifecycle",
            source: r#"
                import { once } from 'node:events';
                import { Readable } from 'node:stream';
                const events = [];
                const chunks = [];
                const readable = Readable.from([{ step: 1 }, { step: 2 }], { objectMode: true });
                readable.on('data', (chunk) => { events.push('data'); chunks.push(chunk.step); });
                readable.on('end', () => events.push('end'));
                readable.on('close', () => events.push('close'));
                await once(readable, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "data,data,end,close\n1,2",
        },
    ]);
}

#[test]
fn readable_from_is_lazy_and_observes_reentrant_array_growth() {
    assert_cases(&[EvalCase {
        ids: &[],
        description: "Readable.from consumes its array source lazily across pump turns",
        source: r#"
            const { Readable } = require('stream');
            const source = ['old'];
            const readable = Readable.from(source);
            source[0] = 'new';
            source.push('before');
            const seen = [];
            readable.on('data', (chunk) => {
              seen.push(String(chunk));
              if (seen.length === 1) source.push('during');
            });
            readable.on('end', () => console.log(seen.join(',')));
        "#,
        expected: "new,before,during",
    }]);
}

#[test]
fn every_data_observer_form_activates_finite_readable_flow() {
    assert_cases(&[
        EvalCase {
            ids: &[],
            description: "EventEmitter.once(data) starts finite readable flow",
            source: r#"
                const { Readable } = require('stream');
                const readable = Readable.from(['once']);
                readable.once('data', (chunk) => console.log(String(chunk)));
            "#,
            expected: "once",
        },
        EvalCase {
            ids: &[],
            description: "prependListener(data) starts finite readable flow",
            source: r#"
                const { Readable } = require('stream');
                const readable = Readable.from(['prepend']);
                readable.prependListener('data', (chunk) => console.log(String(chunk)));
            "#,
            expected: "prepend",
        },
        EvalCase {
            ids: &[],
            description: "prependOnceListener(data) starts finite readable flow",
            source: r#"
                const { Readable } = require('stream');
                const readable = Readable.from(['prepend-once']);
                readable.prependOnceListener('data', (chunk) => console.log(String(chunk)));
            "#,
            expected: "prepend-once",
        },
        EvalCase {
            ids: &[],
            description: "static events.once(data) starts finite readable flow",
            source: r#"
                const { once } = require('events');
                const { Readable } = require('stream');
                const readable = Readable.from(['promise-once']);
                once(readable, 'data').then((args) => console.log(String(args[0])));
            "#,
            expected: "promise-once",
        },
    ]);
}

#[test]
fn stream_provenance_does_not_cross_lexical_shadowing() {
    assert_cases(&[
        EvalCase {
            ids: &[],
            description: "function and arrow parameters shadow the imported binding",
            source: r#"
                const { Readable } = require('stream');
                const custom = { from(values) { return values.join('+'); } };
                function declared(Readable) { return Readable.from(['function']); }
                const arrow = (Readable) => Readable.from(['arrow']);
                console.log(declared(custom));
                console.log(arrow(custom));
            "#,
            expected: "function\narrow",
        },
        EvalCase {
            ids: &[],
            description: "block, catch, and for-of bindings shadow the imported binding",
            source: r#"
                const { Readable } = require('stream');
                const custom = { from(values) { return values.join('+'); } };
                { const Readable = custom; console.log(Readable.from(['block'])); }
                try { throw custom; } catch (Readable) { console.log(Readable.from(['catch'])); }
                for (const Readable of [custom]) { console.log(Readable.from(['loop'])); }
            "#,
            expected: "block\ncatch\nloop",
        },
        EvalCase {
            ids: &[],
            description: "class method parameters shadow the imported binding",
            source: r#"
                const { Readable } = require('stream');
                const custom = { from(values) { return values.join('+'); } };
                class Consumer { run(Readable) { return Readable.from(['method']); } }
                console.log(new Consumer().run(custom));
            "#,
            expected: "method",
        },
    ]);
}

#[test]
fn stream_provenance_is_suppressed_before_defaults_and_self_bindings() {
    for source in [
        r#"
            const { Readable } = require('stream');
            Readable.from([]);
            function defaulted(Readable = Readable.from(['wrong'])) { return Readable; }
            defaulted();
        "#,
        r#"
            const { Readable } = require('stream');
            Readable.from([]);
            const custom = { from(values) { return values.join('+'); } };
            function later(x = Readable.from(['wrong']), Readable = custom) { return x; }
            later();
        "#,
        r#"
            const { Readable } = require('stream');
            Readable.from([]);
            const invoke = function Readable() { return Readable.from(['wrong']); };
            invoke();
        "#,
        r#"
            const { Readable } = require('stream');
            Readable.from([]);
            for (const Readable of Readable.from(['wrong'])) { console.log(Readable); }
        "#,
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("type error")
                || error.contains("TypeError")
                || error.contains("ReferenceError")
                || error.contains("uninitialized")
                || error.contains("temporal dead zone"),
            "shadowed Readable must not lower to the stream builtin: {error:?}",
        );
    }
}

#[test]
fn stream_constructor_provenance_does_not_bypass_cjs_tdz() {
    for source in [
        r#"
            new Readable({ read() {} });
            const { Readable } = require('stream');
        "#,
        r#"
            const make = () => new Writable({ write(c, e, cb) { cb(); } });
            make();
            const { Writable } = require('stream');
        "#,
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ReferenceError")
                || error.contains("uninitialized")
                || error.contains("temporal dead zone")
                || error.contains("type error"),
            "pre-declaration stream constructor use must not become a builtin: {error:?}",
        );
    }
}

#[test]
fn readable_custom_push_paused_read_and_encoding() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0005"],
            description: "paused readable drains explicitly before end",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                readable.push('pq');
                readable.push(null);
                readable.on('readable', () => {
                  let chunk;
                  while ((chunk = readable.read()) !== null) console.log('read:' + chunk.toString());
                });
                readable.on('end', () => console.log('end'));
            "#,
            expected: "read:pq\nend",
        },
        EvalCase {
            ids: &["tc::stream::0006"],
            description: "custom _read pushes ordered chunks and null terminates",
            source: r#"
                const { Readable } = require('stream');
                const items = ['n1', 'n2'];
                const readable = new Readable({
                  read() { this.push(items.length ? items.shift() : null); }
                });
                const output = [];
                readable.on('data', (chunk) => output.push(chunk.toString()));
                readable.on('end', () => console.log(output.join(',')));
            "#,
            expected: "n1,n2",
        },
        EvalCase {
            ids: &["tc::stream::0023"],
            description: "buffered byte chunks may coalesce during explicit read",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                const seen = [];
                readable.on('readable', () => {
                  let chunk;
                  while ((chunk = readable.read()) !== null) seen.push(chunk.toString());
                });
                readable.on('end', () => console.log(seen.join(',')));
                readable.push('r1');
                readable.push('r2');
                readable.push(null);
            "#,
            expected: "r1r2",
        },
        EvalCase {
            ids: &["tc::stream::0029"],
            description: "setEncoding makes data listeners receive strings",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                readable.setEncoding('utf8');
                readable.on('data', (chunk) => console.log(typeof chunk + ':' + chunk));
                readable.on('end', () => console.log('end'));
                readable.push(Buffer.from('enc'));
                readable.push(null);
            "#,
            expected: "string:enc\nend",
        },
        EvalCase {
            ids: &[],
            description: "byte-mode data is Buffer-backed and UTF-8 decoding retains split suffixes",
            source: r#"
                const { Readable } = require('stream');
                const bytes = new Readable({ read() {} });
                bytes.on('data', (chunk) => console.log('buffer:' + Buffer.isBuffer(chunk) + ':' + chunk.toString()));
                bytes.on('end', () => {
                  const decoded = new Readable({ read() {} });
                  decoded.setEncoding('utf-8');
                  decoded.on('data', (chunk) => console.log(typeof chunk + ':' + chunk));
                  decoded.on('end', () => console.log('decoded-end'));
                  decoded.push(Buffer.from([0xe2, 0x82]));
                  decoded.push(Buffer.from([0xac]));
                  decoded.push(null);
                });
                bytes.push('raw');
                bytes.push(null);
            "#,
            expected: "buffer:true:raw\nstring:€\ndecoded-end",
        },
        EvalCase {
            ids: &[],
            description: "a custom _read that makes no progress parks without spinning",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                readable.on('data', () => console.log('unexpected'));
                console.log('parked');
            "#,
            expected: "parked",
        },
        EvalCase {
            ids: &[],
            description: "partial UTF-8 output counts as custom _read progress",
            source: r#"
                const { Readable } = require('stream');
                const pieces = [Buffer.from([0xe2, 0x82]), Buffer.from([0xac]), null];
                const readable = new Readable({
                  read() { this.push(pieces.shift()); }
                });
                readable.setEncoding('utf8');
                readable.on('data', (chunk) => console.log(chunk));
                readable.on('end', () => console.log('end'));
            "#,
            expected: "€\nend",
        },
        EvalCase {
            ids: &[],
            description: "setEncoding converts bytes already buffered before the call",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                readable.push(Buffer.from([0xe2, 0x82]));
                readable.push(Buffer.from([0xac]));
                readable.setEncoding('utf8');
                console.log(readable.readableLength);
                console.log(readable.read());
                readable.push(null);
            "#,
            expected: "1\n€",
        },
        EvalCase {
            ids: &["tc::stream::0047"],
            description: "ESM paused Readable.from preserves iterator chunk boundaries",
            source: r#"
                import { once } from 'node:events';
                import { Readable } from 'node:stream';
                const events = [];
                const chunks = [];
                const readable = Readable.from(['left', 'right']);
                readable.pause();
                readable.on('readable', () => events.push('readable'));
                readable.on('end', () => events.push('end'));
                readable.on('close', () => events.push('close'));
                await once(readable, 'readable');
                let chunk = readable.read();
                while (chunk !== null) { chunks.push(String(chunk)); chunk = readable.read(); }
                await once(readable, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "readable,readable,readable,end,close\nleft,right",
        },
    ]);

    for source in [
        "const { Readable } = require('stream'); new Readable({ read: 1 });",
        "const { Readable } = require('stream'); new Readable({ read() {} }).setEncoding('bogus');",
    ] {
        assert!(eval_error(source).contains("type error"));
    }
}

#[test]
fn readable_state_flags_high_water_marks_and_to_array() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0008", "tc::stream::0009"],
            description: "configured and default high-water marks are observable",
            source: r#"
                const { Readable, Writable } = require('stream');
                const readable = new Readable({ highWaterMark: 4, read() {} });
                const writable = new Writable({ highWaterMark: 8, write(c, e, cb) { cb(); } });
                const objects = new Readable({ objectMode: true, read() {} });
                console.log(readable.readableHighWaterMark);
                console.log(writable.writableHighWaterMark);
                console.log(typeof new Readable({ read() {} }).readableHighWaterMark === 'number');
                console.log(objects.readableHighWaterMark);
                console.log(objects.readableObjectMode);
                objects.push(null);
            "#,
            expected: "4\n8\ntrue\n16\ntrue",
        },
        EvalCase {
            ids: &["tc::stream::0030"],
            description: "pause and resume update isPaused synchronously",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                console.log('initial:' + readable.isPaused());
                readable.pause();
                console.log('paused:' + readable.isPaused());
                readable.resume();
                console.log('resumed:' + readable.isPaused());
                readable.push(null);
            "#,
            expected: "initial:false\npaused:true\nresumed:false",
        },
        EvalCase {
            ids: &["tc::stream::0032"],
            description: "toArray resolves with all chunks in order",
            source: r#"
                const { Readable } = require('stream');
                (async () => {
                  const values = await Readable.from(['t1', 't2']).toArray();
                  console.log(Array.isArray(values) + ':' + values.length + ':' + values.join('+'));
                })();
            "#,
            expected: "true:2:t1+t2",
        },
        EvalCase {
            ids: &[],
            description: "toArray retains the chunk prefetched for a readable observer",
            source: r#"
                const { once } = require('events');
                const { Readable } = require('stream');
                (async () => {
                  const readable = Readable.from(['prefetched', 'remaining']);
                  await once(readable, 'readable');
                  const values = await readable.toArray();
                  console.log(values.join(','));
                })();
            "#,
            expected: "prefetched,remaining",
        },
        EvalCase {
            ids: &["tc::stream::0035"],
            description: "readableEnded turns true by the end event",
            source: r#"
                const { Readable } = require('stream');
                const readable = Readable.from(['e']);
                console.log('before:' + readable.readableEnded);
                readable.on('data', () => {});
                readable.on('end', () => console.log('at-end:' + readable.readableEnded));
            "#,
            expected: "before:false\nat-end:true",
        },
        EvalCase {
            ids: &["tc::stream::0036"],
            description: "readableFlowing tracks listener, pause, and resume transitions",
            source: r#"
                const { Readable } = require('stream');
                const readable = Readable.from(['fl']);
                console.log('initial:' + readable.readableFlowing);
                readable.on('data', () => {});
                console.log('after-on:' + readable.readableFlowing);
                readable.pause();
                console.log('after-pause:' + readable.readableFlowing);
                readable.resume();
                readable.on('end', () => console.log('end'));
            "#,
            expected: "initial:null\nafter-on:true\nafter-pause:false\nend",
        },
    ]);
}

#[test]
fn readable_destroy_is_synchronous_then_emits_error_before_close() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0022"],
            description: "destroy(error) flips destroyed then emits error and close",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                readable.on('error', (error) => console.log('error:' + error.message));
                readable.on('close', () => console.log('close'));
                readable.destroy(new Error('killed'));
                console.log('destroyed:' + readable.destroyed);
            "#,
            expected: "destroyed:true\nerror:killed\nclose",
        },
        EvalCase {
            ids: &["tc::stream::0033"],
            description: "destroy without error closes without an error event",
            source: r#"
                const { Readable } = require('stream');
                const readable = new Readable({ read() {} });
                readable.on('error', () => console.log('wrong'));
                readable.on('close', () => console.log('close'));
                console.log('before:' + readable.destroyed);
                readable.destroy();
                console.log('after:' + readable.destroyed);
            "#,
            expected: "before:false\nafter:true\nclose",
        },
        EvalCase {
            ids: &["tc::stream::0050"],
            description: "manual error plus destroy does not duplicate the error",
            source: r#"
                import { once } from 'node:events';
                import { Readable } from 'node:stream';
                const events = [];
                const readable = new Readable({ read() { this.push('before-destroy'); } });
                readable.on('error', (error) => events.push('error:' + error.message));
                readable.on('close', () => events.push('close'));
                readable.emit('error', new Error('read-fail'));
                readable.destroy();
                await once(readable, 'close');
                console.log(events.join(','));
            "#,
            expected: "error:read-fail,close",
        },
    ]);
}

#[test]
fn writable_write_end_final_flags_and_callbacks() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0010"],
            description: "custom _write receives write and end chunks in order",
            source: r#"
                const { Writable } = require('stream');
                const writable = new Writable({
                  write(chunk, encoding, callback) { console.log('wrote:' + chunk.toString()); callback(); }
                });
                writable.write('first');
                writable.write('second');
                writable.end('last');
            "#,
            expected: "wrote:first\nwrote:second\nwrote:last",
        },
        EvalCase {
            ids: &["tc::stream::0011"],
            description: "finish is singular and end callback settles before later immediates",
            source: r#"
                const { Writable } = require('stream');
                const writable = new Writable({ write(c, e, cb) { cb(); } });
                let finishes = 0;
                let callbackRan = false;
                writable.on('finish', () => finishes++);
                writable.write('x');
                writable.end(() => { callbackRan = true; });
                setImmediate(() => setImmediate(() => console.log('finish-count:' + finishes + ',cb:' + callbackRan)));
            "#,
            expected: "finish-count:1,cb:true",
        },
        EvalCase {
            ids: &["tc::stream::0012"],
            description: "close follows finish",
            source: r#"
                const { Writable } = require('stream');
                const writable = new Writable({ write(c, e, cb) { cb(); } });
                writable.on('finish', () => console.log('finish'));
                writable.on('close', () => console.log('close'));
                writable.end('bye');
            "#,
            expected: "finish\nclose",
        },
        EvalCase {
            ids: &["tc::stream::0034"],
            description: "writableEnded is synchronous and writableFinished is true at finish",
            source: r#"
                const { Writable } = require('stream');
                const writable = new Writable({ write(c, e, cb) { cb(); } });
                console.log('ended-before:' + writable.writableEnded);
                writable.on('finish', () => console.log('finished-flag:' + writable.writableFinished));
                writable.end('z');
                console.log('ended-after:' + writable.writableEnded);
            "#,
            expected: "ended-before:false\nended-after:true\nfinished-flag:true",
        },
        EvalCase {
            ids: &["tc::stream::0051"],
            description: "write/final/prefinish/callback/finish/close order matches Node",
            source: r#"
                import { once } from 'node:events';
                import { Writable } from 'node:stream';
                const events = [];
                const chunks = [];
                const writable = new Writable({
                  write(chunk, encoding, callback) { chunks.push(String(chunk)); events.push('write:' + String(chunk)); callback(); },
                  final(callback) { events.push('final'); callback(); }
                });
                writable.on('prefinish', () => events.push('prefinish'));
                writable.on('finish', () => events.push('finish'));
                writable.on('close', () => events.push('close'));
                writable.write('alpha', () => events.push('callback:alpha'));
                writable.end('omega', () => events.push('callback:end'));
                await once(writable, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "write:alpha,write:omega,final,prefinish,callback:alpha,callback:end,finish,close\nalpha,omega",
        },
        EvalCase {
            ids: &["tc::stream::0054"],
            description: "_final precedes prefinish, finish, and close",
            source: r#"
                import { once } from 'node:events';
                import { Writable } from 'node:stream';
                const events = [];
                const writable = new Writable({
                  write(chunk, encoding, callback) { events.push('write'); callback(); },
                  final(callback) { events.push('final'); callback(); }
                });
                writable.on('prefinish', () => events.push('prefinish'));
                writable.on('finish', () => events.push('finish'));
                writable.on('close', () => events.push('close'));
                writable.end('payload');
                await once(writable, 'close');
                console.log(events.join(','));
            "#,
            expected: "write,final,prefinish,finish,close",
        },
    ]);
}

#[test]
#[ignore = "bd-8nrud: process.nextTick prerequisite not implemented yet"]
fn writable_cork_next_tick_prerequisite() {
    assert_cases(&[EvalCase {
        ids: &["tc::stream::0013"],
        description: "cork defers _write until uncork and keeps FIFO order",
        source: r#"
                const { Writable } = require('stream');
                const writable = new Writable({ write(c, e, cb) { console.log('w:' + c.toString()); cb(); } });
                writable.cork();
                writable.write('a');
                writable.write('b');
                console.log('corked-no-writes-yet');
                process.nextTick(() => { writable.uncork(); console.log('after-uncork'); writable.end(); });
            "#,
        expected: "corked-no-writes-yet\nw:a\nw:b\nafter-uncork",
    }]);
}

#[test]
fn writable_cork_uncork_and_destroy() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0052"],
            description: "cork exposes buffered byte length and flushes before finish",
            source: r#"
                import { once } from 'node:events';
                import { Writable } from 'node:stream';
                const events = [];
                const chunks = [];
                const writable = new Writable({
                  write(chunk, encoding, callback) { chunks.push(String(chunk)); events.push('write:' + String(chunk)); callback(); }
                });
                writable.on('finish', () => events.push('finish'));
                writable.on('close', () => events.push('close'));
                writable.cork();
                writable.write('one');
                writable.write('two');
                events.push('buffered:' + writable.writableLength);
                writable.uncork();
                writable.end();
                await once(writable, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "buffered:6,write:one,write:two,finish,close\none,two",
        },
        EvalCase {
            ids: &["tc::stream::0044"],
            description: "destroy closes a Writable without finish",
            source: r#"
                const { Writable } = require('stream');
                const writable = new Writable({ write(c, e, cb) { cb(); } });
                writable.on('finish', () => console.log('wrong'));
                writable.on('close', () => console.log('close'));
                writable.write('a');
                writable.destroy();
                console.log('destroyed:' + writable.destroyed);
            "#,
            expected: "destroyed:true\nclose",
        },
        EvalCase {
            ids: &["tc::stream::0055"],
            description: "Writable error is observed before destroy close",
            source: r#"
                import { once } from 'node:events';
                import { Writable } from 'node:stream';
                const events = [];
                const writable = new Writable({ write(chunk, encoding, callback) { callback(); } });
                writable.on('error', (error) => events.push('error:' + error.message));
                writable.on('finish', () => events.push('finish'));
                writable.on('close', () => events.push('close'));
                writable.emit('error', new Error('write-fail'));
                writable.destroy();
                await once(writable, 'close');
                console.log(events.join(','));
            "#,
            expected: "error:write-fail,close",
        },
    ]);
}

#[test]
fn writable_destroy_error_argument_is_deferred_and_handled() {
    assert_eq!(
        eval_console(
            r#"
                const { Writable } = require('stream');
                const writable = new Writable({ write(chunk, encoding, callback) { callback(); } });
                writable.on('error', (error) => console.log('error:' + error.message));
                writable.on('close', () => console.log('close'));
                writable.destroy(new Error('boom'));
                console.log('sync:' + writable.destroyed + ':' + writable.closed);
            "#,
        ),
        "sync:true:true\nerror:boom\nclose"
    );
}

#[test]
#[ignore = "bd-fw7zd: Transform/PassThrough slice not implemented yet"]
fn transform_flush_object_mode_and_pass_through() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0014"],
            description: "Transform maps byte chunks in write order",
            source: r#"
                const { Transform } = require('stream');
                const transform = new Transform({
                  transform(chunk, encoding, callback) { callback(null, chunk.toString().toUpperCase()); }
                });
                transform.on('data', (chunk) => console.log('out:' + chunk.toString()));
                transform.on('end', () => console.log('end'));
                transform.write('abc');
                transform.end('def');
            "#,
            expected: "out:ABC\nout:DEF\nend",
        },
        EvalCase {
            ids: &["tc::stream::0015"],
            description: "_flush appends a final readable chunk",
            source: r#"
                const { Transform } = require('stream');
                const transform = new Transform({
                  transform(chunk, encoding, callback) { callback(null, chunk); },
                  flush(callback) { this.push('FLUSHED'); callback(); }
                });
                const output = [];
                transform.on('data', (chunk) => output.push(chunk.toString()));
                transform.on('end', () => console.log(output.join('|')));
                transform.end('body');
            "#,
            expected: "body|FLUSHED",
        },
        EvalCase {
            ids: &["tc::stream::0038"],
            description: "object-mode Transform maps objects one-to-one",
            source: r#"
                const { Transform } = require('stream');
                const transform = new Transform({
                  objectMode: true,
                  transform(value, encoding, callback) { callback(null, { v: value.v * 2 }); }
                });
                transform.on('data', (value) => console.log('v:' + value.v));
                transform.on('end', () => console.log('end'));
                transform.write({ v: 3 });
                transform.end({ v: 5 });
            "#,
            expected: "v:6\nv:10\nend",
        },
        EvalCase {
            ids: &["tc::stream::0016"],
            description: "PassThrough preserves byte chunks",
            source: r#"
                const { PassThrough } = require('stream');
                const stream = new PassThrough();
                const output = [];
                stream.on('data', (chunk) => output.push(chunk.toString()));
                stream.on('end', () => console.log(output.join(',')));
                stream.write('1');
                stream.write('2');
                stream.end('3');
            "#,
            expected: "1,2,3",
        },
        EvalCase {
            ids: &["tc::stream::0064"],
            description: "ESM PassThrough emits data, end, and close in order",
            source: r#"
                import { once } from 'node:events';
                import { PassThrough } from 'node:stream';
                const events = [];
                const chunks = [];
                const stream = new PassThrough();
                stream.on('data', (chunk) => { events.push('data'); chunks.push(String(chunk)); });
                stream.on('end', () => events.push('end'));
                stream.on('close', () => events.push('close'));
                stream.write('front');
                stream.end('back');
                await once(stream, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "data,data,end,close\nfront,back",
        },
    ]);
}

#[test]
#[ignore = "bd-fw7zd: promise pipeline slice not implemented yet"]
fn promise_pipeline_covers_sync_transform_object_mode_and_flush() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0056"],
            description: "promise pipeline resolves after transformed bytes reach the sink",
            source: r#"
                import { Readable, Transform, Writable } from 'node:stream';
                import { pipeline } from 'node:stream/promises';
                const events = [];
                const chunks = [];
                const upper = new Transform({
                  transform(chunk, encoding, callback) { events.push('transform'); callback(null, String(chunk).toUpperCase()); }
                });
                const sink = new Writable({
                  write(chunk, encoding, callback) { events.push('write'); chunks.push(String(chunk)); callback(); }
                });
                await pipeline(Readable.from(['ab', 'cd']), upper, sink);
                events.push('pipeline:resolved');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "transform,write,transform,write,pipeline:resolved\nAB,CD",
        },
        EvalCase {
            ids: &["tc::stream::0057"],
            description: "promise pipeline preserves object-mode mapping order",
            source: r#"
                import { Readable, Transform, Writable } from 'node:stream';
                import { pipeline } from 'node:stream/promises';
                const events = [];
                const chunks = [];
                const mapper = new Transform({
                  objectMode: true,
                  transform(chunk, encoding, callback) { events.push('map:' + chunk.value); callback(null, { value: chunk.value * 2 }); }
                });
                const sink = new Writable({
                  objectMode: true,
                  write(chunk, encoding, callback) { chunks.push(chunk.value); events.push('write:' + chunk.value); callback(); }
                });
                await pipeline(Readable.from([{ value: 2 }, { value: 4 }], { objectMode: true }), mapper, sink);
                events.push('pipeline:resolved');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "map:2,write:4,map:4,write:8,pipeline:resolved\n4,8",
        },
        EvalCase {
            ids: &["tc::stream::0058"],
            description: "_flush output reaches the sink before promise resolution",
            source: r#"
                import { Readable, Transform, Writable } from 'node:stream';
                import { pipeline } from 'node:stream/promises';
                const events = [];
                const chunks = [];
                const transform = new Transform({
                  transform(chunk, encoding, callback) { events.push('transform:' + String(chunk)); callback(null, chunk); },
                  flush(callback) { events.push('flush'); callback(null, 'tail'); }
                });
                const sink = new Writable({
                  write(chunk, encoding, callback) { events.push('write:' + String(chunk)); chunks.push(String(chunk)); callback(); }
                });
                await pipeline(Readable.from(['head']), transform, sink);
                events.push('pipeline:resolved');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "transform:head,write:head,flush,write:tail,pipeline:resolved\nhead,tail",
        },
    ]);
}

#[test]
#[ignore = "bd-fw7zd: pipe/unpipe slice not implemented yet"]
fn pipe_unpipe_and_event_emitter_inheritance() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0017", "tc::stream::0018"],
            description: "pipe returns the destination and finishes after ordered writes",
            source: r#"
                const { Readable, Writable } = require('stream');
                const source = Readable.from(['p1', 'p2']);
                const chunks = [];
                const sink = new Writable({ write(chunk, encoding, callback) { chunks.push(chunk.toString()); callback(); } });
                sink.on('finish', () => console.log(chunks.join(',')));
                console.log(source.pipe(sink) === sink);
            "#,
            expected: "true\np1,p2",
        },
        EvalCase {
            ids: &["tc::stream::0021"],
            description: "unpipe emits on the destination and stops later forwarding",
            source: r#"
                const { PassThrough, Writable } = require('stream');
                const source = new PassThrough();
                const chunks = [];
                const sink = new Writable({ write(chunk, encoding, callback) { chunks.push(chunk.toString()); callback(); } });
                sink.on('unpipe', () => console.log('unpipe-event'));
                source.pipe(sink);
                source.write('kept');
                setImmediate(() => {
                  source.unpipe(sink);
                  source.write('dropped');
                  setImmediate(() => console.log('got:' + chunks.join(',')));
                });
            "#,
            expected: "unpipe-event\ngot:kept",
        },
        EvalCase {
            ids: &["tc::stream::0062"],
            description: "ESM pipe event precedes writes, finish, and close",
            source: r#"
                import { once } from 'node:events';
                import { Readable, Writable } from 'node:stream';
                const events = [];
                const chunks = [];
                const source = Readable.from(['north', 'south']);
                const sink = new Writable({
                  write(chunk, encoding, callback) { chunks.push(String(chunk)); events.push('write:' + String(chunk)); callback(); }
                });
                sink.on('pipe', () => events.push('pipe'));
                sink.on('finish', () => events.push('finish'));
                sink.on('close', () => events.push('close'));
                source.pipe(sink);
                await once(sink, 'close');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "pipe,write:north,write:south,finish,close\nnorth,south",
        },
        EvalCase {
            ids: &["tc::stream::0063"],
            description: "ESM unpipe precedes manual destination finish and close",
            source: r#"
                import { once } from 'node:events';
                import { PassThrough, Writable } from 'node:stream';
                const events = [];
                const source = new PassThrough();
                const sink = new Writable({ write(chunk, encoding, callback) { events.push('write'); callback(); } });
                sink.on('pipe', () => events.push('pipe'));
                sink.on('unpipe', () => events.push('unpipe'));
                sink.on('finish', () => events.push('finish'));
                sink.on('close', () => events.push('close'));
                source.pipe(sink);
                source.write('before-unpipe');
                source.unpipe(sink);
                sink.end();
                source.end('after-unpipe');
                await once(sink, 'close');
                console.log(events.join(','));
            "#,
            expected: "pipe,write,unpipe,finish,close",
        },
    ]);

    let source = r#"
        const { PassThrough } = require('stream');
        const stream = new PassThrough();
        let onceCount = 0;
        console.log(stream.on('custom', () => console.log('on')) === stream);
        console.log(stream.once('custom', () => { onceCount++; console.log('once'); }) === stream);
        console.log(stream.emit('custom'));
        console.log(stream.emit('custom'));
        console.log('once-count:' + onceCount);
        stream.end();
    "#;
    assert_eq!(
        eval_console(source),
        "true\ntrue\non\nonce\ntrue\non\ntrue\nonce-count:1"
    );
}

#[test]
#[ignore = "bd-fw7zd: callback pipeline slice not implemented yet"]
fn callback_pipeline_success_error_and_three_stage_order() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0019"],
            description: "callback pipeline reports success after destination consumption",
            source: r#"
                const { pipeline, Readable, Writable } = require('stream');
                const sink = new Writable({ write(chunk, encoding, callback) { console.log('got:' + chunk.toString()); callback(); } });
                pipeline(Readable.from(['pl']), sink, (error) => console.log('clean:' + (error == null)));
            "#,
            expected: "got:pl\nclean:true",
        },
        EvalCase {
            ids: &["tc::stream::0020"],
            description: "callback pipeline preserves a source destroy error",
            source: r#"
                const { pipeline, Readable, Writable } = require('stream');
                const source = new Readable({ read() { this.destroy(new Error('src-fail')); } });
                const sink = new Writable({ write(chunk, encoding, callback) { callback(); } });
                pipeline(source, sink, (error) => console.log('err:' + (error ? error.message : 'none')));
            "#,
            expected: "err:src-fail",
        },
        EvalCase {
            ids: &["tc::stream::0039"],
            description: "three-stage callback pipeline transforms in order",
            source: r#"
                const { pipeline, Readable, Transform, Writable } = require('stream');
                const upper = new Transform({ transform(chunk, encoding, callback) { callback(null, chunk.toString().toUpperCase()); } });
                const output = [];
                const sink = new Writable({ write(chunk, encoding, callback) { output.push(chunk.toString()); callback(); } });
                pipeline(Readable.from(['aa', 'bb']), upper, sink, (error) => console.log((error == null) + ':' + output.join(',')));
            "#,
            expected: "true:AA,BB",
        },
    ]);
}

#[test]
#[ignore = "bd-fw7zd: promise pipeline slice not implemented yet"]
fn promise_pipeline_success_order_and_error_propagation() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0045"],
            description: "CJS stream.promises.pipeline resolves after writes",
            source: r#"
                const { promises, Readable, Writable } = require('stream');
                (async () => {
                  const output = [];
                  const sink = new Writable({ write(chunk, encoding, callback) { output.push(chunk.toString()); callback(); } });
                  await promises.pipeline(Readable.from(['pp1', 'pp2']), sink);
                  console.log('done:' + output.join(','));
                })();
            "#,
            expected: "done:pp1,pp2",
        },
        EvalCase {
            ids: &["tc::stream::0060"],
            description: "node:stream/promises resolves after source end and sink finish",
            source: r#"
                import { Readable, Writable } from 'node:stream';
                import { pipeline } from 'node:stream/promises';
                const events = [];
                const chunks = [];
                const source = Readable.from(['first', 'second']);
                const sink = new Writable({
                  write(chunk, encoding, callback) { events.push('write:' + String(chunk)); chunks.push(String(chunk)); callback(); }
                });
                source.on('end', () => events.push('source:end'));
                sink.on('finish', () => events.push('sink:finish'));
                await pipeline(source, sink);
                events.push('pipeline:resolved');
                console.log(events.join(','));
                console.log(chunks.join(','));
            "#,
            expected: "write:first,write:second,source:end,sink:finish,pipeline:resolved\nfirst,second",
        },
        EvalCase {
            ids: &["tc::stream::0061"],
            description: "promise pipeline rejects with the transform error and stops later data",
            source: r#"
                import { Readable, Transform, Writable } from 'node:stream';
                import { pipeline } from 'node:stream/promises';
                const events = [];
                const transform = new Transform({
                  transform(chunk, encoding, callback) {
                    const text = String(chunk);
                    events.push('transform:' + text);
                    callback(text === 'bad' ? new Error('transform-fail') : null, chunk);
                  }
                });
                const sink = new Writable({ write(chunk, encoding, callback) { events.push('write:' + String(chunk)); callback(); } });
                try {
                  await pipeline(Readable.from(['ok', 'bad', 'later']), transform, sink);
                  events.push('pipeline:resolved');
                } catch (error) {
                  events.push('pipeline:rejected:' + error.message);
                }
                console.log(events.join(','));
            "#,
            expected: "transform:ok,write:ok,transform:bad,pipeline:rejected:transform-fail",
        },
    ]);
}

#[test]
#[ignore = "bd-fw7zd: finished slice not implemented yet"]
fn finished_observes_readable_and_writable_completion() {
    assert_cases(&[
        EvalCase {
            ids: &["tc::stream::0025"],
            description: "finished reports consumed Readable completion",
            source: r#"
                const { finished, Readable } = require('stream');
                const readable = Readable.from(['f']);
                readable.on('data', () => {});
                finished(readable, (error) => console.log('finished:' + (error == null)));
            "#,
            expected: "finished:true",
        },
        EvalCase {
            ids: &["tc::stream::0026"],
            description: "finished reports Writable finish",
            source: r#"
                const { finished, Writable } = require('stream');
                const writable = new Writable({ write(chunk, encoding, callback) { callback(); } });
                finished(writable, (error) => console.log('wfinished:' + (error == null)));
                writable.end('done');
            "#,
            expected: "wfinished:true",
        },
    ]);
}

#[test]
fn unsupported_module_possession_computed_and_dynamic_forms_fail_closed() {
    for source in [
        "const stream = require('stream'); console.log(stream);",
        "const stream = require('node:stream'); console.log(stream.Readable);",
        "const stream = require('stream'); console.log(stream['Readable'].from(['x']));",
        "const stream = require('stream'); const key = 'Readable'; console.log(stream[key]);",
        "const name = 'stream'; const stream = require(name); console.log(stream);",
        "const stream = require('stream'); console.log(stream.unsupportedExport);",
        "const { Duplex } = require('stream'); console.log(Duplex);",
        "let { Readable } = require('stream'); Readable = { from(values) { return values; } }; console.log(Readable.from(['x']));",
        "var { Readable } = require('stream'); Readable = { from(values) { return values; } }; console.log(Readable.from(['x']));",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation")
                || error.contains("unsupported")
                || error.contains("not supported"),
            "unsupported stream access must fail closed, got {error:?} for {source:?}",
        );
    }
}

#[test]
fn unsupported_esm_namespace_possession_and_dynamic_import_fail_closed() {
    for source in [
        "import * as stream from 'node:stream'; console.log(stream);",
        "import { Readable, Writable } from 'node:stream'; const readable = Readable.from([]); console.log(readable, Writable);",
        "const name = 'node:stream'; import(name).then((stream) => console.log(stream));",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation")
                || error.contains("unsupported")
                || error.contains("not supported")
                || error.contains("dynamic import")
                || error.contains("type error"),
            "unsupported ESM stream possession must fail closed, got {error:?} for {source:?}",
        );
    }
}
