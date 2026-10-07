//! bd-305gi.1: the engine-owned `stream` module (lowering_pipeline/
//! stream_module.js) against Node v22.2.0, one event-order probe each.
//!
//! Each program logs what its streams do (data, readable, end, finish,
//! close, error, drain, pause/resume, callbacks) and prints the log from
//! a final timer. The expected line is Node's, captured by running the
//! probe under Node v22.2.0. The probes cover push/read modes, encodings,
//! Readable.from, async iteration, Writable buffering, cork/writev,
//! _final, construct, destroy, errors with Node's codes, Transform
//! subclassing through `class` and util.inherits, pipe backpressure,
//! pipeline (callback, promises and async-generator stages), Duplex and
//! the legacy Stream. Each probe reads `require('stream')` through a
//! namespace binding, a form the lowering facade never claims, so every
//! probe runs the module (the facade's own forms are pinned by
//! stream_builtin_bd_m8vaa).
//!
//! The 40th probe, f01 (finished and stream.promises.finished), is not
//! here: it never matched. Readable.from closes through a process.nextTick
//! queued inside a promise job, which Node runs after the whole microtask
//! queue drains and the engine runs between promise jobs (bd-9vouw.319).
//! It returns with that fix.

use frankenengine_engine::HybridRouter;

/// Large enough for every probe; the default lane budgets are a
/// containment posture, not part of what these probes check.
const INSTRUCTION_BUDGET: u64 = 200_000_000;

fn console_line(source: &str) -> String {
    let outcome = HybridRouter::default()
        .eval_with_instruction_budget(source, INSTRUCTION_BUDGET)
        .unwrap_or_else(|error| panic!("stream probe failed: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn c01_construct() {
    let source = r##"
const __stream = require('stream');
const { Readable, Writable } = __stream;
const log = [];
const r = new Readable({ construct(cb) { log.push('r-construct'); setTimeout(() => { log.push('r-constructed'); cb(); }, 5); }, read() { log.push('read'); this.push('x'); this.push(null); } });
r.on('data', (d) => log.push('data:' + d));
r.on('end', () => log.push('end'));
const w = new Writable({ construct(cb) { log.push('w-construct'); setTimeout(cb, 3); }, write(c, e, cb) { log.push('w:' + c); cb(); } });
w.write('early');
w.end();
w.on('finish', () => log.push('w-finish'));

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "r-construct w-construct w:early w-finish r-constructed read data:x end"
    );
}

#[test]
fn d01_duplex() {
    let source = r##"
const __stream = require('stream');
const { Duplex, Writable, Readable } = __stream;
const log = [];
const d = new Duplex({
  read() {},
  write(chunk, enc, cb) { log.push('got:' + chunk); this.push(String(chunk).toUpperCase()); cb(); },
  final(cb) { this.push(null); cb(); },
});
d.on('data', (x) => log.push('data:' + x));
d.on('end', () => log.push('end'));
d.on('finish', () => log.push('finish'));
d.on('close', () => log.push('close'));
d.write('hi'); d.end('yo');
log.push([d instanceof Writable, d instanceof Readable, d.allowHalfOpen, d.writable, d.readable].join(','));
const d2 = new Duplex({ allowHalfOpen: false, read() {}, write(c, e, cb) { cb(); } });
d2.on('finish', () => log.push('d2-finish'));
d2.on('end', () => log.push('d2-end'));
d2.resume(); d2.push(null);

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "got:hi got:yo true,true,true,false,true data:HI data:YO finish end d2-end close d2-finish"
    );
}

#[test]
fn e01_errors() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = new Readable({ read() {} });
r.on('error', (e) => log.push('err:' + e.code + ':' + e.message));
r.push(null);
r.push('late');
const r2 = new Readable({ read() {} });
r2.on('error', (e) => log.push('err2:' + e.code + ':' + e.message));
r2.push(42);
const r3 = new Readable();
r3.on('error', (e) => log.push('err3:' + e.code + ':' + e.message));
r3.resume();

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "err:ERR_STREAM_PUSH_AFTER_EOF:stream.push() after EOF err2:ERR_INVALID_ARG_TYPE:The \"chunk\" argument must be of type string or an instance of Buffer, TypedArray, or DataView. Received type number (42) err3:ERR_METHOD_NOT_IMPLEMENTED:The _read() method is not implemented"
    );
}

#[test]
fn e02_iter_error() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
(async () => {
  const r = new Readable({ objectMode: true, read() {} });
  r.push(1);
  setTimeout(() => r.destroy(new Error('mid')), 5);
  try { for await (const v of r) log.push('v:' + v); } catch (e) { log.push('caught:' + e.message); }
  log.push('destroyed:' + r.destroyed);
})();

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "v:1 caught:mid destroyed:true");
}

#[test]
fn e03_premature() {
    let source = r##"
const __stream = require('stream');
const { pipeline, PassThrough, Writable } = __stream;
const log = [];
const src = new PassThrough();
const dst = new Writable({ write(c, e, cb) { cb(); } });
pipeline(src, dst, (err) => log.push('pipeline:' + (err && err.code)));
src.write('x');
setTimeout(() => dst.destroy(), 5);

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "pipeline:ERR_STREAM_PREMATURE_CLOSE");
}

#[test]
fn l01_legacy_stream() {
    let source = r##"
const __stream = require('stream');
const Stream = __stream;
const log = [];
log.push(typeof Stream + ':' + (Stream.Stream === Stream) + ':' + typeof Stream.Readable + ':' + typeof Stream.promises.pipeline);
const s = new Stream();
s.readable = true;
const { Writable } = Stream;
const w = new Writable({ write(c, e, cb) { log.push('w:' + c); cb(); } });
s.pipe(w);
s.emit('data', 'legacy');
s.emit('end');
w.on('finish', () => log.push('finish'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "function:true:function:function w:legacy finish"
    );
}

#[test]
fn m01_member_access() {
    let source = r##"
const __stream = require('stream');
const stream = __stream;
const log = [];
class Counter extends stream.Readable {
  constructor(max) { super({ objectMode: true }); this.n = 0; this.max = max; }
  _read() { this.n++; this.push(this.n <= this.max ? this.n : null); }
}
class Sum extends stream.Writable {
  constructor() { super({ objectMode: true }); this.total = 0; }
  _write(n, e, cb) { this.total += n; cb(); }
  _final(cb) { log.push('final:' + this.total); cb(); }
}
const s = new Sum();
new Counter(4).pipe(s).on('finish', () => log.push('sum:' + s.total));

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "final:10 sum:10");
}

#[test]
fn p01_pipe_chain() {
    let source = r##"
const __stream = require('stream');
const { Readable, PassThrough, Writable } = __stream;
const log = [];
const sink = new Writable({ write(c, e, cb) { log.push('sink:' + c); cb(); } });
sink.on('finish', () => log.push('finish'));
sink.on('pipe', () => log.push('pipe-event'));
const pt = new PassThrough();
pt.on('end', () => log.push('pt-end'));
Readable.from(['1', '2', '3'], { objectMode: false }).pipe(pt).pipe(sink);

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "pipe-event sink:1 sink:2 sink:3 pt-end finish"
    );
}

#[test]
fn p02_pipe_backpressure() {
    let source = r##"
const __stream = require('stream');
const { Readable, Writable } = __stream;
const log = [];
let i = 0;
const src = new Readable({ highWaterMark: 2, objectMode: true, read() { i++; log.push('read' + i); this.push(i <= 5 ? i : null); } });
const slow = new Writable({ objectMode: true, highWaterMark: 1, write(c, e, cb) { log.push('w' + c); setTimeout(cb, 2); } });
slow.on('finish', () => log.push('finish'));
src.pipe(slow);

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "read1 read2 w1 read3 read4 w2 read5 w3 read6 w4 w5 finish"
    );
}

#[test]
fn p03_pipeline_cb() {
    let source = r##"
const __stream = require('stream');
const { pipeline, Readable, Transform, Writable } = __stream;
const log = [];
const out = [];
pipeline(
  Readable.from(['a', 'b']),
  new Transform({ transform(c, e, cb) { cb(null, String(c) + String(c)); } }),
  new Writable({ write(c, e, cb) { out.push(String(c)); cb(); } }),
  (err) => log.push('done:' + err + ':' + out.join(',')),
);
const bad = new Transform({ transform(c, e, cb) { cb(new Error('bad chunk')); } });
const w2 = new Writable({ write(c, e, cb) { cb(); } });
pipeline(Readable.from(['x']), bad, w2, (err) => log.push('err:' + err.message + ':' + bad.destroyed + ':' + w2.destroyed));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "err:bad chunk:true:true done:undefined:aa,bb"
    );
}

#[test]
fn p04_pipeline_promise() {
    let source = r##"
const __stream = require('stream');
const { Readable, Writable } = __stream;
const { pipeline } = require('stream/promises');
const log = [];
const out = [];
(async () => {
  await pipeline(
    Readable.from([1, 2, 3]),
    async function* (source) { for await (const n of source) yield n * 10; },
    new Writable({ objectMode: true, write(c, e, cb) { out.push(c); cb(); } }),
  );
  log.push('out:' + out.join(','));
  try {
    await pipeline(Readable.from([1]), async function* (s) { for await (const n of s) throw new Error('gen fail ' + n); }, new Writable({ objectMode: true, write(c, e, cb) { cb(); } }));
  } catch (e) { log.push('caught:' + e.message); }
  const res = await pipeline(Readable.from(['q']), async (source) => { let s = ''; for await (const c of source) s += c; return s.toUpperCase(); });
  log.push('res:' + res);
})();

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(console_line(source), "out:10,20,30 caught:gen fail 1 res:Q");
}

#[test]
fn p05_multi_dest() {
    let source = r##"
const __stream = require('stream');
const { Readable, Writable } = __stream;
const log = [];
function sink(name, delay) { return new Writable({ highWaterMark: 1, objectMode: true, write(c, e, cb) { log.push(name + c); setTimeout(cb, delay); } }); }
const src = Readable.from([1, 2, 3]);
const a = sink('a', 1); const b = sink('b', 4);
a.on('finish', () => log.push('a-fin')); b.on('finish', () => log.push('b-fin'));
src.pipe(a); src.pipe(b);

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "a1 b1 a2 b2 a3 b3 a-fin b-fin");
}

#[test]
fn p06_unpipe() {
    let source = r##"
const __stream = require('stream');
const { PassThrough, Writable } = __stream;
const log = [];
const src = new PassThrough();
const w = new Writable({ write(c, e, cb) { log.push('w:' + c); cb(); } });
w.on('unpipe', () => log.push('unpipe-event'));
src.pipe(w);
src.write('one');
setTimeout(() => { src.unpipe(w); log.push('flowing:' + src.readableFlowing); src.write('two'); setTimeout(() => log.push('len:' + src.readableLength), 5); }, 5);

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "w:one unpipe-event flowing:false len:3"
    );
}

#[test]
fn r01_push_data() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
let n = 0;
const r = new Readable({ read() { n++; if (n <= 3) this.push('c' + n); else this.push(null); } });
r.on('data', (d) => log.push('data:' + d + ':' + Buffer.isBuffer(d)));
r.on('end', () => log.push('end'));
r.on('close', () => log.push('close'));
log.push('sync-done');
Promise.resolve().then(() => log.push('micro'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "sync-done data:c1:true data:c2:true data:c3:true end close micro"
    );
}

#[test]
fn r02_readable_event() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = new Readable({ read() {} });
r.push('ab'); r.push('cd'); r.push(null);
r.on('readable', () => { let c; while ((c = r.read()) !== null) log.push('read:' + c); log.push('readable-done'); });
r.on('end', () => log.push('end'));
r.on('close', () => log.push('close'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "read:abcd readable-done readable-done end close"
    );
}

#[test]
fn r03_object_mode() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = new Readable({ objectMode: true, read() {} });
r.push({ a: 1 }); r.push([2]); r.push(3); r.push(null);
r.on('data', (d) => log.push('data:' + JSON.stringify(d)));
r.on('end', () => log.push('end:' + r.readableEnded + ':' + r.readableLength));
log.push('hwm:' + r.readableHighWaterMark + ':' + r.readableObjectMode + ':' + r.readableFlowing);

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "hwm:16:true:true data:{\"a\":1} data:[2] data:3 end:true:0"
    );
}

#[test]
fn r04_from_variants() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
Readable.from(['a', 'b', 'c']).on('data', (d) => log.push('arr:' + d)).on('end', () => log.push('arr-end'));
Readable.from('whole').on('data', (d) => log.push('str:' + d));
function* gen() { yield 1; yield 2; }
Readable.from(gen()).on('data', (d) => log.push('gen:' + d)).on('end', () => log.push('gen-end'));
async function* agen() { yield 'x'; await null; yield 'y'; }
Readable.from(agen()).on('data', (d) => log.push('agen:' + d)).on('end', () => log.push('agen-end'));
Readable.from([Promise.resolve('p1'), 'p2']).on('data', (d) => log.push('prom:' + d));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "arr:a arr:b arr:c str:whole gen:1 gen:2 arr-end gen-end prom:p1 prom:p2 agen:x agen:y agen-end"
    );
}

#[test]
fn r05_set_encoding() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const bytes = Buffer.from('héllo wörld €');
const r = new Readable({ read() {} });
r.setEncoding('utf8');
for (let i = 0; i < bytes.length; i += 3) r.push(bytes.slice(i, i + 3));
r.push(null);
r.on('data', (d) => log.push(typeof d + ':' + d));
r.on('end', () => log.push('end:' + r.readableEncoding));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "string:hé string:llo string: w string:örl string:d  string:€ end:utf8"
    );
}

#[test]
fn r06_async_iter() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
(async () => {
  const r = new Readable({ objectMode: true, read() {} });
  setTimeout(() => { r.push(1); r.push(2); setTimeout(() => { r.push(3); r.push(null); }, 5); }, 5);
  for await (const v of r) log.push('v:' + v);
  log.push('done:' + r.destroyed);
  const r2 = Readable.from(['a', 'b', 'c']);
  for await (const v of r2) { log.push('b:' + v); if (v === 'b') break; }
  log.push('broke:' + r2.destroyed);
  log.push('arr:' + (await Readable.from([4, 5, 6]).toArray()).join(','));
})();

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "v:1 v:2 v:3 done:true b:a b:b broke:true arr:4,5,6"
    );
}

#[test]
fn r07_destroy_error() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = new Readable({ read() {} });
r.on('error', (e) => log.push('error:' + e.message));
r.on('close', () => log.push('close:' + r.destroyed + ':' + (r.errored && r.errored.message)));
r.destroy(new Error('boom'));
log.push('after:' + r.destroyed);
const r2 = new Readable({ read() {}, destroy(err, cb) { log.push('custom-destroy:' + err); cb(err); } });
r2.on('close', () => log.push('close2'));
r2.destroy();

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "after:true custom-destroy:null error:boom close:true:boom close2"
    );
}

#[test]
fn r08_unshift_readn() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = new Readable({ read() {} });
r.push('hello'); r.push('world'); r.push(null);
r.once('readable', () => {
  const a = r.read(3); log.push('a:' + a);
  r.unshift(Buffer.from('XY'));
  const b = r.read(4); log.push('b:' + b);
  const c = r.read(); log.push('c:' + c);
  const d = r.read(); log.push('d:' + d);
});
r.on('end', () => log.push('end'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(console_line(source), "a:hel b:XYlo c:world d:null end");
}

#[test]
fn r09_pause_resume() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = Readable.from([1, 2, 3, 4]);
r.on('data', (d) => { log.push('d' + d); if (d === 2) { r.pause(); log.push('paused:' + r.isPaused()); setTimeout(() => { log.push('resume'); r.resume(); }, 5); } });
r.on('pause', () => log.push('ev-pause'));
r.on('resume', () => log.push('ev-resume'));
r.on('end', () => log.push('end'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "ev-resume d1 d2 ev-pause paused:true resume ev-resume d3 d4 end"
    );
}

#[test]
fn r10_wrap() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const EventEmitter = require('events');
const log = [];
const old = new EventEmitter();
old.pause = () => log.push('old-pause');
old.resume = () => log.push('old-resume');
const r = new Readable({ objectMode: true }).wrap(old);
r.on('data', (d) => log.push('d:' + d));
r.on('end', () => log.push('end'));
old.emit('data', 'a'); old.emit('data', 'b'); old.emit('end');

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "d:a d:b end");
}

#[test]
fn r11_flowing_state() {
    let source = r##"
const __stream = require('stream');
const { Readable, PassThrough } = __stream;
const log = [];
const r = new PassThrough();
log.push('init:' + r.readableFlowing + ':' + r.isPaused());
r.pause(); log.push('paused:' + r.readableFlowing + ':' + r.isPaused());
r.on('data', (d) => log.push('d:' + d));
log.push('after-on:' + r.readableFlowing);
r.resume(); log.push('resumed:' + r.readableFlowing + ':' + r.isPaused());
r.write('q'); r.end();
r.on('end', () => log.push('end:' + r.readableEnded + ':' + r.readable));

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "init:null:false paused:false:true after-on:false resumed:true:false d:q end:true:false"
    );
}

#[test]
fn r12_readable_hwm() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
let calls = 0;
const r = new Readable({ highWaterMark: 6, read(size) { calls++; log.push('read(' + size + ')'); if (calls <= 3) this.push('abcd'); else this.push(null); } });
r.on('readable', () => { log.push('readable:' + r.readableLength); let c; while ((c = r.read(5)) !== null) log.push('got:' + c); });
r.on('end', () => log.push('end'));

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "read(6) readable:4 read(6) got:abcda read(6) got:bcdab read(6) got:cd readable:0 readable:0 end"
    );
}

#[test]
fn r13_multibyte_read() {
    let source = r##"
const __stream = require('stream');
const { Readable } = __stream;
const log = [];
const r = new Readable({ encoding: 'utf8', read() {} });
r.push(Buffer.from([0xe2, 0x82]));
r.push(Buffer.from([0xac, 0x41]));
r.push(null);
r.on('data', (d) => log.push(JSON.stringify(d)));
r.on('end', () => log.push('end'));

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "\"€A\" end");
}

#[test]
fn s01_statics() {
    let source = r##"
const __stream = require('stream');
const stream = __stream;
const log = [];
const r = stream.Readable.from(['a']);
log.push('isReadable:' + stream.isReadable(r) + ':' + stream.isErrored(r) + ':' + stream.isDisturbed(r));
r.resume();
r.on('end', () => setTimeout(() => log.push('later:' + stream.isReadable(r) + ':' + stream.isDisturbed(r) + ':' + stream.isDestroyed(r)), 0));
const w = new stream.Writable({ write(c, e, cb) { cb(new Error('w-fail')); } });
w.on('error', () => log.push('err:' + stream.isErrored(w) + ':' + stream.isWritable(w)));
w.write('x');
log.push('keys:' + ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough', 'pipeline', 'finished', 'promises', 'Stream'].map((k) => typeof stream[k]).join(','));

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "isReadable:true:false:false keys:function,function,function,function,function,function,function,object,function err:true:false later:false:true:true"
    );
}

#[test]
fn t01_class_transform() {
    let source = r##"
const __stream = require('stream');
const { Transform, Readable, Writable, Duplex, Stream } = __stream;
const EventEmitter = require('events');
const log = [];
class Upper extends Transform {
  _transform(chunk, enc, cb) { cb(null, String(chunk).toUpperCase()); }
  _flush(cb) { this.push('!'); cb(); }
}
const t = new Upper();
t.on('data', (d) => log.push('data:' + d));
t.on('end', () => log.push('end'));
t.on('finish', () => log.push('finish'));
t.on('close', () => log.push('close'));
t.write('ab'); t.write('cd'); t.end();
log.push([t instanceof Transform, t instanceof Duplex, t instanceof Readable, t instanceof Writable, t instanceof Stream, t instanceof EventEmitter].join(','));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "data:AB data:CD data:! true,true,true,true,true,true end finish close"
    );
}

#[test]
fn t02_inherits_transform() {
    let source = r##"
const __stream = require('stream');
const stream = __stream;
const util = require('util');
const log = [];
function Rev(options) { if (!(this instanceof Rev)) return new Rev(options); stream.Transform.call(this, options); }
util.inherits(Rev, stream.Transform);
Rev.prototype._transform = function (chunk, enc, cb) { this.push(String(chunk).split('').reverse().join('')); cb(); };
const t = Rev();
t.on('data', (d) => log.push('d:' + d));
t.on('end', () => log.push('end'));
t.end('abc');
const t2 = new stream.Transform({ objectMode: true, transform(o, e, cb) { cb(null, o * 2); } });
t2.on('data', (d) => log.push('o:' + d));
t2.write(1); t2.write(2); t2.end();

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(console_line(source), "d:cba o:2 o:4 end");
}

#[test]
fn t03_line_splitter() {
    let source = r##"
const __stream = require('stream');
const { Transform, Readable } = __stream;
const log = [];
class Lines extends Transform {
  constructor() { super({ readableObjectMode: true }); this.rest = ''; }
  _transform(chunk, enc, cb) { const parts = (this.rest + chunk).split('\n'); this.rest = parts.pop(); for (const p of parts) this.push(p); cb(); }
  _flush(cb) { if (this.rest) this.push(this.rest); cb(); }
}
Readable.from(['a\nb', 'c\nd\n', 'e']).pipe(new Lines()).on('data', (l) => log.push('line:' + l)).on('end', () => log.push('end'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(console_line(source), "line:a line:bc line:d line:e end");
}

#[test]
fn t04_hwm_zero() {
    let source = r##"
const __stream = require('stream');
const { Transform, Readable } = __stream;
const log = [];
const t = new Transform({ objectMode: true, highWaterMark: 0, transform(c, e, cb) { log.push('t' + c); cb(null, c); } });
t.on('data', (d) => log.push('d' + d));
t.on('end', () => log.push('end'));
Readable.from([1, 2, 3]).pipe(t);
log.push('hwm:' + t.readableHighWaterMark + ':' + t.writableHighWaterMark);

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(console_line(source), "hwm:0:0 t1 d1 t2 d2 t3 d3 end");
}

#[test]
fn w01_basic() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({ write(chunk, enc, cb) { log.push('write:' + chunk + ':' + enc + ':' + Buffer.isBuffer(chunk)); cb(); } });
w.on('finish', () => log.push('finish:' + w.writableFinished));
w.on('close', () => log.push('close'));
log.push('ret:' + w.write('a', () => log.push('cb-a')));
w.write('b');
w.end('c', () => log.push('end-cb'));
log.push('ended:' + w.writableEnded + ':' + w.writable);

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "write:a:buffer:true ret:true write:b:buffer:true write:c:buffer:true ended:true:false cb-a end-cb finish:true close"
    );
}

#[test]
fn w02_backpressure() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({ highWaterMark: 4, write(chunk, enc, cb) { log.push('w:' + chunk); setTimeout(cb, 1); } });
w.on('drain', () => log.push('drain'));
log.push('r1:' + w.write('ab'));
log.push('r2:' + w.write('cd'));
log.push('need:' + w.writableNeedDrain + ':' + w.writableLength);
w.on('finish', () => log.push('finish'));
setTimeout(() => w.end(), 20);

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "w:ab r1:true r2:false need:true:4 w:cd drain finish"
    );
}

#[test]
fn w03_writev_cork() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({
  write(chunk, enc, cb) { log.push('single:' + chunk); cb(); },
  writev(chunks, cb) { log.push('writev:' + chunks.map((c) => String(c.chunk)).join('|')); cb(); },
});
w.cork(); w.write('a'); w.write('b'); w.write('c');
log.push('corked:' + w.writableCorked);
process.nextTick(() => w.uncork());
setTimeout(() => { w.write('d'); w.end(); }, 5);
w.on('finish', () => log.push('finish'));

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "corked:1 writev:a|b|c single:d finish"
    );
}

#[test]
fn w04_final() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({
  write(chunk, enc, cb) { log.push('write'); cb(); },
  final(cb) { log.push('final'); setTimeout(() => { log.push('final-done'); cb(); }, 2); },
});
w.on('prefinish', () => log.push('prefinish'));
w.on('finish', () => log.push('finish'));
w.on('close', () => log.push('close'));
w.end('x');

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "write final final-done prefinish finish close"
    );
}

#[test]
fn w05_write_after_end() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({ write(c, e, cb) { cb(); } });
w.on('error', (e) => log.push('error:' + e.code + ':' + e.message));
w.end();
w.write('late', (e) => log.push('cb:' + (e && e.code)));
try { w.write(null); } catch (e) { log.push('null:' + e.code + ':' + e.message); }
try { new Writable({ write(c, e, cb) { cb(); } }).write(42); } catch (e) { log.push('num:' + e.code + ':' + e.message); }

setTimeout(() => console.log(log.join(' ')), 100);
"##;
    assert_eq!(
        console_line(source),
        "null:ERR_STREAM_NULL_VALUES:May not write null values to stream num:ERR_INVALID_ARG_TYPE:The \"chunk\" argument must be of type string or an instance of Buffer, TypedArray, or DataView. Received type number (42) cb:ERR_STREAM_WRITE_AFTER_END error:ERR_STREAM_WRITE_AFTER_END:write after end"
    );
}

#[test]
fn w06_decode_false() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({ decodeStrings: false, write(c, e, cb) { log.push(typeof c + ':' + e + ':' + c); cb(); } });
w.write('abc');
w.write('6869', 'hex');
w.setDefaultEncoding('latin1');
w.write('z');
const w2 = new Writable({ write(c, e, cb) { log.push('w2:' + e + ':' + c.toString('hex')); cb(); } });
w2.write('6869', 'hex');
try { w2.setDefaultEncoding('nope'); } catch (e) { log.push(e.code + ':' + e.message); }

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "string:utf8:abc string:hex:6869 string:latin1:z w2:buffer:6869 ERR_UNKNOWN_ENCODING:Unknown encoding: nope"
    );
}

#[test]
fn w07_destroy_pending() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({ write(c, e, cb) { log.push('w:' + c); setTimeout(cb, 5); } });
w.write('a', (e) => log.push('cb-a:' + (e && e.code)));
w.write('b', (e) => log.push('cb-b:' + (e && e.code)));
w.end((e) => log.push('end-cb:' + (e && e.code)));
w.on('error', (e) => log.push('error:' + e.message));
w.on('close', () => log.push('close'));
w.destroy();
log.push('destroyed:' + w.destroyed);

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "w:a destroyed:true close cb-a:null cb-b:ERR_STREAM_DESTROYED end-cb:ERR_STREAM_DESTROYED"
    );
}

#[test]
fn w08_end_twice() {
    let source = r##"
const __stream = require('stream');
const { Writable } = __stream;
const log = [];
const w = new Writable({ write(c, e, cb) { cb(); } });
w.on('error', (e) => log.push('error:' + e.code));
w.end('a');
w.end((e) => log.push('second:' + (e && e.code)));
w.on('finish', () => { log.push('finish'); w.end((e) => log.push('third:' + (e && e.code))); });

setTimeout(() => console.log(log.join(' ')), 120);
"##;
    assert_eq!(
        console_line(source),
        "second:null finish third:ERR_STREAM_ALREADY_FINISHED"
    );
}
