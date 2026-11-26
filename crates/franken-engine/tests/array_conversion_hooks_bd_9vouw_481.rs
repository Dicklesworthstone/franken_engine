//! bd-9vouw.481: whether an object has a guest conversion hook no longer depends on
//! whether %Object.prototype% was materialized: an ordinary object's default
//! prototype link reaches the intrinsic's virtual methods either way. This pins
//! Node v22.2.0's output for nested arrays (four conversion forms, 100, 200
//! and 1,000 levels deep and 10,000 levels a RangeError, before and
//! after Object.prototype is touched), matrices, plain, hooked, null-prototype,
//! class and @@toPrimitive objects, a cycle, and a patched
//! Array.prototype.toString, which nested arrays still observe.

use std::process::Command;

#[path = "support/persistent_scratch_dir.rs"]
mod persistent_scratch_dir;

const PROGRAM: &str = r#"function nest(depth) { var x = [1]; for (var i = 0; i < depth; i++) x = [x]; return x; }
function forms(x) { return [String(x), x.join(), "" + x, x.toString()].join("|"); }
function deep(depth) { try { return forms(nest(depth)); } catch (e) { return e.constructor.name + ": " + e.message; } }
console.log("deep", deep(200), deep(1000), deep(10000));
console.log("before", forms(nest(100)), forms([[1, 2], [3, [4, 5]]]), [[1, 2], [3, 4]].join(";"));
console.log(String({}), "" + { toString: function () { return "T"; } }, "" + { valueOf: function () { return 7; } }, [{ toString: function () { return "E"; } }, [8]].join());
try { console.log("" + Object.create(null)); } catch (e) { console.log(e.constructor.name); }
class C { toString() { return "C!"; } }
console.log([new C(), [new C()]].join("/"), [{ [Symbol.toPrimitive]: function (h) { return h; } }].join());
var touch = Object.prototype; touch.zz = 1; delete touch.zz;
console.log("deep after", deep(200), deep(1000), deep(10000));
console.log("after", forms(nest(100)), forms([[1, 2], [3, [4, 5]]]));
var a = [1, 2]; a.push(a);
console.log("cycle", a.join(), String([a, [a]]));
Array.prototype.toString = function () { return "P"; };
console.log("patched", [[1], [2]].join(), String([[1], 2]));
"#;

const EXPECTED: &[&str] = &[
    "deep 1|1|1|1 1|1|1|1 RangeError: Maximum call stack size exceeded",
    "before 1|1|1|1 1,2,3,4,5|1,2,3,4,5|1,2,3,4,5|1,2,3,4,5 1,2;3,4",
    "[object Object] T 7 E,8",
    "TypeError",
    "C!/C! string",
    "deep after 1|1|1|1 1|1|1|1 RangeError: Maximum call stack size exceeded",
    "after 1|1|1|1 1,2,3,4,5|1,2,3,4,5|1,2,3,4,5|1,2,3,4,5",
    "cycle 1,2, 1,2,,1,2,",
    "patched P,P P",
];

#[test]
fn array_conversion_hooks_match_node() {
    assert_console_output(PROGRAM, EXPECTED);
}

fn assert_console_output(program: &str, expected: &[&str]) {
    let root = persistent_scratch_dir::ScratchDir::new("bd_9vouw_481_hooks");
    let entry = root.path().join("array_conversion_hooks_bd_9vouw_481.js");
    std::fs::write(&entry, program).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "array-conversion-hooks",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(printed, expected);
}

#[test]
fn array_to_string_observes_join_receiver_and_intrinsic_fallback() {
    // ES2020 22.1.3.30. These expectations were also executed in a live
    // JavaScript reference runtime; the assertion runs the shipped CLI.
    let source = r#"const method = Array.prototype.toString;
const array = [1, 2];
array.join = null;
console.log(method.call(array));
const result = {};
const order = [];
Object.defineProperty(array, 'join', {configurable: true, get() {
  order.push('get:' + (this === array));
  return function() { order.push('call:' + (this === array) + ':' + arguments.length); return result; };
}});
console.log(method.call(array, 'ignored') === result, order.join('/'));
const parent = Object.create(Array.prototype);
Object.defineProperty(parent, 'join', {get() { return function() { return this[0] + 5; }; }});
const inherited = Object.setPrototypeOf([7], parent);
console.log(method.call(inherited));
const tagged = [3];
const tags = [];
Object.defineProperty(tagged, 'join', {get() { tags.push('join'); return undefined; }});
Object.defineProperty(tagged, Symbol.toStringTag, {get() { tags.push('tag'); return 'Tagged'; }});
console.log(method.call(tagged), tags.join('/'));
const nonStringTag = [4]; nonStringTag.join = false; nonStringTag[Symbol.toStringTag] = 123;
console.log(method.call(nonStringTag));
const trapOrder = [];
const proxy = new Proxy({join: null}, {get(target, key, receiver) {
  trapOrder.push((key === 'join' ? 'join' : key === Symbol.toStringTag ? 'tag' : 'other') + ':' + (receiver === proxy));
  return key === Symbol.toStringTag ? 'ProxyTag' : Reflect.get(target, key, receiver);
}});
console.log(method.call(proxy), trapOrder.join('/'));
const token = {};
const throwing = [8];
Object.defineProperty(throwing, 'join', {get() { throw token; }});
let caught = false;
try { method.call(throwing); } catch (error) { caught = error === token; }
console.log(caught, [1, 2].toString(), new Uint8Array([3, 4]).toString());
const tagThrow = {join: null};
Object.defineProperty(tagThrow, Symbol.toStringTag, {get() {throw token;}});
let tagCaught = false;
try { method.call(tagThrow); } catch (error) {tagCaught = error === token;}
console.log(tagCaught);
const errors = [];
for (const value of [null, undefined]) {
  try { method.call(value); errors.push('miss'); } catch (error) {errors.push(error.name);}
}
const revoked = Proxy.revocable([], {}); revoked.revoke();
try { method.call(revoked.proxy); errors.push('miss'); } catch (error) {errors.push(error.name);}
try { [1, 2].join(Symbol('separator')); errors.push('miss'); } catch (error) {errors.push(error.name);}
console.log(errors.join('/'));
const receivers = [function f() {}, Promise.resolve(), (function* () {})(), [1].values()];
const identities = [];
for (const receiver of receivers) {
  Object.defineProperty(receiver, 'join', {get() {
    const same = this === receiver;
    return function() {return same && this === receiver && arguments.length === 0;};
  }});
  identities.push(method.call(receiver));
}
console.log(identities.join('/'));
let boxed;
Object.defineProperty(Number.prototype, 'join', {configurable: true, get() {
  boxed = this;
  return function() { 'use strict'; return [typeof this, this === boxed, this.valueOf() === 7, arguments.length].join(':'); };
}});
try { console.log(method.call(7)); } finally {delete Number.prototype.join;}
const original = Object.prototype.toString;
try {
  Object.prototype.toString = function() {return 'patched';};
  console.log(method.call({join: 0}), Uint8Array.prototype.toString === method);
} finally {Object.prototype.toString = original;}
const callableTarget = {};
let calls = '';
const callableJoin = new Proxy(function() {return this === callableTarget;}, {
  apply(target, receiver, args) {calls += String(receiver === callableTarget) + ':' + args.length; return Reflect.apply(target, receiver, args);}
});
callableTarget.join = callableJoin;
console.log(method.call(callableTarget, 'ignored'), calls);
console.log(method.call({join() {return '\ud800';}}).charCodeAt(0), method.call({join() {}}) === undefined);
try { [].join(Symbol()); console.log('miss'); } catch(error) {console.log(error.name);}
"#;
    assert_console_output(
        source,
        &[
            "[object Array]",
            "true get:true/call:true:0",
            "12",
            "[object Tagged] join/tag",
            "[object Array]",
            "[object ProxyTag] join:true/tag:true",
            "true 1,2 3,4",
            "true",
            "TypeError/TypeError/TypeError/TypeError",
            "true/true/true/true",
            "object:true:true:0",
            "[object Object] true",
            "true true:0",
            "55296 true",
            "TypeError",
        ],
    );
}
