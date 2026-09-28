//! ES2020 21.2.5.13: RegExp.prototype.test is `RegExpExec(R, S) !== null`, so
//! a global or sticky regex reads and advances `lastIndex` exactly like
//! `exec`. FrankenEngine's test ignored `lastIndex` and the flags: a /g regex
//! answered true forever (`while (re.test(s)) n++` never ended) and a sticky
//! regex matched anywhere. Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn global_and_sticky_test_advance_last_index() {
    let source = "const r = /a/g; const s = 'aXa'; \
                  const a = [r.test(s), r.lastIndex, r.test(s), r.lastIndex, r.test(s), r.lastIndex];\n\
                  const y = /a/y; y.lastIndex = 1; a.push(y.test('ba'), y.lastIndex, y.test('ba'), y.lastIndex);\n\
                  const re = /o/g; let n = 0; while (re.test('foo boo')) n++; a.push(n);\n\
                  const plain = /a/; a.push(plain.test('bab'), plain.lastIndex);\n\
                  a.join(',');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "true,1,true,3,false,0,true,2,false,0,4,true,0");
}
