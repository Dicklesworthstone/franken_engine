//! ES2020 13.15.7: a catch clause parameter may be a destructuring pattern,
//! `catch ({ message })` or `catch ([a, b])`, binding the pattern's names from
//! the thrown value (and throwing a TypeError when that value is null or
//! undefined). FrankenEngine kept the pattern's source text as the parameter
//! name, so none of the names were bound and the first use failed with
//! "m is not defined". Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn catch_parameter_patterns_bind_their_names() {
    let source = "const out = [];\n\
                  try { throw {m: 1, n: 2}; } catch ({m, n}) { out.push(m + n); }\n\
                  try { throw [3, 4]; } catch ([a, b]) { out.push(a * b); }\n\
                  try { throw {}; } catch ({m = 5}) { out.push(m); }\n\
                  try { throw {a: {b: 6}}; } catch ({a: {b}}) { out.push(b); }\n\
                  try { throw {a: 1, b: 2, c: 3}; } catch ({a, ...rest}) { out.push(a + ':' + Object.keys(rest).join('')); }\n\
                  try { throw new Error('boom'); } catch ({message}) { out.push(message); }\n\
                  const fns = [];\n\
                  for (const v of [7, 8]) { try { throw {v}; } catch ({v: w}) { fns.push(() => w); } }\n\
                  out.push(fns.map(f => f()).join('+'));\n\
                  for (const thrown of [null, undefined]) {\n\
                    try { try { throw thrown; } catch ({m}) { out.push('no throw'); } } catch (e) { out.push(e instanceof TypeError); }\n\
                  }\n\
                  let m = 'outer';\n\
                  try { throw {m: 'inner'}; } catch ({m}) { out.push(m); }\n\
                  out.push(m);\n\
                  out.join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "3 12 5 6 1:bc boom 7+8 true true inner outer");
}

/// ES2020 13.15.7: every entry to a catch clause creates a fresh environment,
/// so closures made in different loop iterations keep their own catch
/// parameter and catch-body bindings. They all shared one cell and saw the
/// last value (`8+8` for the first case). Expected string is Node v22.2.0's.
#[test]
fn catch_bindings_are_fresh_on_each_entry_in_a_loop() {
    let source = "const out = [];\n\
                  const a = []; for (const v of [7, 8]) { try { throw v; } catch (w) { a.push(() => w); } } out.push(a.map(f => f()).join('+'));\n\
                  const b = []; for (let i = 0; i < 2; i++) { try { throw {v: i}; } catch ({v: w}) { b.push(() => w); } } out.push(b.map(f => f()).join('+'));\n\
                  const c = []; for (const v of [7, 8]) { try { throw v; } catch (e) { let w = e * 2; c.push(() => w); } } out.push(c.map(f => f()).join('+'));\n\
                  const d = []; let k = 0; while (k < 2) { try { throw k; } catch (e) { d.push(() => e); } k++; } out.push(d.map(f => f()).join('+'));\n\
                  const e2 = []; for (const v of [1, 2]) { try { throw v; } catch (e) { e = e * 10; e2.push(() => e); } } out.push(e2.map(f => f()).join('+'));\n\
                  const g = []; for (const v of [3, 4]) { try { throw v; } catch (e) { g.push(() => e); } finally { g.push(() => v); } } out.push(g.map(f => f()).join('+'));\n\
                  out.join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "7+8 0+1 14+16 0+1 10+20 3+3+4+4");
}
