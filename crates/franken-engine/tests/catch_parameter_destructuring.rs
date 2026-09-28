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
