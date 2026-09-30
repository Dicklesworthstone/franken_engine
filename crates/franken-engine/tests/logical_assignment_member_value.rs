//! ES2021 12.15.2 logical assignment to a member target: `o.k ||= v`,
//! `o[k] &&= v`, `o[k] ??= v`. When the operator short-circuits, the value is
//! the current property value; otherwise it is the assigned RHS value. The
//! lowering left a value on the stack from each path, and the two paths used
//! different registers, so a short-circuited member logical assignment
//! evaluated to whatever the assignment path's register held (undefined or a
//! stale value). The everyday grouping and memoisation idioms
//! `(acc[k] ||= []).push(x)` and `cache[k] ??= compute(k)` broke on the second
//! use of a key. Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn member_logical_assignment_yields_the_current_or_assigned_value() {
    let source = "const out = [];\n\
                  const o = {k: [1], z: 0, n: 3, u: undefined};\n\
                  out.push((o.k ||= []) === o.k, (o.z &&= 5), (o.n ??= 9));\n\
                  const key = 'k';\n\
                  out.push((o[key] ||= []) === o.k, (o['z'] ||= 'set'), (o.u ??= 'dflt'), o.z, o.u);\n\
                  const groups = ['apple', 'avocado', 'banana', 'blueberry', 'cherry'].reduce((acc, it) => {\n\
                    (acc[it[0]] ||= []).push(it);\n\
                    return acc;\n\
                  }, {});\n\
                  out.push(JSON.stringify(groups));\n\
                  const cache = {};\n\
                  let computed = 0;\n\
                  const get = k => (cache[k] ??= (computed++, k.toUpperCase()));\n\
                  out.push(get('a') + get('a') + get('b'), computed);\n\
                  let sets = 0;\n\
                  const target = { get v() { return 1; }, set v(x) { sets++; } };\n\
                  out.push((target.v ||= 2), (target.v &&= 7), sets);\n\
                  out.join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "true 0 3 true set dflt set dflt \
         {\"a\":[\"apple\",\"avocado\"],\"b\":[\"banana\",\"blueberry\"],\"c\":[\"cherry\"]} \
         AAB 2 1 7 1"
    );
}
