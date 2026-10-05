#![forbid(unsafe_code)]

//! bd-9vouw.182: the Array.prototype callback methods check IsCallable
//! before the first element (an empty or all-holes array threw nothing), and
//! the native element loops and Object.values read an accessor through its
//! getter (the engine's internal accessor value leaked: `map` gave NaN,
//! `indexOf` -1, Object.values "[object Object]"). Expected lines are Node
//! v22.2.0's output for the same programs, captured programmatically (Bun
//! 1.4.2 prints the same).

use frankenengine_engine::HybridRouter;

fn console_output(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

/// Every callback method throws a TypeError for a non-callable callback, also on an empty or all-holes array.
#[test]
fn callbacks_are_checked_before_the_first_element() {
    let source = "const out = [];\nfor (const m of ['every', 'some', 'forEach', 'map', 'filter', 'reduce', 'reduceRight', 'find', 'findIndex', 'findLast', 'findLastIndex', 'flatMap']) {\n  for (const [label, arr] of [['holes', new Array(3)], ['empty', []], ['full', [1]]]) {\n    try { m.startsWith('reduce') ? arr[m](null, 0) : arr[m](null); out.push(m + ':' + label + ':ok'); }\n    catch (e) { out.push(m + ':' + label + ':' + e.constructor.name); }\n  }\n}\nconsole.log(out.join(' '));\ntry { [].reduce(1); } catch (e) { console.log(e.constructor.name); }\n";
    assert_eq!(
        console_output(source),
        [
            "every:holes:TypeError every:empty:TypeError every:full:TypeError some:holes:TypeError some:empty:TypeError some:full:TypeError forEach:holes:TypeError forEach:empty:TypeError forEach:full:TypeError map:holes:TypeError map:empty:TypeError map:full:TypeError filter:holes:TypeError filter:empty:TypeError filter:full:TypeError reduce:holes:TypeError reduce:empty:TypeError reduce:full:TypeError reduceRight:holes:TypeError reduceRight:empty:TypeError reduceRight:full:TypeError find:holes:TypeError find:empty:TypeError find:full:TypeError findIndex:holes:TypeError findIndex:empty:TypeError findIndex:full:TypeError findLast:holes:TypeError findLast:empty:TypeError findLast:full:TypeError findLastIndex:holes:TypeError findLastIndex:empty:TypeError findLastIndex:full:TypeError flatMap:holes:TypeError flatMap:empty:TypeError flatMap:full:TypeError",
            "TypeError"
        ]
    );
}

/// An element defined with a getter is read through it, with the array as `this`, by the Array.prototype methods.
#[test]
fn accessor_elements_read_through_their_getters() {
    let source = "function make() {\n  const arr = [1, , 3];\n  Object.defineProperty(arr, '1', { get() { return 20; }, configurable: true, enumerable: true });\n  return arr;\n}\nconst seen = [];\nmake().forEach((v, i) => seen.push(i + '=' + v));\nconsole.log(seen.join(), make().map((v) => v * 2).join(), make().filter((v) => v > 2).join(), make().some((v) => v === 20), make().every((v) => v > 0));\nconsole.log(make().indexOf(20), make().lastIndexOf(20), make().includes(20), make().reduce((a, v) => a + v, 0), make().reduceRight((a, v) => a + ',' + v, ''), make().join('-'));\nconsole.log(make().find((v) => v > 10), make().findIndex((v) => v > 10), make().at(1), make().slice(1, 2)[0], make().concat([4]).join(), make().reverse().join(), make().pop(), make().toReversed().join());\nconst self = [];\nObject.defineProperty(self, '0', { get() { return this === self; } });\nlet gets = 0;\nconst counted = [0];\nObject.defineProperty(counted, '0', { get() { gets++; return 'g'; } });\ncounted.forEach(() => {});\ncounted.map((v) => v);\nconsole.log(self.map((v) => v)[0], gets);\n";
    assert_eq!(
        console_output(source),
        [
            "0=1,1=20,2=3 2,40,6 20,3 true true",
            "1 1 true 24 ,3,20,1 1-20-3",
            "20 1 20 20 1,20,3,4 3,20,1 3 3,20,1",
            "true 2"
        ]
    );
}

/// Object.values runs an accessor property's getter, as for a TypeScript-compiled re-export, and an accessor element's.
#[test]
fn object_values_reads_getters() {
    let source = "const plain = { get a() { return 1; }, b: 2 };\nconst exportsLike = {};\nObject.defineProperty(exportsLike, 'helper', { enumerable: true, get() { return 'lazy'; } });\nconst arr = [0];\nObject.defineProperty(arr, '0', { enumerable: true, get() { return 'element'; } });\nconsole.log(Object.values(plain).join(), Object.values(exportsLike).join(), Object.values(arr).join());\n";
    assert_eq!(console_output(source), ["1,2 lazy element"]);
}
