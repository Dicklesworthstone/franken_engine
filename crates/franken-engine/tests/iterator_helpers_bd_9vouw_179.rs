#![forbid(unsafe_code)]

//! bd-9vouw.179: ES2025 Iterator helpers as Node v22.2.0 ships them: the
//! abstract `Iterator` constructor, `Iterator.from`, and the lazy (`map`,
//! `filter`, `take`, `drop`, `flatMap`) and eager (`reduce`, `toArray`,
//! `forEach`, `some`, `every`, `find`) methods of %IteratorPrototype%.
//! Expected lines are Node v22.2.0's output for the same programs, captured
//! programmatically (Bun 1.4.2 prints the same lines except for the two
//! constructor error messages).

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

/// map, filter, take, drop and flatMap over array iterators and an infinite generator.
#[test]
fn lazy_helpers_over_arrays_and_generators() {
    let source = "function* nat() { let i = 0; while (true) yield i++; }\nconsole.log([1, 2, 3].values().map((x) => x * 2).toArray().join());\nconsole.log(nat().filter((x) => x % 2).map((x) => x * x).take(4).toArray().join());\nconsole.log(nat().drop(3).take(3).toArray().join());\nconsole.log([[1, 2], [3]].values().flatMap((a) => a).toArray().join());\nconsole.log([...new Set(['a', 'b']).values().map((s, i) => s + i)].join());\n";
    assert_eq!(
        console_output(source),
        ["2,4,6", "1,9,25,49", "3,4,5", "1,2,3", "a0,b1"]
    );
}

/// reduce, toArray, forEach, some, every and find, with counters.
#[test]
fn eager_helpers() {
    let source = "function* nat() { let i = 0; while (true) yield i++; }\nconsole.log(nat().take(5).reduce((a, b) => a + b), nat().take(5).reduce((a, b) => a + b, 10));\nconsole.log(nat().some((x) => x > 3), nat().take(3).every((x) => x < 3), nat().find((x) => x > 5));\nconst seen = [];\n[7, 8].values().forEach((v, i) => seen.push(v + ':' + i));\nconsole.log(seen.join());\ntry { [].values().reduce((a, b) => a + b); } catch (e) { console.log(e.constructor.name); }\n";
    assert_eq!(
        console_output(source),
        ["10 20", "true true 6", "7:0,8:1", "TypeError"]
    );
}

/// Iterator.from wraps a plain iterator; a helper's next/return and closing.
#[test]
fn iterator_from_and_helper_protocol() {
    let source = "let closed = 0;\nconst it = { i: 0, next() { return this.i < 3 ? { value: this.i++, done: false } : { value: undefined, done: true }; }, return() { closed++; return {}; } };\nconst w = Iterator.from(it);\nconsole.log(Object.getPrototypeOf(w) === Iterator.prototype, w instanceof Iterator, w.take(2).toArray().join(), closed);\nconst h = [1, 2, 3].values().map((x) => x);\nconsole.log(h.next().value, h.return().done, h.next().done);\nconsole.log(Object.prototype.toString.call(h), h instanceof Iterator, typeof h[Symbol.iterator], h[Symbol.iterator]() === h);\nconst g = (function* () { yield 1; })();\nconsole.log(Iterator.from(g) === g, Iterator.from('ab').toArray().join());\n";
    assert_eq!(
        console_output(source),
        [
            "false true 0,1 1",
            "1 true true",
            "[object Iterator Helper] true function true",
            "true a,b"
        ]
    );
}

/// The abstract constructor, its prototype and a subclass.
#[test]
fn iterator_constructor() {
    let source = "console.log(typeof Iterator, Iterator.name, Iterator.length, Iterator.prototype === Object.getPrototypeOf(Object.getPrototypeOf([].values())));\nconsole.log(Iterator.prototype.constructor === Iterator, Iterator.prototype[Symbol.toStringTag]);\ntry { new Iterator(); } catch (e) { console.log(e.constructor.name, e.message); }\ntry { Iterator(); } catch (e) { console.log(e.constructor.name, e.message); }\nclass Counter extends Iterator {\n  constructor() { super(); this.n = 0; }\n  next() { return this.n < 2 ? { value: this.n++, done: false } : { value: undefined, done: true }; }\n}\nconsole.log(new Counter().map((x) => x + 10).toArray().join(), new Counter() instanceof Iterator);\n";
    assert_eq!(
        console_output(source),
        [
            "function Iterator 0 true",
            "true Iterator",
            "TypeError Abstract class Iterator not directly constructable",
            "TypeError Constructor Iterator requires 'new'",
            "10,11 true"
        ]
    );
}

/// Bad arguments throw; a callback that throws closes the underlying iterator.
#[test]
fn argument_errors() {
    let source = "try { [1].values().map(1); } catch (e) { console.log(e.constructor.name); }\ntry { [1].values().take(-1); } catch (e) { console.log(e.constructor.name); }\ntry { [1].values().drop(NaN); } catch (e) { console.log(e.constructor.name); }\nlet closed = 0;\nconst source = { __proto__: Iterator.prototype, next() { return { value: 1, done: false }; }, return() { closed++; return {}; } };\ntry { source.map(() => { throw new Error('boom'); }).next(); } catch (e) { console.log(e.message, closed); }\ntry { source.forEach(() => { throw new Error('bang'); }); } catch (e) { console.log(e.message, closed); }\nconsole.log(source.take(1).toArray().length, closed);\n";
    assert_eq!(
        console_output(source),
        [
            "TypeError",
            "RangeError",
            "RangeError",
            "boom 1",
            "bang 2",
            "1 3"
        ]
    );
}
