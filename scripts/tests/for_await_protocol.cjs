#!/usr/bin/env node
"use strict";

// Execute the exact shared Rust renderer, then compare its JavaScript with
// native for-await in Node. This is protocol-oracle evidence, not native VM
// execution. Set FRANKEN_FOR_AWAIT_LOWERER to reuse an already-built harness.
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");

function rendererBinary() {
  if (process.env.FRANKEN_FOR_AWAIT_LOWERER) return process.env.FRANKEN_FOR_AWAIT_LOWERER;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "franken-for-await-oracle-"));
  const production = path.resolve(__dirname, "../../crates/franken-core/src/ts_normalization");
  for (const file of ["for_await.rs", "namespaces.rs", "enums.rs", "namespaces"]) {
    fs.symlinkSync(path.join(production, file), path.join(directory, file));
  }
  fs.writeFileSync(path.join(directory, "main.rs"), `
#![allow(dead_code)]
mod namespaces;
mod enums;
mod for_await;
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let labels: Vec<&str> = args[2..].iter().map(String::as_str).collect();
    match for_await::lower(&args[0], &args[1], &labels) {
        Ok(lowered) => println!("{}", lowered.source),
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    }
}
`);
  const binary = path.join(directory, "lower-for-await");
  const compiled = spawnSync(process.env.RUSTC || "rustc", [
    "--edition=2024", "--crate-name", "for_await_oracle", path.join(directory, "main.rs"), "-o", binary,
  ], { encoding: "utf8", timeout: 60000 });
  assert.equal(compiled.status, 0, `production renderer compilation: ${compiled.stderr || compiled.error}`);
  return binary;
}

const binary = rendererBinary();
function render(header, body, labels = []) {
  const result = spawnSync(binary, [header, body, ...labels], { encoding: "utf8", timeout: 5000 });
  assert.equal(result.status, 0, `render ${header}: ${result.stderr || result.error}`);
  return result.stdout.trim();
}

const cases = [];
function fixture(name, before, header = "const value of source", body = "{ log(value); }", expected, extra = {}) {
  cases.push({ name, before, header, body, expected, ...extra });
}

fixture("cached async next and receiver", `
  let count = 0;
  const iterator = {
    get next() { log('get-next'); return function() {
      log('next', this === iterator, arguments.length);
      return { value: ++count, done: count > 2 };
    }; },
    return() { log('close'); return {}; }
  };
  const acquire = function() { log('acquire', this === source, arguments.length); return iterator; };
  acquire.call = () => { throw 'wrong-call'; };
  const source = { get [Symbol.asyncIterator]() { log('get-async'); return acquire; },
    get [Symbol.iterator]() { throw 'wrong-sync'; } };
`, undefined, `{ log('body', value); Object.defineProperty(iterator, 'next', { value() { throw 'uncached-next'; } }); }`,
  ["get-async", "acquire:true:0", "get-next", "next:true:0", "body:1", "next:true:0", "body:2", "next:true:0"]);

fixture("nullish async method falls back once", `
  let count = 0;
  const source = { get [Symbol.asyncIterator]() { log('async'); return null; },
    get [Symbol.iterator]() { log('sync'); return function() { log('factory', this === source, arguments.length);
      return { next() { return { value: ++count, done: count > 1 }; } }; }; } };
`, undefined, undefined, ["async", "sync", "factory:true:0", "1"]);

fixture("non-callable async method does not fall back", `
  const source = { [Symbol.asyncIterator]: 1, get [Symbol.iterator]() { throw 'wrong-fallback'; } };
`, undefined, undefined, ["error:TypeError"]);

for (const protocol of ["asyncIterator", "iterator"]) {
  fixture(`${protocol} validates iterator object`, `const source = { [Symbol.${protocol}]() { return 1; } };`,
    undefined, undefined, ["error:TypeError"]);
  fixture(`${protocol} validates next result`, `
    const source = { [Symbol.${protocol}]() { return this; }, next() { return 1; }, return() { log('wrong-close'); return {}; } };
  `, undefined, undefined, ["error:TypeError"], { specOnly: protocol === "iterator" });
  fixture(`${protocol} caches throwing next getter before iteration`, `
    const source = { [Symbol.${protocol}]() { return this; }, get next() { throw 'next-getter'; }, return() { log('wrong-close'); return {}; } };
  `, undefined, undefined, ["error:next-getter"]);
  for (const property of ["done", "value"]) {
    fixture(`${protocol} ${property} getter failure does not close`, `
      const source = { [Symbol.${protocol}]() { return this; },
        next() { return { get ${property}() { throw '${property}'; } }; },
        return() { log('wrong-close'); return {}; } };
    `, undefined, undefined, [`error:${property}`], { specOnly: protocol === "iterator" });
  }
}

fixture("async values retain their identity without assimilation", `
  const token = { then() { log('wrong-assimilation'); } };
  let count = 0;
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return { value: token, done: ++count > 1 }; } };
`, undefined, "{ log(value === token); }", ["true"]);

fixture("synchronous raw result is not awaited", `
  let count = 0;
  const source = { [Symbol.iterator]() { return this; }, next() { return {
    then() { throw 'wrong-result-assimilation'; }, value: 7, done: ++count > 1
  }; } };
`, undefined, undefined, ["7"]);

fixture("synchronous terminal value is read and awaited", `
  const source = { [Symbol.iterator]() { return this; }, next() { return {
    get done() { log('done'); return true; }, get value() { log('value'); return { then(resolve) { log('then'); resolve(9); } }; }
  }; } };
`, undefined, undefined, ["done", "value", "then"]);

fixture("synchronous rejected value closes and preserves rejection", `
  const source = { [Symbol.iterator]() { return this; }, next() { return { value: Promise.reject('value-failure'), done: false }; },
    get return() { log('get-return'); return function() { log('return', this === source, arguments.length); throw 'close-failure'; }; } };
`, undefined, undefined, ["get-return", "return:true:0", "error:value-failure"]);

fixture("synchronous terminal rejection does not close", `
  const source = { [Symbol.iterator]() { return this; }, next() { return { value: Promise.reject('terminal'), done: true }; },
    return() { log('wrong-close'); return {}; } };
`, undefined, undefined, ["error:terminal"]);

fixture("synchronous close awaits return value, not the result object", `
  const source = { [Symbol.iterator]() { return this; }, next() { return { value: 1, done: false }; }, return() {
    log('return', this === source, arguments.length); return {
      then() { throw 'wrong-return-assimilation'; },
      get done() { log('return-done'); return false; },
      get value() { log('return-value'); return { then(resolve) { log('return-then'); resolve(2); } }; }
    };
  } };
`, undefined, "{ log('body'); break; }", ["body", "return:true:0", "return-done", "return-value", "return-then", "after"],
  { after: "log('after');" });

fixture("async close awaits result without reading done or value", `
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return { value: 1, done: false }; }, return() {
    log('return', this === source, arguments.length); return { then(resolve) { log('return-then'); resolve({
      get done() { throw 'wrong-done'; }, get value() { throw 'wrong-value'; }
    }); } };
  } };
`, undefined, "{ log('body'); break; }", ["body", "return:true:0", "return-then", "after"],
  { after: "log('after');" });

for (const protocol of ["asyncIterator", "iterator"]) {
  for (const close of [
    "get return() { throw 'close-getter'; }",
    "return: 1",
    "return() { throw 'close-call'; }",
    "return() { return 1; }",
    protocol === "asyncIterator" ? "return() { return Promise.reject('close-reject'); }" : "return() { return { value: Promise.reject('close-reject') }; }",
  ]) {
    fixture(`${protocol} original throw wins over ${close}`, `
      const source = { [Symbol.${protocol}]() { return this; }, next() { return { value: 1, done: false }; }, ${close} };
    `, undefined, "{ throw 'body'; }", ["error:body"]);
  }
  fixture(`${protocol} break validates return object`, `
    const source = { [Symbol.${protocol}]() { return this; }, next() { return { value: 1, done: false }; }, return() { return false; } };
  `, undefined, "{ break; }", ["error:TypeError"]);
}

fixture("callable objects are iterator results", `
  let count = 0;
  const source = { [Symbol.asyncIterator]() { return this; }, next() {
    const result = function() {}; result.value = ++count; result.done = count > 1; return result;
  } };
`, undefined, undefined, ["1"]);

fixture("destructuring binding failure closes", `
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return { value: null, done: false }; },
    return() { log('closed'); return {}; } };
`, "const { x } of source", "{}", ["closed", "error:TypeError"]);

fixture("lexical RHS is in the binding TDZ", "const source = [1]; const value = source;",
  "const value of value", "{ log('wrong-body'); }", ["error:ReferenceError"]);

fixture("lexical bindings are fresh each iteration", "const source = [1, 2]; const getters = [];",
  "let value of source", "{ getters.push(() => value); }", ["1:2"], { after: "log(...getters.map(f => f()));" });

fixture("var bindings remain shared", "const source = [1, 2]; const getters = [];",
  "var value of source", "{ getters.push(() => value); }", ["2:2"], { after: "log(...getters.map(f => f()));" });

fixture("labels continue without closing and break closes once", `
  let count = 0;
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return { value: ++count, done: false }; }, return() { log('close'); return {}; } };
`, undefined, "{ log(value); if (value === 1) continue outer; break inner; }", ["1", "2", "close"],
  { labels: ["outer", "inner"] });

fixture("outward continue awaits close", `
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return { value: 1, done: false }; },
    return() { return Promise.resolve().then(() => { log('closed'); return {}; }); } };
`, undefined, "{ log('body', round); continue outer; }", ["body:0", "closed", "body:1", "closed"],
  { wrap: "outer: for (let round = 0; round < 2; round++) { LOOP log('wrong-after'); }" });

fixture("generated names avoid source references including escapes", String.raw`
  const source = [3]; const __franken_fa_0_src = 10; const __franken_fa_\u0031_next = 20; const __franken_fa_2_value = 30;
`, undefined, String.raw`{ log(value + __franken_fa_0_src + __franken_fa_\u0031_next, ` + "`${__franken_fa_2_value}`" + "); }",
  ["33:30"]);

fixture("source and assignment references are evaluated at their specified times", `
  const target = []; let index = 0; const source = { get values() { log('rhs'); return [5, 6]; } };
  function key() { log('key', index); return index++; }
`, "target[key()] of source.values", "{ log('body'); }", ["rhs", "key:0", "body", "key:1", "body", "5,6"],
  { after: "log(target.join());" });

fixture("contextual of and compact destructuring headers", "const source = [[1, 2]];",
  "const[of,value]of source", "{ log(of, value); }", ["1:2"]);

fixture("parenthesized RHS comma retains ordering", "const source = [8];",
  "const value of (log('rhs'), source)", undefined, ["rhs", "8"]);

fixture("sync value assimilation preserves promise-job order", `
  const source = [1, Promise.resolve(2)]; let remaining = 12;
  function tick() { log('tick'); if (--remaining) Promise.resolve().then(tick); }
  Promise.resolve().then(tick);
`, undefined, "{ log('body', value); }", undefined, { after: "log('after');" });

fixture("async return preserves promise-job order", `
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return Promise.resolve({ value: 1 }); },
    return() { log('return'); return Promise.resolve({}); } }; let remaining = 12;
  function tick() { log('tick'); if (--remaining) Promise.resolve().then(tick); }
  Promise.resolve().then(tick);
`, undefined, "{ log('body'); break; }", undefined, { after: "log('after');" });

async function execute(test, loop) {
  if (test.wrap) loop = test.wrap.replace("LOOP", () => loop);
  const program = `(async () => {
    const trace = []; const log = (...values) => trace.push(values.join(':'));
    ${test.before}
    try { ${loop} } catch (error) { log('error', error && error.name || error); }
    ${test.after || ""}
    return JSON.stringify(trace);
  })()`;
  return JSON.parse(await vm.runInNewContext(program, {}, { timeout: 2000, filename: test.name }));
}

(async () => {
  for (const test of cases) {
    const labels = test.labels || [];
    const nativeLoop = `${labels.map(label => `${label}: `).join("")}for await (${test.header}) ${test.body}`;
    const native = await execute(test, nativeLoop);
    const lowered = await execute(test, render(test.header, test.body, labels));
    if (test.specOnly) {
      // Node 24.22.1 closes the sync iterator on these early adapter errors.
      // TC39 AsyncFromSyncIterator.next steps 6-7 / Continuation steps 2-5
      // reject directly; they do not run IteratorClose. Keep the normative
      // outcome explicit rather than copying this V8 oracle discrepancy.
      // https://tc39.es/ecma262/#sec-asyncfromsynciteratorcontinuation
      assert.deepEqual(lowered, test.expected, `${test.name}: specification outcome`);
      assert(native.join() === test.expected.join() || native.join() === ['wrong-close', ...test.expected].join(),
        `${test.name}: unexpected Node oracle change ${native}`);
    } else {
      if (test.expected) assert.deepEqual(native, test.expected, `${test.name}: oracle expectation`);
      assert.deepEqual(lowered, native, `${test.name}: production renderer versus Node`);
    }
  }
  for (const header of ["const x in source", "let x,y of source", "var x=1 of source", ";;", "x of", "const x of source,source"]) {
    assert.throws(() => new Function(`return async function() { for await (${header}) {} };`), SyntaxError);
    const result = spawnSync(binary, [header, "{}"], { encoding: "utf8", timeout: 5000 });
    assert.notEqual(result.status, 0, `invalid header must be refused: ${header}`);
  }
  const specificationCases = cases.filter(test => test.specOnly).length;
  console.log(`PASS ${cases.length - specificationCases} production Rust renderer / Node semantic differentials; ${specificationCases} explicit specification cases; 6 grammar refusals`);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
