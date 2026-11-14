//! Real source through HybridRouter: cached protocol methods, intrinsic
//! identity, AsyncFromSync continuation and awaited abrupt cleanup.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &str) {
    let result = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("{error}: {source}"));
    let output = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(output, expected, "{source}");
}

#[test]
fn next_is_cached_and_called_with_the_iterator_receiver_and_zero_arguments() {
    check(
        r#"
      (async () => {
        let n = 0; let reads = 0; const log = [];
        const iterator = { get next() { reads++; return function() {
          log.push('next:' + (this === iterator) + ':' + arguments.length);
          return { value: ++n, done: n > 2 };
        }; } };
        const acquire = function() { return iterator; };
        acquire.call = function() { throw 'wrong-call'; };
        const source = { [Symbol.asyncIterator]: acquire };
        for await (const value of source) {
          log.push(value);
          Object.defineProperty(iterator, 'next', { value() { throw 'uncached'; } });
        }
        console.log(reads, log.join('|'));
      })();
    "#,
        "1 next:true:0|1|next:true:0|2|next:true:0",
    );
}

#[test]
fn shadowed_globals_cannot_intercept_language_iteration() {
    check(
        r#"
      const source = { [Symbol.asyncIterator]() { return this; }, next() { return 1; } };
      (async function(Symbol, Reflect, TypeError, Promise) {
        const seen = [];
        for await (const value of [1, 2]) seen.push(value);
        try { for await (const value of source) {} } catch (error) { seen.push(error.name); }
        console.log(seen.join('|'));
      })(null, null, null, null);
    "#,
        "1|2|TypeError",
    );
}

#[test]
fn async_yielded_values_are_not_awaited_and_function_results_are_objects() {
    check(
        r#"
      (async () => {
        const token = { then() { throw 'wrong-assimilation'; } }; let n = 0;
        const source = { [Symbol.asyncIterator]() { return this; }, next() {
          const result = function() {}; result.value = token; result.done = ++n > 1; return result;
        } };
        for await (const value of source) console.log(value === token);
      })();
    "#,
        "true",
    );
}

#[test]
fn sync_terminal_and_return_values_are_awaited_but_raw_results_are_not() {
    check(
        r#"
      (async () => {
        const log = [];
        const terminal = { [Symbol.iterator]() { return this; }, next() { return {
          done: true, get value() { log.push('terminal'); return { then(resolve) { log.push('terminal-then'); resolve(1); } }; }
        }; } };
        for await (const value of terminal) log.push('wrong-body');
        const source = { [Symbol.iterator]() { return this; }, next() { return {
          value: 1, done: false, then() { throw 'wrong-result-await'; }
        }; }, return() { log.push('close'); return {
          done: true, value: { then(resolve) { log.push('close-then'); resolve(2); } }
        }; } };
        for await (const value of source) { log.push(value); break; }
        log.push('after'); console.log(log.join('|'));
      })();
    "#,
        "terminal|terminal-then|1|close|close-then|after",
    );
}

#[test]
fn body_throw_wins_but_break_reports_an_invalid_return_result() {
    check(
        r#"
      (async () => {
        const log = []; const source = { [Symbol.asyncIterator]() { return this; },
          next() { return { value: 1 }; }, return() { log.push('close'); return Promise.resolve(1); } };
        try { for await (const value of source) { throw 'body'; } } catch (error) { log.push(error); }
        try { for await (const value of source) { break; } } catch (error) { log.push(error.name); }
        console.log(log.join('|'));
      })();
    "#,
        "close|body|close|TypeError",
    );
}

#[test]
fn labeled_continue_stays_inside_the_loop_and_labeled_break_closes_once() {
    check(
        r#"
      (async () => {
        const log = []; let n = 0; const source = { [Symbol.asyncIterator]() { return this; },
          next() { return { value: ++n }; }, return() { return Promise.resolve().then(() => { log.push('closed'); return {}; }); } };
        outer: inner: for await (const value of source) {
          log.push(value); if (value === 1) continue outer; break inner;
        }
        log.push('after'); console.log(log.join('|'));
      })();
    "#,
        "1|2|closed|after",
    );
}

#[test]
fn helpers_are_hygienic_and_the_rhs_observes_lexical_tdz() {
    check(
        r#"
      (async () => {
        const __franken_fa_0_src = 10; const __franken_fa_\u0031_next = 20;
        const values = [1]; const log = [];
        for await (const value of values) log.push(value + __franken_fa_0_src + __franken_fa_\u0031_next);
        try { for await (const values of values) {} } catch (error) { log.push(error.name); }
        console.log(log.join('|'));
      })();
    "#,
        "31|ReferenceError",
    );
}
