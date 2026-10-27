//! Combinator failure ownership at the real parser/interpreter boundary.
//! Embedded JavaScript also supplies an independently executable Node oracle.
use super::*;
use crate::promise_model::PromiseState;

fn module(source: &str) -> Ir3Module {
    let tree = crate::parser_api_stability::parse_script(source).expect("source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "promise-combinator-completions.js"),
        &LoweringContext::new("combinator", "completion-ownership", "builtin-only"),
    )
    .expect("source lowers")
    .ir3
}

fn config(throughput: bool) -> InterpreterConfig {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = 100_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    config
}

fn assert_fixture(source: &str, expected: &str) {
    let module = module(source);
    for throughput in [false, true] {
        for stress in [None, Some(7)] {
            let mut core = InterpreterCore::new(config(throughput), "combinator-completions");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).expect("native execution");
            let actual = result.console_output.iter().map(|entry| entry.message.as_str())
                .collect::<Vec<_>>().join("\n");
            assert_eq!(actual, expected, "throughput={throughput}, stress={stress:?}");
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}

const CLOSE_IDENTITY_SOURCE: &str = r#"
(async () => {
  const reasons = [undefined, null, false, -0, Symbol('reason'), 17n, '\ud800', function reason() {}, {}];
  const modes = ['missing', 'null', 'noncallable', 'normal', 'primitive', 'getThrow', 'callThrow', 'handled'];
  let checked = 0;
  for (const method of ['all', 'allSettled', 'any', 'race']) {
    for (const site of ['resolve', 'thenGet', 'thenCall']) {
      for (const mode of modes) {
        for (const reason of reasons) {
          const events = []; const cleanup = {};
          class C extends Promise {}
          C.resolve = function () {
            events.push('resolve');
            if (site === 'resolve') throw reason;
            return { get then() {
              events.push('thenGet');
              if (site === 'thenGet') throw reason;
              return function () { events.push('thenCall'); throw reason; };
            } };
          };
          const iterator = { next() { events.push('next'); return {value: 1, done: false}; } };
          if (mode !== 'missing') Object.defineProperty(iterator, 'return', { get() {
            events.push('returnGet');
            if (mode === 'getThrow') throw cleanup;
            if (mode === 'null') return null;
            if (mode === 'noncallable') return 1;
            return function () {
              if (this !== iterator) throw Error('close receiver');
              events.push('returnCall');
              if (mode === 'callThrow') throw cleanup;
              if (mode === 'handled') { try { throw cleanup; } catch (caught) {} }
              return mode === 'primitive' ? 0 : {};
            };
          } });
          const iterable = { [Symbol.iterator]() { events.push('iterator'); return iterator; } };
          let rejected = false;
          try { await Promise[method].call(C, iterable); }
          catch (caught) { rejected = true; if (!Object.is(caught, reason)) throw Error('lost original'); }
          if (!rejected) throw Error('not rejected');
          let expected = 'iterator:next:resolve';
          if (site !== 'resolve') expected += ':thenGet';
          if (site === 'thenCall') expected += ':thenCall';
          if (mode !== 'missing') expected += ':returnGet';
          if (['normal', 'primitive', 'callThrow', 'handled'].includes(mode)) expected += ':returnCall';
          if (events.join(':') !== expected) throw Error('close order ' + events.join(':'));
          checked++;
        }
      }
    }
  }
  console.log('identity', checked);
})().catch(error => console.log('FAIL', error.message));
"#;
const CLOSE_IDENTITY_EXPECTED: &str = "identity 864";

#[test]
fn original_completions_survive_every_observable_iterator_close_failure() {
    assert_fixture(CLOSE_IDENTITY_SOURCE, CLOSE_IDENTITY_EXPECTED);
}

const ITERATOR_FAILURE_SOURCE: &str = r#"
(async () => {
  let checked = 0;
  for (const method of ['all', 'allSettled', 'any', 'race']) {
    for (const site of ['next', 'done', 'value']) {
      const reason = {}; let closes = 0, resolves = 0;
      class C extends Promise {}
      C.resolve = value => { resolves++; return Promise.resolve(value); };
      const iterator = {
        next() {
          if (site === 'next') throw reason;
          return { get done() { if (site === 'done') throw reason; return false; },
            get value() { throw reason; } };
        },
        get return() { closes++; throw Error('must not close a failed iterator step'); }
      };
      let rejected = false;
      try { await Promise[method].call(C, { [Symbol.iterator]() { return iterator; } }); }
      catch (caught) { rejected = caught === reason; }
      if (!rejected || closes !== 0 || resolves !== 0) throw Error('iterator failure boundary');
      checked++;
    }
  }
  console.log('iterator', checked);
})().catch(error => console.log('FAIL', error.message));
"#;
const ITERATOR_FAILURE_EXPECTED: &str = "iterator 12";

#[test]
fn iterator_step_failures_do_not_invoke_return_or_constructor_resolve() {
    assert_fixture(ITERATOR_FAILURE_SOURCE, ITERATOR_FAILURE_EXPECTED);
}

const CUSTOM_REJECT_SOURCE: &str = r#"
let checked = 0;
for (const method of ['all', 'allSettled', 'any', 'race']) {
  for (const rejectThrows of [false, true]) {
    const original = {}, closeFailure = {}, rejectFailure = {}, product = {};
    const events = [];
    function C(executor) {
      executor(function () { throw Error('unexpected fulfillment'); }, function (reason) {
        'use strict';
        if (this !== undefined || reason !== original) throw Error('reject argument/receiver');
        events.push('reject');
        if (rejectThrows) throw rejectFailure;
      });
      return product;
    }
    C.resolve = function () { events.push('resolve'); throw original; };
    const iterable = { [Symbol.iterator]() { return {
      next() { return {value: 1, done: false}; },
      return() { events.push('return'); throw closeFailure; }
    }; } };
    let escaped = false;
    try {
      if (Promise[method].call(C, iterable) !== product) throw Error('capability identity');
    } catch (error) {
      if (!rejectThrows || error !== rejectFailure) throw error;
      escaped = true;
    }
    if (escaped !== rejectThrows || events.join(':') !== 'resolve:return:reject')
      throw Error('custom reject completion');
    checked++;
  }
}
console.log('custom', checked);
"#;
const CUSTOM_REJECT_EXPECTED: &str = "custom 8";

#[test]
fn arbitrary_capabilities_observe_the_original_reason_and_their_own_reject_failure() {
    assert_fixture(CUSTOM_REJECT_SOURCE, CUSTOM_REJECT_EXPECTED);
}

fn failure_core(close_body: &str) -> (InterpreterCore, Ir3Module, Value, ObjectId, PromiseCapabilityRecord) {
    let source = format!(
        "const state = {{marker: 9182, closes: 0}}; \
         const iterable = {{[Symbol.iterator]() {{return {{ \
           next() {{return {{value: 1, done: false}};}}, \
           get return() {{state.closes++; {close_body}}} \
         }};}}}}; \
         const holder = {{marker: 9183, state, iterable}};"
    );
    let module = module(&source);
    let mut core = InterpreterCore::new(config(false), "combinator-failure-injection");
    core.execute(&module).expect("setup executes");
    let holder = core.heap.iter().find(|entry| entry.properties.get("marker") == Some(&Value::Int(9183)))
        .expect("holder");
    let iterable = holder.properties.get("iterable").unwrap().clone();
    let Value::Object(state) = holder.properties.get("state").unwrap().clone() else { panic!("state"); };
    let iterator = core.init_for_of_iterator(Some(&module), iterable).expect("native iterator");
    let promise = core.create_promise().unwrap();
    let capability = PromiseCapabilityRecord {
        promise: Value::Promise(promise.0),
        resolve: core.make_promise_capability(BuiltinFunctionKind::PromiseResolve, promise),
        reject: core.make_promise_capability(BuiltinFunctionKind::PromiseReject, promise),
    };
    (core, module, iterator, state, capability)
}

#[test]
fn fatal_step_errors_skip_guest_cleanup_and_rejection_even_at_the_memory_ceiling() {
    // Inject the actual interpreter error variants at the post-step seam; this
    // is a native state-transition test, not a simulated cancellation token.
    for error in [
        InterpreterError::Cancelled,
        InterpreterError::BudgetExhausted { executed: 3, budget: 2 },
        InterpreterError::MemoryBudgetExceeded {
            requested_bytes: 2, max_bytes: 1,
            requested_heap_objects: 0, max_heap_objects: 1,
        },
        InterpreterError::CapabilityDenied { capability: "fs:write".into() },
        InterpreterError::InternalError { details: "host failed".into() },
    ] {
        let (mut core, module, iterator, state, capability) = failure_core("throw 'cleanup must not run';");
        core.replace_pending_abrupt_slots(Some((Value::Int(9), Label::Secret)), None).unwrap();
        let expected = format!("{error:?}");
        let heap_len = core.heap.len();
        let promises = core.promise_store.len();
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        let actual = core.reject_combinator_step(&module, &capability, iterator, error).unwrap_err();
        assert_eq!(format!("{actual:?}"), expected);
        assert_eq!(core.heap[state.0 as usize].properties.get("closes"), Some(&Value::Int(0)));
        let promise = InterpreterCore::capability_native_promise(&capability).unwrap();
        assert_eq!(core.promise_store.get(promise).unwrap().state, PromiseState::Pending);
        assert_eq!(core.heap.len(), heap_len);
        assert_eq!(core.promise_store.len(), promises);
        assert_eq!(core.take_pending_exception_slot(), Some((Value::Int(9), Label::Secret)));
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}

#[test]
fn cleanup_cannot_replace_the_thrown_value_or_erase_its_observation_label() {
    for thrown_label in [Label::Public, Label::Secret] {
        let (mut core, module, iterator, state, capability) = failure_core("throw {replacement: true};");
        let reason = Value::Object(state);
        core.replace_pending_abrupt_slots(Some((reason.clone(), thrown_label)), None).unwrap();
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        let result = core.reject_combinator_step(
            &module, &capability, iterator,
            InterpreterError::UncaughtException { value: "description is not identity".into() },
        ).expect("reject original completion");
        assert_eq!(result, capability.promise);
        let promise = InterpreterCore::capability_native_promise(&capability).unwrap();
        let record = core.promise_store.get(promise).unwrap();
        let PromiseState::Rejected(value) = &record.state else { panic!("must reject"); };
        assert_eq!(core.js_value_to_value(value), reason);
        assert_eq!(record.label, Label::Secret);
        assert_eq!(core.heap[state.0 as usize].properties.get("closes"), Some(&Value::Int(1)));
        assert!(core.take_pending_exception_slot().is_none());
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}

const ANY_EXACT_REASONS_SOURCE: &str = r#"
(async () => {
  const reasons = [function reason() {}, () => 1, (function () {}).bind(null),
    async function () {}, function* () {}, async function* () {}, Array.prototype.slice,
    (function* () {})(), (async function* () {})(), [1].values(), Promise.resolve(5),
    Symbol('reason'), 123456789012345678901234567890n, '\ud800', -0, NaN, undefined, null, false, {}];
  let observations = 0;
  // Rejection collection is not PromiseResolve: no reason.then getter runs.
  Object.defineProperty(reasons[0], 'then', { get() { observations++; throw Error('assimilated rejection'); } });
  let checks = 0;
  for (const mode of ['custom', 'subclass', 'iterable']) {
    let promise, syncError, rejectCalls = 0;
    if (mode === 'custom') {
      const product = {};
      function C(executor) {
        executor(() => { throw Error('resolved all-rejected input'); }, error => {
          rejectCalls++; syncError = error;
        });
        return product;
      }
      C.resolve = reason => ({then(resolve, reject) { reject(reason); reject('duplicate'); }});
      if (Promise.any.call(C, reasons) !== product) throw Error('custom result identity');
      if (rejectCalls !== 1) throw Error('custom rejection count');
    } else {
      class C extends Promise {}
      C.resolve = reason => ({then(resolve, reject) { reject(reason); reject('duplicate'); }});
      if (mode === 'subclass') promise = Promise.any.call(C, reasons);
      else promise = Promise.any((function* () {
        for (const reason of reasons) yield Promise.reject(reason);
      })());
      try { await promise; throw Error('unexpected fulfillment'); }
      catch (error) { syncError = error; }
    }
    if (!(syncError instanceof AggregateError) || syncError.errors.length !== reasons.length)
      throw Error('aggregate shape');
    const descriptor = Object.getOwnPropertyDescriptor(syncError, 'errors');
    if (!descriptor.writable || descriptor.enumerable || !descriptor.configurable)
      throw Error('errors descriptor');
    for (let i = 0; i < reasons.length; i++) {
      if (!Object.is(syncError.errors[i], reasons[i])) throw Error('lost reason ' + mode + ':' + i);
      checks++;
    }
  }
  if (observations !== 0) throw Error('rejection then observed');
  console.log('exact reasons', checks, observations);
})().catch(error => console.log('FAIL', error.message));
"#;
const ANY_EXACT_REASONS_EXPECTED: &str = "exact reasons 60 0";

#[test]
fn any_preserves_all_rejection_representations_without_assimilation() {
    assert_fixture(ANY_EXACT_REASONS_SOURCE, ANY_EXACT_REASONS_EXPECTED);
}

const ANY_ORDER_SOURCE: &str = r#"
(async () => {
  const first = function first() {}, second = [1].values(), third = 77n;
  const reasons = [first, second, third]; const rejectors = []; let closeCalls = 0;
  class C extends Promise {}
  C.resolve = index => ({then(resolve, reject) { rejectors[index] = reject; }});
  const source = { [Symbol.iterator]() {
    let index = 0;
    return { next() { return index < 3 ? {value: index++, done: false} : {done: true}; },
      return() { closeCalls++; return {}; } };
  } };
  const promise = Promise.any.call(C, source);
  let completed = false, aggregate;
  promise.then(() => { throw Error('fulfilled'); }, error => { completed = true; aggregate = error; });
  rejectors[2](third); rejectors[0](first); rejectors[2]('duplicate');
  await 0;
  if (completed) throw Error('premature aggregate');
  rejectors[1](second); rejectors[0]('late');
  try { await promise; } catch (error) { aggregate = error; }
  if (!completed || aggregate.errors.length !== 3 || closeCalls !== 0) throw Error('completion count');
  for (let i = 0; i < reasons.length; i++) {
    if (aggregate.errors[i] !== reasons[i]) throw Error('input order or identity');
  }
  let empty;
  try { await Promise.any.call(C, []); } catch (error) { empty = error; }
  if (!(empty instanceof AggregateError) || empty.errors.length !== 0) throw Error('empty any');
  console.log('ordering', aggregate.errors.length, closeCalls, empty.errors.length);
})().catch(error => console.log('FAIL', error.message));
"#;
const ANY_ORDER_EXPECTED: &str = "ordering 3 0 0";

#[test]
fn any_retains_input_order_across_out_of_order_and_duplicate_rejections() {
    assert_fixture(ANY_ORDER_SOURCE, ANY_ORDER_EXPECTED);
}

#[test]
fn any_aggregate_uses_exact_native_values_and_retains_the_shared_label() {
    let source = "const holder = {marker: 9312, values: [function () {}, [1].values(), 99n, '\\ud800']};";
    let module = module(source);
    let mut core = InterpreterCore::new(config(false), "any-exact-carriers");
    core.execute(&module).unwrap();
    let holder = core.heap.iter().find(|entry| entry.properties.get("marker") == Some(&Value::Int(9312)))
        .expect("source holder");
    let values = holder.properties.get("values").unwrap().clone();
    let mut originals = Vec::new();
    for index in 0..4 {
        originals.push(core.get_v(&module, &values, &InterpreterCore::generic_index_key(index)).unwrap());
    }
    let promise = core.create_promise().unwrap();
    let shared = core.alloc_object_with_properties(&[
        (SHARED_LENGTH, Value::Int(4)),
        (SHARED_REMAINING, Value::Int(1)),
        (SHARED_VALUES, values),
        (CAPABILITY_RESOLVE, core.make_promise_capability(BuiltinFunctionKind::PromiseResolve, promise)),
        (CAPABILITY_REJECT, core.make_promise_capability(BuiltinFunctionKind::PromiseReject, promise)),
    ]).unwrap();
    core.join_direct_object_mutation_label(shared, &Label::Secret).unwrap();
    core.promise_combinator_element_done(&module, PromiseCombinatorKind::Any, shared).unwrap();
    let record = core.promise_store.get(promise).unwrap();
    let PromiseState::Rejected(error) = &record.state else { panic!("any must reject"); };
    assert_eq!(record.label, Label::Secret);
    let error = core.js_value_to_value(error);
    let errors = core.get_v(&module, &error, &RuntimePropertyKey::String(JsString::from("errors"))).unwrap();
    for (index, original) in originals.into_iter().enumerate() {
        let actual = core.get_v(&module, &errors, &InterpreterCore::generic_index_key(index as u64)).unwrap();
        assert_eq!(actual, original);
    }
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
}

const NATIVE_RESOLUTION_0_SOURCE: &str = r#"
(async () => {
  let checks = 0;
  for (const method of ['all', 'allSettled']) {
    const kinds = method === 'all' ? ['primitive', 'fulfilled', 'pending']
      : ['primitive', 'fulfilled', 'pending', 'rejected'];
    for (const kind of kinds) {
      for (const mode of ['callable', 'throw', 'noncallable']) {
        let release;
        const input = kind === 'primitive' ? 4
          : kind === 'fulfilled' ? Promise.resolve(4)
          : kind === 'rejected' ? Promise.reject(4)
          : new Promise(resolve => { release = resolve; });
        const promise = Promise[method]([input]);
        const events = []; const reason = {}; let receiver, reads = 0, calls = 0;
        Object.defineProperty(Array.prototype, 'then', {
          configurable: true,
          get() {
            reads++; receiver = this; events.push('get');
            if (this.length !== 1) throw Error('result array receiver');
            if (method === 'all' && this[0] !== 4) throw Error('all payload');
            if (method === 'allSettled') {
              const entry = this[0];
              if (entry.status !== (kind === 'rejected' ? 'rejected' : 'fulfilled')
                || entry[kind === 'rejected' ? 'reason' : 'value'] !== 4)
                throw Error('allSettled payload');
            }
            if (mode === 'throw') throw reason;
            if (mode === 'noncallable') return 17;
            return function (resolve, reject) {
              calls++; events.push('call');
              if (this !== receiver) throw Error('then receiver');
              resolve(73); reject(reason); resolve(99);
            };
          }
        });
        if (release) release(4);
        Promise.resolve().then(() => events.push('tick'));
        let rejected = false;
        try {
          const value = await promise;
          events.push('after');
          if (mode === 'throw' || value !== (mode === 'callable' ? 73 : receiver))
            throw Error('result resolution');
        } catch (error) {
          rejected = true; events.push('catch');
          if (mode !== 'throw' || error !== reason) throw error;
        } finally {
          delete Array.prototype.then;
        }
        const expected = mode === 'throw' ? 'get:tick:catch'
          : mode === 'callable' ? 'get:tick:call:after' : 'get:tick:after';
        if (reads !== 1 || calls !== (mode === 'callable' ? 1 : 0)
          || rejected !== (mode === 'throw') || events.join(':') !== expected)
          throw Error('late order ' + method + ':' + kind + ':' + mode + ':' + events.join(':'));
        checks++;
      }
    }
  }
  console.log('late arrays', checks);
})().catch(error => console.log('FAIL', error.message));
"#;

#[test]
fn native_array_results_observe_late_then_changes() {
    assert_fixture(NATIVE_RESOLUTION_0_SOURCE, "late arrays 21");
}

const NATIVE_RESOLUTION_1_SOURCE: &str = r#"
(async () => {
  let checks = 0;
  for (const method of ['race', 'any']) {
    for (const kind of ['object', 'function', 'bound', 'iterator']) {
      for (const mode of ['callable', 'throw']) {
        const value = kind === 'object' ? {} : kind === 'function' ? function () {}
          : kind === 'bound' ? (function () {}).bind(null) : [1].values();
        const input = Promise.resolve(value);
        const promise = Promise[method]([input]);
        const reason = {}; const events = []; let reads = 0, calls = 0;
        Object.defineProperty(value, 'then', { configurable: true, get() {
          reads++; events.push('get');
          if (this !== value) throw Error('getter receiver');
          if (mode === 'throw') throw reason;
          return function (resolve, reject) {
            calls++; events.push('call');
            if (this !== value) throw Error('call receiver');
            resolve(91); reject(reason); throw reason;
          };
        } });
        Promise.resolve().then(() => events.push('tick'));
        let rejected = false;
        try {
          if (await promise !== 91) throw Error('late value not adopted');
          events.push('after');
          if (mode === 'throw') throw Error('missing rejection');
        } catch (error) {
          rejected = true; events.push('catch');
          if (mode !== 'throw' || error !== reason) throw error;
        } finally { delete value.then; }
        if (reads !== 1 || calls !== (mode === 'callable' ? 1 : 0)
          || rejected !== (mode === 'throw')
          || events.join(':') !== (mode === 'throw' ? 'get:tick:catch' : 'get:tick:call:after'))
          throw Error('race/any resolution ' + method + ':' + kind + ':' + events.join(':'));
        checks++;
      }
    }
  }
  console.log('late winners', checks);
})().catch(error => console.log('FAIL', error.message));
"#;

#[test]
fn native_race_and_any_resolve_winner_values_again() {
    assert_fixture(NATIVE_RESOLUTION_1_SOURCE, "late winners 16");
}

const NATIVE_RESOLUTION_2_SOURCE: &str = r#"
(async () => {
  let checks = 0;
  for (const route of ['resolve', 'executor', 'reaction', 'async', 'await']) {
    for (const kind of ['function', 'bound', 'asyncFunction', 'generatorFunction', 'iterator']) {
      for (const callable of [false, true]) {
        const value = kind === 'function' ? function () {}
          : kind === 'bound' ? (function () {}).bind(null)
          : kind === 'asyncFunction' ? async function () {}
          : kind === 'generatorFunction' ? function* () {}
          : [1].values();
        let reads = 0, calls = 0;
        Object.defineProperty(value, 'then', { configurable: true, get() {
          reads++;
          if (this !== value) throw Error('Get receiver');
          if (!callable) return 7;
          return function (resolve, reject) {
            calls++;
            if (this !== value) throw Error('Call receiver');
            resolve(88); reject(0); resolve(99);
          };
        } });
        const promise = route === 'resolve' ? Promise.resolve(value)
          : route === 'executor' ? new Promise(resolve => resolve(value))
          : route === 'reaction' ? Promise.resolve().then(() => value)
          : route === 'async' ? (async () => value)()
          : value;
        const result = await promise;
        if (result !== (callable ? 88 : value) || reads !== 1 || calls !== (callable ? 1 : 0))
          throw Error('object-like resolve ' + route + ':' + kind);
        delete value.then;
        checks++;
      }
    }
  }
  for (const value of [undefined, null, false, -0, NaN, 7n, Symbol('s'), '\ud800']) {
    if (!Object.is(await new Promise(resolve => resolve(value)), value))
      throw Error('primitive identity');
  }
  console.log('object-like resolution', checks);
})().catch(error => console.log('FAIL', error.message));
"#;

#[test]
fn all_resolve_entrypoints_assimilate_object_like_representations() {
    assert_fixture(NATIVE_RESOLUTION_2_SOURCE, "object-like resolution 50");
}

const NATIVE_RESOLUTION_3_SOURCE: &str = r#"
(async () => {
  let checks = 0;
  for (const method of ['all', 'allSettled']) {
    for (const timing of ['before', 'after']) {
      for (const length of [0, 1]) {
        for (const exotic of [false, true]) {
          const parent = Object.getPrototypeOf(Array.prototype);
          const events = []; let reads = 0, calls = 0, receiver;
          const getThen = function () {
            reads++; receiver = this; events.push('get');
            if (!Array.isArray(this) || this.length !== length) throw Error('inherited receiver');
            return function (resolve) {
              calls++; events.push('call');
              if (this !== receiver) throw Error('inherited then receiver');
              resolve(62);
            };
          };
          const middle = Object.create(parent);
          let inherited;
          if (exotic) {
            inherited = new Proxy(middle, {
              get(target, key, actualReceiver) {
                return key === 'then' ? getThen.call(actualReceiver) : Reflect.get(target, key, actualReceiver);
              },
              getPrototypeOf() { throw Error('speculative prototype trap'); }
            });
          } else {
            Object.defineProperty(middle, 'then', { get: getThen });
            inherited = middle;
          }
          if (timing === 'before') Object.setPrototypeOf(Array.prototype, inherited);
          const promise = Promise[method](length === 0 ? [] : [8]);
          if (timing === 'after') Object.setPrototypeOf(Array.prototype, inherited);
          Promise.resolve().then(() => events.push('tick'));
          try {
            const result = await promise;
            events.push('after');
            const alreadyFulfilled = timing === 'after' && length === 0;
            if (alreadyFulfilled) {
              if (!Array.isArray(result) || result.length !== 0 || reads !== 0 || calls !== 0
                || events.join(':') !== 'tick:after') throw Error('empty settlement observed later change');
            } else {
              const order = length === 0 ? 'get:call:tick:after' : 'get:tick:call:after';
              if (result !== 62 || reads !== 1 || calls !== 1 || events.join(':') !== order)
                throw Error('inherited result ' + method + ':' + timing + ':' + length + ':' + events.join(':'));
            }
            checks++;
          } finally {
            Object.setPrototypeOf(Array.prototype, parent);
          }
        }
      }
    }
  }
  console.log('inherited arrays', checks);
})().catch(error => console.log('FAIL', error.message));
"#;

#[test]
fn native_array_resolution_observes_actual_prototypes_at_the_correct_time() {
    assert_fixture(NATIVE_RESOLUTION_3_SOURCE, "inherited arrays 16");
}

fn pending_native_resolution_fixture(
    getter_body: &str,
) -> (
    InterpreterCore,
    Ir3Module,
    crate::promise_model::PromiseHandle,
    crate::promise_model::PromiseHandle,
    ObjectId,
) {
    let source = format!(
        "const state = {{marker: 9471, calls: 0}}; \
         const input = new Promise(function () {{}}); \
         const aggregate = Promise.all([input]); \
         const holder = {{marker: 9472, state, input, aggregate}}; \
         Object.defineProperty(Array.prototype, 'then', {{configurable: true, \
           get: function () {{state.calls++; {getter_body}}} \
         }});"
    );
    let module = module(&source);
    let mut core = InterpreterCore::new(config(false), "native-combinator-resolution");
    core.execute(&module).expect("pending native aggregate setup");
    assert_eq!(
        core.promise_combinators.len(),
        1,
        "exercise native registration"
    );
    let holder = core
        .heap
        .iter()
        .find(|object| object.properties.get("marker") == Some(&Value::Int(9472)))
        .expect("retained holder");
    let Value::Object(state) = holder.properties.get("state").unwrap().clone() else {
        panic!("state object");
    };
    let Value::Promise(input) = holder.properties.get("input").unwrap().clone() else {
        panic!("input promise");
    };
    let Value::Promise(result) = holder.properties.get("aggregate").unwrap().clone() else {
        panic!("aggregate promise");
    };
    (
        core,
        module,
        crate::promise_model::PromiseHandle(input),
        crate::promise_model::PromiseHandle(result),
        state,
    )
}

#[test]
fn native_resolution_getter_throws_reject_with_exact_value_and_observation_label() {
    for label in [Label::Public, Label::Secret] {
        let (mut core, module, input, result, state) =
            pending_native_resolution_fixture("throw 23;");
        core.fulfill_promise(input, crate::object_model::JsValue::Int(4), label.clone())
            .expect("input fulfillment");
        core.drain_microtasks(Some(&module))
            .expect("catchable getter error rejects aggregate");
        let record = core.promise_store.get(result).unwrap();
        assert_eq!(
            record.state,
            PromiseState::Rejected(crate::object_model::JsValue::Int(23))
        );
        assert_eq!(record.label, label);
        assert_eq!(
            core.heap[state.0 as usize].properties.get("calls"),
            Some(&Value::Int(1))
        );
        assert_eq!(core.own_property_label(state, "calls"), label);
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert!(core.promise_combinators.is_empty());
        assert!(core.promise_combinator_watchers.is_empty());
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_resolution_getter_effects_use_the_aggregate_floor_and_fatal_cleanup() {
    for label in [Label::Public, Label::Secret] {
        let (mut core, module, input, result, state) =
            pending_native_resolution_fixture("console.log(); return undefined;");
        let dependent = core
            .register_promise_then(result, None, None, Label::Public)
            .expect("aggregate dependent");
        core.fulfill_promise(input, crate::object_model::JsValue::Int(4), label.clone())
            .expect("input fulfillment");
        let outcome = core.drain_microtasks(Some(&module));
        if label == Label::Secret {
            assert!(
                matches!(outcome, Err(InterpreterError::CapabilityDenied { ref capability })
                    if capability == "console:log:confidentiality")
            );
            assert!(core.console_output.is_empty());
            for promise in [result, dependent] {
                let record = core.promise_store.get(promise).unwrap();
                assert_eq!(
                    record.state,
                    PromiseState::Rejected(crate::object_model::JsValue::Undefined)
                );
                assert_eq!(record.label, Label::Secret);
                assert!(record.reactions.is_empty());
            }
        } else {
            outcome.expect("Public getter effect is admitted");
            assert_eq!(core.console_output.len(), 1);
            assert_eq!(core.console_output[0].message, "");
            for promise in [result, dependent] {
                assert!(
                    core.promise_store
                        .get(promise)
                        .unwrap()
                        .state
                        .is_fulfilled()
                );
            }
        }
        assert_eq!(
            core.heap[state.0 as usize].properties.get("calls"),
            Some(&Value::Int(1))
        );
        assert_eq!(core.own_property_label(state, "calls"), label);
        assert!(core.active_inline_callback_context_label.is_none());
        assert!(core.promise_combinators.is_empty());
        assert!(core.promise_combinator_watchers.is_empty());
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn object_like_resolution_getters_preserve_the_input_label_for_effects() {
    for expression in [
        "function value() {}",
        "(function value() {}).bind(null)",
        "async function value() {}",
        "function* value() {}",
        "(function* value() { yield 1; })()",
    ] {
        for label in [Label::Public, Label::Secret] {
            let source = format!(
                "const state = {{marker: 9481, calls: 0}}; \
                 const value = {expression}; \
                 const result = new Promise(function () {{}}); \
                 const holder = {{marker: 9482, state, value, result}}; \
                 Object.defineProperty(value, 'then', {{configurable: true, \
                   get: function () {{state.calls++; console.log(); return undefined;}} \
                 }});"
            );
            let module = module(&source);
            let mut core =
                InterpreterCore::new(config(false), "object-like-resolution-label");
            core.execute(&module).expect("object-like resolution setup");
            let holder = core
                .heap
                .iter()
                .find(|object| object.properties.get("marker") == Some(&Value::Int(9482)))
                .expect("retained holder");
            let Value::Object(state) = holder.properties.get("state").unwrap().clone() else {
                panic!("state object");
            };
            let value = holder.properties.get("value").unwrap().clone();
            let Value::Promise(result) = holder.properties.get("result").unwrap().clone() else {
                panic!("result promise");
            };
            let result = crate::promise_model::PromiseHandle(result);
            let outcome =
                core.resolve_promise_with_value(Some(&module), result, value, label.clone());
            if label == Label::Secret {
                assert!(
                    matches!(outcome, Err(InterpreterError::CapabilityDenied { ref capability })
                        if capability == "console:log:confidentiality"),
                    "{expression}"
                );
                assert!(core.console_output.is_empty());
            } else {
                outcome.expect("Public getter effect is admitted");
                assert_eq!(core.console_output.len(), 1);
                assert!(core.promise_store.get(result).unwrap().state.is_fulfilled());
            }
            assert_eq!(
                core.heap[state.0 as usize].properties.get("calls"),
                Some(&Value::Int(1)),
                "{expression}"
            );
            assert_eq!(core.own_property_label(state, "calls"), label);
            assert!(core.pending_exception.is_none());
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn native_primitive_carriers_are_reused_without_payload_copies() {
    for value in [
        Value::BigInt("9".repeat(32_768).into()),
        Value::Str(JsString::from_code_units(&vec![0xd800; 16_384])),
    ] {
        let mut core = InterpreterCore::new(config(false), "native-primitive-carrier-budget");
        let result = core.create_promise().expect("result promise");
        let carrier = core.promise_value(&value).expect("exact carrier");
        drop(value);
        let before = core.estimated_memory_bytes();
        let carriers_before = core.promise_value_carriers.len();
        let next_before = core.next_promise_value_carrier;
        core.config.max_total_memory_bytes = before;
        core.resolve_native_combinator_result(
            None,
            result,
            carrier.clone(),
            Label::Public,
            false,
        )
        .expect("primitive winner needs no extra payload ownership");
        assert_eq!(
            core.promise_store.get(result).unwrap().state,
            PromiseState::Fulfilled(carrier)
        );
        assert_eq!(core.promise_value_carriers.len(), carriers_before);
        assert_eq!(core.next_promise_value_carrier, next_before);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_object_like_carrier_copies_are_preflighted_before_resolution() {
    let mut core = InterpreterCore::new(config(false), "native-object-carrier-budget");
    let result = core.create_promise().expect("result promise");
    let value = Value::BuiltinFunction(BuiltinFunction::require("x".repeat(32_768)));
    let payload_bytes = InterpreterCore::estimate_value_bytes(&value);
    assert!(payload_bytes >= 32_768);
    let carrier = core.promise_value(&value).expect("builtin carrier");
    drop(value);
    let before = core.estimated_memory_bytes();
    let carriers_before = core.promise_value_carriers.len();
    let next_before = core.next_promise_value_carrier;
    let required = before.saturating_add(payload_bytes.saturating_mul(2));
    core.config.max_total_memory_bytes = required - 1;
    let error = core
        .resolve_native_combinator_result(None, result, carrier, Label::Public, false)
        .expect_err("both decoded and rooted payload owners require budget");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { requested_bytes, max_bytes, .. }
            if requested_bytes == required && max_bytes == required - 1
    ));
    assert_eq!(core.promise_store.get(result).unwrap().state, PromiseState::Pending);
    assert_eq!(core.promise_value_carriers.len(), carriers_before);
    assert_eq!(core.next_promise_value_carrier, next_before);
    assert!(core.active_inline_callback_context_label.is_none());
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(core.estimated_memory_bytes(), before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn module_await_assimilates_object_like_values_with_exact_order_and_abrupt_completions() {
    let source = r#"
let checks = 0;
for (const kind of ['function', 'bound', 'asyncFunction', 'generatorFunction', 'iterator']) {
  for (const mode of ['callable', 'noncallable', 'getThrow', 'thenThrow']) {
    const value = kind === 'function' ? function () {}
      : kind === 'bound' ? (function () {}).bind(null)
      : kind === 'asyncFunction' ? async function () {}
      : kind === 'generatorFunction' ? function* () {}
      : [1].values();
    const reason = {};
    const events = [];
    let reads = 0, calls = 0;
    Object.defineProperty(value, 'then', { configurable: true, get() {
      reads++; events.push('get');
      if (this !== value) throw Error('Get receiver');
      if (mode === 'getThrow') throw reason;
      if (mode === 'noncallable') return 17;
      return function (resolve, reject) {
        calls++; events.push('call');
        if (this !== value) throw Error('Call receiver');
        if (mode === 'thenThrow') throw reason;
        resolve(91); reject(reason); resolve(92);
      };
    } });
    Promise.resolve().then(() => events.push('tick'));
    let result, caught = false;
    try { result = await value; events.push('resume'); }
    catch (error) { caught = error === reason; events.push('catch'); }
    const rejects = mode === 'getThrow' || mode === 'thenThrow';
    const expected = mode === 'getThrow' ? 'get,tick,catch'
      : mode === 'noncallable' ? 'get,tick,resume'
      : mode === 'thenThrow' ? 'get,tick,call,catch'
      : 'get,tick,call,resume';
    if (caught !== rejects || reads !== 1 || calls !== (mode === 'callable' || mode === 'thenThrow' ? 1 : 0)
        || (!rejects && result !== (mode === 'callable' ? 91 : value))
        || events.join(',') !== expected)
      throw Error('module await ' + kind + ':' + mode + ':' + events.join(','));
    delete value.then;
    checks++;
  }
}
console.log('module object-like await', checks);
"#;
    let tree = crate::parser_api_stability::parse_module(source).expect("module source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "promise-object-like-await.mjs"),
        &LoweringContext::new("promise-await", "object-like-resolution", "module-await"),
    )
    .expect("module source lowers")
    .ir3;
    assert!(
        module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::ModuleAwaitValue { .. })),
        "exercise the module-await instruction"
    );
    for throughput in [false, true] {
        for stress in [None, Some(7)] {
            let mut core = InterpreterCore::new(config(throughput), "module-object-like-await");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).expect("module await executes");
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                actual, "module object-like await 20",
                "throughput={throughput}, stress={stress:?}"
            );
            assert!(core.top_level_await_resumption_contexts.is_empty());
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}
