'use strict';
// Host-side differential validation of the exact engine-owned events prelude.
// The adapters use Node's native emitter/once in place of two Rust hostcalls.
// This does NOT execute FrankenEngine's parser, lowering, interpreter, or IFC.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const nodeEvents = require('node:events');
const { spawnSync } = require('node:child_process');
const nativeOnce = nodeEvents.once;
const source = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/events_module.js'), 'utf8');
const factory = new Function('__franken_events_constructor', '__franken_events_once',
  'AbortController', 'AbortSignal', 'return ' + source);
function candidate(Controller = AbortController, Signal = AbortSignal) {
  class AdapterEmitter extends nodeEvents.EventEmitter {}
  Object.defineProperty(AdapterEmitter, 'name', { value: 'EventEmitter' });
  return factory(() => AdapterEmitter, (...args) => nativeOnce(...args), Controller, Signal);
}
function reason(error) {
  return { name: error && error.name, code: error && error.code, cause: error && error.cause };
}
async function outcome(promise) {
  try { return { ok: await promise }; } catch (error) { return { error: reason(error) }; }
}
async function bounded(work) {
  let timer;
  try {
    return await Promise.race([work, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('scenario did not settle')), 2000);
    })]);
  } finally { clearTimeout(timer); }
}
let count = 0;
async function compare(name, scenario) {
  const expected = await bounded(Promise.resolve().then(() => scenario(nodeEvents)));
  const actual = await bounded(Promise.resolve().then(() => scenario(candidate())));
  assert.deepStrictEqual(actual, expected, name);
  count++;
}
async function run() {
  const rustTests = fs.readFileSync(path.join(__dirname,
    '../crates/franken-engine/tests/events_default_import_bd_9vouw_165.rs'), 'utf8');
  const programs = new Map([...rustTests.matchAll(/const (\w+): &str = r#"([\s\S]*?)"#;/g)]
    .map(match => [match[1], match[2]]));
  let rustSourceChecks=0;
  let protectedSourceChecks = 0;
  for (const match of rustTests.matchAll(/assert_native_events\(\s*(\w+),\s*("(?:[^"\\]|\\.)*"),\s*false,?\s*\)/g)) {
    const name = match[1], program = programs.get(name), expected = JSON.parse(match[2]);
    assert.ok(program, 'missing regression source ' + name);
    if (name.startsWith('PROTECTED_')) {
      // A separate process contains the intentional primordial mutations.
      // These stronger cancellation-state contracts are candidate-only, not
      // Node-equivalence cases and not executions of the Rust test harness.
      const child = spawnSync(process.execPath, ['-'], {
        input: `const nodeEvents = require('node:events');
          class AdapterEmitter extends nodeEvents.EventEmitter {}
          const make = new Function('__franken_events_constructor', '__franken_events_once', ${JSON.stringify('return ' + source)});
          const E = make(() => AdapterEmitter, nodeEvents.once);
          new Function('require', ${JSON.stringify(program)})(name => {
            if (name !== 'events' && name !== 'node:events') throw new Error('unexpected dependency');
            return E;
          });`,
        encoding: 'utf8', timeout: 2000,
      });
      if (child.error) throw child.error;
      assert.equal(child.status, 0, name + ': ' + child.stderr);
      assert.equal(child.stdout.trimEnd(), expected, name);
      protectedSourceChecks++;
      continue;
    }
    await compare('Rust regression source under host adapters ' + name, async E => {
      const lines = [];
      const log = (...args) => lines.push(require('node:util').format(...args));
      new Function('require', 'console', program)(specifier => {
        assert.ok(specifier === 'events' || specifier === 'node:events');
        return E;
      }, { log });
      await new Promise(setImmediate);
      const actual = lines.join('\n');
      assert.equal(actual, expected, name + ' declared output');
      return actual;
    });
    rustSourceChecks++;
  }
  assert.equal(protectedSourceChecks, 4, 'every protected-state fixture must be exercised');
  assert.equal(rustSourceChecks + protectedSourceChecks, programs.size-1,
    'every non-ESM regression source must be exercised');
  const esm=require('node:child_process').spawnSync(process.execPath,
    ['--input-type=module','-e',programs.get('ESM_EXPORTS')],{encoding:'utf8',timeout:2000});
  assert.equal(esm.status,0,esm.stderr);
  assert.equal(esm.stdout.trim(),'true function function\n42','ESM fixture reference output only');
  await compare('constructor identity and first-class exports', async E => {
    const { EventEmitter, once, on } = E;
    const Constructor = (x => x)(EventEmitter);
    const emitter = new Constructor();
    return [E === EventEmitter, typeof once, typeof on, once.length, on.length,
      emitter instanceof E, E.name];
  });
  await compare('once retains native reaction ordering', async E => {
    const e = new E, order = [];
    E.once(e, 'x').then(() => order.push('once'));
    e.emit('x'); order.push('sync'); queueMicrotask(() => order.push('queued'));
    await Promise.resolve(); await Promise.resolve();
    return [order, e.listenerCount('x'), e.listenerCount('error')];
  });
  for (const hasSignal of [false, true]) {
    for (const kind of ['success', 'error', 'error-event', 'abort']) {
      if (!hasSignal && kind === 'abort') continue;
      await compare('once ' + hasSignal + ' ' + kind, async E => {
        const e = new E, controller = new AbortController;
        const name = kind === 'error-event' ? 'error' : 'x';
        const original = new Error('original');
        const p = E.once(e, name, hasSignal ? { signal: controller.signal } : undefined)
          .then(v => ['ok', v.map(x => x === original ? 'same-error' : x)],
            err => ['error', err === original, reason(err)]);
        if (kind === 'abort') controller.abort('stop');
        else if (kind === 'error' || kind === 'error-event') e.emit('error', original);
        else e.emit('x', 1, 'two', { value: 3 });
        return [await p, e.listenerCount('x'), e.listenerCount('error'),
          nodeEvents.getEventListeners(controller.signal, 'abort').length];
      });
    }
  }
  for (const method of ['on', 'once']) {
    for (const options of [null, false, 3, 'x', [], {signal: null}, {signal: {}}]) {
      await compare(method + ' invalid options ' + JSON.stringify(options), async E => {
        try {
          const result = E[method](new E, 'x', options);
          return await outcome(result);
        } catch (error) { return { error: reason(error) }; }
      });
    }
    await compare(method + ' pre-aborted signal', async E => {
      const e = new E, c = new AbortController; c.abort('before');
      try { return await outcome(E[method](e, 'x', {signal:c.signal})); }
      catch (error) { return { error: reason(error) }; }
    });
  }
  await compare('queued events, close, and async iterator identity', async E => {
    const e = new E, it = E.on(e, 'x', {close:['end']});
    const same = it[Symbol.asyncIterator]() === it;
    e.emit('x', 1); e.emit('x', 2, 3); e.emit('end');
    return [same, await it.next(), await it.next(), await it.next(),
      e.listenerCount('x'), e.listenerCount('end'), e.listenerCount('error')];
  });
  await compare('concurrent next preserves waiter order', async E => {
    const e = new E, it = E.on(e, 'x');
    const a=it.next(), b=it.next(), c=it.next();
    e.emit('x', 'a'); e.emit('x', 'b'); await it.return();
    return [await a, await b, await c, await it.next(), e.eventNames()];
  });
  for (const buffered of [0,1,5]) {
    for (const pending of [0,1,3]) {
      for (const terminal of ['error', 'abort', 'return', 'close', 'throw']) {
        await compare(`terminal ${terminal} buffered=${buffered} pending=${pending}`, async E => {
          const e=new E, controller=new AbortController;
          const it=E.on(e,'x',{signal:controller.signal,close:['end']});
          const waits=[];
          for(let i=0;i<pending;i++) waits.push(outcome(it.next()));
          for(let i=0;i<buffered;i++) e.emit('x',i);
          let returned;
          if(terminal==='error') e.emit('error',new Error('failed'));
          if(terminal==='abort') controller.abort('cancelled');
          if(terminal==='return') returned=await it.return();
          if(terminal==='close') e.emit('end');
          if(terminal==='throw') returned=it.throw(new Error('injected'));
          const results=await Promise.all(waits);
          for(let i=0;i<buffered+2;i++) results.push(await outcome(it.next()));
          return [returned,results,e.eventNames(),nodeEvents.getEventListeners(controller.signal,'abort').length];
        });
      }
    }
  }
  await compare('error event yields instead of rejecting', async E => {
    const e=new E, it=E.on(e,'error'), original=new Error('x');
    const wait=it.next(); e.emit('error',original);
    const value=await wait; await it.return();
    return [value.done,value.value[0]===original,e.eventNames()];
  });
  for (const sequence of ['return-throw', 'error-throw', 'throw-return', 'throw-throw']) {
    await compare('terminal reentry ' + sequence, async E => {
      const e=new E, it=E.on(e,'x'), original=new Error('injected');
      for(const op of sequence.split('-')) {
        if(op==='return') await it.return();
        if(op==='error') e.emit('error',new Error('first'));
        if(op==='throw') it.throw(original);
      }
      let same=false;try{await it.next();}catch(error){same=error===original;}
      return [same,await it.next(),e.listenerCount('x'),e.listenerCount('error')];
    });
  }
  for(const targetKind of ['on','once']) {
    await compare('EventTarget no signal '+targetKind,async E=>{
      const target=new EventTarget, event=new Event('ready');
      const value=E[targetKind](target,'ready');
      const wait=targetKind==='on'?value.next():value;
      target.dispatchEvent(event);const result=await wait;
      if(targetKind==='on')await value.return();
      return [(targetKind==='on'?result.value:result)[0]===event,
        nodeEvents.getEventListeners(target,'ready').length];
    });
    await compare('EventTarget '+targetKind, async E=>{
      const target=new EventTarget, c=new AbortController, event=new Event('ready');
      const value=E[targetKind](target,'ready',{signal:c.signal});
      const wait=targetKind==='on'?value.next():value;
      target.dispatchEvent(event);
      const result=await wait;
      if(targetKind==='on') await value.return();
      return [(targetKind==='on'?result.value:result)[0]===event,
        nodeEvents.getEventListeners(target,'ready').length,
        nodeEvents.getEventListeners(c.signal,'abort').length];
    });
  }
  for (const options of [
    {highWaterMark:2,lowWaterMark:1}, {highWatermark:2,lowWatermark:2},
    {highWaterMark:3,highWatermark:1,lowWaterMark:2},
    {highWaterMark:null,highWatermark:2}, {highWaterMark:2,lowWaterMark:4}
  ]) {
    await compare('watermarks '+JSON.stringify(options), async E => {
      const e=new E, calls=[]; e.pause=()=>calls.push('pause');e.resume=()=>calls.push('resume');
      const it=E.on(e,'x',options), output=[];
      for(let i=0;i<5;i++){e.emit('x',i);output.push(calls.slice());}
      for(let i=0;i<5;i++){output.push(await it.next());output.push(calls.slice());}
      await it.return();return output;
    });
  }
  for(const name of ['highWaterMark','lowWaterMark','highWatermark','lowWatermark']) {
    for(const value of [0,-1,1.1,NaN,Infinity,'1',false,9007199254740992]) {
      await compare('watermark validation '+name+' '+value,async E=>{
        try {const it=E.on(new E,'x',{[name]:value});await it.return();return 'accepted';}
        catch(error){return reason(error);}
      });
    }
  }
  // Deterministic operation streams compare queue terminal semantics without
  // leaving unresolved next() promises. No generated expected-output goldens.
  for(let seed=1;seed<=128;seed++) {
    await compare('queue trace '+seed,async E=>{
      let state=seed; const random=()=>state=(Math.imul(state,1664525)+1013904223)>>>0;
      const e=new E, it=E.on(e,'x',{close:['end']}), waits=[];let emitted=0,read=0;
      for(let i=0;i<32;i++){
        if((random()&3)===0 && emitted>read){waits.push(it.next());read++;}
        else {e.emit('x',seed,i);emitted++;}
      }
      e.emit('end');
      for(;read<emitted+1;read++)waits.push(it.next());
      return [await Promise.all(waits),e.eventNames()];
    });
  }
  // A Node limitation is not promoted into an equivalence claim: operations
  // that finish during newListener must not leak a listener installed later.
  for (const action of ['abort','throw']) {
    const E=candidate(), e=new E, controller=new AbortController;
    const original=new Error('registration failed');
    e.on('newListener',name=>{
      if(name==='x'){
        if(action==='abort')controller.abort('during registration');
        else throw original;
      }
    });
    if(action==='abort'){
      const it=E.on(e,'x',{signal:controller.signal});
      assert.equal((await outcome(it.next())).error.code,'ABORT_ERR');
    }else assert.throws(()=>E.on(e,'x'),e=>e===original);
    assert.equal(e.listenerCount('x'),0);
    assert.equal(e.listenerCount('error'),0);
    assert.equal(nodeEvents.getEventListeners(controller.signal,'abort').length,0);
  }
  // Observe actual native Node controllers/compositions behind the adapter.
  // This establishes that the JS layer releases the private source on every
  // terminal path; native FrankenEngine graph unlinking/GC is a separate gate.
  let privateLifetimeChecks = 0;
  for (const action of ['once-success', 'once-error', 'once-abort', 'on-return',
    'on-close', 'on-throw', 'on-abort', 'cleanup-failure', 'registration-failure']) {
    const controllers = [], dependents = [], root = new AbortController();
    const failure = new Error('composition registration failed');
    function TrackedController() {
      const controller = new AbortController();
      controllers.push(controller);
      return controller;
    }
    TrackedController.prototype = AbortController.prototype;
    const TrackedSignal = {
      prototype: AbortSignal.prototype,
      any(sources) {
        // Exercise the private iterable protocol as FrankenEngine does, even
        // though Node's any() directly indexes its Array argument.
        const iterator = sources[Symbol.iterator]();
        assert.equal(iterator.next().value, sources[0]);
        assert.equal(iterator.next().value, sources[1]);
        assert.equal(iterator.next().done, true);
        assert.equal(iterator.return().done, true);
        const dependent = AbortSignal.any(sources);
        dependents.push(dependent);
        if (action === 'registration-failure') throw failure;
        return dependent;
      },
    };
    const E = candidate(TrackedController, TrackedSignal), emitter = new E();
    const options = { signal: root.signal, close: ['end'] };
    if (action === 'registration-failure') {
      assert.throws(() => E.on(emitter, 'work', options), error => error === failure);
    } else if (action.startsWith('once-')) {
      const pending = outcome(E.once(emitter, 'work', options));
      if (action === 'once-success') emitter.emit('work', 42);
      if (action === 'once-error') emitter.emit('error', failure);
      if (action === 'once-abort') root.abort(failure);
      await bounded(pending);
    } else {
      const iterator = E.on(emitter, 'work', options);
      const pending = outcome(iterator.next());
      if (action === 'cleanup-failure') {
        const remove = emitter.removeListener;
        emitter.removeListener = function (name, listener) {
          remove.call(this, name, listener);
          if (name === 'work') throw failure;
          return this;
        };
        await iterator.return();
      }
      if (action === 'on-return') await iterator.return();
      if (action === 'on-close') emitter.emit('end');
      if (action === 'on-throw') iterator.throw(failure);
      if (action === 'on-abort') root.abort(failure);
      await bounded(pending);
      await iterator.return();
    }
    assert.equal(controllers.length, 1, action);
    assert.equal(dependents.length, 1, action);
    assert.equal(controllers[0].signal.aborted, true, action + ' release source');
    assert.equal(dependents[0].aborted, true, action + ' private dependent');
    assert.equal(root.signal.aborted, action.endsWith('-abort'), action + ' caller state');
    assert.equal(nodeEvents.getEventListeners(dependents[0], 'abort').length, 0, action);
    assert.equal(emitter.eventNames().length, 0, action);
    privateLifetimeChecks++;
  }
  // Do not count the private-dependent dispatch phase as Node-equivalent.
  // A public listener can observe the emitter before the private event has
  // removed its listeners, although ready/error/next paths already enforce
  // the native cancellation state and the operation settles as cancelled.
  async function cleanupPhase(E) {
    const root = new AbortController(), emitter = new E();
    const iterator = E.on(emitter, 'work', { signal: root.signal });
    const pending = outcome(iterator.next());
    let countDuringSourceEvent;
    root.signal.addEventListener('abort', () => {
      countDuringSourceEvent = emitter.listenerCount('work');
    });
    root.abort();
    assert.equal((await bounded(pending)).error.code, 'ABORT_ERR');
    return countDuringSourceEvent;
  }
  const referencePhase = await cleanupPhase(nodeEvents);
  const candidatePhase = await cleanupPhase(candidate());
  assert.equal(referencePhase, 0);
  assert.equal(candidatePhase, 1);
  console.log(JSON.stringify({node:process.version,differentialChecks:count,
    rustRegressionSourcesCheckedThroughHostAdapters:rustSourceChecks,esmReferenceOnly:1,
    candidateOnlyProtectedSourceChecks:protectedSourceChecks,
    candidateOnlyPrivateLifetimeChecks:privateLifetimeChecks,
    disclosedNonParity: { listenersDuringSourceAbort: { node: referencePhase, candidate: candidatePhase } },
    registrationCleanupInvariants:2,failures:0,
    scope:'exact events JavaScript plus Node hostcall adapters; Rust path not executed'},null,2));
}
run().catch(error=>{console.error(error);process.exitCode=1;});
