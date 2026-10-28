(function () {
  'use strict';
  // Engine-owned diagnostics. Publishing and store callbacks run in the
  // caller's ordinary execution context; this module grants no host effects.
  // Named channels are retained for this module instance's lifetime. Unlike
  // Node's weak registry, inactive names are not reclaimed before that point.
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const create = Object.create;
  const MapClass = Map;
  const mapGet = Map.prototype.get;
  const mapHas = Map.prototype.has;
  const mapSet = Map.prototype.set;
  const mapDelete = Map.prototype.delete;
  const mapForEach = Map.prototype.forEach;
  const Weak = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const splice = Array.prototype.splice;
  const at = Array.prototype.at;
  const Type = TypeError;
  const schedule = queueMicrotask;
  const registry = new MapClass();
  const states = new Weak();
  const eventNames = ['start', 'end', 'asyncStart', 'asyncEnd', 'error'];

  function invalid(name) {
    const error = new Type('Invalid ' + name);
    const descriptor = create(null);
    descriptor.value = 'ERR_INVALID_ARG_TYPE'; descriptor.configurable = true; descriptor.writable = true;
    define(error, 'code', descriptor);
    return error;
  }
  function state(channel) {
    const value = apply(weakGet, states, [channel]);
    if (value === undefined) throw invalid('Channel receiver');
    return value;
  }
  function report(error) { schedule(function () { throw error; }); }
  function validName(name) {
    if (typeof name !== 'string' && typeof name !== 'symbol') throw invalid('channel');
  }
  function subscriberList() {
    // These snapshots never escape the module. Ordinary arrays let inherited
    // numeric setters intercept registration and species hooks observe copies.
    // Null-prototype storage keeps every indexed read/write module-owned.
    const list = create(null);
    list.length = 0;
    return list;
  }
  function publish(channel, message) {
    const subscribers = state(channel).subscribers;
    // Subscription changes replace the list, so a publish sees one immutable
    // snapshot without allocating per message. Reentrant publishes see the new
    // list. Duplicate subscriptions remain separate, ordered registrations.
    for (let i = 0; i < subscribers.length; i++) {
      try { apply(subscribers[i], undefined, [message, channel.name]); }
      catch (error) { report(error); }
    }
  }
  class Channel {
    constructor(name) {
      validName(name);
      this.name = name;
      apply(weakSet, states, [this, { subscribers: subscriberList(), stores: new MapClass(), storeCount: 0 }]);
      apply(mapSet, registry, [name, this]);
    }
    get hasSubscribers() {
      const s = state(this);
      return s.subscribers.length !== 0 || s.storeCount !== 0;
    }
    subscribe(subscription) {
      if (typeof subscription !== 'function') throw invalid('subscription');
      const s = state(this), current = s.subscribers, next = subscriberList();
      for (let i = 0; i < current.length; i++) next[i] = current[i];
      next[current.length] = subscription;
      next.length = current.length + 1;
      s.subscribers = next;
    }
    unsubscribe(subscription) {
      const s = state(this), current = s.subscribers;
      for (let i = 0; i < current.length; i++) {
        if (current[i] === subscription) {
          const next = subscriberList();
          for (let j = 0; j < i; j++) next[j] = current[j];
          for (let j = i + 1; j < current.length; j++) next[j - 1] = current[j];
          next.length = current.length - 1;
          s.subscribers = next;
          return true;
        }
      }
      return false;
    }
    publish(message) { publish(this, message); }
    bindStore(store, transform) {
      const s = state(this);
      // Entries, including those whose transform is undefined, need an
      // explicit presence test; rebinding does not change insertion order.
      if (!apply(mapHas, s.stores, [store])) s.storeCount++;
      apply(mapSet, s.stores, [store, transform]);
    }
    unbindStore(store) {
      const s = state(this), removed = apply(mapDelete, s.stores, [store]);
      if (removed) s.storeCount--;
      return removed;
    }
    runStores(context, fn, thisArg, ...args) {
      const self = this, s = state(self);
      let run = function () { publish(self, context); return apply(fn, thisArg, args); };
      // Last bound store is outermost. Each transformer therefore observes
      // the enclosing store, and publishing runs inside every bound context.
      // Snapshot the wrappers before executing any user transform/run code.
      apply(mapForEach, s.stores, [function (transform, store) {
        const inner = run;
        run = function () {
          let value = context;
          if (transform !== undefined) {
            try { value = apply(transform, undefined, [context]); }
            catch (error) { value = undefined; report(error); }
          }
          return store.run(value, inner);
        };
      }]);
      return run();
    }
  }
  function channel(name) {
    validName(name);
    const found = apply(mapGet, registry, [name]);
    return found === undefined ? new Channel(name) : found;
  }
  function hasSubscribers(name) {
    const found = apply(mapGet, registry, [name]);
    return found === undefined ? false : found.hasSubscribers;
  }
  function subscribe(name, subscription) { channel(name).subscribe(subscription); }
  function unsubscribe(name, subscription) { return channel(name).unsubscribe(subscription); }

  class TracingChannel {
    constructor(nameOrChannels) {
      if (typeof nameOrChannels === 'string') {
        for (let i = 0; i < eventNames.length; i++) {
          const event = eventNames[i];
          this[event] = channel('tracing:' + nameOrChannels + ':' + event);
        }
      } else {
        if (nameOrChannels === null || typeof nameOrChannels !== 'object') throw invalid('nameOrChannels');
        for (let i = 0; i < eventNames.length; i++) {
          const event = eventNames[i], value = nameOrChannels[event];
          state(value); this[event] = value;
        }
      }
    }
    get hasSubscribers() {
      for (let i = 0; i < eventNames.length; i++) if (this[eventNames[i]].hasSubscribers) return true;
      return false;
    }
    subscribe(subscribers) {
      for (let i = 0; i < eventNames.length; i++) {
        const name = eventNames[i], fn = subscribers[name];
        if (fn) this[name].subscribe(fn);
      }
    }
    unsubscribe(subscribers) {
      let removed = true;
      for (let i = 0; i < eventNames.length; i++) {
        const name = eventNames[i], fn = subscribers[name];
        if (fn) removed = this[name].unsubscribe(fn) && removed;
      }
      return removed;
    }
    traceSync(fn, context, thisArg, ...args) {
      if (!this.hasSubscribers) return apply(fn, thisArg, args);
      if (context === undefined) context = {};
      const channels = this;
      return channels.start.runStores(context, function () {
        try { const value = apply(fn, thisArg, args); context.result = value; return value; }
        catch (error) { context.error = error; channels.error.publish(context); throw error; }
        finally { channels.end.publish(context); }
      });
    }
    tracePromise(fn, context, thisArg, ...args) {
      // An inactive trace is transparent, including promise identity and
      // non-promise return values. Active traces observe actual settlement.
      if (!this.hasSubscribers) return apply(fn, thisArg, args);
      if (context === undefined) context = {};
      const channels = this;
      async function settle(input) {
        let value, failed = false;
        try { value = await input; }
        catch (error) { failed = true; value = error; }
        if (failed) { context.error = value; channels.error.publish(context); }
        else context.result = value;
        // Promise reactions already inherit the start store scope. Unlike
        // callback continuation, this phase publishes without rebinding the
        // asyncStart store (the reference's two tracing APIs differ here).
        channels.asyncStart.publish(context);
        try { if (failed) throw value; return value; }
        finally { channels.asyncEnd.publish(context); }
      }
      return channels.start.runStores(context, function () {
        try { return settle(apply(fn, thisArg, args)); }
        // A throw before the function returns is still synchronous. Do not
        // confuse it with rejection of the function's returned promise.
        catch (error) { context.error = error; channels.error.publish(context); throw error; }
        finally { channels.end.publish(context); }
      });
    }
    traceCallback(fn, position, context, thisArg, ...args) {
      if (!this.hasSubscribers) return apply(fn, thisArg, args);
      if (position === undefined) position = -1;
      const callback = apply(at, args, [position]);
      if (typeof callback !== 'function') throw invalid('callback');
      if (context === undefined) context = {};
      const channels = this;
      function tracedCallback(...values) {
        // Callback error slots follow the error-first convention: falsy
        // slots are success; thrown and rejected falsy values remain errors.
        if (values[0]) { context.error = values[0]; channels.error.publish(context); }
        else context.result = values[1];
        const receiver = this;
        channels.asyncStart.runStores(context, function () {
          try { apply(callback, receiver, values); }
          finally { channels.asyncEnd.publish(context); }
        });
      }
      apply(splice, args, [position, 1, tracedCallback]);
      return channels.start.runStores(context, function () {
        try { return apply(fn, thisArg, args); }
        catch (error) { context.error = error; channels.error.publish(context); throw error; }
        finally { channels.end.publish(context); }
      });
    }
  }
  function tracingChannel(nameOrChannels) { return new TracingChannel(nameOrChannels); }
  return { channel: channel, hasSubscribers: hasSubscribers, subscribe: subscribe,
    unsubscribe: unsubscribe, tracingChannel: tracingChannel, Channel: Channel };
})()
