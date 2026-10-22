(function installMIME(util) {
  'use strict';
  // MIME records and their ordered parameters share util's existing loader.
  // Specification-based parsing retains Node's parameter recovery behavior.
  // No I/O, ambient module loading, or additional execution budget is used.
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const create = Object.create;
  const setPrototype = Object.setPrototypeOf;
  const getPrototype = Object.getPrototypeOf;
  const slice = String.prototype.slice;
  const lower = String.prototype.toLowerCase;
  const join = Array.prototype.join;
  const Maps = Map;
  const mapGet = Map.prototype.get;
  const mapHas = Map.prototype.has;
  const mapSet = Map.prototype.set;
  const mapDelete = Map.prototype.delete;
  const mapEntries = Map.prototype.entries;
  const mapKeys = Map.prototype.keys;
  const mapValues = Map.prototype.values;
  const mapNext = getPrototype(apply(mapEntries, new Maps(), [])).next;
  const Weak = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const Type = TypeError;
  const iterator = Symbol.iterator;
  let mimeStates, parameterStates;

  function property(object, key, value) {
    const descriptor = create(null);
    descriptor.value = value; descriptor.writable = true; descriptor.configurable = true;
    define(object, key, descriptor);
  }
  function parts() { return setPrototype([], null); }
  function textPart(text, start, end) { return apply(slice, text, [start, end]); }
  function asciiLower(text) { return apply(lower, text, []); }
  function whitespace(ch) { return ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n'; }
  function token(ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
      (ch >= '0' && ch <= '9') || ch === '!' || ch === '#' || ch === '$' ||
      ch === '%' || ch === '&' || ch === "'" || ch === '*' || ch === '+' ||
      ch === '-' || ch === '.' || ch === '^' || ch === '_' || ch === '`' ||
      ch === '|' || ch === '~';
  }
  function validToken(text) {
    if (text.length === 0) return false;
    for (let i = 0; i < text.length; i++) if (!token(text[i])) return false;
    return true;
  }
  function validValue(text) {
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch !== '\t' && !(ch >= ' ' && ch <= '~') && !(ch >= '\x80' && ch <= '\xff')) return false;
    }
    return true;
  }
  function syntax(part) {
    const error = new Type('Invalid MIME ' + part);
    error.code = 'ERR_INVALID_MIME_SYNTAX';
    return error;
  }
  function mimeState(object) {
    const state = mimeStates === undefined ? undefined : apply(weakGet, mimeStates, [object]);
    if (state === undefined) throw new Type('Invalid MIMEType receiver');
    return state;
  }
  function parameterState(object) {
    const state = parameterStates === undefined ? undefined : apply(weakGet, parameterStates, [object]);
    if (state === undefined) throw new Type('Invalid MIMEParams receiver');
    return state;
  }
  function parametersString(map) {
    const output = parts();
    const entries = apply(mapEntries, map, []);
    for (;;) {
      const item = apply(mapNext, entries, []);
      if (item.done) break;
      const name = item.value[0], value = item.value[1];
      if (output.length !== 0) output[output.length] = ';';
      output[output.length] = name; output[output.length] = '=';
      if (validToken(value)) output[output.length] = value;
      else {
        output[output.length] = '"';
        let start = 0;
        for (let i = 0; i < value.length; i++) {
          if (value[i] === '"' || value[i] === '\\') {
            output[output.length] = textPart(value, start, i);
            output[output.length] = '\\';
            start = i;
          }
        }
        output[output.length] = textPart(value, start, value.length);
        output[output.length] = '"';
      }
    }
    return apply(join, output, ['']);
  }
  class MIMEParams {
    constructor() {
      if (parameterStates === undefined) parameterStates = new Weak();
      apply(weakSet, parameterStates, [this, new Maps()]);
    }
    delete(name) { const map = parameterState(this); apply(mapDelete, map, [name]); }
    get(name) {
      const map = parameterState(this), key = name;
      return apply(mapHas, map, [key]) ? apply(mapGet, map, [key]) : null;
    }
    has(name) { return apply(mapHas, parameterState(this), [name]); }
    set(name, value) {
      const map = parameterState(this), key = `${name}`, text = `${value}`;
      if (!validToken(key)) throw syntax('parameter name');
      if (!validValue(text)) throw syntax('parameter value');
      apply(mapSet, map, [key, text]);
    }
    *entries() {
      const iterator = apply(mapEntries, parameterState(this), []);
      for (;;) { const item = apply(mapNext, iterator, []); if (item.done) return; yield item.value; }
    }
    *keys() {
      const iterator = apply(mapKeys, parameterState(this), []);
      for (;;) { const item = apply(mapNext, iterator, []); if (item.done) return; yield item.value; }
    }
    *values() {
      const iterator = apply(mapValues, parameterState(this), []);
      for (;;) { const item = apply(mapNext, iterator, []); if (item.done) return; yield item.value; }
    }
    toString() { return parametersString(parameterState(this)); }
  }
  property(MIMEParams.prototype, iterator, MIMEParams.prototype.entries);
  property(MIMEParams.prototype, 'toJSON', MIMEParams.prototype.toString);

  function parse(input) {
    let start = 0, end = input.length;
    while (start < end && whitespace(input[start])) start++;
    let position = start;
    while (position < end && input[position] !== '/') position++;
    const type = textPart(input, start, position);
    if (position === end || !validToken(type)) throw syntax('type');
    start = ++position;
    while (position < end && input[position] !== ';') position++;
    let subtypeEnd = position;
    while (subtypeEnd > start && whitespace(input[subtypeEnd - 1])) subtypeEnd--;
    const subtype = textPart(input, start, subtypeEnd);
    if (!validToken(subtype)) throw syntax('subtype');
    const params = new MIMEParams(), map = parameterState(params);
    while (position < end) {
      position++; // The semicolon at the end of the preceding component.
      while (position < end && whitespace(input[position])) position++;
      start = position;
      while (position < end && input[position] !== ';' && input[position] !== '=') position++;
      const name = asciiLower(textPart(input, start, position));
      if (position === end) break;
      if (input[position] === ';') continue;
      if (++position === end) break;
      let value;
      if (input[position] === '"') {
        start = ++position;
        let fragments;
        while (position < end && input[position] !== '"') {
          if (input[position] === '\\') {
            if (fragments === undefined) fragments = parts();
            fragments[fragments.length] = textPart(input, start, position);
            position++;
            if (position === end) { start = position - 1; break; }
            // A quoted pair contributes exactly the escaped code unit.
            fragments[fragments.length] = input[position++]; start = position;
          } else position++;
        }
        value = textPart(input, start, position);
        if (fragments !== undefined) {
          fragments[fragments.length] = value; value = apply(join, fragments, ['']);
        }
        if (position < end) position++;
        // Node's MIMEParams parser resumes at the next character after a
        // quoted value, even when the following separator is not ';'.
      } else {
        start = position;
        while (position < end && input[position] !== ';') position++;
        let valueEnd = position;
        while (valueEnd > start && whitespace(input[valueEnd - 1])) valueEnd--;
        value = textPart(input, start, valueEnd);
        if (value.length === 0) continue;
      }
      if (validToken(name) && validValue(value) && !apply(mapHas, map, [name])) {
        apply(mapSet, map, [name, value]);
      }
    }
    return { type: asciiLower(type), subtype: asciiLower(subtype), params: params };
  }
  class MIMEType {
    constructor(input) {
      const state = parse(`${input}`);
      if (mimeStates === undefined) mimeStates = new Weak();
      apply(weakSet, mimeStates, [this, state]);
    }
    get type() { return mimeState(this).type; }
    set type(value) {
      const text = `${value}`;
      if (!validToken(text)) throw syntax('type');
      mimeState(this).type = asciiLower(text);
    }
    get subtype() { return mimeState(this).subtype; }
    set subtype(value) {
      const text = `${value}`;
      if (!validToken(text)) throw syntax('subtype');
      mimeState(this).subtype = asciiLower(text);
    }
    get essence() { const state = mimeState(this); return state.type + '/' + state.subtype; }
    get params() { return mimeState(this).params; }
    toString() {
      const state = mimeState(this), parameters = parametersString(parameterState(state.params));
      return state.type + '/' + state.subtype + (parameters.length === 0 ? '' : ';' + parameters);
    }
  }
  property(MIMEType.prototype, 'toJSON', MIMEType.prototype.toString);
  // Do not consult guest iteration or inherited setters while publishing exports.
  function exportClass(name, value) {
    const descriptor = create(null);
    descriptor.value = value; descriptor.writable = true;
    descriptor.configurable = true; descriptor.enumerable = true;
    define(util, name, descriptor);
  }
  exportClass('MIMEType', MIMEType); exportClass('MIMEParams', MIMEParams);
  return util;
})
