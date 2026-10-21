async function verifyReadlineDelimiters(readline, EventEmitter) {
  function check(value, message) { if (!value) throw new Error(message); }
  function open() {
    const input = new EventEmitter();
    input.resume = function () { return this; };
    input.pause = function () { return this; };
    const rl = readline.createInterface({ input: input, terminal: false, crlfDelay: Infinity });
    return { input: input, rl: rl };
  }
  function collect(chunks, direct) {
    const r = open(), lines = [];
    let closed = 0;
    r.rl.on('line', function (line) { lines.push(line); });
    r.rl.on('close', function () { closed++; });
    for (const chunk of chunks) {
      if (direct) r.rl.write(chunk); else r.input.emit('data', chunk);
    }
    r.input.emit('end');
    check(closed === 1 && r.input.listenerCount('data') === 0, 'teardown');
    return lines;
  }
  function same(actual, expected, name) {
    check(JSON.stringify(actual) === JSON.stringify(expected), name);
  }
  const long = 'x'.repeat(4096);
  same(collect([long, '\r', '\n', long, '\nlast'], false), [long, long, 'last'], 'long fragments');
  const text = '\r\naé\ud800🚀\rB\n\nC\r\nfinal';
  const expected = ['', 'aé\ud800🚀', 'B', '', 'C', 'final'];
  for (let at = 0; at <= text.length; at++) {
    same(collect([text.slice(0, at), text.slice(at)], false), expected, 'UTF-16 split ' + at);
    same(collect([text.slice(0, at), text.slice(at)], true), expected, 'direct split ' + at);
  }
  same(collect(['a\n'.repeat(64) + 'tail\r'], false),
    Array(64).fill('a').concat(['tail']), 'late CR');
  same(collect(['b\r'.repeat(64) + 'tail\n'], false),
    Array(64).fill('b').concat(['tail']), 'late LF');
  same(collect([new Uint8Array([97, 0xc3]), new Uint8Array([0xa9, 13]),
    new Uint8Array([10, 0xf0, 0x9f]), new Uint8Array([0x9a, 0x80, 10])], false), ['aé', '🚀'], 'UTF-8 boundaries');
  const reentrant = open(), order = [];
  reentrant.rl.on('line', function (line) {
    order.push(line);
    if (line === 'first') reentrant.input.emit('data', 'inner\n');
  });
  reentrant.input.emit('data', 'first\nsecond\nsuffix');
  reentrant.input.emit('end');
  same(order, ['first', 'suffixinner', 'second'], 'reentrant publication');
  const question = open(), answers = [];
  question.rl.question('?', function (answer) { answers.push('answer:' + answer); });
  question.rl.on('line', function (line) { answers.push('line:' + line); });
  question.input.emit('data', 'yes\r\nnext\n');
  question.input.emit('end');
  same(answers, ['answer:yes', 'line:next'], 'question');
  const asynchronous = open(), iter = asynchronous.rl[Symbol.asyncIterator]();
  asynchronous.input.emit('data', 'one\r\ntwo\rthree\n');
  asynchronous.input.emit('end');
  const items = [];
  for await (const line of iter) items.push(line);
  same(items, ['one', 'two', 'three'], 'async iteration');
  // Exercise the complete-line path as well as a first line assembled from
  // pending fragments. Later lines must not consume the trailing suffix.
  for (const count of [1, 2, 65]) {
    same(collect(['row\n'.repeat(count)], false), Array(count).fill('row'), 'whole lines');
    same(collect(['\n'.repeat(count)], true), Array(count).fill(''), 'empty whole lines');
  }
  same(collect(['p'.repeat(64), 'p', 'tail\nrow\nunfinished', '-end\n'], false),
    ['p'.repeat(65) + 'tail', 'row', 'unfinished-end'], 'prefix and complete lines');
  {
    const r = open(), values = [];
    const reason = { later: true };
    function listener(line) {
      values.push(line);
      if (line === 'second') throw reason;
    }
    r.rl.on('line', listener);
    let caught = false;
    try { r.input.emit('data', 'first\nsecond\nthird\nsuffix'); }
    catch (error) { check(error === reason, 'later error identity'); caught = true; }
    check(caught, 'later callback must throw');
    r.rl.removeListener('line', listener);
    r.rl.on('line', function (line) { values.push(line); });
    r.input.emit('data', 'tail\n'); r.input.emit('end');
    same(values, ['first', 'second', 'suffixtail'], 'later throw retains suffix only');
  }
  {
    const r = open();
    let trace = '';
    const prototype = Object.getPrototypeOf([]);
    const previous = Object.getOwnPropertyDescriptor(prototype, '1');
    r.rl.on('line', function (line) {
      trace += '[' + line + ']';
      if (line === 'first') {
        Object.defineProperty(prototype, '1', {
          configurable: true,
          get: function () { throw new Error('inherited publication read'); },
          set: function () { throw new Error('inherited publication write'); }
        });
        r.input.emit('data', 'nested1\nnested2\nnested3\n');
      }
    });
    try { r.input.emit('data', 'first\nsecond\nthird\nsuffix'); }
    finally {
      if (previous === undefined) delete prototype[1];
      else Object.defineProperty(prototype, '1', previous);
      r.rl.close();
    }
    check(trace === '[first][suffixnested1][nested2][nested3][second][third]', 'private publication reentry');
  }
  return 'readline delimiters: long lines, CRLF, UTF-16, UTF-8, reentry, question, iteration';
}
