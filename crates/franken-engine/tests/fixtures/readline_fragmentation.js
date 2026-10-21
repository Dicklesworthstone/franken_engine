async function verifyReadlineFragments(readline, EventEmitter) {
  function check(value, message) { if (!value) throw new Error(message); }
  function input() {
    const source = new EventEmitter();
    source.resume = function () { return this; };
    source.pause = function () { return this; };
    return source;
  }
  function collect(chunks, direct) {
    const source = input();
    const rl = readline.createInterface({ input: source, terminal: false, crlfDelay: Infinity });
    const lines = [];
    let closes = 0;
    rl.on('line', function (line) { lines.push(line); });
    rl.on('close', function () { closes++; });
    for (const chunk of chunks) {
      if (direct) rl.write(chunk); else source.emit('data', chunk);
    }
    source.emit('end');
    check(closes === 1, 'exactly one close');
    check(source.listenerCount('data') === 0, 'release data listener');
    return lines;
  }
  for (const count of [1, 63, 64, 65, 127, 128, 129]) {
    const chunks = [];
    for (let n = 0; n < count; n++) chunks.push('x');
    check(collect(chunks, false).join('|') === 'x'.repeat(count), 'flush short EOF batch');
    chunks.push('\r\n');
    check(collect(chunks, true).join('|') === 'x'.repeat(count), 'direct write delimiter');
  }
  check(collect(['left\ud83d', '\ude80right', '\r', '\n', '\ud800', '\n'], false).join('|') ===
    'left🚀right|\ud800', 'preserve UTF-16 and CRLF');
  const bytes = [0x61, 0xc3, 0xa9, 13, 10, 0xf0, 0x9f, 0x9a, 0x80, 10];
  const chunks = [];
  for (const byte of bytes) chunks.push(new Uint8Array([byte]));
  check(collect(chunks, false).join('|') === 'aé|🚀', 'incremental UTF-8');
  check(collect([new Uint8Array([0x61, 0xe2, 0x82])], false).join('|') === 'a',
    'EOF must not flush incomplete decoder bytes');
  {
    const source = input();
    const rl = readline.createInterface({ input: source, terminal: false, crlfDelay: Infinity });
    const lines = [];
    rl.on('line', function (line) {
      lines.push(line);
      if (line === 'head') source.emit('data', 'tail\n');
    });
    for (let n = 0; n < 65; n++) source.emit('data', 'q');
    source.emit('data', '\nhead\n');
    source.emit('end');
    check(lines.join('|') === 'q'.repeat(65) + '|head|tail', 'reentrant line input');
  }
  {
    const source = input();
    const rl = readline.promises.createInterface({ input: source, terminal: false });
    const answer = rl.question('question');
    for (let n = 0; n < 65; n++) source.emit('data', 'a');
    source.emit('data', '\n');
    check(await answer === 'a'.repeat(65), 'promise question');
    source.emit('end');
  }
  {
    const source = input();
    const rl = readline.createInterface({ input: source, terminal: false });
    const iterator = rl[Symbol.asyncIterator]();
    const first = iterator.next();
    for (let n = 0; n < 65; n++) source.emit('data', 'z');
    source.emit('data', '\n');
    check((await first).value === 'z'.repeat(65), 'async iterator');
    check((await iterator.return()).done, 'iterator return result');
    // Explicit ownership cleanup is portable; the engine's stronger automatic
    // close-on-return behavior is checked separately in its host suite.
    rl.close();
    check(rl.closed && source.listenerCount('data') === 0, 'iterator teardown');
  }
  {
    const source = input();
    const rl = readline.createInterface({ input: source, terminal: false });
    let observed;
    rl.on('line', function (line) { observed = line; });
    const prototype = Object.getPrototypeOf([]);
    const previous = Object.getOwnPropertyDescriptor(prototype, '1');
    Object.defineProperty(prototype, '1', {
      configurable: true,
      get: function () { throw new Error('private fragment inherited read'); },
      set: function () { throw new Error('private fragment inherited write'); }
    });
    try {
      for (let n = 0; n < 129; n++) source.emit('data', 'p');
      source.emit('data', '\n');
    } finally {
      if (previous === undefined) delete prototype[1];
      else Object.defineProperty(prototype, '1', previous);
      rl.close();
    }
    check(observed === 'p'.repeat(129), 'private fragments bypass inherited indexed access');
  }
  return 'readline fragmentation: content, EOF, UTF-16, UTF-8, reentry, question, iteration';
}
