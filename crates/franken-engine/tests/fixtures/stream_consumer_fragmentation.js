(async function (consumer, index) {
  function equal(actual, expected) {
    if (actual !== expected) throw new Error('consumer mismatch: ' + actual + ' != ' + expected);
  }
  if (index === 0) {
    async function* input() {
      for (let i = 0; i < 512; i++) { yield ''; yield new Uint8Array(0); }
      yield new Uint8Array([0xef, 0xbb]);
      yield new Uint8Array([0xbf, 0xe2]);
      yield '';
      yield new Uint8Array([0x82, 0xac]);
    }
    equal(await consumer.text(input()), '€');
  } else if (index === 1) {
    async function* input() {
      for (let i = 0; i < 257; i++) yield 'x';
      yield '\ud83d'; yield '\ude00'; yield '\ud800'; yield '\udfff';
    }
    equal(await consumer.text(input()), 'x'.repeat(257) + '\ud83d\ude00\ud800\udfff');
  } else if (index === 2) {
    async function* input() {
      yield new Uint8Array([0xe2]);
      for (let i = 0; i < 128; i++) yield 'x';
      yield new Uint8Array([0x82]); yield 'y';
      yield new Uint8Array([0xac, 0xff, 0xe2, 0x82]);
    }
    equal(await consumer.text(input()), 'x'.repeat(128) + 'y€��');
  } else if (index === 3) {
    const input = JSON.stringify({ numbers: [0, 1, 2, 3], name: '😀€', padding: 'x'.repeat(130) });
    async function* pieces() { for (let i = 0; i < input.length; i++) yield input[i]; }
    equal(JSON.stringify(await consumer.json(pieces())), input);
  } else if (index === 4) {
    let closed = 0;
    async function* invalid() { try { yield 'x'; yield {}; } finally { closed++; } }
    let rejected = false;
    try { await consumer.text(invalid()); } catch (error) { rejected = error.name === 'TypeError'; }
    equal(rejected, true); equal(closed, 1);
    for (const reason of [undefined, null, false, 0]) {
      async function* fails() { yield 'x'; throw reason; }
      let caught = false;
      try { await consumer.text(fails()); } catch (error) { equal(error, reason); caught = true; }
      equal(caught, true);
    }
  } else if (index === 5) {
    const large = '😀'.repeat(8192);
    async function* input() { yield 'a'; yield 'b'; yield large; yield 'c'; yield 'd'; }
    equal(await consumer.text(input()), 'ab' + large + 'cd');
    async function* reused() {
      const data = new Uint8Array([120, 65, 66, 120]);
      yield new DataView(data.buffer, 1, 2);
      data[1] = 67; data[2] = 68;
      yield new Uint8Array(data.buffer, 1, 2);
    }
    equal(await consumer.text(reused()), 'ABCD');
  } else throw new Error('unknown consumer case');
})
