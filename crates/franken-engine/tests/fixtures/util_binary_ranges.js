function verifyUtilBinaryRanges(eq) {
  function check(value, label) { if (!value) throw new Error(label); }
  function bytes(length, seed) {
    const result = new Uint8Array(length);
    for (let i = 0; i < length; i++) result[i] = (i * 29 + seed) & 255;
    return result;
  }
  for (const length of [0, 1, 127, 1023, 1024, 1025]) {
    const a = bytes(length, 7), b = bytes(length, 7);
    check(eq(a.buffer, b.buffer), 'equal ArrayBuffer');
    if (length !== 0) {
      b[length - 1] ^= 1;
      check(!eq(a.buffer, b.buffer), 'last byte differs');
      b[length - 1] ^= 1;
    }
    check(!eq(a.buffer, new ArrayBuffer(length + 1)), 'different lengths');
  }
  const left = bytes(1033, 9), right = bytes(1043, 3);
  for (let i = 0; i < 1025; i++) right[i + 5] = left[i + 1];
  const a = new DataView(left.buffer, 1, 1025);
  const b = new DataView(right.buffer, 5, 1025);
  check(eq(a, b), 'unaligned, distinct byte windows');
  right[0] ^= 1;
  right[1042] ^= 1;
  check(eq(a, b), 'bytes outside the windows are ignored');
  right[1029] ^= 1;
  check(!eq(a, b), 'last byte in the window differs');
  right[1029] ^= 1;
  const marker = Symbol('metadata');
  a[marker] = { version: 1 }; b[marker] = { version: 2 };
  check(!eq(a, b), 'binary equality still compares symbol properties');
  b[marker].version = 1;
  check(eq(a, b), 'matching metadata');
  delete a[marker]; delete b[marker];
  let reads = 0;
  Object.defineProperty(a, 'change', { enumerable: true, get: function () {
    reads++;
    right[5] ^= 1;
    return 1;
  } });
  Object.defineProperty(b, 'change', { enumerable: true, value: 1 });
  check(eq(a, b), 'payload is compared before own getters');
  check(reads === 1, 'getter runs once');
  check(!eq(a, b), 'next comparison observes changed bytes');
  check(reads === 1, 'unequal payload short-circuits before getters');
  const failure = { message: 'metadata failure' };
  const c = bytes(1024, 4).buffer, d = bytes(1024, 4).buffer;
  Object.defineProperty(c, 'extra', { enumerable: true, get: function () { throw failure; } });
  Object.defineProperty(d, 'extra', { enumerable: true, value: 1 });
  let caught = false;
  try { eq(c, d); } catch (error) { caught = error === failure; }
  check(caught, 'original thrown value');
  let x = bytes(1024, 6).buffer, y = bytes(1024, 6).buffer;
  for (let i = 0; i < 80; i++) { x = { next: x }; y = { next: y }; }
  check(eq(x, y), 'iterative graph path uses the same binary comparison');
  check(eq(new Float64Array([NaN, -0]), new Float64Array([NaN, -0])), 'float values unchanged');
  check(!eq(new Float64Array([0]), new Float64Array([-0])), 'signed zero is not byte-coerced');
  return 'util binary ranges: windows, payloads, metadata, ordering, exceptions, deep graphs';
}
