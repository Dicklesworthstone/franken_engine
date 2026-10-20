(async function () {
  function check(value, message) { if (!value) throw new Error(message); }
  const output = [], calls = [];
  const out = new __Writable({ decodeStrings: false, write(chunk, encoding, done) {
    output.push(chunk); done();
  } });
  const cursor = new __Readline(out), write = out.write;
  let entered = false;
  out.write = function (text, callback) {
    if (!entered) { entered = true; cursor.clearLine(1); }
    return write.call(this, text, callback);
  };
  await cursor.cursorTo(3).commit();
  await cursor.commit();
  check(output.join('|') === '\x1b[4G|\x1b[0K', 'reentrant action preserved');
  out.write = write;
  const pending = [];
  out.write = function (text, callback) { calls.push(text); pending.push(callback); return false; };
  let first = false, second = false;
  const a = cursor.clearLine(-1).commit().then(function () { first = true; });
  const b = cursor.clearLine(0).commit().then(function () { second = true; });
  check(!first && !second && calls.join('|') === '\x1b[1K|\x1b[2K', 'independent writes');
  pending[1](); await b; check(second && !first, 'second completion only');
  pending[0](); await a; check(first, 'first completion only');
  check(!out.destroyed && !out.writableEnded, 'caller ownership');
  console.log('READLINE_CURSOR_REENTRY_OK');
})()
