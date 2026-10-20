(async function () {
  function check(value, message) { if (!value) throw new Error(message); }
  check(__r.promises.Readline === __Readline, 'promise module alias');
  const chunks = [], callbacks = [];
  const out = new __Writable({ decodeStrings: false, write(chunk, encoding, done) {
    chunks.push(chunk); done();
  } });
  __r.cursorTo(out, 2, 3, function (error) { check(error == null, 'cursor callback'); callbacks.push('cursor'); });
  __r.moveCursor(out, -1, 2);
  __r.clearLine(out, 0);
  __r.clearScreenDown(out);
  await new Promise(function (resolve) { __r.moveCursor(null, 0, 0, function (error) {
    check(error === null, 'noop callback value'); resolve();
  }); });
  check(callbacks.join(',') === 'cursor', 'write completion');
  check(chunks.join('') === '\x1b[4;3H\x1b[1D\x1b[2B\x1b[2K\x1b[0J', 'callback bytes');

  const cursor = new __Readline(out);
  check(cursor.cursorTo(0).clearLine(-1).moveCursor(2, -3).clearScreenDown() === cursor, 'chain identity');
  const before = chunks.length;
  await cursor.commit();
  check(chunks.length === before + 1, 'one batch');
  check(chunks[chunks.length - 1] === '\x1b[1G\x1b[1K\x1b[2C\x1b[3A\x1b[0J', 'batch bytes');
  cursor.clearLine(0).rollback(); await cursor.commit();
  check(chunks[chunks.length - 1] === '', 'rollback');

  let invalid = false;
  try { cursor.clearLine(2); } catch (error) { invalid = error.name === 'RangeError' && error.code === 'ERR_OUT_OF_RANGE'; }
  check(invalid, 'range validation');
  const auto = new __Readline(out, { autoCommit: true });
  const start = chunks.length;
  auto.cursorTo(7).clearLine(1).rollback();
  check(chunks.length === start, 'automatic output is deferred');
  await new Promise(function (resolve) { __r.clearScreenDown(null, resolve); });
  check(chunks.slice(start).join('') === '\x1b[8G\x1b[0K', 'automatic output order');
  check(!out.destroyed && !out.writableEnded, 'caller still owns stream');
  console.log('READLINE_CURSOR_OK');
})()
