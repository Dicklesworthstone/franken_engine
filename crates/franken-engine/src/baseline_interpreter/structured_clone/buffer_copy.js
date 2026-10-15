(function () {
    function check(value, reason) { if (!value) throw new Error(reason); }
    var buffer = new ArrayBuffer(16);
    var bytes = new Uint8Array(buffer);
    for (var i = 0; i < bytes.length; i++) bytes[i] = i * 7;
    var view = new Uint16Array(buffer, 4, 3);
    var data = new DataView(buffer, 2, 9);
    var original = {buffer: buffer, view: view, alias: view, data: data};
    original.self = original;
    var copy = structuredClone(original);
    check(copy.self === copy && copy.view === copy.alias, 'graph identity');
    check(copy.buffer !== buffer && copy.view.buffer === copy.buffer &&
          copy.data.buffer === copy.buffer, 'buffer aliasing');
    check(copy.view.byteOffset === 4 && copy.view.length === 3 &&
          copy.data.byteOffset === 2 && copy.data.byteLength === 9, 'view bounds');
    var clonedBytes = new Uint8Array(copy.buffer);
    for (var i = 0; i < bytes.length; i++) check(bytes[i] === clonedBytes[i], 'copied bytes');
    clonedBytes[0] = 201;
    check(bytes[0] === 0, 'independent clone');
    var calls = [];
    var ordered = structuredClone({
        get first() { calls.push('first'); bytes[0] = 41; return buffer; },
        get second() { calls.push('second'); bytes[0] = 99; return buffer; }
    });
    check(ordered.first === ordered.second && ordered.first !== buffer, 'memoized buffer');
    check(new Uint8Array(ordered.first)[0] === 41 && bytes[0] === 99, 'snapshot time');
    check(calls.join(',') === 'first,second', 'getter order');
    var rab = new ArrayBuffer(8, {maxByteLength: 32});
    var rabBytes = new Uint8Array(rab);
    rabBytes[0] = 31;
    var rabCopy = structuredClone({buffer: rab, view: rabBytes});
    check(rabCopy.buffer.resizable && rabCopy.buffer.maxByteLength === 32, 'resizable clone');
    rab.resize(16);
    check(rabCopy.view.length === 8, 'independent growth');
    rabCopy.buffer.resize(12);
    check(rabCopy.view.length === 12 && rabCopy.view[0] === 31 && rabCopy.view[11] === 0,
          'cloned tracking view');
    var moving = new ArrayBuffer(4);
    new Uint8Array(moving)[0] = 61;
    var moved = structuredClone({buffer: moving}, {transfer: [moving]});
    check(moving.byteLength === 0 && new Uint8Array(moved.buffer)[0] === 61, 'transfer unchanged');
    var detached = false;
    try { structuredClone(moving); } catch (error) { detached = error.name === 'DataCloneError'; }
    check(detached, 'detached input');
    var sentinel = {};
    var failure;
    try { structuredClone({buffer: buffer, get bad() { throw sentinel; }}); }
    catch (error) { failure = error; }
    check(failure === sentinel && buffer.byteLength === 16 && bytes[0] === 99, 'late abrupt completion');
    check(new Uint8Array(structuredClone(buffer))[0] === 99, 'retry');
    return 'buffer-copy-ok';
})();
