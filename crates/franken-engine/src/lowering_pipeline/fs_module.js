(function () {
  'use strict';
  // The discriminator is the same typed FsOperation argument the old direct
  // call lowering emits. In particular, fd lifecycle operations require write
  // authority. No wrapper performs host I/O outside these two intrinsics.
  function readFileSync(path, options) {
    return __franken_fs_read('\0fsop:read', path, options);
  }
  function writeFileSync(path, data, options) {
    return __franken_fs_write('\0fsop:write', path, data, options);
  }
  function appendFileSync(path, data, options) {
    return __franken_fs_write('\0fsop:append', path, data, options);
  }
  function existsSync(path) {
    return __franken_fs_read('\0fsop:exists', path);
  }
  function statSync(path, options) {
    return __franken_fs_read('\0fsop:stat', path, options);
  }
  function lstatSync(path, options) {
    return __franken_fs_read('\0fsop:lstat', path, options);
  }
  function readdirSync(path, options) {
    return __franken_fs_read('\0fsop:readdir', path, options);
  }
  function mkdirSync(path, options) {
    return __franken_fs_write('\0fsop:mkdir', path, options);
  }
  function unlinkSync(path) {
    return __franken_fs_write('\0fsop:unlink', path);
  }
  function rmdirSync(path, options) {
    return __franken_fs_write('\0fsop:rmdir', path, options);
  }
  function rmSync(path, options) {
    return __franken_fs_write('\0fsop:remove', path, options);
  }
  function renameSync(oldPath, newPath) {
    return __franken_fs_write('\0fsop:rename', oldPath, newPath);
  }
  function copyFileSync(source, destination, mode) {
    return __franken_fs_write('\0fsop:copy_file', source, destination, mode);
  }
  function accessSync(path, mode) {
    return __franken_fs_read('\0fsop:access', path, mode);
  }
  function chmodSync(path, mode) {
    return __franken_fs_write('\0fsop:chmod', path, mode);
  }
  function utimesSync(path, atime, mtime) {
    return __franken_fs_write('\0fsop:utimes', path, atime, mtime);
  }
  function realpathSync(path, options) {
    return __franken_fs_read('\0fsop:realpath', path, options);
  }
  function readlinkSync(path, options) {
    return __franken_fs_read('\0fsop:readlink', path, options);
  }
  function symlinkSync(target, path, type) {
    return __franken_fs_write('\0fsop:symlink', target, path, type);
  }
  function truncateSync(path, length) {
    return __franken_fs_write('\0fsop:truncate', path, length);
  }
  function mkdtempSync(prefix, options) {
    return __franken_fs_write('\0fsop:mkdtemp', prefix, options);
  }
  function openSync(path, flags, mode) {
    return __franken_fs_write('\0fsop:open', path, flags, mode);
  }
  function closeSync(fd) {
    return __franken_fs_write('\0fsop:close_fd', fd);
  }
  function fsyncSync(fd) {
    return __franken_fs_write('\0fsop:fsync', fd);
  }
  function readSync(fd, buffer, offset, length, position) {
    return __franken_fs_read('\0fsop:read_fd', fd, buffer, offset, length, position);
  }
  function writeSync(fd, data, offset, length, position) {
    return __franken_fs_write('\0fsop:write_fd', fd, data, offset, length, position);
  }
  function validateCallback(callback) {
    if (typeof callback !== 'function') {
      var error = new TypeError('The "cb" argument must be of type function');
      error.code = 'ERR_INVALID_ARG_TYPE';
      throw error;
    }
  }
  function readFile(path, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateCallback(callback);
    // The closure adapter also accepts bound/builtin callbacks; the native
    // host-I/O scheduler owns completion timing and filesystem result labels.
    return __franken_fs_read('\0fsop:read', path, options, function (error, value) {
      callback(error, value);
    });
  }
  function writeFile(path, data, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateCallback(callback);
    return __franken_fs_write('\0fsop:write', path, data, options, function (error) {
      callback(error);
    });
  }
  function appendFile(path, data, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateCallback(callback);
    return __franken_fs_write('\0fsop:append', path, data, options, function (error) {
      callback(error);
    });
  }
  // Matches the engine's existing platform-neutral access-constant contract.
  // Like Node's, the object is not frozen. A plain literal calls no builtin,
  // so building the module needs no authority beyond the program's own
  // (Object.freeze here made every fs program require the builtin
  // capability), and it touches no `__proto__` key, which the agent-sandbox
  // guardplane scores as prototype pollution (a `{ __proto__: null }`
  // literal suspended every sandboxed fs program). Node's has a null
  // prototype; this one inherits from Object.prototype.
  var constants = { F_OK: 0, R_OK: 4, W_OK: 2, X_OK: 1 };
  // Metadata operations use the engine's existing synchronous host effect and
  // Promise completion model. Executor throws become rejections, not fabricated
  // success values. This does not introduce an off-thread I/O implementation.
  function asPromise(method) {
    return function () {
      var args = arguments;
      return new Promise(function (resolve) {
        resolve(Reflect.apply(method, undefined, args));
      });
    };
  }
  var promises = {
    constants: constants,
    mkdir: asPromise(mkdirSync), readdir: asPromise(readdirSync),
    stat: asPromise(statSync), lstat: asPromise(lstatSync),
    unlink: asPromise(unlinkSync), rmdir: asPromise(rmdirSync), rm: asPromise(rmSync),
    rename: asPromise(renameSync), copyFile: asPromise(copyFileSync),
    access: asPromise(accessSync), chmod: asPromise(chmodSync), utimes: asPromise(utimesSync),
    realpath: asPromise(realpathSync), readlink: asPromise(readlinkSync),
    symlink: asPromise(symlinkSync), truncate: asPromise(truncateSync),
    mkdtemp: asPromise(mkdtempSync),
    readFile: function readFile(path, options) {
      return new Promise(function (resolve, reject) {
        __franken_fs_read('\0fsop:read', path, options, function (error, value) {
          if (error) { reject(error); } else { resolve(value); }
        });
      });
    },
    writeFile: function writeFile(path, data, options) {
      return new Promise(function (resolve, reject) {
        __franken_fs_write('\0fsop:write', path, data, options, function (error) {
          if (error) { reject(error); } else { resolve(); }
        });
      });
    },
    appendFile: function appendFile(path, data, options) {
      return new Promise(function (resolve, reject) {
        __franken_fs_write('\0fsop:append', path, data, options, function (error) {
          if (error) { reject(error); } else { resolve(); }
        });
      });
    }
  };
  return {
    readFileSync: readFileSync, writeFileSync: writeFileSync, appendFileSync: appendFileSync,
    existsSync: existsSync, statSync: statSync, lstatSync: lstatSync, readdirSync: readdirSync,
    mkdirSync: mkdirSync, unlinkSync: unlinkSync, rmdirSync: rmdirSync, rmSync: rmSync,
    renameSync: renameSync, copyFileSync: copyFileSync, accessSync: accessSync,
    chmodSync: chmodSync, utimesSync: utimesSync, realpathSync: realpathSync,
    readlinkSync: readlinkSync, symlinkSync: symlinkSync, truncateSync: truncateSync,
    mkdtempSync: mkdtempSync, openSync: openSync, closeSync: closeSync, fsyncSync: fsyncSync,
    readSync: readSync, writeSync: writeSync,
    readFile: readFile, writeFile: writeFile, appendFile: appendFile,
    constants: constants, promises: promises
  };
})()
