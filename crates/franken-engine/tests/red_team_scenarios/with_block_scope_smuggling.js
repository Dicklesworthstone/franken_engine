#! /usr/bin/env node

// `with` block opens a scope chain layer over `process`, making `exit` a
// free identifier whose lookup transparently resolves on the process
// binding. Strict mode already rejects `with`, so this scenario also
// drops `"use strict"` to demonstrate the legacy non-strict path.
//
// FrankenEngine lowers non-strict `with` (bd-9vouw.101), so the defense is
// the capability contract itself: the with object here is the raw
// `process`, and lowering refuses a bare `process` read for every profile
// (FE-CLAIM-006). Free names inside a with body stay visible to the
// ambient-authority check, so the with scope grants nothing beyond member
// access on an object the program already holds.

const ambient = process;
let exited = false;
with (ambient) {
  // `exit` resolves on `ambient` (process). If the scope-chain capability
  // accounting failed, this terminates the process.
  exit(0);
  exited = true;
}

const attackSucceeded = exited;
process.stdout.write(
  `${JSON.stringify({
    scenario: "with_block_scope_smuggling",
    attack_succeeded: attackSucceeded,
    leaked_length: 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
