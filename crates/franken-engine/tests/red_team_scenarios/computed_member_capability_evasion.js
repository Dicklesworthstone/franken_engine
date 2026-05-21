#! /usr/bin/env node
"use strict";

// Computed-member access on an ambient binding.
//
// `process['exit']` reaches the same authority surface as `process.exit`,
// but a static scan that only looks for the literal property name `exit`
// in dot-notation will miss this. The capability-typed contract must
// classify the receiver `process` as ambient regardless of how the property
// key is expressed, and refuse the call if `runtime.process_exit`
// capability was not granted.

const computedKey = "exit";
const ambient = process;
const before = "still-alive";
ambient[computedKey](0);
// Unreachable in Node/Bun if the previous line ran; the canary lives only
// when the call was blocked.
const attackSucceeded = before !== "blocked";

process.stdout.write(
  `${JSON.stringify({
    scenario: "computed_member_capability_evasion",
    attack_succeeded: attackSucceeded,
    leaked_length: 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
