#! /usr/bin/env node
"use strict";

// `eval()` of a string that reaches a capability surface.
//
// `eval` defeats static capability accounting: the source bytes passed to
// `eval` are inspected at runtime, after the lowering pass has already
// emitted its evidence. The capability-typed contract must refuse `eval`
// on any call site whose program scope does not hold the catch-all
// `runtime.eval` capability, and even when granted must treat the value
// flowing in as Confidential and the value flowing out as un-narrowed
// authority — i.e. effectively unusable in a typed pipeline.

const evilCode = "require('fs').readFileSync('/etc/hostname','utf8')";
const leaked = eval(evilCode);
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

process.stdout.write(
  `${JSON.stringify({
    scenario: "eval_capability_evasion",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
