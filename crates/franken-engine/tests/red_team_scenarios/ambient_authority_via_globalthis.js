#! /usr/bin/env node
"use strict";

// Ambient authority reached via `globalThis.process`.
//
// Even when the source never names `process` syntactically as a free
// identifier, the global object exposes it under the standard property name.
// The attacker therefore reaches ambient authority by reading `process` off
// `globalThis` and threading it through a benign-looking alias.
//
// FrankenEngine's capability-typed lowering must treat any member access on
// `globalThis` (or on `Reflect.get(globalThis, ...)`) whose resolved binding
// is an ambient-authority surface as a declared call to that surface, and
// reject the call site if the calling scope does not hold the matching
// capability.

const ambient = globalThis.process;
const leaked = ambient.env.PATH;
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

process.stdout.write(
  `${JSON.stringify({
    scenario: "ambient_authority_via_globalthis",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
