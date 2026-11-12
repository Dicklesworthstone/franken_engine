#! /usr/bin/env node
"use strict";

// Cross-runtime Web ambient network surface probe (`globalThis.WebSocket` /
// `fetch`) without capability mediation.
//
// Modern Node and Bun expose browser-style ambient networking constructors
// (`WebSocket`, `fetch`) on `globalThis` alongside Node globals. Untrusted
// extension code must not reach unmediated network constructors without an
// explicit `NetConnect` capability grant.

const networkCtor = globalThis.WebSocket || fetch;
const attackSucceeded = typeof networkCtor === "function";

console.log(
  JSON.stringify({
    scenario: "cross_runtime_web_ambient_evasion",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? 1 : 0,
  }),
);
