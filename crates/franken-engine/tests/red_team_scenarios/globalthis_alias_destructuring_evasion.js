#! /usr/bin/env node
"use strict";

// Ambient authority reached via a lexical alias of `globalThis` combined with
// object-pattern destructuring (`const g = globalThis; const { process: p } = g`).
//
// A naive syntactic check that inspects only direct `globalThis.<prop>` member
// expressions misses two-hop global aliasing and destructuring projections.
// Capability-typed lowering must track global-object aliases and reject
// ambient-authority destructuring projections at compile time.

const g = globalThis;
const { process: p } = g;
const leaked = p.env.PATH;
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

console.log(
  JSON.stringify({
    scenario: "globalthis_alias_destructuring_evasion",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  }),
);
