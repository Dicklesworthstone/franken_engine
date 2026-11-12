#! /usr/bin/env node
"use strict";

// Ambient authority reached via constant-folded computed string concatenation
// on `globalThis` (`globalThis["pro" + "cess"].env.PATH`).
//
// Splitting `"process"` across string-concatenation operands defeats literal
// identifier/property scanners while evaluating to the exact ambient binding.
// Capability-typed lowering folds constant string-concatenation property keys
// and rejects ambient-authority projections at compile time.

const leaked = globalThis["pro" + "cess"].env.PATH;
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

console.log(
  JSON.stringify({
    scenario: "static_folded_computed_globalthis_evasion",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  }),
);
