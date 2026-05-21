#! /usr/bin/env node
"use strict";

// Typed-effect laundering downcast.
//
// A high-trust function takes an effect-carrying argument (an `fs.readFile`-
// style capability handle) and passes it to a less-privileged caller that
// promises not to use it. The contract was a lie: the less-privileged caller
// then invokes the handle with attacker-controlled inputs.
//
// In Node/Bun the value is just a function reference; there is no static
// notion that it carries an effect or a trust level, so this works fine. In
// FrankenEngine the capability-typed lowering must reject any call site that
// passes an effect-carrying value as an argument to a less-privileged
// callee — the effect-set of the argument widens the callee's required
// capability set, and a callee that did not declare it cannot receive it.

const fs = require("fs");

// "less-privileged" sink — purported to only read its argument.
function downcastSink(maybeReader) {
  // The promise: "I will not invoke this." The reality: invoke immediately.
  return maybeReader("/etc/passwd", "utf8");
}

const leaked = downcastSink(fs.readFileSync);
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

process.stdout.write(
  `${JSON.stringify({
    scenario: "typed_effect_laundering_downcast",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
