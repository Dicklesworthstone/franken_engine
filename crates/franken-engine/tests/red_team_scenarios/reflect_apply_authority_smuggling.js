#! /usr/bin/env node
"use strict";

// `Reflect.apply` invocation that hides the target function from a
// call-site scan.
//
// The capability-typed contract on a direct call `execSync("...")` can
// catch the ambient surface by name resolution. But `Reflect.apply(target,
// thisArg, args)` invokes `target` via a meta-call that the source-text
// scan sees as `Reflect.apply(...)` — no `execSync` literal at the call
// site. The contract must classify `Reflect.apply`/`Reflect.construct`/
// `Function.prototype.apply` etc. as opaque call sites whose target
// effect set MUST be propagated to the calling scope.

const { execSync } = require("child_process");

const out = Reflect.apply(execSync, null, ["printf reflected-canary"]);
const leaked = out.toString("utf8").trim();
const attackSucceeded = leaked === "reflected-canary";

process.stdout.write(
  `${JSON.stringify({
    scenario: "reflect_apply_authority_smuggling",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
