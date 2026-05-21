#! /usr/bin/env node
"use strict";

// Proxy trap that smuggles ambient authority.
//
// The Proxy handler's `get` trap routes every property access on `target`
// through `process`, so any read on the proxy resolves to a property of the
// ambient `process` object. The source-text shape at the read site is a
// member access on `target` — a benign-looking record — yet the runtime
// reaches the privileged binding.
//
// FrankenEngine's capability-typed lowering must refuse Proxy traps over
// any target whose handler closures reference ambient-authority bindings,
// because the trap erases the static information the contract relies on.

const target = { description: "harmless config record" };
const handler = {
  get(_inner, key) {
    return process[key];
  },
};

const masquerade = new Proxy(target, handler);
const leaked = masquerade.env.PATH;
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

process.stdout.write(
  `${JSON.stringify({
    scenario: "proxy_trap_authority_smuggling",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
