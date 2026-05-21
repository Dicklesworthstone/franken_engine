#! /usr/bin/env node
"use strict";

// Capability-shadowed import laundering attempt.
//
// The attacker controls a Node-style module that re-exports an ambient-
// authority surface under a benign name. Untrusted code then imports the
// benign name, never naming the underlying authority module directly.
//
// In Node/Bun the re-export chain is fully transparent: the imported value
// IS the ambient-authority binding, so the attacker reaches process.env /
// child_process / fs through the laundered identifier with no audit trail
// that they ever touched the privileged module.
//
// The capability-typed compile-time TS->IR contract (bd-cixqu.3, FE-CLAIM-006)
// requires FrankenEngine's lowering to follow the re-export chain transitively
// and refuse any binding whose chain root resolves to ambient authority,
// regardless of the surface alias chosen. This scenario exercises that path:
// the JS code launders `child_process.execSync` through two layers of
// re-export under innocuous names, then invokes it.

// Simulate the laundering chain in a single file — the chain itself is the
// authority leakage, and the manifest declares which call site the lowering
// pass must reject.

// Layer 1: a "compat helper" module silently re-exports the ambient authority.
const compatHelperReexport = require("child_process");

// Layer 2: an "api facade" rebrands the re-export under an unrelated name.
const apiFacade = {
  // The attacker chose a name that suggests pure-data access; the binding
  // value is the privileged execSync function.
  fetchConfig: compatHelperReexport.execSync,
};

// Untrusted call site: invokes the laundered binding. From the source-text
// audit perspective there is no syntactic reference to `child_process` or
// `execSync` here — only the laundered alias. FrankenEngine's capability-
// typed lowering must follow the chain and refuse this call.
const launderedOutput = apiFacade.fetchConfig("printf laundered-canary");
const launderedString = launderedOutput.toString("utf8").trim();
const attackSucceeded = launderedString === "laundered-canary";

process.stdout.write(
  `${JSON.stringify({
    scenario: "capability_shadowed_import",
    attack_succeeded: attackSucceeded,
    laundered_length: launderedString.length,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
