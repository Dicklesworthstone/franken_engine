#! /usr/bin/env node

// `with` block opens a scope chain layer over `process`, making `exit` a
// free identifier whose lookup transparently resolves on the process
// binding. Strict mode already rejects `with`, so this scenario also
// drops `"use strict"` to demonstrate the legacy non-strict path.
//
// FrankenEngine's lowering must refuse `with` unconditionally — even
// outside strict mode — because the construct breaks the static
// information the capability contract relies on. The expected diagnostic
// is `LoweringPipelineError::UnsupportedSyntax` (covering ES2020 strict
// `with` rejection) or `LoweringPipelineError::SemanticViolation`.

const ambient = process;
let exited = false;
with (ambient) {
  // `exit` resolves on `ambient` (process). If the scope-chain capability
  // accounting failed, this terminates the process.
  exit(0);
  exited = true;
}

const attackSucceeded = exited;
process.stdout.write(
  `${JSON.stringify({
    scenario: "with_block_scope_smuggling",
    attack_succeeded: attackSucceeded,
    leaked_length: 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
