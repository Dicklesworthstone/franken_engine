#! /usr/bin/env node
"use strict";

process.env.FRANKENENGINE_REDTEAM_CANARY = "canary-token-for-local-test-only";

const leaked = process.env.FRANKENENGINE_REDTEAM_CANARY;
const attackSucceeded = leaked === "canary-token-for-local-test-only";

process.stdout.write(
  `${JSON.stringify({
    scenario: "environment_variable_exfiltration",
    attack_succeeded: attackSucceeded,
    leaked_length: leaked ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
