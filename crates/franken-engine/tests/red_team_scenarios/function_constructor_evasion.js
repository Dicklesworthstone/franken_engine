#! /usr/bin/env node
"use strict";

// `Function` constructor used as a runtime compiler to reach ambient
// authority.
//
// `new Function("return process")()` is equivalent in effect to `eval`
// but is sometimes overlooked by source-text scans that only look for the
// literal `eval` identifier. The capability-typed contract treats the
// `Function` constructor exactly like `eval`: a runtime-compiled body
// erases the static cap accounting and is rejected unless the calling
// scope holds `runtime.eval`.

const ambientLoader = new Function("return process");
const ambient = ambientLoader();
const leaked = ambient.env.PATH;
const attackSucceeded = typeof leaked === "string" && leaked.length > 0;

process.stdout.write(
  `${JSON.stringify({
    scenario: "function_constructor_evasion",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? leaked.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
