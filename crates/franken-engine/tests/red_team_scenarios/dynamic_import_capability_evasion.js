#! /usr/bin/env node
"use strict";

// Dynamic `import()` of a capability surface chosen at runtime.
//
// The bound import specifier ("fs") is computed from a value the lowering
// cannot statically prove safe, so a static capability scan that only
// considers literal `import "fs"` strings would never see this dependency.
// FrankenEngine's capability-typed lowering must reject any `import()`
// whose specifier is not a compile-time literal AND not declared in the
// module's capability manifest.

async function evade() {
  const specifier = ["f", "s"].join("");
  const mod = await import(specifier);
  const leaked = mod.readFileSync("/etc/hostname", "utf8");
  return typeof leaked === "string" && leaked.length > 0;
}

evade().then(
  (attackSucceeded) => {
    process.stdout.write(
      `${JSON.stringify({
        scenario: "dynamic_import_capability_evasion",
        attack_succeeded: attackSucceeded,
        leaked_length: 0,
      })}\n`,
    );
    process.exit(attackSucceeded ? 0 : 1);
  },
  () => process.exit(1),
);
