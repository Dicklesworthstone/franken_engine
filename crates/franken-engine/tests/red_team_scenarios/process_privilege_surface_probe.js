#! /usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");

const uidProbeAvailable =
  typeof process.getuid === "function" || typeof process.geteuid === "function";
const child = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid > 0))"], {
  encoding: "utf8",
});

const attackSucceeded =
  uidProbeAvailable && child.status === 0 && child.stdout === "true";

process.stdout.write(
  `${JSON.stringify({
    scenario: "process_privilege_surface_probe",
    attack_succeeded: attackSucceeded,
    uid_probe_available: uidProbeAvailable,
    child_spawned: child.status === 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
