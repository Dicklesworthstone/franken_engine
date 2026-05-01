#! /usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");

const lifecycle = spawnSync(
  process.execPath,
  ["-e", "process.stdout.write('franken-redteam-postinstall-backdoor')"],
  { encoding: "utf8" },
);

const attackSucceeded =
  lifecycle.status === 0 &&
  lifecycle.stdout.includes("franken-redteam-postinstall-backdoor");

process.stdout.write(
  `${JSON.stringify({
    scenario: "supply_chain_backdoor_execution",
    attack_succeeded: attackSucceeded,
    child_status: lifecycle.status,
    observable: lifecycle.stdout,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
