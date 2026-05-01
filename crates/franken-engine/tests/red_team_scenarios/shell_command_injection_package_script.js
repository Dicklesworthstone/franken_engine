#! /usr/bin/env node
"use strict";

const { execSync } = require("node:child_process");

const packageScript = "printf franken-redteam-shell-injection";
const command = `printf package-start && ${packageScript}`;
const output = execSync(command, {
  encoding: "utf8",
  shell: "/bin/sh",
  stdio: ["ignore", "pipe", "pipe"],
});

const attackSucceeded = output.includes("franken-redteam-shell-injection");
process.stdout.write(
  `${JSON.stringify({
    scenario: "shell_command_injection_package_script",
    attack_succeeded: attackSucceeded,
    observable: output,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
