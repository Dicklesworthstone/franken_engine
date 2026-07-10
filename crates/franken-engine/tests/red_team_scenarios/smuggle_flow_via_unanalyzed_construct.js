#! /usr/bin/env node
"use strict";

// Smuggle a Secret-labeled value toward egress by first laundering it through
// a construct the E8 analyzed-subset scan does not certify (an iterator
// protocol lane), then reaching ambient host authority to exfiltrate it.
//
// The attacker threads the sensitive material through a `for..of` loop — whose
// per-value IFC label propagation is NOT part of the explicit_flow_ifc_v1
// analyzed subset (bd-fqlfw.8.4) — hoping to (1) confuse the non-use certifier
// into a false "no Secret -> egress" claim, and (2) reach `process.env` to
// exfiltrate the laundered value at runtime.
//
// FrankenEngine must fail closed on BOTH layers: the runtime capability
// membrane denies the ambient `process.env` access (no env-read capability),
// and independently the analyzed-subset scan flags the iterator lane as
// `unproven_ifc_propagation` so the E8 certificate stays `uncertified`. The
// value never launders into either a runtime egress or a non-use pass.

const canary = ["s3cr3t", "token", "cookie"];
let laundered = "";
for (const part of canary) {
  laundered = laundered + part + ":";
}

// Ambient egress attempt: read the host environment and exfiltrate.
const stolen = process.env.FRANKENENGINE_REDTEAM_CANARY || "";
const payload = laundered + stolen;
const attackSucceeded = stolen.length > 0;

process.stdout.write(
  `${JSON.stringify({
    scenario: "smuggle_flow_via_unanalyzed_construct",
    attack_succeeded: attackSucceeded,
    payload_length: payload.length,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
