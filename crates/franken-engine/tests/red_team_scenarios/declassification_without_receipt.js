#! /usr/bin/env node
"use strict";

// Declassification without signed receipt.
//
// A high-clearance value (treated as Confidential in IFC terms) is emitted
// to a low-clearance sink (stdout) without producing a signed declassification
// receipt. The capability/IFC algebra requires every cross-clearance flow to
// be witnessed by a signed declassification record; emission without that
// record is an unsupervised downgrade.
//
// In Node/Bun stdout has no clearance label and the leak is silent. In
// FrankenEngine the IFC lattice must reject this flow at lowering time as
// LoweringPipelineError::UnauthorizedFlow with the source/sink labels and
// no declassification witness.

// Simulated high-clearance secret. The label would be assigned by the
// capability/IFC pipeline; here we only express the source-text shape.
const HIGH_CLEARANCE_SECRET = "secret://hsm/rotated-key#7";

function unsupervisedDeclassify(value) {
  // No declassification receipt produced. No signature emitted. No audit.
  return value;
}

const declassified = unsupervisedDeclassify(HIGH_CLEARANCE_SECRET);
const attackSucceeded = declassified === HIGH_CLEARANCE_SECRET;

process.stdout.write(
  `${JSON.stringify({
    scenario: "declassification_without_receipt",
    attack_succeeded: attackSucceeded,
    leaked_length: attackSucceeded ? declassified.length : 0,
  })}\n`,
);
process.exit(attackSucceeded ? 0 : 1);
