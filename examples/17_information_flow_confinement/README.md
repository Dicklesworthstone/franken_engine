# Information Flow Confinement

> **Fixture shape check — runs no engine code.** `verify.sh` validates the JSON shape of the checked-in fixtures in this directory; their hashes and signatures are placeholders, not outputs of a live run, so a passing check is not evidence that the capability works. Live coverage: `./examples/22_live_ifc_declassification/verify.sh` (IFC policy, declassification pipeline, signed receipts).

This example is a static fixture for FrankenEngine's impossible-by-default
information-flow confinement model: sensitive data starts as
`Confidential`, and any downgrade to `Public` requires an explicit
declassification receipt.

## Files

- `confidential_input.txt`: sample confidential source material.
- `sample_declassification_receipt.json`: checked-in declassification receipt
  tied to that exact input via `data_hash`.
- `verify.sh`: validates the receipt structure and confirms the sample input
  hash matches the receipt.

## Run It

From the repository root:

```bash
./examples/17_information_flow_confinement/verify.sh
```

## What The Output Means

`verify.sh` succeeds only if:

- the confidential fixture still hashes to the `data_hash` recorded in the
  receipt,
- the receipt preserves the `Confidential -> Public` downgrade story, and
- the authorization and signature fields are present in the expected format.

## Why This Is Impossible By Default In Node Or Bun

Node and Bun can pass objects between libraries, but they do not ship a
runtime-native information-flow lattice with signed declassification receipts.
Once sensitive data is copied into a public-facing path, the downgrade proof is
an application convention unless you build your own label tracking, downgrade
policy, and receipt validation on top.

FrankenEngine treats the downgrade itself as a first-class, auditable runtime
event.
