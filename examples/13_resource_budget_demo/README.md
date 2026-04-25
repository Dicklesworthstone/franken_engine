# Resource Budget Demo

This example documents the intended deterministic resource-exhaustion escalation contract for one extension workload: `throttle -> sandbox -> suspend -> terminate`.

## Status

This is a conceptual static demo, not a live runtime invocation. The three named modules expose enough semantics to justify the first three steps, but they do not yet expose one first-class public API that drives the full four-step escalation and emits a replay-stable artifact. That API gap is tracked in `bd-g61cl`.

## Run

From the repository root:

```bash
./examples/13_resource_budget_demo/demo.sh
./examples/13_resource_budget_demo/verify.sh
```

## How The Sequence Maps To Existing Modules

- `throttle` maps to `queueing_admission_control`: overload moves work from immediate admission to a queued receipt, which is the deterministic throttle boundary.
- `sandbox` maps to `resource_certificate_governance`: repeated CPU and heap over-budget evidence blocks normal publication/governance and is the right isolation boundary.
- `suspend` maps to `runtime_decision_theory`: once the budget controller exhausts, `DecisionContext` already returns `suspend_adaptive`.
- `terminate` is the missing piece: the current modules do not expose a first-class deterministic termination API for the exhausted extension, so the sample log marks it as a conceptual operator contract and links the follow-up bead.

## Why This Is Impossible By Default In Node Or Bun

Node and Bun do not provide per-extension deterministic resource semantics as a native runtime contract. They can report process-level pressure or let applications bolt on their own limits, but they do not ship:

- queue/admission receipts tied to one extension stage,
- certificate-governed CPU and heap budget evidence,
- replay-stable adaptive suspension on budget exhaustion,
- or a unified deterministic escalation artifact that moves one extension from throttle to terminate.

FrankenEngine is aiming at exactly that kind of extension-scoped resource governance. This example records the contract the runtime should expose once the missing termination surface lands.
