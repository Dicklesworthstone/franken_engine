# Resource Budget Demo

This example demonstrates the deterministic resource-exhaustion escalation contract for one extension workload: `throttle -> sandbox -> suspend -> terminate`.

## Status

**IMPLEMENTED**: This demo now uses a real runtime implementation via the `resource_escalation_control` module. The `ResourceEscalationController` provides a first-class public API that drives the full four-step escalation sequence and emits replay-stable artifacts. The API gap tracked in `bd-g61cl` has been resolved.

## Run

From the repository root:

```bash
./examples/13_resource_budget_demo/demo.sh
./examples/13_resource_budget_demo/verify.sh
```

## How The Sequence Maps To Modules

- `throttle` maps to `queueing_admission_control`: overload moves work from immediate admission to a queued receipt, which is the deterministic throttle boundary.
- `sandbox` maps to `resource_certificate_governance`: repeated CPU and heap over-budget evidence blocks normal publication/governance and is the right isolation boundary.
- `suspend` maps to `runtime_decision_theory`: once the budget controller exhausts, `DecisionContext` already returns `suspend_adaptive`.
- `terminate` maps to `resource_escalation_control`: **NEW** - provides deterministic termination with audit trails for exhausted extensions after escalation attempts fail.

## Why This Is Impossible By Default In Node Or Bun

Node and Bun do not provide per-extension deterministic resource semantics as a native runtime contract. They can report process-level pressure or let applications bolt on their own limits, but they do not ship:

- queue/admission receipts tied to one extension stage,
- certificate-governed CPU and heap budget evidence,
- replay-stable adaptive suspension on budget exhaustion,
- or a unified deterministic escalation artifact that moves one extension from throttle to terminate.

FrankenEngine is aiming at exactly that kind of extension-scoped resource governance. The checked-in [`sample_exhaustion_log.json`](./sample_exhaustion_log.json) is a fixed-timestamp capture of the same `EscalationLog` schema emitted by `franken_resource_budget_demo`, including the implemented terminate step from `resource_escalation_control`.
