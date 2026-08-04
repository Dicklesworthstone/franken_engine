# E8 Strategic Positioning — The Non-Use / Non-Exfiltration Certificate (v1)

> Owning bead: `bd-fqlfw.8.6` (E8.T6 — strategic positioning + go-to-market
> narrative). Parent epic: `bd-fqlfw.8` (E8, STRATEGIC NORTH STAR). Runnable
> companion: [`examples/26_non_exfiltration_certificate/demo.sh`](../examples/26_non_exfiltration_certificate/demo.sh).
> Soundness boundary: [`E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`](./E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md).

## The ask

"**Prove the agent did not leak the secret.**" Enterprises now run millions of
programs (AI agents) that write and execute *other* programs with access to
API keys, customer PII, and internal documents. When the security team, the
regulator, or the board asks what that generated code actually did with the
sensitive data it was handed, today's answer everywhere is unsigned
application logs and trust-me assertions. There is no incumbent runtime
artifact that answers the question. FrankenEngine emits one: a **signed
certificate of what untrusted code did NOT do with labeled data**, bounded by
an explicit, machine-enforced threat model.

## Two framings, one artifact

Both framings were reached independently in cross-model blind-spot analysis
(see `bd-fqlfw.8`); they describe the same six-file bundle.

1. **The data-owner's contract.** The party who owns the data declares, up
   front, a machine-readable contract: these inputs carry these sensitivity
   labels, these sinks are the only legal destinations, these purposes are
   authorized, and these output claims are requested (`no_flow`,
   `capability_not_used`, `output_independent_of`). The run either honors the
   contract and yields a signed certificate, or fails closed.
2. **The agent as untrusted principal.** The AI agent is treated exactly as
   FrankenEngine treats adversarial extension code: its tool authority is a
   typed capability grant (unknown tool tags are refused, not dropped), every
   tool call crosses the hostcall membrane, the guardplane watches its
   behavior as a firewall it cannot opt out of, and the whole episode lands
   in the signed evidence ledger for replay.

## The artifact

`frankenctl run --data-contract <contract.json> --certificate-out <dir>`
(and the agent-framework shim, `frankenctl agent-sandbox`) emit on exit:

| File | What it answers |
|---|---|
| `non_use_certificate.json` | Ed25519-signed verdicts on the requested non-use claims, with derived status. |
| `use_certificate.json` | Over-approximated positive record of what the run *may* have used. |
| `declassification_receipts.jsonl` | Every authorized label downgrade, or none. |
| `capability_trace.jsonl` | The capability-gated host-boundary crossings. |
| `repro.lock` | The re-run recipe binding the certificate to replayable evidence. |
| `audit.md` | The human-readable audit summary, scope statement included. |

The status is **derived, never asserted**: `certified_within_analyzed_scope`
is reachable only when the analyzed-subset scan of the exact run-input bytes
comes back clean *and* every requested claim evaluates
`holds_within_analyzed_scope`. Anything weaker — an unanalyzed construct, a
missing evidence link, a claim that cannot be established — downgrades the
certificate to `uncertified` with span-level provenance and remediation,
never a silent pass.

## Who needs it

| Segment | The buying question |
|---|---|
| **Agent platforms & frameworks** | "What do we hand enterprises when they ask what the agent's code did?" The `agent-sandbox` manifest is the tool-runner shim: grants in, certificate out. |
| **Enterprises running LLM-generated code over PII/secrets** | "Can we adopt agents without giving generated code ambient authority over customer data?" Data contracts bind labels and sinks before the first instruction runs. |
| **Regtech / AI-governance** | "What evidence artifact maps to our audit obligation?" A signed, replay-anchored certificate with an explicit scope boundary is checkable evidence, not marketing. |
| **Plugin / extension marketplaces** | "How do we vet third-party code at intake?" The same contract gate runs at onboarding (`frankenctl check` / `onboard`) and at runtime. |
| **Security teams with only unsigned logs today** | "Post-incident, can we distinguish 'did not exfiltrate' from 'we did not look'?" The refusal ledger records the difference explicitly. |

## Why incumbent runtimes do not emit this

The certificate composes five substrate properties that ship together nowhere
else by default: runtime IFC labels with a fail-closed flow policy, signed
declassification receipts, a capability-typed hostcall membrane, deterministic
replay of the episode, and a claim gate that refuses wording stronger than
the evidence. Node, Bun, and Deno are excellent general-purpose runtimes; a
signed non-use certificate is not a core runtime primitive in any of them
(see the README *Comparison* table for the gated per-dimension posture).
Retrofitting the five pillars around a binding-led engine is the structurally
expensive path — owning parser-to-scheduler semantics is what makes the label
algebra and the membrane sound enough to sign.

## The honesty boundary (read before quoting)

- **Explicit data flows only** (`explicit_flow_ifc_v1`). Covert channels,
  timing channels, and control-flow implicit channels are out of scope and
  unexpressible in the claim vocabulary by construction.
- **Analyzed subset, fail closed.** `await`/`yield`, async/generator function
  creation, iterator lanes, and module-graph edges are unproven in v1: they
  yield `uncertified` with `unproven_ifc_propagation` at the offending span.
- **Uncertified is the default.** Runs without the scan, without the explain
  bundle, or through surfaces that lack an evidence lane (the v1
  `agent-sandbox` lane) stay `uncertified` even when nothing looks wrong.
- Claim-language for this capability is bound by the claim-to-proof matrix;
  this document intentionally claims no more than the acceptance tests in
  `non_use_certificate_integration.rs` and `data_contract_integration.rs`
  demonstrate at HEAD.

## See it run

```bash
cargo build --release -p frankenengine-engine --bin frankenctl
./examples/26_non_exfiltration_certificate/demo.sh
```

Four acts: (1) an honest agent run emits `certified_within_analyzed_scope`;
(2) a contract-violating Secret-to-egress flow aborts fail-closed before any
certificate exists; (3) a smuggling attempt through an unanalyzed construct
yields an honest `uncertified` with span provenance; (4) the agent-sandbox
membrane refuses an unknown tool tag and reports the agent's exact effective
authority in the bundle it hands back.
