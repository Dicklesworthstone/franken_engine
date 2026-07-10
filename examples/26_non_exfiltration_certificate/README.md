# 26 — Non-Exfiltration Certificate (E8)

"Prove the agent did not leak the secret." This demo runs AI-agent-shaped
code under a data-owner contract and shows the one artifact no unsigned log
can replace: a **signed certificate of what the code did NOT do with labeled
data**, emitted by the runtime itself and bounded by an explicit threat model.

## Run it

```bash
cargo build --release -p frankenengine-engine --bin frankenctl
./examples/26_non_exfiltration_certificate/demo.sh
```

## The four acts

| Act | What happens | Outcome |
|---|---|---|
| 1 | An honest agent step (fully inside the analyzed explicit-flow subset) runs under a contract labeling its input `Confidential`, with one audited sink and three requested non-use claims. | Six-file signed bundle; `certified_within_analyzed_scope`; every claim `holds_within_analyzed_scope`. |
| 2 | The contract labels the input `Secret` and declares only a raw network egress sink that may receive `Public`. | The IFC runtime guard **aborts the run fail-closed** before execution can leak; no certificate exists. |
| 3 | The agent tries to launder the secret through a `for..of` iterator lane — a construct outside the v1 analyzed subset. | Certificate emitted but honestly `uncertified`, with `unproven_ifc_propagation` refusals naming the unproven lanes (`for_of_init`, `for_of_next`, `iterator_close`; expression-level constructs carry `file:line:col` spans where the lowering stamps one). |
| 4 | The agent-sandbox membrane: a manifest granting an unknown tool tag is refused outright; a proper manifest runs the code and hands back the bundle. | The certificate's granted set is exactly the agent's tool authority + the forced VM baseline — never the CLI profile. |

## The bundle (`out/certified_bundle/`)

`non_use_certificate.json` (signed claim verdicts) · `use_certificate.json`
(over-approximated positive record) · `declassification_receipts.jsonl` ·
`capability_trace.jsonl` · `repro.lock` · `audit.md` (human-readable summary,
scope statement included).

## Read before quoting

The certificate covers **explicit data flows only** and certifies **within
the analyzed subset**; unanalyzed constructs, covert/timing channels, and
control-flow implicit channels never certify — they refuse with provenance.
Boundary: [`docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`](../../docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md).
Positioning narrative: [`docs/E8_STRATEGIC_POSITIONING_V1.md`](../../docs/E8_STRATEGIC_POSITIONING_V1.md).
