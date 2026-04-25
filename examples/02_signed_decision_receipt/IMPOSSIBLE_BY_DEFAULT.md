# Impossible by Default

FrankenEngine's signed decision receipt demo is category-defining because it couples runtime judgment, explanation, signing, and replayability in one default path.
Mainstream JavaScript runtimes execute code and return results.
They do not, by default, emit a structured receipt that says what the runtime decided, why it decided it, and how to verify that claim later.

The first differentiator is post-hoc explainability.
The receipt includes a `decision` and a `rationale`.
That means operators can see the enforcement action and the narrative justification in the same artifact.
This is stronger than a log line because the explanation is part of the receipt contract.
It travels with the verdict instead of living in a separate monitoring stack.

The second differentiator is probabilistic transparency.
`posterior_after_millionths` exposes the model state after the observed hostcall sequence.
The value is bounded, machine-readable, and directly comparable across runs.
That makes policy tuning auditable instead of mystical.
You can ask why a decision crossed a threshold and inspect the number that crossed it.

The third differentiator is cryptographic provenance.
`signature_hex` is derived from a keyed authenticity hash over the decision payload.
That gives downstream systems a cheap integrity check before they trust or store the receipt.
It also prevents silent mutation of the rationale or posterior after the fact.
A copied receipt can be verified against the same signing convention.

The fourth differentiator is replayability.
`replay_seed` anchors the receipt to a deterministic reconstruction path.
The same input program and the same sequence of modeled events can be rerun with the same seed.
That turns incident review into a reproducible exercise instead of folklore.
The operator is not limited to reading a narrative.
The operator can replay the path that produced the narrative.

These properties reinforce each other.
Explainability without provenance can be forged.
Provenance without explanation is opaque.
Replayability without a signed verdict can drift into unverifiable storytelling.
FrankenEngine binds all three into one artifact.

That is why this capability is impossible by default in Node and Bun.
They can be surrounded with extra systems, wrappers, or custom audit pipelines.
But the runtime itself does not normally output a signed, interpretable, replay-oriented containment receipt.
Achieving that behavior there requires bespoke engineering around the runtime.
Here it is demonstrated as a first-class path.

The practical result is higher-trust operations.
A security analyst gets a verdict, a reason, a posterior, a replay handle, and an authenticity proof in one JSON object.
CI can assert receipt shape automatically.
Humans can read it.
Forensics can preserve it.
Replay tooling can reuse it.
That end-to-end contract is the product, not an afterthought.
