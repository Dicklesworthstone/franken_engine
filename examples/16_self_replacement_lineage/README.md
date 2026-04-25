# Self-Replacement Lineage

This example is a static demo of impossible-by-default capability #11.
It shows one delegated parser implementation being promoted to a native one.
The point is not the hash values themselves.
The point is the existence of a first-class lineage receipt.

The fixture starts with [`before_promotion.json`](./before_promotion.json).
That file records the delegated component name and its implementation hash.
Here the component is `parser_lite`.
Its delegate hash is `aaaa1111`.

The fixture ends with [`after_promotion.json`](./after_promotion.json).
That file records the same component after native promotion.
The native implementation hash is `bbbb2222`.

[`lineage_receipt.json`](./lineage_receipt.json) ties those two states together.
It states which delegate hash was replaced.
It states which native hash became authoritative.
It records the promotion timestamp.
It includes a fixed-width signature placeholder for provenance.
It carries a short evidence chain explaining why promotion happened.

The verifier is [`verify.sh`](./verify.sh).
It is intentionally shell-only and `jq`-only.
No Rust binary is required for this demo.
No runtime mutation happens during verification.
The demo is pure fixture validation.

Why call this impossible by default?
Node and Bun do not expose engine-component self-replacement receipts as a native contract.
An application can log that it swapped code.
An application can maybe sign its own record afterward.
But the runtime does not surface an authoritative delegate-to-native lineage artifact.

FrankenEngine is aiming for the stronger default.
The runtime should be able to say which implementation previously held authority.
It should say which implementation now holds authority.
It should bind that transition to signed evidence.
It should make replay and audit practical instead of aspirational.

This tiny fixture demonstrates the artifact shape for that contract.
It is useful in docs, tests, and design reviews before real machinery lands.
It also makes the requirement concrete for future promotion code.
If the receipt is malformed, verification fails closed.
If the signature is not 64 lowercase hex characters, verification fails closed.
If the hashes do not link before to after, verification fails closed.

From the repository root, run `./examples/16_self_replacement_lineage/verify.sh`.
A successful run confirms the static lineage receipt is internally coherent.
