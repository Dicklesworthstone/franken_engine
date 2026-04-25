# Quarantine Mesh

This example demonstrates FrankenEngine's "impossible-by-default" quarantine mesh: one signed revocation is observed by three simulated instances, each instance appends it to a local `RevocationChain`, emits fleet evidence plus a `quarantine` intent, and converges on a quorum checkpoint inside a bounded SLO.

## Run It

From the repository root:

```bash
./examples/07_quarantine_mesh/demo.sh
```

To refresh the checked-in sample log:

```bash
./examples/07_quarantine_mesh/demo.sh > examples/07_quarantine_mesh/sample_propagation_log.json
```

## What The Demo Proves

- `mesh-a`, `mesh-b`, and `mesh-c` each maintain a separate `RevocationChain`.
- The same signed revocation is applied locally on all three instances.
- Each instance broadcasts evidence and a quarantine intent through the real `fleet_immune_protocol` message types.
- Each instance reaches a checkpointed `quarantine` decision within the configured bounded convergence SLO.

## Why This Is Impossible By Default In Node Or Bun

Node and Bun can unload a process or clear an app-level cache, but they do not ship a runtime-native, signed revocation fabric that can prove "this already-loaded module is now revoked everywhere" and converge that claim across a fleet. Once code is loaded, post-load revocation is an application convention unless you build your own quarantine, signature, replay-protection, and convergence layers on top.

FrankenEngine exposes those semantics directly:

- `revocation_chain.rs` gives a signed, append-only revocation history with verifiable head advancement.
- `fleet_immune_protocol.rs` gives deterministic evidence, intent, heartbeat, and checkpoint messages for bounded fleet convergence.
- The sample log shows both the local revocation timestamps and the eventual quorum checkpoint timestamps, so operators can measure whether containment stayed inside the promised SLO.
