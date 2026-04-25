# Signed Checkpoints

This example is a static demo of impossible-by-default capability #3: signed policy checkpoints with rollback resistance, freshness evidence, and replay-stable artifacts.

## Files

- `sample_checkpoint.json`: the canonical checkpoint fixture.
- `replay_checkpoint.json`: an identical render of the same fixture, proving the artifact is replay-stable.
- `verify.sh`: shell-only verifier for signature shape, replay identity, and basic parent-link sanity.

## Run

From the repository root:

```bash
./examples/20_signed_checkpoints/verify.sh
```

## What The Verifier Checks

- `signature_hex` is exactly 64 lowercase hex characters.
- `parent_checkpoint_id` is present and differs from `checkpoint_id`, so the fixture cannot self-loop.
- `sample_checkpoint.json` and `replay_checkpoint.json` are byte-for-byte identical after canonical JSON normalization.

## Why This Is Impossible By Default In Node Or Bun

Node and Bun can load configuration or application snapshots, but they do not expose runtime-native signed policy checkpoints with rollback-resistant parent linkage and freshness witnesses as a built-in contract. An application can build its own log format, but the runtime does not ship an authoritative checkpoint artifact that says:

- which policy checkpoint is current,
- which parent checkpoint it extends,
- why replay should reproduce the same artifact,
- and which signed witness prevents rollback or fork ambiguity.

FrankenEngine is aiming for that stronger default. This static fixture makes the checkpoint artifact shape concrete before full runtime plumbing lands.
