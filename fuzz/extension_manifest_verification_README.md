# Extension Manifest Verification Fuzz Target

## Overview

This fuzz target provides comprehensive coverage for Ed25519 signature verification in extension manifest validation, focusing on security-critical attack vectors identified during code review.

## Target: `extension_manifest_verification.rs`

### Attack Vectors Covered

1. **Tampered Signatures** (Mode 0): Bit-flipping in signature bytes
2. **Wrong-Length Signatures** (Mode 1): Empty, too-short, too-long, valid-length-invalid-content
3. **Malformed Public Key Encodings** (Mode 2): Invalid hex, wrong length, non-hex characters
4. **Edge Sizes** (Mode 3): Zero-size and maximum-size components
5. **Cross-Manifest Replay** (Mode 4): Valid signature for different content
6. **Signature Malleability** (Mode 5): S-component manipulation attempts
7. **Domain Separation Bypass** (Mode 6): Wrong domain tags, fake payloads
8. **High-Entropy Random** (Mode 7): Pure libFuzzer mutations

### Oracle Properties

- **Determinism**: Verification must be deterministic across multiple runs
- **Consistency**: Trust chain and signature presence must be consistent
- **Length Validation**: Non-64-byte signatures must be rejected
- **Round-Trip Stability**: Recomputed content hashes must yield consistent results

### Corpus

Located in `corpus/extension_manifest_verification/`:
- `empty`: Zero-byte baseline
- `minimal_valid`: Basic valid manifest structure
- `tampered_signature`: High-entropy signature for tampering detection
- `wrong_length_sig`: 32-byte signature (invalid length)
- `malformed_pubkey`: Invalid hex encoding
- `edge_sizes`: Min/max size components
- `domain_bypass`: Domain separation attack payload

### Dictionary

Located in `dictionaries/extension_manifest.dict`:
- Ed25519 signature/key lengths (0x20, 0x40)
- Common hex patterns and invalid hex
- Domain separation tags
- Capability bitmasks
- Manifest field patterns

### Usage

```bash
# Build the fuzz target
cargo fuzz build extension_manifest_verification

# Run fuzzing campaign
cargo fuzz run extension_manifest_verification

# Minimize crash cases
cargo fuzz tmin extension_manifest_verification artifacts/...

# Coverage information
cargo fuzz coverage extension_manifest_verification
```

### Validation

The harness has been validated to correctly:
- Parse structured fuzz inputs across all attack modes
- Convert inputs to valid ExtensionManifest structs
- Handle edge cases and malformed inputs gracefully
- Execute without panics on diverse inputs

This provides defense-in-depth against Ed25519 verification vulnerabilities including the domain separation issue identified and fixed in bd-1m6kf.