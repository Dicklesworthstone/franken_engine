# BRIDGE Closeout Policy

Enforces decomposed-parent closeout and exact required-child completion for the
`bd-performance-conformance-bridge-tu32j` program tracker.

- Owning bead: `bd-performance-conformance-bridge-tu32j.22.61` ([BRIDGE-21.61])
- Consumers: every agent/operator closing a manifest-listed node;
  `scripts/e2e/bridge_closeout_guard_smoke.sh` gates regressions.
- Deletion condition: archive together with the BRIDGE tracker when the program
  root closes.

## Mechanism (all native br 0.4.1 primitives; no wrappers)

| Layer | File | Effect |
|---|---|---|
| Policy | `.beads/policy.yaml` | `allow_bypass: false` (kills `--bypass-policy`); label-scoped transition gates require native gate `bridge_closeout` for `open|in_progress|blocked|deferred -> closed` |
| Manifest | `docs/bridge_closeout_manifest_v1.json` | One exact snapshot of all 466 tree nodes; typed exceptions (`pre_harness_architecture`, `post_cert_research`, `external_owner`) fixed by the owning bead text; content-hashed |
| Verifier | `scripts/bridge_closeout_verify.py` | Read-only single-transaction check: edge-exactness vs manifest, unmanifested/tombstone/reparent drift, recursive required-child completion with closure evidence, cross-node requirements, gate-pass provenance |
| Reporter | `scripts/run_bridge_closeout_gate.sh` | Records the pass/fail verdict bound by br to the issue's current status revision (stales automatically on any later status change) |
| Break-glass | `scripts/bridge_breakglass.sh` | HMAC-signed override pass; flagged `breakglass_not_normal_completion` forever by the verifier |

## Closing a protected node

```bash
scripts/run_bridge_closeout_gate.sh <bead-id>          # verify + record pass
br close <bead-id> --reason "<evidence-cited reason>"   # now accepted
```

Any status change after the pass stales it; re-run the reporter.

## Documented residuals

- Direct SQLite tampering outside br bypasses all tooling-level control; it is
  detectable post hoc (events table, export hashes, verifier provenance rows)
  but not preventable without upstream beads_rust changes.
- A forged `br gate report` from a non-sanctioned provider satisfies the native
  gate layer; the verifier flags such nodes (`unsanctioned_gate_pass`) so any
  covered verification denies. Provenance, not prevention.
- `workflow.strict: true` with empty `statuses:`/`transitions:` was chosen so
  the gates activate with zero vocabulary or transition friction for unrelated
  work; plain issues close exactly as before (proven: S10).
