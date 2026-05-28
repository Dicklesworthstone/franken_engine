# Golden File Provenance — `tests/golden/cli/` (CLI capture JSON)

Companion to the canonical inventory at `tests/golden/PROVENANCE.md` and the
canonical-location decision in
[docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md](../../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md).

This directory holds CLI-binary capture JSONs for `frankenctl_help`,
`frankenctl_version`, and `decision_demo_help`. The
`architecture_inventory_{help,stdout,check}.json` captures that previously
lived here were removed in bd-ub6x8.10 because their substantive contract is
already covered by `tests/architecture_inventory_golden.rs` against
`docs/ARCHITECTURE_INVENTORY.md`.

This directory was migrated from `tests/golden_tests/` to its current
canonical location at `tests/golden/cli/` in bd-ub6x8.6.2.

## Regeneration

All franken-engine golden tests honor the project-wide `UPDATE_GOLDENS=1`
contract (bd-ub6x8.2):

```bash
UPDATE_GOLDENS=1 cargo test
```

The CLI captures are built on demand and emitted by the owning test below
(bd-ub6x8.20 — "build CLI golden binaries on demand").

## Fixtures

### `frankenctl_help.json`, `frankenctl_version.json`, `decision_demo_help.json`

- **Owning test:** `tests/cli_golden.rs`
- **Subject under test:** `frankenctl` and `decision_demo` CLI surface —
  the `--help` text and `--version` output captured as JSON so a
  surprise CLI change (renamed flag, dropped subcommand) trips the
  golden mismatch and forces a conscious update.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test cli_golden`
- **Scrubbing:** none — `--help` / `--version` output is deterministic.
- **Binary build:** the helper test compiles `frankenctl` and
  `decision_demo` on demand inside the test (bd-ub6x8.20) rather than
  expecting a pre-built artifact.

## Toolchain

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Mode: `UPDATE_GOLDENS=1` for blessing; default compare mode otherwise.
