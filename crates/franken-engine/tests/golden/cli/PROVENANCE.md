# Golden File Provenance — `tests/golden/cli/` (CLI capture JSON)

Companion to the canonical inventory at `tests/golden/PROVENANCE.md` and the
canonical-location decision in
[docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md](../../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md).

This directory retains legacy CLI-binary capture JSONs for `frankenctl_help`,
`frankenctl_version`, and `decision_demo_help`; the active comparison fixtures
now live as insta snapshots under `tests/snapshots/` (bd-ub6x8.21.7). The
`architecture_inventory_{help,stdout,check}.json` captures that previously
lived here were removed in bd-ub6x8.10 because their substantive contract is
already covered by `tests/architecture_inventory_golden.rs` against
`docs/ARCHITECTURE_INVENTORY.md`.

This directory was migrated from `tests/golden_tests/` to its current
canonical location at `tests/golden/cli/` in bd-ub6x8.6.2.

## Regeneration

The active CLI snapshots use insta's update flow:

```bash
INSTA_UPDATE=always cargo test -p frankenengine-engine --test cli_golden
```

The CLI captures are built on demand and emitted by the owning test below
(bd-ub6x8.20 — "build CLI golden binaries on demand").

## Fixtures

### `cli_golden__{frankenctl_help,frankenctl_version,decision_demo_help}.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.7)*

- **Owning test:** `tests/cli_golden.rs`
- **Subject under test:** `frankenctl` and `decision_demo` CLI surface —
  the `--help` text and `--version` output captured as JSON so a
  surprise CLI change (renamed flag, dropped subcommand) trips the
  snapshot mismatch and forces a conscious update.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test cli_golden`,
  followed by `cargo insta review` for interactive blessing. The legacy JSON
  files in this directory are retained for audit history until explicit
  deletion/move approval is given.
- **Scrubbing:** shared timestamp/path scrubbers from `tests/_support/golden_diag.rs`;
  flag names such as `--target-platform` are preserved verbatim.
- **Binary resolution:** the test prefers Cargo's integration-test
  `CARGO_BIN_EXE_*` binary paths, honors `CLI_GOLDEN_BIN_DIR` for CI-provided
  artifacts, and keeps the bd-ub6x8.20 build-on-demand resolver as fallback.

## Toolchain

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Mode: `INSTA_UPDATE=always` for blessing; default compare mode otherwise.
