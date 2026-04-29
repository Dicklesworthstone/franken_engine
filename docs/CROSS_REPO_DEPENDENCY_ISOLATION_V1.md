# Cross-Repo Dependency Isolation (`bd-6a61n.6`)

Canonical contract for FrankenEngine's optional asupersync dependencies,
standalone build mode, and full-integration verification posture.

## Scope

`frankenengine-engine` currently carries one asupersync dependency family behind
a feature gate:

- `franken-kernel = "0.3.1"`
- `franken-decision = "0.3.1"`
- `franken-evidence = "0.3.1"`

These dependencies are optional at the Cargo layer, enabled by default through
the `asupersync-integration` feature, and consumed as versioned crates rather
than hard `/dp` path dependencies. That keeps the repo standalone-ready while
preserving an explicit full-integration feature surface.

## Dependency Manifest

The canonical dependency manifest is:

- `docs/cross_repo_dependency_isolation_v1.json`

That JSON contract records the external package keys, registry source,
feature gate, approved boundary files, imported symbols, verification scripts,
and operator commands.

## Feature Gate and Build Modes

`crates/franken-engine/Cargo.toml` defines:

- default feature set: `["asupersync-integration"]`
- gated sibling dependencies: `franken-kernel`, `franken-decision`,
  `franken-evidence`

The supported operator build modes are:

- standalone mode:
  `cargo check -p frankenengine-engine --no-default-features`
- standalone test mode:
  `cargo test -p frankenengine-engine --no-default-features`
- full integration mode:
  `cargo check -p frankenengine-engine --all-features`

Standalone mode is the blocking portability gate. Full integration mode verifies
the asupersync-backed control-plane surface with the versioned tripod enabled.

## Verification Surfaces

Two RC-6 operator surfaces are normative:

- `./scripts/audit_external_deps.sh`
- `./scripts/test_standalone_build.sh ci`

The audit script enumerates hard `/dp` path dependencies, records boundary
metadata when such dependencies exist, and optionally uses `rch` to verify each
sibling crate. A clean manifest with zero hard `/dp` dependencies is
standalone-ready. The build-gate script records the standalone and
full-integration outcomes and fails closed on local fallbacks. The
machine-readable contract pins both surfaces to
`strict_mode: "rch_only_no_local_fallback"` so remote-only verification is part
of the evidence contract, not just a README note. These exact invocations are
the canonical operator commands recorded in
`docs/cross_repo_dependency_isolation_v1.json`.

## Artifacts

The dependency audit writes:

- `artifacts/dependency_audit/manifest.json`
- `artifacts/dependency_audit/commands.txt`
- `artifacts/dependency_audit/logs/`

The standalone/full-integration build gate writes:

- `artifacts/standalone_build_gate/<timestamp>/manifest.json`
- `artifacts/standalone_build_gate/<timestamp>/events.jsonl`
- `artifacts/standalone_build_gate/<timestamp>/commands.txt`
- `artifacts/standalone_build_gate/<timestamp>/step_logs/`

The JSON contract pins these artifact names so the scripts, docs, and
regression tests all agree on the same evidence bundle layout.

## RCH-Only Operator Commands

Heavy Rust verification for this lane must stay remote:

```bash
./scripts/audit_external_deps.sh
./scripts/test_standalone_build.sh ci
```

Both scripts are expected to route heavy Cargo commands through `rch`.
