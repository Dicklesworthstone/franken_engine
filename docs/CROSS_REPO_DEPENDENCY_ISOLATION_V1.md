# Cross-Repo Dependency Isolation (`bd-6a61n.6`)

Updated by `bd-gw4cg`. Canonical contract for FrankenEngine's optional
cross-repository dependencies, standalone build mode, and full-integration
verification posture.

## Scope

`frankenengine-engine` carries four external dependency families behind
feature gates:

- asupersync: `franken-kernel`, `franken-decision`, `franken-evidence` at `0.3.4`
- persistence: `sqlmodel`, `sqlmodel-core`, `sqlmodel-frankensqlite` at upstream
  Git revision `7f432ff690260ef85aca5227e2372b2eb63230c9` (package version `0.5.0`)
- service API: `fastapi-core` at `0.3.1`
- dataframes: `fp-io`, `fp-frame`, `fp-columnar`, `fp-index`, `fp-types` at `0.2.0`

These dependencies are optional at the Cargo layer, enabled by default through
four explicit feature gates, and consumed as registry crates or an immutable
upstream Git revision rather than hard `/dp` path dependencies. That keeps the
repo standalone-ready while preserving
an explicit full-integration feature surface.

The SQLModel pin consumes its existing numeric `PRAGMA synchronous` FULL-readback
fix, which is absent from crates.io `0.5.0`. All three direct SQLModel dependencies
share that revision, and the lockfile keeps all eight SQLModel packages coherent.
FrankenSQLite remains the SDK's selected registry `0.4.10`; the engine adds no
root patch, cache modification, or durability-policy replacement. The Git entries
have no registry version fallback, so packaging cannot silently substitute the
broken driver. A future registry release must be qualified before replacing this
pin.

## Dependency Manifest

The canonical dependency manifest is:

- `docs/cross_repo_dependency_isolation_v1.json`

That JSON contract records the external package keys, source kind and revision,
feature gate, approved boundary files, imported symbols, verification scripts,
and operator commands.

## Feature Gate and Build Modes

`crates/franken-engine/Cargo.toml` defines:

- default feature set: `["asupersync-integration", "sibling-persistence",
  "sibling-service-api", "sibling-dataframes"]`
- gated sibling dependencies: the four families listed above

The supported operator build modes are:

- standalone mode:
  `cargo check -p frankenengine-engine --no-default-features`
- standalone test mode:
  `cargo test -p frankenengine-engine --no-default-features`
- retained fleet test coverage:
  `cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test fleet_quarantine_integration`
- retained Buffer public API coverage:
  `cargo test -p frankenengine-control-plane-integration-tests --no-default-features --test buffer_value_bd_9vouw_104`
- standalone release mode:
  `cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl`
- full integration mode:
  `cargo check -p frankenengine-engine --all-features`

Standalone mode is the blocking portability gate. Full integration mode verifies
the control-plane, persistence, service, and dataframe surfaces.
The fleet and Buffer targets use the existing control-plane test package's
explicit Asupersync and mock-TEE features. Its simulator is not hardware
attestation. The standalone gate runs all three test commands and rejects any
command's failure. The companion package owns 26 integration targets, including
the unchanged Buffer source; its default `engine-defaults` feature forwards
`frankenengine-engine/default` to preserve Buffer's original default-feature
coverage. `--no-default-features` disables that forwarding. Both-package CI
continues to run the default coverage, while these explicit standalone commands
keep persistence, service, and dataframe features disabled.
The internal moved-target sentinel is off for default/no-default workspace
selection. `--all-features` enables that sentinel and reactivates engine copies,
so this arrangement does not establish universal target uniqueness.

## Verification Surfaces

Two RC-6 operator surfaces are normative:

- `./scripts/audit_external_deps.sh`
- `./scripts/test_standalone_build.sh ci`

The audit script enumerates hard `/dp` path dependencies, records boundary
metadata when such dependencies exist, and optionally uses `rch` to verify each
sibling crate. The build gate rejects any `/dp` manifest edge, records the
standalone and full-integration outcomes, requires check, test, and release
success for its standalone verdict, and fails closed on local fallbacks or any
recorded failed lane. The machine-readable contract pins both surfaces to
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

## Historical Sibling Checkout Inventory (2026-05-21)

The following table preserves the earlier checkout inventory. The current
`Cargo.toml`, `Cargo.lock`, and explicit source pin above govern dependency
selection; this historical table does not attest a current build.

| Repository | Commit SHA | Updated |
|------------|------------|---------|
| `asupersync` | `094b59c859611f7f804fac79d185538d6e7aa171` | 2026-05-21 |
| `frankentui` | `33ad1c57d545292242e41a477c8278c70ed7e0d6` | 2026-05-21 |
| `frankensqlite` | `c0c8f32892a71f432a3ead0e5a04a9352549ccd4` | 2026-05-21 |
| `sqlmodel_rust` | `542292f276aad96702be42bc84f7e2bf341600e9` | 2026-05-21 |
| `fastapi_rust` | `bbbb388fd4b4a16dc2e7afb50275e56e37323dac` | 2026-05-21 |
| `frankenpandas` | `19aebfec6677f0866062efb0ec0d8d520e7e89ca` | 2026-05-21 |

### Verification Commands

To verify current sibling repository states match these pinned SHAs:

```bash
for repo in asupersync frankentui frankensqlite sqlmodel_rust fastapi_rust frankenpandas; do
  cd "/dp/$repo" && echo "$repo: $(git rev-parse HEAD)"
done
```

To update this table after a release cut:

1. Verify all sibling repositories are at the desired commit states
2. Run the verification commands above to capture current SHAs  
3. Update the table with new SHAs and current date
4. Commit the updated documentation as part of the release process
