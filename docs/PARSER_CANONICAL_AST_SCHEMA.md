# Parser Canonical AST Schema Contract

This document freezes the parser canonical AST schema + hash contract for
`bd-2mds.1.1.2`.

## Contract IDs (v1)

- `contract_version`: `franken-engine.parser-ast.contract.v1`
- `schema_version`: `franken-engine.parser-ast.schema.v1`
- `hash_algorithm`: `sha256`
- `hash_prefix`: `sha256:`

Source of truth: [`crates/franken-engine/src/ast.rs`](../crates/franken-engine/src/ast.rs)
constants:

- `CANONICAL_AST_CONTRACT_VERSION`
- `CANONICAL_AST_SCHEMA_VERSION`
- `CANONICAL_AST_HASH_ALGORITHM`
- `CANONICAL_AST_HASH_PREFIX`

## Canonical Encoding Rules

Canonical AST bytes are produced by:

1. `SyntaxTree::canonical_value()`
2. `deterministic_serde::encode_value(...)`

`deterministic_serde` contract (v1):

- map key ordering is lexicographic (`BTreeMap`)
- arrays preserve insertion order
- typed tags are stable (`U64`, `I64`, `Bool`, `String`, `Array`, `Map`, `Null`)
- no optional-field omission inside canonical values

Hash contract (v1):

- `canonical_hash = "sha256:" + hex(sha256(canonical_bytes))`

## Canonical AST Shape (v1)

`SyntaxTree` canonical map keys:

- `goal` (`"script"` or `"module"`)
- `body` (`Array<Statement>`)
- `span` (`SourceSpan`)

`Statement` canonical map keys:

- `kind` (`"import" | "export" | "expression"`)
- `payload` (kind-specific node)
- `span` (`SourceSpan`)

`SourceSpan` canonical map keys:

- `start_offset`
- `end_offset`
- `start_line`
- `start_column`
- `end_line`
- `end_column`

`Expression` canonical map keys:

- `kind` (`identifier|string|numeric|boolean|null|undefined|await|raw`)
- `value` (typed value by expression variant)

## Compatibility Policy

- v1 is fail-closed for drift in:
  - contract constants,
  - canonical encoding algorithm,
  - hash prefix/algorithm,
  - pinned compatibility vectors.
- Any incompatible change requires:
  1. new version constants (`...v2`),
  2. new compatibility vectors,
  3. migration note in this doc and parser verification docs.

## FrankenCore Native Parser Schema v2

The repository split now has two parser AST seams. The compatibility parser in
`crates/franken-engine` retains the v1 contract described above. The native
parser/lowering path in `crates/franken-core` advances its
`CANONICAL_AST_SCHEMA_VERSION` to `franken-engine.parser-ast.schema.v2` for
`bd-1tafi`.

Schema v2 adds `pre_loop_initializer` to the canonical `ForInStatement` map.
It is the ordinary expression value for the non-strict Script Annex-B form
`for (var identifier = initializer in object)` and explicit `Null` for every
other for-in head. This preserves the canonical no-omission rule and makes the
one-time pre-loop side effect hash-visible. Existing core canonical hashes that
contain a for-in statement therefore intentionally change under the v2 schema
tag.

The derived JSON/serde carrier remains backward-readable: the field defaults
to `None` when absent and is skipped while serializing `None`. This keeps legacy
IR0 JSON readable without weakening canonical v2, where the field is always
present. Consumers must bind cached core canonical hashes to the reported
schema version and regenerate v2 hashes rather than comparing them to v1.

## FrankenCore Native Parser Schema v3

The native `franken-core` parser advances to
`franken-engine.parser-ast.schema.v3` for `bd-vltnh`. Schema v3 widens
`Expression::StringLiteral` from Rust `String` to the exact ECMAScript
`JsString` carrier so quoted source escapes such as `"\uD800"` survive as
their original UTF-16 code units.

Well-formed literal values retain the historical `CanonicalValue::String`
shape and byte encoding. A value containing a lone surrogate is encoded as a
tagged canonical map whose `$wtf16` entry is the exact array of UTF-16 units.
Derived serde follows the same compatibility rule: historical plain JSON
strings remain readable and byte-stable, while exact values use
`{"$wtf16":[...]}`. Consumers must bind caches to schema v3 even when a
particular well-formed tree happens to retain its previous canonical payload
bytes.

## Compatibility Checks

Pinned by tests:

- [`crates/franken-engine/tests/parser_trait_ast.rs`](../crates/franken-engine/tests/parser_trait_ast.rs)
  - contract constants/accessors are stable
  - hash vectors:
    - `-7` (script) -> `sha256:d959b7cbce9a409871d9a288d6feb3c043bdf3ce6ee54ff39051909db432adc4`
    - `import dep from "pkg"` (module) -> `sha256:6f9b81a8dfbaad70c345e5508dd1fae29d3d6cfdc1d18954d3486abd00d75f6c`
    - `export default true` (module) -> `sha256:ebb993de589945a2cf22f17db58200599ae3e1e6c21cd33a0fc59eab99fd8ef6`
- [`crates/franken-engine/tests/ast_integration.rs`](../crates/franken-engine/tests/ast_integration.rs)
  - contract constants/accessors and hash prefix checks
- [`crates/franken-core/src/ast.rs`](../crates/franken-core/src/ast.rs)
  - core v3 lone-surrogate string-literal vector (`D800`) ->
    `sha256:2d2912b4ee4142810f692d25a6f154e758dccf2aeb9926f5abebab7f5d63773a`
  - core v3 Annex-B for-in vector (payload bytes unchanged from v2) ->
    `sha256:166c2e3ca50abc0b25c83ce8cfefb4be4a7eac33e7337809f1594e22ff9fe963`

## Replay Commands

Use `rch` for heavy runs:

```bash
rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_ast_contract \
  cargo test -p frankenengine-engine --test parser_trait_ast --test ast_integration
```

Parser phase0 gate (includes parser trait vectors):

```bash
./scripts/run_parser_phase0_gate.sh ci
```
