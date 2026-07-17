# Parser Canonical AST Schema Contract

This document freezes the parser canonical AST schema + hash contract for
`bd-2mds.1.1.2`.

## Historical Contract IDs (v1)

- `contract_version`: `franken-engine.parser-ast.contract.v1`
- `schema_version`: `franken-engine.parser-ast.schema.v1`
- `hash_algorithm`: `sha256`
- `hash_prefix`: `sha256:`

The historical v1 vector remains pinned by `GoldenVersionVector::v1()`. Live
constants are exposed by
[`crates/franken-engine/src/ast.rs`](../crates/franken-engine/src/ast.rs):

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

- Each live schema vector is fail-closed for drift in:
  - contract constants,
  - canonical encoding algorithm,
  - hash prefix/algorithm,
  - pinned compatibility vectors.
- Any incompatible change requires:
  1. new version constants (`...v2`),
  2. new compatibility vectors,
  3. migration note in this doc and parser verification docs.

## Engine Compatibility Parser Schema v2

The compatibility parser in `crates/franken-engine` advances its live
`CANONICAL_AST_SCHEMA_VERSION` to `franken-engine.parser-ast.schema.v2` for
`bd-vltnh`. The contract version, hash algorithm, and hash prefix remain v1.

Schema v2 widens `Expression::StringLiteral` and the parser arena mirror from
Rust `String` to the exact ECMAScript `JsString` carrier. Well-formed values
retain the historical canonical string leaf and plain JSON string shape. A
value containing a lone surrogate is represented canonically and in serde as
`{"$wtf16":[...]}`, preserving every UTF-16 code unit without projecting it
through UTF-8. A valid surrogate pair normalizes to its ordinary Unicode scalar
string representation.

The historical engine v1 vector remains available for artifact identification;
`GoldenVersionVector::v2()` records this exact-string checkpoint. The later
EOF-coordinate migration makes `v3()` the live vector while preserving v2 for
historical identification. The pinned v2 `D800` syntax-tree vector is:

`sha256:2d2912b4ee4142810f692d25a6f154e758dccf2aeb9926f5abebab7f5d63773a`

## FrankenCore Native Parser Schema v2

The repository split has two parser AST seams with independent schema histories.
The native parser/lowering path in `crates/franken-core` advances its
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

## Canonical Root EOF Coordinate Migration

The compatibility parser advances its live AST schema from v2 to
`franken-engine.parser-ast.schema.v3` for `bd-4tt6s`. The native core parser
advances independently from v3 to `franken-engine.parser-ast.schema.v4`.

Both seams now encode the `SyntaxTree` root span's `end_column` as the
one-based UTF-8 byte column immediately after the original source on its final
physical line. A non-empty single-line source therefore ends at
`source.len() + 1`; a non-empty multiline tail is measured from the final line
start; and a trailing LF or CRLF creates an empty final line at column 1. The
core seam applies the same rule to its existing CR, U+2028, and U+2029 line
terminators. Horizontal trailing whitespace and multibyte UTF-8 source bytes
remain visible in the column, matching the established `SourceSpan` byte
coordinate contract.

This migration changes values, not shape. The AST contract version, serde
representation, canonical map keys, SHA-256 algorithm, and hash prefix remain
unchanged. Historical AST JSON with `end_column: 1` therefore remains readable
and reproduces its historical hash. Engine `GoldenVersionVector::v1()` and
`v2()` remain available for artifact identification; `v3()` and `current()`
bind live checks to the corrected coordinate semantics. Consumers must never
compare canonical hashes across AST schema versions without an explicit
migration.

Source-backed Parse Event IR readers retain a narrow historical path for the
pre-migration defect. They accept an old stream only when its terminal event
matches the current parsed root span in every field except an `end_column` of
1 and its payload hash exactly authenticates that reconstructed historical
tree. Any additional span or hash drift still fails closed. No Parse Event IR
or materializer wire version changes because this compatibility path adds no
serialized field.

## Compatibility Checks

Pinned by tests:

- [`crates/franken-engine/tests/parser_trait_ast.rs`](../crates/franken-engine/tests/parser_trait_ast.rs)
  - contract constants/accessors are stable
  - live schema-v3 hash vectors:
    - `-7` (script) -> `sha256:8fbc2bb1f3f8fbf7c6e7fc08a89dc768a0ac973390555ecae9b215d442e604c7`
    - `import dep from "pkg"` (module) -> `sha256:58af3ebe9640c16302cc30b9ac25be14d592d62ffd33595310a2cacf0a7c11be`
    - `export default true` (module) -> `sha256:3165b53e61ee5a66ab81a15b52e6ff84ebd4de83501dbb6e64629dbefe294b36`
  - the corresponding schema-v2 hashes remain asserted after reconstructing
    the historical root column, including a serde reader round-trip
- [`crates/franken-engine/tests/ast_integration.rs`](../crates/franken-engine/tests/ast_integration.rs)
  - engine v3 contract constants/accessors and hash prefix checks
  - exact `D800` serde, canonical-value, and pinned hash checks
- [`crates/franken-engine/src/parser_arena.rs`](../crates/franken-engine/src/parser_arena.rs)
  - exact string-literal arena round-trip without UTF-8 projection
- [`crates/franken-core/src/ast.rs`](../crates/franken-core/src/ast.rs)
  - core v4 carries forward the v3 lone-surrogate string-literal vector
    (`D800`) ->
    `sha256:2d2912b4ee4142810f692d25a6f154e758dccf2aeb9926f5abebab7f5d63773a`
  - core v4 carries forward the v3 Annex-B for-in vector ->
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
