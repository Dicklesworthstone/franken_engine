# RGC Compound JSON Runtime Contract V1

Bead: `bd-2muur.1.1` (`RGC-920A.1`)

## Purpose

This contract defines the real shipped semantics for compound `JSON.parse` and
`JSON.stringify` behavior in FrankenEngine's stdlib lane. It exists to unblock:

- `bd-2muur.1.2` heap-backed `JSON.parse` materialization
- `bd-2muur.1.3` real `JSON.stringify` traversal
- `bd-2muur.1.4` closure/scanner proof work

The goal is to eliminate placeholder descriptor strings without inventing a
second temporary representation.

## Runtime Representation And Ownership

Compound JSON values must use the existing object-model substrate:

- Scalar leaves materialize as existing `JsValue` variants:
  - `null` -> `JsValue::Null`
  - booleans -> `JsValue::Bool`
  - strings -> `JsValue::Str`
  - numbers -> `JsValue::Int` using the existing fixed-point millionths model
- Compound arrays and objects materialize as `JsValue::Object(ObjectHandle)`.
- The owning storage is `ObjectHeap`; the returned `ObjectHandle` is the stable
  runtime reference.
- Arrays use the existing stdlib array instance shape:
  - class tag `Array`
  - array prototype chosen from the installed stdlib `Array.prototype`
  - dense own data properties `"0"` through `"length - 1"`
  - hidden non-enumerable own data property `"length"` storing the element
    count in fixed-point count units
- Plain JSON objects use ordinary heap objects with class tag `Object` and own
  enumerable string-keyed data properties.
- No JSON-specific descriptor strings, shadow metadata objects, or parallel
  heap formats are allowed.

Code anchors:

- `crates/franken-engine/src/object_model.rs`
- `crates/franken-engine/src/stdlib.rs`

## Supported `JSON.parse` Contract

`JSON.parse` must accept a JSON text string and return a real runtime value.

Supported behavior:

- Leading and trailing ASCII/Unicode whitespace around the full input is ignored.
- Top-level scalars remain supported.
- Top-level arrays and objects are supported.
- Nested arrays and objects are supported recursively.
- Object member keys are UTF-8 strings decoded through the existing JSON string
  escape logic.
- Duplicate object keys are resolved deterministically by "last key wins".
- Arrays are materialized densely in source order.
- Numeric leaves use `JsValue::Int` fixed-point millionths.
  - Supported numeric syntax for this contract version:
    - integer literals
    - finite decimal literals without exponent notation
    - at most 6 fractional decimal digits
  - Values that cannot be represented exactly in the fixed-point lane fail with
    `StdlibError::JsonParseError`.

Unsupported parse surfaces in this contract version:

- `reviver`
- exponent notation
- `NaN`, `Infinity`, and `-Infinity`
- precision-expanding numeric forms beyond the fixed-point lane

Unsupported or malformed inputs must fail deterministically with
`StdlibError::JsonParseError`; they must never collapse to a placeholder
descriptor value.

## Supported `JSON.stringify` Contract

`JSON.stringify` must derive output from real runtime state, not from summary
placeholders.

Supported behavior:

- Top-level `Null`, `Bool`, `Int`, and `Str` follow the existing scalar rules.
- Top-level `JsValue::Object(ObjectHandle)` is supported when the handle points
  to:
  - a dense stdlib array instance, or
  - an ordinary object with own enumerable string-keyed data properties
- Arrays serialize by iterating indices `0..length-1`.
- Plain objects serialize by iterating own enumerable string keys in
  `ObjectHeap` `own_property_keys()` order after filtering to strings.
  - This yields integer-index keys first in ascending numeric order, then other
    string keys in deterministic `BTreeMap` order.
- Nested arrays and objects are supported recursively.
- String escaping uses the existing JSON string escaping rules.

Unsupported-value handling:

- Top-level `Undefined`, `Symbol`, and `Function(_)` return `JsValue::Undefined`.
- Inside objects:
  - property values equal to `Undefined`, `Symbol`, or `Function(_)` are omitted
- Inside arrays:
  - elements equal to `Undefined`, `Symbol`, or `Function(_)` serialize as `null`
- Symbol-keyed properties are omitted.

Fail-closed surfaces for this contract version:

- cyclic object graphs
- proxy objects
- accessor-backed properties that would require getter execution
- object graphs whose array shape violates the dense `"0"..length-1"` invariant
- replacer functions/arrays
- `space` pretty-print formatting

These cases must return `StdlibError::JsonStringifyError` with deterministic,
actionable error text. They must never fall back to `[json-object]` or another
summary placeholder.

## Invariants For Later Leaves

`bd-2muur.1.2` and `bd-2muur.1.3` must preserve these invariants:

- Compound JSON values only cross the public boundary as real `JsValue`s.
- Every supported compound parse result can be fed into stringify without
  needing descriptor recovery.
- Stringify omission/failure behavior is container-sensitive and deterministic.
- Scanner closure work in `bd-2muur.1.4` can prove both placeholder strings are
  dead because the supported path no longer emits them.
