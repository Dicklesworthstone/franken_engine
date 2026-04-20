# Open Specs Publication

## Protocol Name

FrankenEngine Trust Replay Policy Open Specifications.

## Scope

This publication covers the public protocol contracts for deterministic trust
decisions, replay evidence, and policy evaluation artifacts. The scope includes
stable field names, artifact relationships, conformance expectations, and
failure semantics required for third-party verification.

The scope does not include private deployment topology, secret material,
operator credentials, or implementation-specific optimization details that are
not required for independent protocol adoption.

## Versioning

The specification follows explicit schema-version identifiers in published
artifacts and semantic versioning for externally consumed protocol revisions.
Backward-compatible clarifications may update prose without changing the
protocol version. Any change that alters required fields, validation behavior,
or failure outcomes requires a new minor or major version.

Deprecated fields must remain documented until the next major version and must
include the replacement field, migration rule, and last supported version.

## Extension Hooks

Implementations may add extension hooks for new policy predicates, replay
validators, artifact transports, or conformance vector suites when those hooks
preserve deterministic ordering and fail-closed validation semantics.

Every extension hook must declare:

- Hook name and version.
- Inputs and outputs with stable JSON field names.
- Deterministic ordering rules.
- Error codes for invalid input, unsupported version, and failed validation.
- Conformance vectors that prove compatibility with the base specification.

## License

This specification is distributed under the repository license: MIT License
with the OpenAI/Anthropic rider. Redistribution of the specification must retain
the license text and rider from the repository `LICENSE` file.
