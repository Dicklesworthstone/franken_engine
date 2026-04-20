# E2E Mock-Free Test Manifest

## Real Database Isolation
- Require tests that exercise persistence paths to run against a real database instance.
- Use transactional setup per test with explicit connection pool limits and deterministic test users.
- Enforce per-suite namespaces or schemas to prevent cross-suite state bleed.

## Transaction Rollback
- Wrap each test body in a rollback-capable transaction boundary and restore schema state automatically.
- Use savepoints for nested test phases when multi-step assertions are required.
- Reject tests that leave side effects outside the transaction layer.

## Service-Level Fixtures
- Build real-service fixtures (database rows, queues, caches) through shared factory helpers.
- Require fixtures to encode required business invariants, security posture, and timing assumptions.
- Keep fixture creation deterministic via explicit seeds and stable ordering.

## Structured Test Logging
- Emit JSON-line test logs containing phase markers, timing, and DB snapshot metadata.
- Capture request IDs, SQL statement classes, and rollback outcomes for each test case.
- Archive failure logs and artifacts to allow deterministic replay of assertions.

## Observability Assertions
- Assert on real telemetry signals such as spans, counters, and error classifications.
- Verify fallback and retry behavior via observable service outputs rather than mocked responses.
- Fail tests on missing or degraded observability signals where production behavior depends on them.
