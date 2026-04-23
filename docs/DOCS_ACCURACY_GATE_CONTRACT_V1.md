# Docs Accuracy Gate Contract V1

> **Bead**: `bd-1lsy.10.11.3` — [RGC-911C]  
> **Policy**: Comprehensive docs accuracy gate for README, CLI help, operator guides, and observability-mode guidance  
> **Component**: `docs_accuracy_gate`  
> **Schema Version**: `franken-engine.docs-accuracy-gate.v1`

## Overview

The Docs Accuracy Gate enforces **comprehensive documentation accuracy** across all user-facing documentation sources. It prevents documentation drift by systematically validating that README, CLI help, operator guides, and observability-mode guidance accurately reflect shipped behavior.

**Key Principle**: Any documentation that contradicts shipped behavior blocks release until manual review and explicit override.

## Documentation Sources

The gate validates accuracy across these documentation sources:

| Source | Coverage | Examples |
|--------|----------|----------|
| **README** | Primary user documentation | Installation, quick start, basic usage |
| **CLI Help** | `frankenctl --help` output | Commands, flags, subcommands |
| **Operator Docs** | `docs/` directory guides | Deployment, troubleshooting, advanced configuration |
| **Inline Comments** | Code documentation | API behavior, configuration options |
| **Observability Guidance** | Telemetry and monitoring docs | ObservabilityMode usage, telemetry configuration |

## Surface Types

Each documented surface is classified by type:

| Type | Description | Examples |
|------|-------------|----------|
| **Command** | CLI commands | `frankenctl compile`, `frankenctl run` |
| **Flag** | CLI flags | `--input`, `--output`, `--verbose` |
| **Subcommand** | CLI subcommands | `verify compile-artifact`, `benchmark score` |
| **ConfigOption** | Configuration keys | TOML options, environment variables |
| **RuntimeBehavior** | System behavior | Deterministic replay, observability modes |
| **ApiSurface** | Library/API functions | Public interfaces, callbacks |
| **OutputFormat** | Data schemas | JSON artifacts, log formats |

## Drift Classification

Documentation drift is classified by severity and user impact:

| Class | Severity | Publication Impact | Description |
|-------|----------|-------------------|-------------|
| **Aligned** | 0 | ✅ **Allowed** | Documentation matches shipped behavior |
| **MinorSyntaxDrift** | 20K | ✅ **Allowed** | Minor syntax differences (e.g., `-v` vs `--verbose`) |
| **AspirationalClaim** | 500K | 🚫 **BLOCKED** | Documentation describes unshipped features |
| **UndocumentedFeature** | 100K | 🚫 **BLOCKED** | Shipped behavior not documented |
| **ContradictoryBehavior** | 900K | 🚫 **BLOCKED** | Documentation contradicts shipped behavior |
| **DeprecatedReference** | 300K | 🚫 **BLOCKED** | Documentation references removed features |
| **BrokenExample** | 700K | 🚫 **BLOCKED** | Examples that would fail if executed |

## Gate Configuration

The gate uses strict configuration for release gating:

```rust
GateConfig {
    max_aspirational_claims: 0,        // No aspirational documentation
    max_broken_examples: 0,            // No broken examples
    fail_on_contradictory: true,       // Hard fail on contradictions
    max_avg_severity_millionths: 50_000,    // Low average severity
    min_alignment_rate_millionths: 950_000,  // 95% alignment required
}
```

## Required Surface Coverage

The following surfaces **MUST** be documented and aligned:

### CLI Commands

1. `frankenctl version` — Print version information
2. `frankenctl compile` — Compile source to bytecode artifact
3. `frankenctl run` — Execute source through orchestrator
4. `frankenctl doctor` — Runtime diagnostics and health check
5. `frankenctl verify compile-artifact` — Validate compiled artifact
6. `frankenctl verify receipt` — Verify execution receipt bundle
7. `frankenctl benchmark run` — Execute benchmark workloads
8. `frankenctl benchmark score` — Score publication gate thresholds
9. `frankenctl benchmark verify` — Verify benchmark evidence claims
10. `frankenctl replay run` — Replay execution traces

### Observability Modes

1. **BudgetedCapture** — Production-safe telemetry with bounded overhead
2. **ExactShadow** — Perfect accuracy telemetry for validation only
3. **DegradedCapture** — Reduced accuracy fallback mode during incidents
4. **IncidentCapture** — Emergency full telemetry capture mode

### Operator Documentation

1. **V8 Supremacy Evidence Publication** — Gate-based publication workflow
2. **Parser Supremacy Criteria** — Parser-specific verification requirements
3. **Observability Publication Policy** — Structured observability requirements
4. **RGC Compliance Matrix** — Verification contract documentation

## Smoke Testing Infrastructure

The gate includes comprehensive smoke testing:

### Scripts

- `scripts/run_docs_accuracy_gate_suite.sh` — Main suite runner with rch integration
- `scripts/e2e/docs_accuracy_gate_smoke.sh` — Smoke test entry point

### Binaries

- `frankenctl_docs_accuracy_builder` — Build comprehensive inventories from shipped behavior
- `frankenctl_docs_accuracy_evaluator` — Evaluate inventories using gate logic

### Artifacts

- `docs_accuracy_inventory.json` — Complete documented surface inventory
- `docs_accuracy_gate_report.json` — Gate evaluation report with verdict
- `drift_analysis.md` — Human-readable drift analysis and recommendations

## Release Gate Integration

### CI/CD Integration

```bash
# Release gate check
./scripts/e2e/docs_accuracy_gate_smoke.sh

# Verify gate verdict
if jq -e '.verdict == "Pass"' artifacts/docs_accuracy_gate/latest/docs_accuracy_gate_report.json; then
  echo "✅ Documentation accuracy verified — release approved"
else
  echo "🚫 Documentation drift detected — release BLOCKED"
  exit 1
fi
```

### Manual Verification

```bash
# Check latest gate report
cat artifacts/docs_accuracy_gate/latest/docs_accuracy_gate_report.json | jq '.verdict'

# Review drift analysis
cat artifacts/docs_accuracy_gate/latest/drift_analysis.md

# Replay gate evaluation
./scripts/e2e/docs_accuracy_gate_smoke.sh
```

## Unsupported Surface Contracts

Explicit unsupported surfaces are documented to set user expectations:

| Surface | Reason | Workaround | Planned | Tracking |
|---------|--------|------------|---------|----------|
| `frankenctl workspace init` | Multi-project workspace not implemented | Manual setup | ✅ Yes | `bd-future-workspace` |
| `frankenctl tui` | Requires frankentui integration | Use `frankenctl doctor` | ✅ Yes | — |
| `frankenctl promote` | Deployment promotion not implemented | Use vercel promote | ✅ Yes | — |
| `frankenctl profile live` | Live profiling not implemented | Use offline benchmarks | ✅ Yes | `bd-live-profiling` |

## Failure Scenarios and Resolution

### Common Drift Types

#### 1. Aspirational Documentation
**Symptom**: Documentation describes unshipped features  
**Resolution**: Remove aspirational claims or implement features before release

#### 2. Contradictory CLI Help
**Symptom**: `--help` output contradicts README examples  
**Resolution**: Update documentation to match shipped CLI behavior

#### 3. Broken Examples
**Symptom**: Code examples in docs would fail if executed  
**Resolution**: Test and fix all examples before release

#### 4. Missing Observability Guidance
**Symptom**: ObservabilityMode usage not documented  
**Resolution**: Add comprehensive observability mode documentation

### Emergency Overrides

In exceptional circumstances, the gate can be bypassed:

```bash
# Create override with business justification (requires escalation)
echo "DOCS_ACCURACY_GATE_OVERRIDE_REASON='Emergency security hotfix - docs will be updated in follow-up'" > .docs_gate_override
```

**Override Policy**: 
- Temporary only (≤48 hours)
- Requires security incident or critical production issue
- Must include follow-up tracking bead
- Automatically expires and blocks future releases

## Monitoring and Alerting

### Key Metrics

- **Alignment Rate**: Percentage of surfaces with acceptable drift
- **Gate Pass Rate**: Frequency of successful evaluations
- **Drift Velocity**: Rate of new drift introduction
- **Override Frequency**: Rate of emergency bypasses

### Alerting Thresholds

- Alignment rate drops below 95% → **Warning**
- Any ContradictoryBehavior drift → **Critical**
- Gate failure rate exceeds 10% → **Warning**
- Emergency override used → **Critical** (requires incident)

## Debugging and Verification

### Diagnostic Commands

```bash
# Full gate evaluation with detailed logging
./scripts/run_docs_accuracy_gate_suite.sh ci

# Inspect specific drift
jq '.surfaces[] | select(.drift_class != "aligned")' \
  artifacts/docs_accuracy_gate/latest/docs_accuracy_inventory.json

# Validate gate logic
cargo test -p frankenengine-engine --test docs_accuracy_gate_smoke_integration

# Check observability mode coverage
jq '.surfaces[] | select(.name | contains("Capture"))' \
  artifacts/docs_accuracy_gate/latest/docs_accuracy_inventory.json
```

### Manual Validation

```bash
# Verify CLI help matches documented commands
frankenctl --help | grep "frankenctl " | sort

# Check operator docs exist
ls docs/V8_SUPREMACY_EVIDENCE_BUNDLE_PUBLICATION_V1.md
ls docs/RGC_V8_SUPREMACY_CLAIM_CONTRACT_V1.md
ls docs/PARSER_SUPREMACY_CRITERIA_CONTRACT.md

# Validate observability modes
rg -n "BudgetedCapture|ExactShadow|DegradedCapture|IncidentCapture" crates/
```

## Schema and Evolution

### Current Schema

- **Inventory**: `franken-engine.docs-accuracy-inventory.v1`
- **Gate Report**: `franken-engine.docs-accuracy-gate-report.v1`
- **Manifest**: `franken-engine.docs-accuracy-gate.run-manifest.v1`

### Backward Compatibility

- No breaking changes to existing inventory fields
- New surface types added as optional with sensible defaults
- Migration tooling for major version upgrades

## Security Considerations

### Threat Model

- **Documentation Spoofing**: Gate validates against shipped binaries, not just source
- **Drift Accumulation**: Systematic validation prevents gradual documentation decay
- **Release Integrity**: Failed gate blocks releases with inaccurate user guidance

### Cryptographic Integrity

- All artifacts include SHA-256 content hashes
- Gate reports are deterministically reproducible
- Evaluation chain validation ensures no tampering

## Related Documentation

- [docs_accuracy_gate.rs](../crates/franken-engine/src/docs_accuracy_gate.rs) — Core implementation
- [V8_SUPREMACY_EVIDENCE_BUNDLE_PUBLICATION_V1.md](V8_SUPREMACY_EVIDENCE_BUNDLE_PUBLICATION_V1.md) — V8 supremacy gate
- [RGC_V8_SUPREMACY_CLAIM_CONTRACT_V1.md](RGC_V8_SUPREMACY_CLAIM_CONTRACT_V1.md) — Supremacy claim verification
- [rgc_docs_help_surface_audit_v1.json](rgc_docs_help_surface_audit_v1.json) — CLI help audit contract

## Support and Escalation

### Runbook Contacts

- **Primary**: Technical Writing Team
- **Secondary**: Release Engineering Team
- **Escalation**: Architecture Council

### SLA Commitments

- Gate evaluation: <5 minutes
- Issue response: <2 hours during business hours
- Critical drift resolution: <24 hours

---

**Document Version**: v1.0  
**Last Updated**: 2026-04-23  
**Next Review**: 2026-07-23  
**Owner**: Technical Writing + Release Engineering Teams