# FrankenEngine CLI Workflow Smoke Test

This directory contains a smoke test for the complete frankenctl CLI workflow end-to-end validation.

## Overview

The CLI workflow smoke test validates the complete frankenctl command-line interface through a comprehensive end-to-end workflow that exercises:

- Core CLI commands (compile, run, doctor, etc.)
- Artifact generation and validation 
- Support bundle creation
- Trace and event logging
- Deterministic replay capabilities
- CI/CD integration workflows

## Workflow Components

The E2E workflow (`scripts/e2e/frankenctl_cli_workflow.sh`) produces a complete artifact bundle including:

### Core Artifacts
- `run_manifest.json` - Workflow execution manifest with metadata
- `events.jsonl` - Structured event log of all operations
- `trace_ids.json` - Trace identifiers for replay and debugging
- `commands.txt` - Complete command history

### Support Bundle
- `support_bundle/index.json` - Bundle inventory and metadata
- `support_bundle/preflight_report.json` - Pre-execution environment checks
- `support_bundle/onboarding_scorecard.json` - Workflow quality metrics
- `support_bundle/rollout_decision_artifact.json` - Deployment readiness assessment
- `support_bundle/frankenctl_doctor_report.json` - Diagnostic output

### Step Logs
- `step_logs/step_000.log` - Detailed execution logs per workflow step

## Usage

### Run the Complete Workflow
```bash
./run.sh
```

### Verify Artifact Completeness
```bash
./verify.sh
```

### Manual Execution
```bash
# Run the underlying E2E workflow in CI mode
bash scripts/e2e/frankenctl_cli_workflow.sh ci

# Check the generated artifacts
ls -la artifacts/frankenctl_cli_workflow/$(ls -1t artifacts/frankenctl_cli_workflow/ | head -1)/
```

## Artifact Structure

See `sample_artifact_listing.txt` for an example of a complete artifact tree structure.

## Success Criteria

- All required files present in artifact directory
- Support bundle index validates successfully
- No errors in step logs
- Doctor report shows healthy CLI state
- Trace IDs are properly formatted and linkable