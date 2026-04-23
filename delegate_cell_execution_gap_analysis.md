# Delegate Cell Execution vs Plan Requirements Gap Analysis

## Summary

The plan's Section 8.8 requires delegate cells to be "governed exactly like untrusted extensions" with capability constraints and runtime execution. The current `slot_registry.rs` provides comprehensive schema and tracking for delegate vs native promotion, but **lacks any actual delegate cell execution harness** with the required capability controls.

## Plan Requirements (Section 8.8 Constitutional Rules)

**From line 390**: Delegate cells must be governed exactly like untrusted extensions:
- **Cx capability threading** - capability-bounded execution
- **Guardplane monitoring** - security monitoring during execution  
- **Decision contracts** - policy-based decisions on delegate behavior
- **Evidence-ledger receipts** - provenance tracking for all delegate actions
- **Deterministic replay coverage** - all delegate execution must be replayable

**From line 1252**: "Implement delegate-cell runtime harness for not-yet-native slots with explicit capability envelopes, sandbox controls, and replay hooks."

**Plan Architecture Assumption**: Delegate cells are **actual execution environments** that run untrusted code with security constraints.

## Current Implementation Analysis

### SlotRegistry Schema (Comprehensive)
**Source**: `crates/franken-engine/src/slot_registry.rs`

The slot registry provides complete **tracking infrastructure**:
- ✅ **SlotEntry**: Complete registration records with promotion status
- ✅ **PromotionStatus**: Delegate → PromotionCandidate → Promoted → Demoted lifecycle
- ✅ **AuthorityEnvelope**: Required/permitted capabilities for slots
- ✅ **SlotCapability**: Granular capabilities (ReadSource, EmitIr, HeapAlloc, etc.)
- ✅ **LineageEvent**: Promotion/demotion history with receipts
- ✅ **SlotKind**: 12 replaceable slot types (Parser, Interpreter, ObjectModel, etc.)

**Methods Available**:
- `register_delegate()` - Register slots as delegates
- `native_count()` / `delegate_count()` - Track promotion statistics  
- `native_coverage()` - Percentage of slots promoted to native
- Comprehensive getter/iterator methods for slot inspection

### Execution Infrastructure (Missing)
**Critical Gap**: SlotRegistry has **zero execution methods**:
- ❌ No `execute_delegate()` or `run_slot()` method
- ❌ No capability enforcement during delegate execution
- ❌ No sandbox controls or isolation
- ❌ No Guardplane integration during delegate runtime
- ❌ No evidence collection from delegate execution
- ❌ No deterministic replay hooks

### Verification Against Current Execution Architecture

**From previous analysis** (`ga_success_criteria_gap_analysis.md`):
- All current execution goes through native `InterpreterCore`
- LaneRouter (QuickJs/V8) both use identical native implementation
- No external engine bindings or delegate execution environments

**Conclusion**: The plan assumes delegate cells are separate execution environments, but current implementation has **pure schema with no runtime**.

## The Fundamental Architectural Gap

| Plan Requirement | Current Implementation |
|-----------------|---------------------|
| Delegate cells execute untrusted code | Delegate cells are tracking records only |
| Capability enforcement during execution | Authority envelopes are schema only |
| Guardplane monitoring of delegate runtime | No delegate runtime to monitor |
| Evidence collection from delegate actions | No delegate actions to collect evidence from |
| Deterministic replay of delegate execution | No delegate execution to replay |

## Resolution Options

### Option 1: Implement Full Delegate Runtime (Plan-Compliant)
**What it requires**:
1. **Delegate Execution Harness**: 
   - `ExecutorCell` trait with native/delegate implementations
   - Capability enforcement wrapper around delegate execution
   - Sandbox isolation using process boundaries or WASM
   
2. **Runtime Integration**:
   - Modify LaneRouter to dispatch through SlotRegistry
   - Route execution to delegate vs native based on slot promotion status
   - Real capability checking that blocks unauthorized operations
   
3. **Monitoring Integration**:
   - Guardplane hooks into every delegate hostcall/operation
   - Evidence collection from delegate execution traces
   - Decision contracts triggered by delegate behavior
   
4. **External Engine Integration**:
   - QuickJS bindings for actual delegate execution
   - Capability-constrained FFI layer
   - Deterministic replay infrastructure

**Estimated Cost**: 8-12 weeks major architectural work

### Option 2: Update Plan to Match Schema-Only Reality (Recommended)
**Rationale**: Current schema serves a different but valid architectural purpose.

**Current Value**: 
- SlotRegistry provides **promotion tracking** for native implementation completeness
- Authority envelopes document **intended capability boundaries** for verification
- Promotion lineage provides **audit trail** for security certification

**Recommended Plan Updates**:
1. Replace "delegate cell execution" with "slot implementation tracking"
2. Clarify that delegate status means "not yet implemented natively"
3. Remove requirements for delegate runtime execution with capability constraints
4. Focus on native implementation completeness rather than delegate→native promotion

### Option 3: Hybrid Approach - Implement Minimal Delegate Runtime
**For specific slots that benefit from external implementations**:
- **Parser slot**: Delegate to external parser (babel, swc) for compatibility
- **Builtins slot**: Delegate to Node.js built-ins for ecosystem compatibility
- Keep other slots pure native

**Selective Implementation**: Only implement delegate runtime for slots where external delegation provides real value.

## Recommendation

**Choose Option 2: Update Plan to Match Current Architecture**

The current SlotRegistry schema provides valuable **implementation completeness tracking** but attempting to build a full delegate runtime execution environment would:
1. Duplicate existing native execution infrastructure
2. Introduce significant security attack surface
3. Add substantial complexity without clear value
4. Delay native implementation work

**Proposed Section 8.8 Revision**:
- ✅ "SlotRegistry tracks implementation status of replaceable runtime components"
- ✅ "Authority envelopes document capability requirements for verification"  
- ✅ "Promotion lineage provides audit trail for native implementation coverage"
- ❌ ~~"Delegate cells must be governed exactly like untrusted extensions"~~
- ❌ ~~"Delegate-cell runtime harness with explicit capability envelopes"~~

This preserves the valuable schema-based architecture tracking while eliminating the requirement for a parallel execution environment that conflicts with the current unified native approach.