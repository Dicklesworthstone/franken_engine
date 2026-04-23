# GA Success Criteria vs Current Reality Gap Analysis

## Summary
The plan's Section 13 success criteria assume a lane-based architecture with delegate cells as separate execution engines that need elimination for GA. The current implementation has lane infrastructure but uses a unified native interpreter, creating a fundamental mismatch between plan assumptions and implementation reality.

## Plan Requirements (Section 13)

The plan states GA success requires:
- **Line 1291**: "native execution lanes run without external engine bindings"  
- **Line 1329**: "GA default lanes run with zero mandatory delegate cells for core runtime slots"
- **Line 1067**: "GA default lanes are fully native (0 mandatory delegate cells), with complete signed replacement lineage for all formerly delegated core slots"

**Plan Architecture Assumption**: The success criteria assume:
1. Execution happens in "lanes" that can be either native or delegate  
2. Delegate cells represent external engine dependencies (performance limitation)
3. GA requires promoting all delegate cells to native implementations
4. This promotion needs signed replacement receipts proving equivalence

## Current Implementation Reality

### Lane Architecture Analysis
**Source**: `crates/franken-core/src/baseline_interpreter.rs`

Current LaneRouter has two lanes:
- **QuickJsLane**: "Deterministic baseline-interpreter profile"
- **V8Lane**: "Throughput-tuned baseline-interpreter profile"

**Key Finding**: Both lanes use **identical execution logic** via `InterpreterCore`:
```rust
// Both QuickJsLane and V8Lane execute_with_hook methods:
let mut core = InterpreterCore::new(self.config.clone(), trace_id);
```

**From line 17-19 comment**:
> "Both profiles share the same `InterpreterCore` execution logic; the profile difference is in policy (instruction budget, register limit, dispatch strategy), not in a second engine backend."

### Delegate Cell Analysis  
**Source**: `crates/franken-core/src/execution_cell.rs`

Current delegate cells are **execution tracking units**, not separate engines:
- `CellKind::Extension` - hosts loaded extensions
- `CellKind::Session` - hosts sessions within extensions  
- `CellKind::Delegate` - hosts delegate computations

**Key Finding**: Delegate cells are organizational/tracking constructs, not performance bottlenecks requiring elimination.

### External Engine Binding Analysis
**Finding**: **ZERO external engine bindings exist**
- V8Lane name is misleading - it doesn't use V8 engine
- No FFI to Node, Bun, V8, or other external JavaScript engines
- All execution happens via native `InterpreterCore` 

## The Fundamental Gap

| Plan Assumption | Current Reality |
|-----------------|-----------------|
| Delegate cells = external engine dependency | Delegate cells = execution tracking only |
| V8Lane = external V8 engine binding | V8Lane = native interpreter with V8-like config |
| GA requires delegate→native promotion | Already 100% native execution |
| Need signed replacement receipts | No external engines to replace |

## Resolution Options

### Option 1: Update Success Criteria (Recommended)
**Rationale**: The current implementation already achieves the plan's **intended** goal (native execution without external dependencies) but doesn't match the **literal** criteria.

**Required Changes**:
1. Replace "zero mandatory delegate cells" with "100% native execution"
2. Remove references to delegate→native promotion receipts  
3. Clarify that execution profiles (QuickJs/V8) are configuration variants, not engine bindings
4. Update Section 13 language to match current hybrid-native architecture

### Option 2: Implement Full Lane Architecture  
**Rationale**: Build the architecture the plan actually describes.

**Required Implementation**:
1. Create actual external engine bindings (V8, Node.js)
2. Make delegate cells represent external execution environments
3. Implement delegate→native promotion with replacement receipts
4. Build lane selection policy that can choose between native/external engines

**Cost**: ~6+ months major architectural work, external dependencies, FFI complexity

### Option 3: Rename Current Architecture
**Rationale**: Keep current implementation but rename to match plan vocabulary.

**Required Changes**:
1. Rename V8Lane to ThroughputNativeLane 
2. Remove all delegate cell terminology where it means "tracking units"
3. Use "native profile" instead of "lane" terminology
4. Update all documentation to avoid misleading names

## Recommendation

**Choose Option 1: Update Success Criteria**

The current implementation is architecturally sound and achieves the security/performance goals the plan intended. The gap is in terminology and success criteria language, not in missing core functionality.

**Proposed Success Criteria Revision**:
- ✅ "FrankenEngine executes JavaScript using native interpreter without external engine bindings"
- ✅ "Multiple execution profiles (deterministic/throughput) available via configuration"  
- ✅ "All core runtime slots implemented natively in Rust"
- ❌ ~~"GA default lanes run with zero mandatory delegate cells"~~
- ❌ ~~"complete signed replacement lineage for all formerly delegated core slots"~~

This preserves the plan's security and performance intentions while matching implementation reality.