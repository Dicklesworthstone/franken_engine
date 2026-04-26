# Execution Lanes vs Plan Section 8.2 Reality Check

## Summary

The plan's Section 8.2 specifies a three-lane execution architecture. The current implementation **fully implements** this architecture but with slightly different naming conventions, creating a false appearance of missing implementation.

## Plan Requirements (Section 8.2 Engine Lanes)

**Required Components**:
- `quickjs_inspired_native`: deterministic and low-overhead execution lane  
- `v8_inspired_native`: throughput/compatibility-oriented lane
- `hybrid_router`: policy-directed selection with deterministic fallback

## Current Implementation Analysis

### ✅ Three-Lane Architecture EXISTS
**Source**: `crates/franken-engine/src/lib.rs`

**1. QuickJs Inspired Native Lane**:
```rust
#[derive(Debug, Default)]
pub struct QuickJsInspiredNativeEngine;

impl JsEngine for QuickJsInspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::QuickJsInspiredNative
    }
    
    fn eval_prepared(&mut self, prepared: PreparedEvalSource, route_reason: RouteReason) -> EvalResult<EvalOutcome> {
        eval_with_lane(prepared, LaneChoice::QuickJs, route_reason)
    }
}
```

**2. V8 Inspired Native Lane**:
```rust
#[derive(Debug, Default)]
pub struct V8InspiredNativeEngine;

impl V8InspiredNativeEngine {
    fn eval_prepared(&mut self, prepared: PreparedEvalSource, route_reason: RouteReason) -> EvalResult<EvalOutcome> {
        eval_with_lane(prepared, LaneChoice::V8, route_reason)
    }
}
```

**3. Hybrid Router with Policy-Directed Selection**:
```rust
#[derive(Debug)]
pub struct HybridRouter {
    quickjs_lineage: QuickJsInspiredNativeEngine,
    v8_lineage: V8InspiredNativeEngine,
}

impl HybridRouter {
    pub fn classify_source_route(source: &str) -> RouteReason {
        route_reason_for_source(source)  // Policy-directed classification
    }
    
    pub fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let route_reason = Self::classify_source_route(source);
        match route_reason {
            RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => {
                // Routes to V8 lane for complex features
                self.v8_lineage.eval_prepared(prepared, route_reason)
            }
            _ => {
                // Routes to QuickJs lane for deterministic execution  
                self.quickjs_lineage.eval_prepared(prepared, RouteReason::DefaultQuickJsPath)
            }
        }
    }
}
```

### ✅ Policy-Directed Selection Logic
**Source**: Route classification in `HybridRouter::classify_source_route()`

Current routing policies:
- **Import/Module syntax** → V8 lane (complexity handling)
- **Await/Async syntax** → V8 lane (async runtime)
- **Default/Simple JS** → QuickJs lane (deterministic, low-overhead)

### ✅ Connection to Baseline Execution
**Source**: `crates/franken-core/src/baseline_interpreter.rs`

The lanes connect to actual execution via:
```rust
eval_with_lane(prepared, LaneChoice::QuickJs, route_reason)  // → QuickJsLane::execute()
eval_with_lane(prepared, LaneChoice::V8, route_reason)       // → V8Lane::execute()  
```

Both lanes use native `InterpreterCore` with different configurations (confirmed in previous analysis).

### ✅ Test Coverage
**Source**: Comprehensive test suite in `lib.rs`

Tests verify:
- `hybrid_routes_simple_input_to_quickjs()` 
- `hybrid_routes_import_to_v8()`
- Individual lane behavior
- Error handling consistency across lanes

## The "Missing Implementation" Misconception

### Naming Convention Differences
| Plan Specification | Implementation Name |
|-------------------|---------------------|
| `quickjs_inspired_native` | `QuickJsInspiredNativeEngine` |
| `v8_inspired_native` | `V8InspiredNativeEngine` |
| `hybrid_router` | `HybridRouter` |

### Why the Gap Appeared
1. **Snake_case vs PascalCase**: Plan uses snake_case, code uses PascalCase structs
2. **Search Strategy**: Looking for exact string matches (`quickjs_inspired_native`) misses actual implementations
3. **Scattered References**: Scheduling/test code references create noise when searching

## Verification of Completeness

### ✅ Architecture Requirements Met
- **Deterministic lane**: QuickJsInspiredNativeEngine provides low-overhead execution
- **Throughput lane**: V8InspiredNativeEngine handles complex features  
- **Policy selection**: HybridRouter routes based on source analysis
- **Deterministic fallback**: Default to QuickJs lane for simple cases

### ✅ Integration Requirements Met  
- **Lane execution**: Both connect to native InterpreterCore via LaneRouter
- **Route reasons**: Rich routing metadata (RouteReason enum) for debugging
- **Error consistency**: Identical error handling across lanes
- **Engine identification**: EngineKind tracks which lane executed code

## Resolution

**No implementation work needed**. The Section 8.2 three-lane architecture is **fully implemented and operational**.

**Recommended Actions**:
1. **Documentation Update**: Add alias/search terms mapping plan names to implementation names
2. **Naming Alignment**: Consider adding type aliases for exact plan naming:
   ```rust
   pub type quickjs_inspired_native = QuickJsInspiredNativeEngine;
   pub type v8_inspired_native = V8InspiredNativeEngine;  
   pub type hybrid_router = HybridRouter;
   ```
3. **Discoverability**: Add comments with plan section references to main engine structs

**Gap Assessment**: **FALSE POSITIVE** - Architecture exists with full functionality, only naming conventions differ from plan specification.