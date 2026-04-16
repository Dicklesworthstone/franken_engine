# Inline Caching Design for FrankenEngine Optimization

**Document Version:** 1.0  
**Created:** 2026-04-16  
**Bead:** RC-3.5 Profiling Infrastructure  

## Executive Summary

Inline caching (IC) is a key optimization technique for bridging the performance gap between baseline interpreters and JIT engines. This document outlines a design for adding type-specialized fast paths to FrankenEngine while preserving deterministic execution, security containment, and replay semantics.

## Current State

FrankenEngine baseline interpreter executes ~50M operations/second for integer arithmetic, which is 10-100x slower than JIT engines. The profiling infrastructure identifies the following optimization opportunities:

1. **Property access operations** - Account for 15-25% of execution time
2. **Function calls** - Account for 20-30% of execution time  
3. **Arithmetic operations** - Account for 10-20% of execution time
4. **Object allocation** - Accounts for 5-15% of execution time

## Inline Caching Strategy

### Core Concept

Replace polymorphic operations with type-specialized fast paths:

```rust
// Current slow path (always polymorphic)
fn get_property(obj: Value, key: Value) -> Value {
    match obj {
        Value::Object(id) => {
            let obj_data = heap.get_object(id);
            obj_data.get_property(&key.to_string())
        }
        _ => Value::Undefined
    }
}

// Optimized with inline caching
fn get_property_cached(obj: Value, key: Value, ic: &mut InlineCache) -> Value {
    // Fast path: check if types match cached assumptions
    if ic.is_valid_for(&obj, &key) {
        return ic.fast_path(&obj, &key);
    }
    
    // Slow path: update cache and execute
    let result = get_property_slow(obj, key);
    ic.update_cache(&obj, &key, &result);
    result
}
```

### Implementation Phases

#### Phase 1: Property Access IC
- Target: `GetProperty` and `SetProperty` instructions
- Cache object shape + property offset for direct access
- Fallback to slow path on cache miss

#### Phase 2: Function Call IC  
- Target: `Call` and `CallMethod` instructions
- Cache function identity + argument types
- Enable specialized calling conventions

#### Phase 3: Arithmetic IC
- Target: `Add`, `Sub`, `Mul`, `Div` instructions  
- Cache operand types (int/float specialization)
- Enable vectorized operations for arrays

#### Phase 4: Allocation IC
- Target: `NewObject` and `NewArray` instructions
- Cache object layouts and pre-allocate common shapes
- Reduce GC pressure

### Technical Design

#### InlineCache Structure
```rust
#[derive(Debug, Clone)]
pub struct InlineCache {
    /// Cache entries (multiple entries for polymorphic sites)
    entries: Vec<CacheEntry>,
    /// Maximum number of cached entries before megamorphic fallback
    max_entries: u8,
    /// Hit count for optimization priority
    hit_count: u64,
    /// Miss count for deoptimization decisions
    miss_count: u64,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Type assumptions for this cache entry
    type_assumptions: TypeAssumptions,
    /// Fast path implementation
    fast_path: FastPathKind,
    /// Validity guard (object shape, etc.)
    guard: Guard,
}
```

#### Integration with Baseline Interpreter
```rust
// Extend Ir3Instruction with IC sites
pub enum Ir3Instruction {
    GetProperty { 
        obj: Reg, 
        key: Reg, 
        dst: Reg,
        ic_site: Option<InlineCacheId>,  // New field
    },
    // ... other instructions
}

// Interpreter state includes IC table
pub struct BaselineInterpreter {
    // ... existing fields
    inline_caches: Vec<InlineCache>,
}
```

### Deterministic Execution Preservation

**Critical Constraint:** All optimizations MUST preserve deterministic replay semantics.

#### Deterministic IC Updates
```rust
impl InlineCache {
    /// Update cache deterministically (no random eviction)
    pub fn update_deterministic(&mut self, assumptions: TypeAssumptions, entry: CacheEntry) {
        // Use deterministic eviction policy (LRU with stable ordering)
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0); // Always evict first entry
        }
        self.entries.push(entry);
    }
}
```

#### Replay Compatibility
- IC state must be serializable for replay bundles
- Cache misses/hits must be logged in witness events  
- Deoptimization triggers must be deterministic

### Security and Containment

#### Security-Safe Fast Paths
- All fast paths must preserve capability checks
- Type guards must prevent escaping containment
- Memory access bounds must be validated

```rust
fn get_property_fast_path(obj: ObjectId, offset: u32, capability: &Capability) -> Option<Value> {
    // Security: validate capability before fast path
    if !capability.allows_property_read(obj) {
        return None; // Force slow path
    }
    
    // Bounds check: validate offset is within object
    let obj_data = heap.get_object_checked(obj)?;
    if offset >= obj_data.property_count() {
        return None; // Force slow path
    }
    
    Some(obj_data.get_property_unchecked(offset))
}
```

### Performance Targets

Based on profiling data and IC literature:

1. **Property access**: 2-5x speedup (polymorphic → monomorphic)
2. **Function calls**: 3-10x speedup (direct calls, argument specialization)  
3. **Arithmetic**: 2-3x speedup (int/float specialization)
4. **Overall interpreter**: 2-4x speedup on typical workloads

**Conservative estimate:** 2x overall speedup, reducing gap from 100x to 50x compared to V8.

### Implementation Roadmap

#### Milestone 1: Infrastructure (2-3 weeks)
- [ ] `InlineCache` data structures
- [ ] IC site instrumentation in IR3  
- [ ] Basic cache lookup/update logic
- [ ] Deterministic cache policies

#### Milestone 2: Property Access IC (2-3 weeks)  
- [ ] Object shape tracking
- [ ] Property offset caching
- [ ] Fast path implementation
- [ ] Security validation integration

#### Milestone 3: Function Call IC (3-4 weeks)
- [ ] Function identity caching
- [ ] Argument type specialization  
- [ ] Direct call optimization
- [ ] Method call fast paths

#### Milestone 4: Arithmetic IC (2-3 weeks)
- [ ] Type-specialized arithmetic
- [ ] Integer/float fast paths
- [ ] Overflow handling
- [ ] SIMD exploration (future)

#### Milestone 5: Integration & Benchmarking (2-3 weeks)
- [ ] IC profiling integration
- [ ] Performance measurement 
- [ ] Regression testing
- [ ] Documentation

### Alternative Approaches Considered

1. **Bytecode specialization**: Pre-specialize bytecode based on types
   - Rejected: Breaks replay determinism, code bloat
2. **Trace compilation**: Record/replay execution traces
   - Rejected: Too complex for baseline interpreter goals  
3. **Template JIT**: Generate specialized code at runtime
   - Future work: Potential Phase 5 after IC proves successful

### Success Metrics

- [ ] 2x overall speedup on benchmark suite
- [ ] Zero regression in deterministic replay
- [ ] Zero regression in security containment
- [ ] IC hit rate >80% on real-world JavaScript workloads
- [ ] Memory overhead <10% for IC metadata

## Conclusion

Inline caching provides a proven path to significantly improving FrankenEngine performance while maintaining its core security and determinism guarantees. The phased implementation approach allows incremental progress and risk mitigation.

The key insight is that most JavaScript programs exhibit stable type patterns that can be exploited for optimization, even in a security-focused baseline interpreter.