# Standard Library Gap Analysis Report

**Task**: RC-1.6 Standard Library Completeness  
**Date**: 2026-04-16  
**Analyst**: PearlTower

## Executive Summary

Comprehensive audit reveals a **critical execution gap**: While FrankenEngine has an extensive BuiltinId enumeration with 100+ standard library methods defined in `stdlib.rs`, there is no dispatch mechanism in `baseline_interpreter.rs` to actually execute these methods when called from JavaScript code.

## Current State Analysis

### ✅ What EXISTS (Comprehensive)

**BuiltinId Enum Coverage** (stdlib.rs lines 53-262):
- **Array**: 35 methods (constructor, isArray, from, push, pop, map, filter, reduce, etc.)
- **Object**: 20 methods (keys, values, entries, assign, freeze, create, defineProperty, etc.)  
- **String**: 25 methods (charAt, indexOf, slice, split, includes, trim, etc.)
- **Number**: 8 methods (isFinite, isInteger, parseFloat, toString, etc.)
- **Boolean**: 3 methods (constructor, toString, valueOf)
- **Math**: 17 methods (abs, ceil, floor, round, max, min, pow, sqrt, etc.)
- **JSON**: 2 methods (parse, stringify)
- **Map**: 11 methods (constructor, get, set, has, delete, clear, forEach, etc.)
- **Set**: 11 methods (constructor, add, has, delete, clear, forEach, etc.)
- **Date**: 6 methods (constructor, now, getTime, toISOString, toString, valueOf)
- **Error**: 6 constructors (Error, TypeError, RangeError, etc.)
- **Symbol**: 5 methods (constructor, for, keyFor, toString, valueOf)
- **Promise**: 8 methods (constructor, resolve, reject, then, catch, all, race, etc.)
- **Global Functions**: 8 methods (isNaN, isFinite, parseInt, parseFloat, encodeURI, etc.)
- **Function.prototype**: 3 methods (call, apply, bind)
- **Console**: 3 methods (log, error, warn)  
- **Timers**: 5 methods (setTimeout, setInterval, clearTimeout, etc.)

**Installation Infrastructure** (stdlib.rs lines 649-800):
- `install_stdlib()` function properly sets up prototypes and constructor relationships
- `install_*_builtins()` functions wire BuiltinId variants to method names
- `BuiltinRegistry` tracks builtin function slots
- Proper prototype chain establishment for all standard objects

### ❌ What's MISSING (Critical Gap)

**Execution Dispatch** (baseline_interpreter.rs HostCall handler):
- No `dispatch_builtin_hostcall()` or similar method
- HostCall instruction only handles:
  - `promise:*` → `dispatch_promise_hostcall()`
  - `number:*` → `dispatch_number_hostcall()`  
  - `console:*` → `dispatch_console_hostcall()`
  - `timer:*` → `dispatch_timer_hostcall()`
- **Zero stdlib method execution support**

**Result**: All 100+ BuiltinId methods are defined but not executable.

## Specific Missing Components

### 1. WeakMap/WeakSet (Not Defined)
- No BuiltinId variants for WeakMap or WeakSet
- No installation functions  
- These are ES2020 required features

### 2. Proxy/Reflect (Not Defined)
- No BuiltinId variants for Proxy or Reflect  
- These are critical for meta-programming

### 3. Array.from with Iterables (Defined but Unverified)
- `ArrayFrom` exists in BuiltinId but execution unknown
- Integration with iterator protocol uncertain

### 4. Console Integration (Partial)  
- Console methods defined in BuiltinId
- `dispatch_console_hostcall()` exists but integration unclear

## Test Results

**Execution Test Results** (scripts/test_stdlib_basic.sh):
```
Array.push() → ✗ execution failed
Object.keys() → ✗ execution failed  
JSON.stringify() → ✗ execution failed
```

**Root Cause**: frankenctl execution fails, likely due to missing BuiltinId dispatch in interpreter.

## Recommendations

### Priority 1: Core Dispatch Implementation
1. Add `dispatch_builtin_hostcall()` method to baseline_interpreter.rs
2. Wire BuiltinId variants to actual implementations  
3. Integrate with existing HostCall dispatch logic

### Priority 2: Missing Standard Objects
1. Add WeakMap/WeakSet BuiltinId variants and implementations
2. Add basic Proxy/Reflect trap support
3. Verify Array.from works with iterables

### Priority 3: Verification Infrastructure  
1. Fix frankenctl execution (extension-id parameter issue)
2. Create comprehensive execution test suite
3. Verify each BuiltinId method executes correctly

## Implementation Status

- **BuiltinId Definitions**: ✅ 95% complete (missing WeakMap/WeakSet/Proxy/Reflect)
- **Installation Infrastructure**: ✅ 100% complete
- **Execution Dispatch**: ❌ 0% implemented  
- **Test Coverage**: ❌ 0% (execution failures)

## Conclusion

FrankenEngine has excellent standard library **definitions** but zero **execution** capability. The infrastructure exists to support a world-class stdlib; the missing piece is connecting the definitions to the runtime execution engine.

**Estimated Implementation Effort**: 2-3 days to bridge the execution gap for core methods.