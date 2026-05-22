# PERF-H2 Write-Site Inventory

Generated for bd-o4cbn.6.1 (PERF-H2.1) on 2026-05-21.

This inventory catalogs all mutation sites for the three seed-surface fields in `baseline_interpreter.rs`:
- `registers: Vec<Value>`
- `heap: Heap`  
- `function_prototypes: FunctionPrototypes`

## Register Write Sites (26 mutation sites)

| Site (file:line) | Field | Current write idiom | Replacement helper |
|---|---|---|---|
| baseline_interpreter.rs:2670 | registers | `self.registers[reg as usize] = value;` | `self.mutate_registers(\|r\| r[reg as usize] = value)` |
| baseline_interpreter.rs:2845 | registers | `self.registers = seed.registers.clone();` | `self.mutate_registers(\|r\| *r = seed.registers.clone())` |
| baseline_interpreter.rs:2889 | registers | `self.registers = snapshot.registers;` | `self.mutate_registers(\|r\| *r = snapshot.registers)` |
| baseline_interpreter.rs:2905 | registers | `self.registers.clear();` | `self.mutate_registers(\|r\| r.clear())` |
| baseline_interpreter.rs:2906 | registers | `self.registers.resize(max_regs, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(max_regs, Value::Undefined))` |
| baseline_interpreter.rs:3946 | registers | `self.registers[reg_start + i] = value;` | `self.mutate_registers(\|r\| r[reg_start + i] = value)` |
| baseline_interpreter.rs:4466 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:4495 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:4498 | registers | `self.registers[saved_base + i] = val;` | `self.mutate_registers(\|r\| r[saved_base + i] = val)` |
| baseline_interpreter.rs:5045 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:5047 | registers | `self.registers[self.register_base..req_len].fill(Value::Undefined);` | `self.mutate_registers(\|r\| r[self.register_base..req_len].fill(Value::Undefined))` |
| baseline_interpreter.rs:5215 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:5217 | registers | `self.registers[self.register_base..req_len].fill(Value::Undefined);` | `self.mutate_registers(\|r\| r[self.register_base..req_len].fill(Value::Undefined))` |
| baseline_interpreter.rs:5405 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:5407 | registers | `self.registers[self.register_base..req_len].fill(Value::Undefined);` | `self.mutate_registers(\|r\| r[self.register_base..req_len].fill(Value::Undefined))` |
| baseline_interpreter.rs:5517 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:5519 | registers | `self.registers[self.register_base..req_len].fill(Value::Undefined);` | `self.mutate_registers(\|r\| r[self.register_base..req_len].fill(Value::Undefined))` |
| baseline_interpreter.rs:6182 | registers | `self.registers.resize(req_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(req_len, Value::Undefined))` |
| baseline_interpreter.rs:6184 | registers | `self.registers[self.register_base..req_len].fill(Value::Undefined);` | `self.mutate_registers(\|r\| r[self.register_base..req_len].fill(Value::Undefined))` |
| baseline_interpreter.rs:10448 | registers | `self.registers = vec![Value::Undefined; self.config.max_registers as usize];` | `self.mutate_registers(\|r\| *r = vec![Value::Undefined; self.config.max_registers as usize])` |
| baseline_interpreter.rs:10533 | registers | `self.registers = vec![Value::Undefined; self.config.max_registers as usize];` | `self.mutate_registers(\|r\| *r = vec![Value::Undefined; self.config.max_registers as usize])` |
| baseline_interpreter.rs:18949 | registers | `self.registers.resize(idx + 1, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(idx + 1, Value::Undefined))` |
| baseline_interpreter.rs:18951 | registers | `self.registers[idx] = value;` | `self.mutate_registers(\|r\| r[idx] = value)` |
| baseline_interpreter.rs:19211 | registers | `self.registers.resize(new_len, Value::Undefined);` | `self.mutate_registers(\|r\| r.resize(new_len, Value::Undefined))` |
| baseline_interpreter.rs:19230 | registers | `self.registers[actual_reg] = value;` | `self.mutate_registers(\|r\| r[actual_reg] = value)` |

## Heap Write Sites (11 mutation sites)

| Site (file:line) | Field | Current write idiom | Replacement helper |
|---|---|---|---|
| baseline_interpreter.rs:2847 | heap | `self.heap = seed.heap.clone();` | `self.mutate_heap(\|h\| *h = seed.heap.clone())` |
| baseline_interpreter.rs:8435 | heap | `self.heap.get_mut(id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:11766 | heap | `self.heap.get_mut(obj_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(obj_id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:12585 | heap | `self.heap.get_mut(array_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(array_id.0 as usize).map(\|array\| ...))` |
| baseline_interpreter.rs:13177 | heap | `self.heap.get_mut(array_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(array_id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:13425 | heap | `self.heap.push(result_obj);` | `self.mutate_heap(\|h\| h.push(result_obj))` |
| baseline_interpreter.rs:15447 | heap | `self.heap.get_mut(obj_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(obj_id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:18273 | heap | `self.heap.get_mut(collection_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(collection_id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:18308 | heap | `self.heap.get_mut(entries_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(entries_id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:18343 | heap | `self.heap.get_mut(values_id.0 as usize)` mutations | `self.mutate_heap(\|h\| h.get_mut(values_id.0 as usize).map(\|obj\| ...))` |
| baseline_interpreter.rs:19534 | heap | `self.heap.push(object);` | `self.mutate_heap(\|h\| h.push(object))` |

## Function Prototypes Write Sites (2 mutation sites)

| Site (file:line) | Field | Current write idiom | Replacement helper |
|---|---|---|---|
| baseline_interpreter.rs:2850 | function_prototypes | `self.function_prototypes = seed.function_prototypes.clone();` | `self.mutate_function_prototypes(\|fp\| *fp = seed.function_prototypes.clone())` |
| baseline_interpreter.rs:19745 | function_prototypes | `self.function_prototypes.insert(func_idx, prototype);` | `self.mutate_function_prototypes(\|fp\| fp.insert(func_idx, prototype))` |

## Summary

**Total: 39 write sites identified across all tracked fields**
- Registers: 25 sites
- Heap: 12 sites  
- Function Prototypes: 2 sites

## Notes

1. **Read-only access sites**: Multiple `get()` calls and read-only operations on heap don't require changes as they don't mutate state.

2. **Complex heap mutations**: Some heap mutations involve `get_mut()` chains with conditional mutations. These will require careful refactoring to extract the mutation logic into the closure passed to `mutate_heap()`.

3. **Seed restoration sites**: Lines 2845, 2847, 2850, 2889 are existing seed restoration logic that will be refactored as part of the new seed system.

4. **Type enforcement**: The `SeedTrackedField<T>` wrapper without `DerefMut` will make it impossible to bypass these chokepoints at compile time.

## Verification

This inventory was generated by:
```bash
rg -n 'self\.registers\s*[\[=\.]' baseline_interpreter.rs
rg -n 'self\.heap\s*[\[=\.]' baseline_interpreter.rs  
rg -n 'self\.function_prototypes\s*[\[=\.]' baseline_interpreter.rs
```

Each site was manually analyzed to determine if it represents a mutation requiring migration to the new `mutate_*` helper API.