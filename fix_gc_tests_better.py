import re

path = 'crates/franken-engine/tests/gc_integration.rs'
with open(path, 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'matches!(result, Err' in line or 'let result =' in line or 'assert!(matches!' in line or 'assert_eq!(result' in line:
        new_lines.append(line)
        continue
    
    # Fix .allocate(...) -> .allocate(...).unwrap()
    line = re.sub(r'(\.allocate\([^)]+\))(?!\.unwrap)', r'\1.unwrap()', line)
    
    # Fix .allocate_tracked(...) -> .allocate_tracked(..., AllocationDomain::ExtensionHeap)
    line = re.sub(r'(\.allocate_tracked\([^,]+,\s*[^,]+,\s*[^)]+)\)', r'\1, frankenengine_engine::gc::AllocationDomain::ExtensionHeap)', line)
    
    new_lines.append(line)

with open(path, 'w') as f:
    f.writelines(new_lines)
