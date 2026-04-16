import re
import sys

path = '/data/projects/franken_engine/crates/franken-engine/tests/gc_integration.rs'
with open(path, 'r') as f:
    content = f.read()

# Fix .allocate(...) -> .allocate(...).unwrap()
# Make sure we don't double unwrap
# We use a regex that matches .allocate(something) that is NOT followed by .unwrap()
# The argument to allocate might not contain parentheses, or might. It's usually `allocate(size)` or `allocate("ext", size)`.
content = re.sub(r'(\.allocate\([^)]+\))(?!\.unwrap)', r'\1.unwrap()', content)

# Fix .allocate_tracked(...) -> .allocate_tracked(..., AllocationDomain::ExtensionHeap)
content = re.sub(r'(\.allocate_tracked\([^,]+,\s*[^,]+,\s*[^)]+)\)', r'\1, AllocationDomain::ExtensionHeap)', content)

with open(path, 'w') as f:
    f.write(content)
