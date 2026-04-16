import re

filepath = 'crates/franken-engine/src/self_replacement.rs'
with open(filepath, 'r') as f:
    content = f.read()

# We need to replace instances like:
# DelegateCellManifest::derive_manifest_id(
#     &test_slot_id(),
#     DelegateType::QuickJsBacked,
#     &test_behavior_hash(),
#     "zone-a",
# )

# The regex needs to handle whitespace and newlines better
pattern = r'(DelegateCellManifest::derive_manifest_id\(\s*)([^,]+),\s*([^,]+),\s*([^,]+),\s*(".*?")(\s*\))'
replacement = r'\1\2, \3, \4, &test_authority_envelope(), &test_sandbox(), &test_monitoring_hooks(), \5\6'

new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

# Handle the case where the third param is &[1u8; 32] or &[2u8; 32]
pattern2 = r'(DelegateCellManifest::derive_manifest_id\(\s*)([^,]+),\s*([^,]+),\s*(\&\[\du8;\s*32\]),\s*(".*?")(\s*\))'
new_content = re.sub(pattern2, replacement, new_content, flags=re.DOTALL)

# Handle the case where the third param is `&hash`
pattern3 = r'(DelegateCellManifest::derive_manifest_id\(\s*)([^,]+),\s*([^,]+),\s*(\&hash),\s*(".*?")(\s*\))'
new_content = re.sub(pattern3, replacement, new_content, flags=re.DOTALL)

if new_content != content:
    with open(filepath, 'w') as f:
        f.write(new_content)
    print('Fixed derive_manifest_id in tests')
else:
    print('No matches found.')
