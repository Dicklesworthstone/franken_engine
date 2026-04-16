import re
import glob

files = glob.glob('crates/franken-engine/src/**/*.rs', recursive=True)

patterns = [
    (r'(serde_json::(?:to_vec|to_string|to_string_pretty)\([^)]+\))\.unwrap_or_default\(\)', r'\1.expect("serialization failed")'),
]

for file in files:
    with open(file, 'r') as f:
        content = f.read()
        
    orig = content
    for pattern, repl in patterns:
        content = re.sub(pattern, repl, content)
        
    if orig != content:
        with open(file, 'w') as f:
            f.write(content)
        print(f"Fixed {file}")
