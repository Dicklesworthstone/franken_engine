import re
import glob

files = glob.glob('crates/franken-engine/src/**/*.rs', recursive=True)

patterns = [
    (r':\s*u64\s*=\s*([^.]+(?:\.[^.]+)*?)\.iter\(\)\.sum\(\);', r': u64 = \1.iter().fold(0u64, |acc, &x| acc.saturating_add(x));'),
    (r':\s*i64\s*=\s*([^.]+(?:\.[^.]+)*?)\.iter\(\)\.sum\(\);', r': i64 = \1.iter().fold(0i64, |acc, &x| acc.saturating_add(x));'),
    (r':\s*u32\s*=\s*([^.]+(?:\.[^.]+)*?)\.iter\(\)\.sum\(\);', r': u32 = \1.iter().fold(0u32, |acc, &x| acc.saturating_add(x));'),
    (r':\s*usize\s*=\s*([^.]+(?:\.[^.]+)*?)\.iter\(\)\.sum\(\);', r': usize = \1.iter().fold(0usize, |acc, &x| acc.saturating_add(x));')
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
