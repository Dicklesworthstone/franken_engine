import re
import glob

files = glob.glob('crates/franken-engine/src/**/*.rs', recursive=True)

patterns = [
    (r'fn isqrt_millionths\((\w+):\s*i64\)\s*->\s*i64\s*\{\s*if\s*\1\s*<=\s*0\s*\{\s*return 0;\s*\}\s*let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(x \+ 1\) / 2;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\s*\}', r'fn isqrt_millionths(\1: i64) -> i64 {\n    if \1 <= 0 { 0 } else { \1.unsigned_abs().isqrt() as i64 }\n}'),
    
    (r'fn isqrt_millionths\((\w+):\s*i64\)\s*->\s*i64\s*\{\s*if\s*\1\s*<=\s*0\s*\{\s*return 1;\s*\}\s*(?://.*\n\s*)*let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(x \+ 1\) / 2;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\.max\(1\)\s*\}', r'fn isqrt_millionths(\1: i64) -> i64 {\n    if \1 <= 0 { 1 } else { (\1.unsigned_abs().isqrt() as i64).max(1) }\n}'),

    (r'fn isqrt_i64\((\w+):\s*i64\)\s*->\s*i64\s*\{\s*if\s*\1\s*<=\s*0\s*\{\s*return 0;\s*\}\s*let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(x \+ 1\) / 2;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\s*\}', r'fn isqrt_i64(\1: i64) -> i64 {\n    if \1 <= 0 { 0 } else { \1.unsigned_abs().isqrt() as i64 }\n}'),
    
    (r'fn isqrt\((\w+):\s*i64\)\s*->\s*i64\s*\{\s*if\s*\1\s*<=\s*0\s*\{\s*return 0;\s*\}\s*let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(x \+ 1\) / 2;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\s*\}', r'fn isqrt(\1: i64) -> i64 {\n    if \1 <= 0 { 0 } else { \1.unsigned_abs().isqrt() as i64 }\n}'),

    (r'fn isqrt\((\w+):\s*u64\)\s*->\s*u64\s*\{\s*if\s*\1\s*==\s*0\s*\{\s*return 0;\s*\}\s*let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(?x(?:\.div_ceil\(2\)|\s*\+\s*1\)\s*/\s*2)\)?;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\s*\}', r'fn isqrt(\1: u64) -> u64 {\n    \1.isqrt()\n}'),

    (r'fn isqrt\((\w+):\s*u128\)\s*->\s*u128\s*\{\s*if\s*\1\s*==\s*0\s*\{\s*return 0;\s*\}\s*let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(x \+ 1\) / 2;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\s*\}', r'fn isqrt(\1: u128) -> u128 {\n    \1.isqrt()\n}'),

    (r'fn isqrt_i128\((\w+):\s*i128\)\s*->\s*i128\s*\{\s*if\s*\1\s*<=\s*0\s*\{\s*return 0;\s*\}\s*(?:if\s*\1\s*==\s*1\s*\{\s*return 1;\s*\}\s*)?let mut x = \1;\s*(?:#\[allow\(clippy::manual_div_ceil\)\]\s*)?let mut y = \(x \+ 1\) / 2;\s*while y < x \{\s*x = y;\s*y = \(x \+ \1 / x\) / 2;\s*\}\s*x\s*\}', r'fn isqrt_i128(\1: i128) -> i128 {\n    if \1 <= 0 { 0 } else { \1.unsigned_abs().isqrt() as i128 }\n}'),
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
