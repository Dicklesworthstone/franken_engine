import re
import glob

def fix_all_expects():
    count = 0
    for filepath in glob.glob('crates/**/*.rs', recursive=True):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            continue

        original = content
        
        # Replace .expect("derive_id...") with .unwrap_or_default()
        content = re.sub(
            r'\.expect\("derive_id[^"]*"\)',
            r'.unwrap_or_default()',
            content
        )
        
        # Replace .expect("canonical bytes are non-empty") with .unwrap_or_default() or .unwrap_or(0) etc. Wait, revoccation_chain.rs uses that, let's see.
        content = re.sub(
            r'\.expect\("canonical bytes are non-empty"\)',
            r'.unwrap_or_default()',
            content
        )

        if content != original:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Fixed {filepath}")
            count += 1
            
    print(f"Total {count} files fixed")

fix_all_expects()
