import re
import glob

def fix_unwrap_or():
    count = 0
    for filepath in glob.glob('crates/**/*.rs', recursive=True):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            continue

        original = content
        
        # Replace .expect("capacity exceeded u32::MAX") with .unwrap_or(u32::MAX)
        content = re.sub(
            r'\.expect\("capacity exceeded u32::MAX"\)',
            r'.unwrap_or(u32::MAX)',
            content
        )
        
        # Also handle .expect("capacity exceeded u16::MAX") if any
        content = re.sub(
            r'\.expect\("capacity exceeded u16::MAX"\)',
            r'.unwrap_or(u16::MAX)',
            content
        )
        
        if content != original:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Fixed {filepath}")
            count += 1

    print(f"Total {count} files fixed")

fix_unwrap_or()
