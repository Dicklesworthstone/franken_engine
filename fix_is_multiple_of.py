import re
import glob
import sys

def fix_is_multiple_of():
    count = 0
    # Match an expression followed by .is_multiple_of(Y).
    # To properly match nested parens, it's easier to just match from the back:
    # Find .is_multiple_of(
    # Then walk backwards to find the start of the expression.
    
    for filepath in glob.glob('crates/**/*.rs', recursive=True):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            continue
            
        original = content
        
        while '.is_multiple_of(' in content:
            idx = content.find('.is_multiple_of(')
            
            # Find the end of the arguments
            arg_start = idx + len('.is_multiple_of(')
            arg_end = arg_start
            paren_depth = 1
            for i in range(arg_start, len(content)):
                if content[i] == '(':
                    paren_depth += 1
                elif content[i] == ')':
                    paren_depth -= 1
                    if paren_depth == 0:
                        arg_end = i
                        break
            
            arg = content[arg_start:arg_end]
            
            # Find the start of the receiver
            # It could be `i`, `byte(data, 4)`, `(self.log_entries.len() as u64)`
            recv_start = idx - 1
            if recv_start < 0:
                break
                
            # Basic backward paren matching and word matching
            depth = 0
            while recv_start >= 0:
                c = content[recv_start]
                if c == ')':
                    depth += 1
                elif c == '(':
                    depth -= 1
                    if depth < 0:
                        recv_start += 1
                        break
                elif c in ' ]}':
                    if depth == 0:
                        recv_start += 1
                        break
                # if c is an operator like = or + or - or ! or < or >
                elif c in '=*+/&|!:<>,-' and depth == 0:
                    recv_start += 1
                    break
                recv_start -= 1
                
            if recv_start < 0:
                recv_start = 0
                
            recv = content[recv_start:idx].strip()
            
            # Replace
            new_expr = f'({recv} % {arg} == 0)'
            # Some things like `if !hex.len().is_multiple_of(2)`:
            # recv is `hex.len()`
            # arg is `2`
            # new_expr: `(hex.len() % 2 == 0)`
            
            content = content[:recv_start] + new_expr + content[arg_end+1:]
            
        if content != original:
            # Let's fix cases where it generates `if (!(...))` or `!((...))` which isn't idiomatic, but works.
            # Rust actually allows `if !(a % b == 0)` or `if a % b != 0`.
            # Let's do a simple string replacement for `!(X % Y == 0)` -> `X % Y != 0`
            content = re.sub(r'!\(([^%]+)\s*%\s*([^=]+)\s*==\s*0\)', r'(\1 % \2 != 0)', content)
            
            # Remove redundant outer parens if it's in an if statement
            content = re.sub(r'if \(([^%]+)\s*%\s*([^=]+)\s*==\s*0\)', r'if \1 % \2 == 0', content)
            content = re.sub(r'if \(([^%]+)\s*%\s*([^=]+)\s*!=\s*0\)', r'if \1 % \2 != 0', content)
            
            with open(filepath, 'w') as f:
                f.write(content)
            count += 1
            print(f'Fixed {filepath}')

    print(f'Fixed {count} files')

fix_is_multiple_of()
