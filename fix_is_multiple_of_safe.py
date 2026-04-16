import re
import glob

def fix_all():
    count = 0
    for filepath in glob.glob('crates/**/*.rs', recursive=True):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            continue

        original = content
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            while '.is_multiple_of(' in line:
                idx = line.find('.is_multiple_of(')
                arg_start = idx + len('.is_multiple_of(')
                arg_end = line.find(')', arg_start)
                arg = line[arg_start:arg_end]
                
                recv_start = idx - 1
                depth = 0
                while recv_start >= 0:
                    c = line[recv_start]
                    if c == ')':
                        depth += 1
                    elif c == '(':
                        depth -= 1
                        if depth < 0:
                            recv_start += 1
                            break
                    elif c in ' ]}=' or c in '+-*/&|!<>,':
                        if depth == 0:
                            recv_start += 1
                            break
                    recv_start -= 1
                
                if recv_start < 0:
                    recv_start = 0
                    
                recv = line[recv_start:idx].strip()
                new_expr = f'({recv} % {arg} == 0)'
                
                line = line[:recv_start] + new_expr + line[arg_end+1:]
                
                line = line.replace(f'!({recv} % {arg} == 0)', f'({recv} % {arg} != 0)')
                line = line.replace(f'if ({recv} % {arg} == 0)', f'if {recv} % {arg} == 0')
                line = line.replace(f'if ({recv} % {arg} != 0)', f'if {recv} % {arg} != 0')
                
            new_lines.append(line)
                
        content = '\n'.join(new_lines)
        if content != original:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Fixed {filepath}")
            count += 1
            
    print(f"Total {count} files fixed")

fix_all()
