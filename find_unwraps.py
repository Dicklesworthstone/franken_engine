import glob

def find_unwraps_outside_tests():
    total = 0
    for filepath in glob.glob('crates/franken-engine/src/**/*.rs', recursive=True):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            continue
            
        # Basic lexer to skip over #[cfg(test)] modules and functions
        i = 0
        in_test_attr = False
        brace_depth = 0
        test_depth = -1
        
        lines = content.split('\n')
        
        for idx, line in enumerate(lines):
            stripped = line.strip()
            
            # Check for test attributes
            if stripped.startswith('#[cfg(test)]') or stripped.startswith('#[test]'):
                in_test_attr = True
                continue
                
            # If we saw an attribute, we wait for the next '{' to mark the depth
            # Note: The '{' could be on the same line as 'mod test' or next line.
            
            open_braces = line.count('{')
            close_braces = line.count('}')
            
            if in_test_attr and '{' in line:
                in_test_attr = False
                # The depth *inside* the test block is brace_depth + open_braces ... up to the first {
                # Actually, simple trick:
                pass
                
        # Let's just do a simpler brace matcher on characters
        i = 0
        depth = 0
        test_depths = []
        clean_content = []
        
        while i < len(content):
            # String literals
            if content[i] == '"' and (i == 0 or content[i-1] != '\\'):
                clean_content.append(content[i])
                i += 1
                while i < len(content):
                    clean_content.append(content[i])
                    if content[i] == '"' and content[i-1] != '\\':
                        i += 1
                        break
                    i += 1
                continue
                
            # Line comments
            if content[i:i+2] == '//':
                while i < len(content) and content[i] != '\n':
                    clean_content.append(content[i])
                    i += 1
                continue
                
            # Block comments
            if content[i:i+2] == '/*':
                while i < len(content) and content[i:i+2] != '*/':
                    clean_content.append(content[i])
                    i += 1
                if i < len(content):
                    clean_content.append('*')
                    clean_content.append('/')
                    i += 2
                continue
                
            if content[i] == '{':
                depth += 1
                if not test_depths:
                    clean_content.append('{')
            elif content[i] == '}':
                if test_depths and depth == test_depths[-1]:
                    test_depths.pop()
                elif not test_depths:
                    clean_content.append('}')
                depth -= 1
            else:
                # Check for #[cfg(test)] or #[test]
                if not test_depths and content[i:i+12] == '#[cfg(test)]':
                    test_depths.append(depth + 1)
                    i += 12
                    continue
                elif not test_depths and content[i:i+7] == '#[test]':
                    test_depths.append(depth + 1)
                    i += 7
                    continue
                    
                if not test_depths:
                    clean_content.append(content[i])
            i += 1
            
        clean_str = ''.join(clean_content)
        
        for line in clean_str.split('\n'):
            if '.unwrap()' in line or '.expect(' in line:
                if 'assert' not in line:
                    print(f'{filepath}: {line.strip()}')
                    total += 1
                    
    print(f'Total outside tests: {total}')

find_unwraps_outside_tests()
