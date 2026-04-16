import glob

def find_unwraps_outside_tests():
    total = 0
    for filepath in glob.glob('crates/franken-engine/src/**/*.rs', recursive=True):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            continue
            
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
        
        for line_num, line in enumerate(content.split('\n')):
            stripped = line.strip()
            if '.unwrap()' in stripped or '.expect(' in stripped:
                if 'assert' not in stripped and '#[test]' not in stripped and '#[cfg(test)]' not in stripped:
                    # check if the line appears in clean_str (approximate, simple substring match)
                    if stripped in clean_str:
                        print(f'{filepath}:{line_num+1}: {stripped}')
                        total += 1
                    
    print(f'Total outside tests: {total}')

find_unwraps_outside_tests()
