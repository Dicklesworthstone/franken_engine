fn find_top_level_eq(source: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;

    for (i, ch) in source.char_indices() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => in_quote = Some(ch),
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                // Skip `==` and `=>`
                let next = source.as_bytes().get(i + 1).copied();
                if next != Some(b'=') && next != Some(b'>') {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}
fn main() {
    println!("{:?}", find_top_level_eq("a = b"));
    println!("{:?}", find_top_level_eq("a == b"));
    println!("{:?}", find_top_level_eq("a === b"));
    println!("{:?}", find_top_level_eq("a => b"));
}