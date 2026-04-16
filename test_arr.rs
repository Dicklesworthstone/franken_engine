fn split_top_level_commas(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    let mut parts = Vec::new();
    let mut start = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                in_quote = Some(b);
                continue;
            }
            b'(' => {
                depth_paren += 1;
                continue;
            }
            b')' => {
                depth_paren -= 1;
                continue;
            }
            b'[' => {
                depth_bracket += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
                continue;
            }
            b'{' => {
                depth_brace += 1;
                continue;
            }
            b'}' => {
                depth_brace -= 1;
                continue;
            }
            _ => {}
        }
        if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && b == b',' {
            parts.push(&s[start..i]);
            start = i + 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

fn parse_array_literal(inner: &str) -> Vec<Option<&str>> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let parts = split_top_level_commas(trimmed);
    let mut elements = Vec::new();
    for part in &parts {
        let p = part.trim();
        if p.is_empty() {
            elements.push(None);
        } else {
            elements.push(Some(p));
        }
    }
    elements
}

fn main() {
    println!("{:?}", parse_array_literal("1, 2, "));
}
