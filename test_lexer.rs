fn main() {
    let input = b"\"a\\";
    let len = input.len();
    let mut index = 1;
    let quote = b'"';
    let mut terminated = false;
    while index < len {
        let current = input[index];
        if current == b'\\' {
            index = index.saturating_add(2);
            continue;
        }
        if current == quote {
            index = index.saturating_add(1);
            terminated = true;
            break;
        }
        if current == b'\n' || current == b'\r' {
            break;
        }
        index = index.saturating_add(1);
    }
    println!("len: {}, index: {}", len, index);
}
