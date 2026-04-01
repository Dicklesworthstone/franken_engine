fn integer_sqrt_u64(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x / 2) + (x % 2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn integer_sqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x / 2) + (x % 2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[test]
fn test_sqrt_max() {
    assert_eq!(integer_sqrt_u64(u64::MAX), 4294967295);
    assert_eq!(integer_sqrt_i128(i128::MAX), 13043817825332782212);
}
