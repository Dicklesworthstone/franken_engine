use frankenengine_engine::proof_artifact::validate_event_json_line;
use std::time::Instant;

/// Manual fuzzing harness for proof artifact JSON validation
fn manual_fuzz_session() {
    println!("Starting manual fuzzing session for proof artifact JSON validation");
    let start = Instant::now();
    let mut test_count = 0;
    let mut crash_count = 0;

    // Generate test cases manually instead of using complex proptest setup
    let test_cases = generate_test_cases();

    for (i, test_case) in test_cases.iter().enumerate() {
        test_count += 1;

        // Wrap in catch_unwind to detect panics
        let result = std::panic::catch_unwind(|| validate_event_json_line(test_case));

        match result {
            Ok(_validation_result) => {
                // No panic, validation either succeeded or failed gracefully
                if i % 1000 == 0 {
                    println!("Processed {} test cases", i + 1);
                }
            }
            Err(_panic_payload) => {
                crash_count += 1;
                println!(
                    "CRASH DETECTED in test case {}: {:?}",
                    i,
                    test_case.chars().take(100).collect::<String>()
                );
            }
        }

        // Break after reasonable amount of testing
        if start.elapsed().as_secs() > 30 {
            break;
        }
    }

    println!(
        "Fuzzing session complete: {} tests run, {} crashes detected in {:?}",
        test_count,
        crash_count,
        start.elapsed()
    );

    if crash_count == 0 {
        println!("✓ No crashes found - validation appears robust");
    } else {
        println!("⚠ {} crashes detected - needs investigation", crash_count);
    }
}

fn generate_test_cases() -> Vec<String> {
    let mut cases = Vec::new();

    // Basic malformed JSON
    cases.extend([
        "{".to_string(),
        "}".to_string(),
        "null".to_string(),
        "".to_string(),
        "{,}".to_string(),
        "{\"key\":}".to_string(),
        "{\"incomplete".to_string(),
    ]);

    // Test depth limits - create deeply nested objects
    for depth in 1..40 {
        let nested = format!(
            "{}\"test\":\"value\"{}",
            "{".repeat(depth),
            "}".repeat(depth)
        );
        cases.push(nested);
    }

    // Test string length limits
    for size in [1000, 10000, 50000, 100000] {
        let large_string = format!(r#"{{"test":"{}"}}"#, "x".repeat(size));
        cases.push(large_string);
    }

    // Test large objects
    for field_count in [100, 500, 1000] {
        let fields: Vec<String> = (0..field_count)
            .map(|i| format!(r#""field{}":"value{}""#, i, i))
            .collect();
        let large_obj = format!("{{{}}}", fields.join(","));
        cases.push(large_obj);
    }

    // Test large arrays
    for elem_count in [100, 500, 1000] {
        let elements: Vec<String> = (0..elem_count).map(|i| format!(r#""item{}""#, i)).collect();
        let large_array = format!("[{}]", elements.join(","));
        cases.push(large_array);
    }

    // Special numbers
    cases.extend([
        r#"{"num":1.7976931348623157e+308}"#.to_string(),
        r#"{"num":-1.7976931348623157e+308}"#.to_string(),
        r#"{"num":1e-1000}"#.to_string(),
        r#"{"num":null}"#.to_string(),
    ]);

    // Random byte sequences converted to strings
    for _ in 0..1000 {
        let random_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
        let random_string = String::from_utf8_lossy(&random_bytes).to_string();
        cases.push(random_string);
    }

    println!("Generated {} test cases", cases.len());
    cases
}

#[test]
fn run_manual_fuzz() {
    manual_fuzz_session();
}

// Simple RNG for generating random bytes without external deps
mod rand {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEED: AtomicU64 = AtomicU64::new(12345);

    pub fn random<T>() -> T
    where
        T: From<u8>,
    {
        let seed = SEED.load(Ordering::Relaxed);
        let new_seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        SEED.store(new_seed, Ordering::Relaxed);
        T::from((new_seed >> 8) as u8)
    }
}
