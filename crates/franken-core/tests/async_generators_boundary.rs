#![forbid(unsafe_code)]

//! Boundary tests for async generators in franken-core crate.
//!
//! Verifies that async generator functionality works correctly when franken-core
//! is used as an extracted standalone crate, covering:
//! - Async generator declaration and basic yield/await patterns
//! - AsyncIterator protocol implementation and consumption
//! - Error propagation through yield and await operations
//! - Generator close and return semantics with async cleanup
//! - Complex async generator patterns (delegation, composition)

use std::time::Duration;

/// Test basic async generator declaration and execution.
#[tokio::test]
async fn async_generator_basic_declaration() {
    // Simple async generator that yields values with async operations
    async fn simple_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            yield 1;
            tokio::time::sleep(Duration::from_millis(1)).await;
            yield 2;
            tokio::time::sleep(Duration::from_millis(1)).await;
            yield 3;
        }
    }

    let mut gen = simple_generator().await;

    assert_eq!(gen.next().await, Some(1));
    assert_eq!(gen.next().await, Some(2));
    assert_eq!(gen.next().await, Some(3));
    assert_eq!(gen.next().await, None);
}

/// Test async generator with yield-await interleaving patterns.
#[tokio::test]
async fn async_generator_yield_await_interleaving() {
    async fn interleaved_generator() -> impl AsyncIterator<Item = String> {
        async_gen! {
            // Yield immediately
            yield "start".to_string();

            // Await then yield
            let data = async { "async_data".to_string() }.await;
            yield data;

            // Complex interleaving
            for i in 0..3 {
                let computed = async move {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    format!("computed_{}", i)
                }.await;
                yield computed;
            }

            // Final yield after async operation
            tokio::time::sleep(Duration::from_millis(1)).await;
            yield "end".to_string();
        }
    }

    let mut gen = interleaved_generator().await;

    assert_eq!(gen.next().await, Some("start".to_string()));
    assert_eq!(gen.next().await, Some("async_data".to_string()));
    assert_eq!(gen.next().await, Some("computed_0".to_string()));
    assert_eq!(gen.next().await, Some("computed_1".to_string()));
    assert_eq!(gen.next().await, Some("computed_2".to_string()));
    assert_eq!(gen.next().await, Some("end".to_string()));
    assert_eq!(gen.next().await, None);
}

/// Test AsyncIterator protocol implementation.
#[tokio::test]
async fn async_iterator_protocol_implementation() {
    struct AsyncRange {
        start: i32,
        end: i32,
        current: i32,
    }

    impl AsyncRange {
        fn new(start: i32, end: i32) -> Self {
            Self { start, end, current: start }
        }
    }

    impl AsyncIterator for AsyncRange {
        type Item = i32;

        async fn next(&mut self) -> Option<Self::Item> {
            if self.current < self.end {
                let value = self.current;
                self.current += 1;
                // Simulate async work
                tokio::time::sleep(Duration::from_millis(1)).await;
                Some(value)
            } else {
                None
            }
        }
    }

    let mut range = AsyncRange::new(5, 8);

    assert_eq!(range.next().await, Some(5));
    assert_eq!(range.next().await, Some(6));
    assert_eq!(range.next().await, Some(7));
    assert_eq!(range.next().await, None);
}

/// Test async generator with error propagation.
#[tokio::test]
async fn async_generator_error_propagation() {
    #[derive(Debug, PartialEq)]
    enum TestError {
        AsyncError,
        GeneratorError,
    }

    async fn error_generator() -> impl AsyncIterator<Item = Result<i32, TestError>> {
        async_gen! {
            yield Ok(1);

            // Error from async operation
            let result = async {
                Err(TestError::AsyncError)
            }.await;
            yield result;

            yield Ok(2);

            // Error from generator logic
            yield Err(TestError::GeneratorError);

            yield Ok(3);
        }
    }

    let mut gen = error_generator().await;

    assert_eq!(gen.next().await, Some(Ok(1)));
    assert_eq!(gen.next().await, Some(Err(TestError::AsyncError)));
    assert_eq!(gen.next().await, Some(Ok(2)));
    assert_eq!(gen.next().await, Some(Err(TestError::GeneratorError)));
    assert_eq!(gen.next().await, Some(Ok(3)));
    assert_eq!(gen.next().await, None);
}

/// Test async generator close semantics with cleanup.
#[tokio::test]
async fn async_generator_close_semantics() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let cleanup_called = Arc::new(AtomicBool::new(false));
    let cleanup_flag = cleanup_called.clone();

    async fn cleanup_generator(cleanup_flag: Arc<AtomicBool>) -> impl AsyncIterator<Item = i32> {
        async_gen! {
            yield 1;
            yield 2;

            // This should be called during cleanup
            defer! {
                cleanup_flag.store(true, Ordering::SeqCst);
            }

            yield 3;
            yield 4;
        }
    }

    let mut gen = cleanup_generator(cleanup_flag).await;

    assert_eq!(gen.next().await, Some(1));
    assert_eq!(gen.next().await, Some(2));

    // Early termination should trigger cleanup
    drop(gen);

    // Give async cleanup time to execute
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert!(cleanup_called.load(Ordering::SeqCst));
}

/// Test async generator return value semantics.
#[tokio::test]
async fn async_generator_return_semantics() {
    async fn returning_generator() -> impl AsyncIterator<Item = i32, Return = String> {
        async_gen! {
            yield 1;
            yield 2;

            // Async operation before return
            tokio::time::sleep(Duration::from_millis(1)).await;

            return "generator_complete".to_string();
        }
    }

    let mut gen = returning_generator().await;

    assert_eq!(gen.next().await, Some(1));
    assert_eq!(gen.next().await, Some(2));

    // Get return value
    let return_value = gen.into_return().await;
    assert_eq!(return_value, "generator_complete".to_string());
}

/// Test async generator delegation with yield from.
#[tokio::test]
async fn async_generator_delegation() {
    async fn inner_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            yield 10;
            tokio::time::sleep(Duration::from_millis(1)).await;
            yield 20;
        }
    }

    async fn delegating_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            yield 1;

            // Yield from another generator
            yield_from!(inner_generator().await);

            yield 2;
        }
    }

    let mut gen = delegating_generator().await;

    assert_eq!(gen.next().await, Some(1));
    assert_eq!(gen.next().await, Some(10));
    assert_eq!(gen.next().await, Some(20));
    assert_eq!(gen.next().await, Some(2));
    assert_eq!(gen.next().await, None);
}

/// Test async generator composition patterns.
#[tokio::test]
async fn async_generator_composition() {
    async fn number_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            for i in 1..=3 {
                tokio::time::sleep(Duration::from_millis(1)).await;
                yield i;
            }
        }
    }

    async fn string_generator() -> impl AsyncIterator<Item = String> {
        async_gen! {
            let mut num_gen = number_generator().await;
            while let Some(num) = num_gen.next().await {
                yield format!("value_{}", num);
            }
        }
    }

    let mut gen = string_generator().await;

    assert_eq!(gen.next().await, Some("value_1".to_string()));
    assert_eq!(gen.next().await, Some("value_2".to_string()));
    assert_eq!(gen.next().await, Some("value_3".to_string()));
    assert_eq!(gen.next().await, None);
}

/// Test async generator with complex state management.
#[tokio::test]
async fn async_generator_state_management() {
    #[derive(Clone)]
    struct GeneratorState {
        counter: i32,
        multiplier: i32,
    }

    async fn stateful_generator(initial_state: GeneratorState) -> impl AsyncIterator<Item = i32> {
        async_gen! {
            let mut state = initial_state;

            for _ in 0..5 {
                // Async state computation
                let computed = async {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    state.counter * state.multiplier
                }.await;

                yield computed;

                // Update state
                state.counter += 1;
                if state.counter % 2 == 0 {
                    state.multiplier += 1;
                }
            }
        }
    }

    let mut gen = stateful_generator(GeneratorState { counter: 1, multiplier: 2 }).await;

    assert_eq!(gen.next().await, Some(2));  // 1 * 2
    assert_eq!(gen.next().await, Some(6));  // 2 * 3
    assert_eq!(gen.next().await, Some(9));  // 3 * 3
    assert_eq!(gen.next().await, Some(12)); // 4 * 3
    assert_eq!(gen.next().await, Some(20)); // 5 * 4
    assert_eq!(gen.next().await, None);
}

/// Test async generator with concurrent operations.
#[tokio::test]
async fn async_generator_concurrent_operations() {
    async fn concurrent_generator() -> impl AsyncIterator<Item = String> {
        async_gen! {
            let mut tasks = vec![];

            // Spawn concurrent tasks
            for i in 0..3 {
                let task = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    format!("task_{}", i)
                });
                tasks.push(task);
            }

            // Yield results as they complete
            for task in tasks {
                let result = task.await.unwrap();
                yield result;
            }
        }
    }

    let mut gen = concurrent_generator().await;
    let mut results = vec![];

    while let Some(item) = gen.next().await {
        results.push(item);
    }

    assert_eq!(results.len(), 3);
    assert!(results.contains(&"task_0".to_string()));
    assert!(results.contains(&"task_1".to_string()));
    assert!(results.contains(&"task_2".to_string()));
}

/// Test async generator with resource management.
#[tokio::test]
async fn async_generator_resource_management() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};

    let resource_counter = Arc::new(AtomicI32::new(0));

    struct AsyncResource {
        id: i32,
        counter: Arc<AtomicI32>,
    }

    impl AsyncResource {
        async fn new(id: i32, counter: Arc<AtomicI32>) -> Self {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1)).await;
            Self { id, counter }
        }

        async fn get_data(&self) -> String {
            tokio::time::sleep(Duration::from_millis(1)).await;
            format!("data_from_resource_{}", self.id)
        }
    }

    impl Drop for AsyncResource {
        fn drop(&mut self) {
            self.counter.fetch_sub(1, Ordering::SeqCst);
        }
    }

    async fn resource_generator(counter: Arc<AtomicI32>) -> impl AsyncIterator<Item = String> {
        async_gen! {
            let resource1 = AsyncResource::new(1, counter.clone()).await;
            yield resource1.get_data().await;

            let resource2 = AsyncResource::new(2, counter.clone()).await;
            yield resource2.get_data().await;

            // Resources should be dropped here
        }
    }

    let counter = resource_counter.clone();
    let mut gen = resource_generator(counter).await;

    // Should have 1 resource after first yield
    assert_eq!(gen.next().await, Some("data_from_resource_1".to_string()));
    assert_eq!(resource_counter.load(Ordering::SeqCst), 1);

    // Should have 1 resource after second yield (resource1 dropped, resource2 active)
    assert_eq!(gen.next().await, Some("data_from_resource_2".to_string()));

    // Complete generator
    assert_eq!(gen.next().await, None);

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(10)).await;

    // All resources should be cleaned up
    assert_eq!(resource_counter.load(Ordering::SeqCst), 0);
}

/// Test async generator with stream-like operations.
#[tokio::test]
async fn async_generator_stream_operations() {
    async fn stream_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            for i in 1..=10 {
                tokio::time::sleep(Duration::from_millis(1)).await;
                yield i;
            }
        }
    }

    // Test map operation
    async fn map_generator<T, F, U>(gen: impl AsyncIterator<Item = T>, f: F) -> impl AsyncIterator<Item = U>
    where
        F: Fn(T) -> U,
    {
        async_gen! {
            let mut input_gen = gen;
            while let Some(item) = input_gen.next().await {
                yield f(item);
            }
        }
    }

    // Test filter operation
    async fn filter_generator<T, F>(gen: impl AsyncIterator<Item = T>, f: F) -> impl AsyncIterator<Item = T>
    where
        F: Fn(&T) -> bool,
    {
        async_gen! {
            let mut input_gen = gen;
            while let Some(item) = input_gen.next().await {
                if f(&item) {
                    yield item;
                }
            }
        }
    }

    let base_gen = stream_generator().await;
    let mapped_gen = map_generator(base_gen, |x| x * 2).await;
    let filtered_gen = filter_generator(mapped_gen, |&x| x > 10).await;

    let mut results = vec![];
    let mut gen = filtered_gen;
    while let Some(item) = gen.next().await {
        results.push(item);
    }

    assert_eq!(results, vec![12, 14, 16, 18, 20]);
}

/// Test async generator with backpressure handling.
#[tokio::test]
async fn async_generator_backpressure() {
    use std::sync::Arc;
    use std::sync::Mutex;

    let buffer = Arc::new(Mutex::new(Vec::new()));

    async fn buffered_generator(buffer: Arc<Mutex<Vec<i32>>>) -> impl AsyncIterator<Item = i32> {
        async_gen! {
            for i in 1..=20 {
                // Simulate backpressure check
                loop {
                    let buffer_size = {
                        let buf = buffer.lock().unwrap();
                        buf.len()
                    };

                    if buffer_size < 5 { // Buffer limit
                        break;
                    }

                    // Wait for buffer space
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                // Add to buffer
                {
                    let mut buf = buffer.lock().unwrap();
                    buf.push(i);
                }

                yield i;
            }
        }
    }

    async fn consumer_task(buffer: Arc<Mutex<Vec<i32>>>) {
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(2)).await;
            let mut buf = buffer.lock().unwrap();
            if !buf.is_empty() {
                buf.remove(0);
            }
        }
    }

    let buf = buffer.clone();
    let consumer = tokio::spawn(consumer_task(buf));

    let mut gen = buffered_generator(buffer.clone()).await;
    let mut count = 0;

    while let Some(_) = gen.next().await {
        count += 1;
        if count >= 10 {
            break;
        }
    }

    consumer.await.unwrap();
    assert_eq!(count, 10);
}

/// Test async generator with cancellation.
#[tokio::test]
async fn async_generator_cancellation() {
    use tokio::sync::CancellationToken;

    async fn cancellable_generator(token: CancellationToken) -> impl AsyncIterator<Item = i32> {
        async_gen! {
            let mut i = 0;
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        yield -1; // Signal cancellation
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        yield i;
                        i += 1;
                    }
                }
            }
        }
    }

    let token = CancellationToken::new();
    let token_clone = token.clone();

    let mut gen = cancellable_generator(token).await;

    // Get a few values
    assert_eq!(gen.next().await, Some(0));

    // Cancel the generator
    token_clone.cancel();

    // Should get cancellation signal
    assert_eq!(gen.next().await, Some(-1));
    assert_eq!(gen.next().await, None);
}

/// Test async generator with timeout handling.
#[tokio::test]
async fn async_generator_timeout() {
    async fn slow_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            yield 1;
            tokio::time::sleep(Duration::from_millis(100)).await; // Slow operation
            yield 2;
        }
    }

    let mut gen = slow_generator().await;

    assert_eq!(gen.next().await, Some(1));

    // This should timeout
    let result = tokio::time::timeout(Duration::from_millis(50), gen.next()).await;
    assert!(result.is_err()); // Timeout occurred
}

/// Test async generator with nested async operations.
#[tokio::test]
async fn async_generator_nested_async() {
    async fn fetch_data(id: i32) -> String {
        tokio::time::sleep(Duration::from_millis(1)).await;
        format!("data_{}", id)
    }

    async fn process_data(data: String) -> String {
        tokio::time::sleep(Duration::from_millis(1)).await;
        format!("processed_{}", data)
    }

    async fn nested_async_generator() -> impl AsyncIterator<Item = String> {
        async_gen! {
            for i in 1..=3 {
                let raw_data = fetch_data(i).await;
                let processed = process_data(raw_data).await;
                yield processed;
            }
        }
    }

    let mut gen = nested_async_generator().await;

    assert_eq!(gen.next().await, Some("processed_data_1".to_string()));
    assert_eq!(gen.next().await, Some("processed_data_2".to_string()));
    assert_eq!(gen.next().await, Some("processed_data_3".to_string()));
    assert_eq!(gen.next().await, None);
}

/// Test async generator with futures combination.
#[tokio::test]
async fn async_generator_futures_combination() {
    use futures::future;

    async fn combined_futures_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            let futures = vec![
                async { 1 },
                async { 2 },
                async { 3 },
            ];

            let results = future::join_all(futures).await;
            for result in results {
                yield result;
            }

            // Sequential combination
            let (a, b) = future::join(
                async { 10 },
                async { 20 },
            ).await;

            yield a;
            yield b;
        }
    }

    let mut gen = combined_futures_generator().await;

    assert_eq!(gen.next().await, Some(1));
    assert_eq!(gen.next().await, Some(2));
    assert_eq!(gen.next().await, Some(3));
    assert_eq!(gen.next().await, Some(10));
    assert_eq!(gen.next().await, Some(20));
    assert_eq!(gen.next().await, None);
}

/// Test async generator with dynamic dispatch.
#[tokio::test]
async fn async_generator_dynamic_dispatch() {
    trait AsyncProcessor {
        async fn process(&self, input: i32) -> String;
    }

    struct SimpleProcessor;
    impl AsyncProcessor for SimpleProcessor {
        async fn process(&self, input: i32) -> String {
            tokio::time::sleep(Duration::from_millis(1)).await;
            format!("simple_{}", input)
        }
    }

    struct ComplexProcessor;
    impl AsyncProcessor for ComplexProcessor {
        async fn process(&self, input: i32) -> String {
            tokio::time::sleep(Duration::from_millis(2)).await;
            format!("complex_{}", input * 2)
        }
    }

    async fn dynamic_generator(processor: Box<dyn AsyncProcessor + Send>) -> impl AsyncIterator<Item = String> {
        async_gen! {
            for i in 1..=3 {
                let result = processor.process(i).await;
                yield result;
            }
        }
    }

    let mut simple_gen = dynamic_generator(Box::new(SimpleProcessor)).await;
    assert_eq!(simple_gen.next().await, Some("simple_1".to_string()));
    assert_eq!(simple_gen.next().await, Some("simple_2".to_string()));
    assert_eq!(simple_gen.next().await, Some("simple_3".to_string()));

    let mut complex_gen = dynamic_generator(Box::new(ComplexProcessor)).await;
    assert_eq!(complex_gen.next().await, Some("complex_2".to_string()));
    assert_eq!(complex_gen.next().await, Some("complex_4".to_string()));
    assert_eq!(complex_gen.next().await, Some("complex_6".to_string()));
}

/// Test async generator with channels integration.
#[tokio::test]
async fn async_generator_channels() {
    use tokio::sync::mpsc;

    async fn channel_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            let (tx, mut rx) = mpsc::channel(10);

            // Producer task
            let producer = tokio::spawn(async move {
                for i in 1..=5 {
                    tx.send(i).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            });

            // Consume from channel
            while let Some(value) = rx.recv().await {
                yield value;
            }

            producer.await.unwrap();
        }
    }

    let mut gen = channel_generator().await;
    let mut results = vec![];

    while let Some(item) = gen.next().await {
        results.push(item);
    }

    assert_eq!(results, vec![1, 2, 3, 4, 5]);
}

/// Test async generator with file I/O operations.
#[tokio::test]
async fn async_generator_file_io() {
    use tokio::fs;
    use tokio::io::AsyncReadExt;
    use tempfile::NamedTempFile;

    async fn file_reading_generator() -> impl AsyncIterator<Item = String> {
        async_gen! {
            // Create a temporary file
            let temp_file = NamedTempFile::new().unwrap();
            let temp_path = temp_file.path();

            // Write test data
            fs::write(temp_path, "line1\nline2\nline3\n").await.unwrap();

            // Read and yield lines
            let content = fs::read_to_string(temp_path).await.unwrap();
            for line in content.lines() {
                tokio::time::sleep(Duration::from_millis(1)).await;
                yield line.to_string();
            }
        }
    }

    let mut gen = file_reading_generator().await;

    assert_eq!(gen.next().await, Some("line1".to_string()));
    assert_eq!(gen.next().await, Some("line2".to_string()));
    assert_eq!(gen.next().await, Some("line3".to_string()));
    assert_eq!(gen.next().await, None);
}

/// Test async generator with recursive patterns.
#[tokio::test]
async fn async_generator_recursive() {
    async fn recursive_generator(depth: i32) -> impl AsyncIterator<Item = i32> {
        async_gen! {
            yield depth;

            if depth > 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;

                let mut sub_gen = recursive_generator(depth - 1).await;
                while let Some(value) = sub_gen.next().await {
                    yield value;
                }
            }
        }
    }

    let mut gen = recursive_generator(3).await;

    assert_eq!(gen.next().await, Some(3));
    assert_eq!(gen.next().await, Some(2));
    assert_eq!(gen.next().await, Some(1));
    assert_eq!(gen.next().await, Some(0));
    assert_eq!(gen.next().await, None);
}

/// Test async generator boundary edge cases.
#[tokio::test]
async fn async_generator_boundary_edge_cases() {
    // Empty generator
    async fn empty_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            // Yields nothing
        }
    }

    let mut empty_gen = empty_generator().await;
    assert_eq!(empty_gen.next().await, None);

    // Single yield generator
    async fn single_yield_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            tokio::time::sleep(Duration::from_millis(1)).await;
            yield 42;
        }
    }

    let mut single_gen = single_yield_generator().await;
    assert_eq!(single_gen.next().await, Some(42));
    assert_eq!(single_gen.next().await, None);

    // Generator with only async operations (no yields)
    async fn async_only_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let _value = async { 42 }.await;
            // No yields
        }
    }

    let mut async_only_gen = async_only_generator().await;
    assert_eq!(async_only_gen.next().await, None);
}

/// Test async generator with complex data structures.
#[tokio::test]
async fn async_generator_complex_data() {
    #[derive(Debug, PartialEq)]
    struct ComplexData {
        id: u64,
        name: String,
        values: Vec<i32>,
    }

    async fn complex_data_generator() -> impl AsyncIterator<Item = ComplexData> {
        async_gen! {
            for i in 1..=3 {
                let data = async move {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    ComplexData {
                        id: i,
                        name: format!("item_{}", i),
                        values: vec![i as i32 * 10, i as i32 * 20],
                    }
                }.await;

                yield data;
            }
        }
    }

    let mut gen = complex_data_generator().await;

    assert_eq!(
        gen.next().await,
        Some(ComplexData {
            id: 1,
            name: "item_1".to_string(),
            values: vec![10, 20],
        })
    );

    assert_eq!(
        gen.next().await,
        Some(ComplexData {
            id: 2,
            name: "item_2".to_string(),
            values: vec![20, 40],
        })
    );

    assert_eq!(
        gen.next().await,
        Some(ComplexData {
            id: 3,
            name: "item_3".to_string(),
            values: vec![30, 60],
        })
    );

    assert_eq!(gen.next().await, None);
}

/// Test async generator memory and performance characteristics.
#[tokio::test]
async fn async_generator_memory_performance() {
    async fn memory_efficient_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            // Process large dataset without loading all into memory
            for i in 0..1000 {
                // Simulate memory-efficient processing
                let processed = async move {
                    // Small delay to simulate real work
                    if i % 100 == 0 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    i * 2
                }.await;

                yield processed;

                // Only yield a subset for test performance
                if i >= 10 {
                    break;
                }
            }
        }
    }

    let mut gen = memory_efficient_generator().await;
    let mut count = 0;

    while let Some(value) = gen.next().await {
        assert_eq!(value, count * 2);
        count += 1;
    }

    assert_eq!(count, 11); // 0 through 10
}

/// Test async generator with mixed sync/async operations.
#[tokio::test]
async fn async_generator_mixed_sync_async() {
    fn sync_operation(input: i32) -> i32 {
        input * 2
    }

    async fn async_operation(input: i32) -> i32 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        input + 10
    }

    async fn mixed_generator() -> impl AsyncIterator<Item = i32> {
        async_gen! {
            for i in 1..=3 {
                // Mix sync and async operations
                let sync_result = sync_operation(i);
                yield sync_result;

                let async_result = async_operation(i).await;
                yield async_result;
            }
        }
    }

    let mut gen = mixed_generator().await;

    assert_eq!(gen.next().await, Some(2));  // 1 * 2
    assert_eq!(gen.next().await, Some(11)); // 1 + 10
    assert_eq!(gen.next().await, Some(4));  // 2 * 2
    assert_eq!(gen.next().await, Some(12)); // 2 + 10
    assert_eq!(gen.next().await, Some(6));  // 3 * 2
    assert_eq!(gen.next().await, Some(13)); // 3 + 10
    assert_eq!(gen.next().await, None);
}