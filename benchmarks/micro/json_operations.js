// Micro-Benchmark 8: JSON Operations
// Tests performance of JSON.parse and JSON.stringify operations

function benchmarkJsonOperations() {
    console.log("Starting JSON Operations benchmark...");
    const startTime = Date.now();

    const iterations = 1000; // 1K roundtrips
    const arraySize = 1000; // 1K-element array

    // Generate test data structures
    const simpleArray = Array.from({length: arraySize}, (_, i) => i);

    const objectArray = Array.from({length: arraySize}, (_, i) => ({
        id: i,
        name: `Item ${i}`,
        value: i * 2.5,
        active: i % 2 === 0,
        metadata: {
            created: `2024-01-${(i % 28) + 1}`,
            tags: [`tag${i % 10}`, `category${i % 5}`]
        }
    }));

    const complexObject = {
        version: "1.0.0",
        timestamp: "2024-01-01T00:00:00Z",
        data: objectArray,
        statistics: {
            total: arraySize,
            active: objectArray.filter(x => x.active).length,
            average: objectArray.reduce((sum, x) => sum + x.value, 0) / arraySize
        },
        config: {
            settings: {
                timeout: 5000,
                retries: 3,
                cache: true
            },
            features: {
                logging: true,
                debugging: false,
                monitoring: true
            }
        }
    };

    const nestedObject = {
        level1: {
            level2: {
                level3: {
                    level4: {
                        level5: {
                            data: Array.from({length: 100}, (_, i) => ({
                                id: i,
                                nested: {
                                    values: Array.from({length: 10}, (_, j) => j * i),
                                    metadata: {
                                        type: 'nested',
                                        depth: 5,
                                        index: i
                                    }
                                }
                            }))
                        }
                    }
                }
            }
        }
    };

    // Simple array JSON roundtrip
    const simpleStart = Date.now();
    let simpleResults = [];
    for (let i = 0; i < iterations; i++) {
        const json = JSON.stringify(simpleArray);
        const parsed = JSON.parse(json);
        simpleResults.push(parsed);
    }
    const simpleTime = Date.now() - simpleStart;

    // Object array JSON roundtrip
    const objectStart = Date.now();
    let objectResults = [];
    for (let i = 0; i < iterations; i++) {
        const json = JSON.stringify(objectArray);
        const parsed = JSON.parse(json);
        objectResults.push(parsed);
    }
    const objectTime = Date.now() - objectStart;

    // Complex object JSON roundtrip
    const complexStart = Date.now();
    let complexResults = [];
    for (let i = 0; i < iterations / 2; i++) { // Fewer iterations for complex objects
        const json = JSON.stringify(complexObject);
        const parsed = JSON.parse(json);
        complexResults.push(parsed);
    }
    const complexTime = Date.now() - complexStart;

    // Nested object JSON roundtrip
    const nestedStart = Date.now();
    let nestedResults = [];
    for (let i = 0; i < iterations / 10; i++) { // Even fewer for deeply nested
        const json = JSON.stringify(nestedObject);
        const parsed = JSON.parse(json);
        nestedResults.push(parsed);
    }
    const nestedTime = Date.now() - nestedStart;

    // JSON.stringify only benchmark
    const stringifyStart = Date.now();
    const stringifyResults = [];
    for (let i = 0; i < iterations * 2; i++) {
        const json1 = JSON.stringify(simpleArray);
        const json2 = JSON.stringify({id: i, value: i * 2});
        stringifyResults.push(json1.length + json2.length);
    }
    const stringifyTime = Date.now() - stringifyStart;

    // JSON.parse only benchmark
    const parseStart = Date.now();
    const jsonStrings = [];
    // Pre-generate JSON strings
    for (let i = 0; i < 100; i++) {
        jsonStrings.push(JSON.stringify({
            id: i,
            data: Array.from({length: 50}, (_, j) => j + i),
            metadata: {
                index: i,
                timestamp: Date.now(),
                active: i % 2 === 0
            }
        }));
    }

    const parseResults = [];
    for (let i = 0; i < iterations * 2; i++) {
        const jsonString = jsonStrings[i % jsonStrings.length];
        const parsed = JSON.parse(jsonString);
        parseResults.push(parsed);
    }
    const parseTime = Date.now() - parseStart;

    // JSON with various data types
    const typesStart = Date.now();
    const typesObject = {
        string: "Hello, World!",
        number: 42.5,
        integer: 1234,
        boolean: true,
        nullValue: null,
        array: [1, 2, 3, "four", true, null],
        nested: {
            date: "2024-01-01T00:00:00Z",
            decimal: 3.14159,
            negative: -273.15,
            scientific: 1.23e-4,
            unicode: "Hello 世界! 🌍"
        }
    };

    let typesResults = [];
    for (let i = 0; i < iterations * 2; i++) {
        const json = JSON.stringify(typesObject);
        const parsed = JSON.parse(json);
        typesResults.push(parsed);
    }
    const typesTime = Date.now() - typesStart;

    // Large string handling
    const largeStringStart = Date.now();
    const largeString = "x".repeat(10000); // 10KB string
    const largeStringObject = {
        data: largeString,
        chunks: Array.from({length: 10}, (_, i) => largeString.substring(i * 1000, (i + 1) * 1000))
    };

    let largeStringResults = [];
    for (let i = 0; i < iterations / 10; i++) {
        const json = JSON.stringify(largeStringObject);
        const parsed = JSON.parse(json);
        largeStringResults.push(parsed);
    }
    const largeStringTime = Date.now() - largeStringStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    // Calculate average JSON sizes
    const sampleSimpleJson = JSON.stringify(simpleArray);
    const sampleObjectJson = JSON.stringify(objectArray);
    const sampleComplexJson = JSON.stringify(complexObject);

    console.log("JSON Operations benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Simple Array: ${simpleTime}ms (${iterations} roundtrips, ${sampleSimpleJson.length} chars)`);
    console.log(`Object Array: ${objectTime}ms (${iterations} roundtrips, ${sampleObjectJson.length} chars)`);
    console.log(`Complex Object: ${complexTime}ms (${iterations / 2} roundtrips, ${sampleComplexJson.length} chars)`);
    console.log(`Nested Object: ${nestedTime}ms (${iterations / 10} roundtrips)`);
    console.log(`Stringify Only: ${stringifyTime}ms (${iterations * 2} operations)`);
    console.log(`Parse Only: ${parseTime}ms (${iterations * 2} operations)`);
    console.log(`Various Types: ${typesTime}ms (${iterations * 2} roundtrips)`);
    console.log(`Large Strings: ${largeStringTime}ms (${iterations / 10} roundtrips)`);
    console.log(`Results count: simple=${simpleResults.length}, object=${objectResults.length}, complex=${complexResults.length}, nested=${nestedResults.length}`);

    return {
        totalTime,
        iterations,
        arraySize,
        operations: {
            simpleRoundtrip: iterations,
            objectRoundtrip: iterations,
            complexRoundtrip: iterations / 2,
            nestedRoundtrip: iterations / 10,
            stringifyOnly: iterations * 2,
            parseOnly: iterations * 2,
            typesRoundtrip: iterations * 2,
            largeStringRoundtrip: iterations / 10
        },
        times: {
            simpleRoundtrip: simpleTime,
            objectRoundtrip: objectTime,
            complexRoundtrip: complexTime,
            nestedRoundtrip: nestedTime,
            stringifyOnly: stringifyTime,
            parseOnly: parseTime,
            typesRoundtrip: typesTime,
            largeStringRoundtrip: largeStringTime
        },
        results: {
            simpleCount: simpleResults.length,
            objectCount: objectResults.length,
            complexCount: complexResults.length,
            nestedCount: nestedResults.length,
            stringifyCount: stringifyResults.length,
            parseCount: parseResults.length,
            typesCount: typesResults.length,
            largeStringCount: largeStringResults.length
        },
        jsonSizes: {
            simpleArray: sampleSimpleJson.length,
            objectArray: sampleObjectJson.length,
            complexObject: sampleComplexJson.length
        },
        opsPerSecond: {
            simpleRoundtrip: Math.round(iterations / (simpleTime / 1000)),
            objectRoundtrip: Math.round(iterations / (objectTime / 1000)),
            complexRoundtrip: Math.round((iterations / 2) / (complexTime / 1000)),
            nestedRoundtrip: Math.round((iterations / 10) / (nestedTime / 1000)),
            stringifyOnly: Math.round((iterations * 2) / (stringifyTime / 1000)),
            parseOnly: Math.round((iterations * 2) / (parseTime / 1000)),
            typesRoundtrip: Math.round((iterations * 2) / (typesTime / 1000)),
            largeStringRoundtrip: Math.round((iterations / 10) / (largeStringTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkJsonOperations();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkJsonOperations;
}