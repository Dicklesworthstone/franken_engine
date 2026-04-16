// Micro-Benchmark 7: String Operations
// Tests performance of string concatenation and manipulation

function benchmarkStringOperations() {
    console.log("Starting String Operations benchmark...");
    const startTime = Date.now();

    const targetLength = 100000; // 100K character string
    const iterations = 10000; // Various iteration counts

    // String concatenation with + operator
    const concatStart = Date.now();
    let concatResult = '';
    for (let i = 0; i < targetLength / 10; i++) {
        concatResult += 'Hello' + i;
    }
    const concatTime = Date.now() - concatStart;

    // Array join string building
    const joinStart = Date.now();
    const joinArray = [];
    for (let i = 0; i < targetLength / 10; i++) {
        joinArray.push('Hello' + i);
    }
    const joinResult = joinArray.join('');
    const joinTime = Date.now() - joinStart;

    // Template literal string building
    const templateStart = Date.now();
    let templateResult = '';
    for (let i = 0; i < targetLength / 10; i++) {
        templateResult += `Hello${i}`;
    }
    const templateTime = Date.now() - templateStart;

    // String repeat operations
    const repeatStart = Date.now();
    let repeatResult = '';
    for (let i = 0; i < 1000; i++) {
        repeatResult = 'x'.repeat(100);
    }
    const repeatTime = Date.now() - repeatStart;

    // String search operations
    const searchStart = Date.now();
    const searchText = 'Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua'.repeat(100);
    let searchCount = 0;
    for (let i = 0; i < iterations; i++) {
        if (searchText.indexOf('lorem') !== -1) searchCount++;
        if (searchText.includes('ipsum')) searchCount++;
        if (searchText.search(/dolor/i) !== -1) searchCount++;
    }
    const searchTime = Date.now() - searchStart;

    // String replacement operations
    const replaceStart = Date.now();
    const replaceText = 'The quick brown fox jumps over the lazy dog. '.repeat(1000);
    let replaceResults = [];
    for (let i = 0; i < 100; i++) {
        let result = replaceText.replace(/the/g, 'THE');
        result = result.replace(/fox/g, 'FOX');
        result = result.replace(/dog/g, 'DOG');
        replaceResults.push(result);
    }
    const replaceTime = Date.now() - replaceStart;

    // String splitting operations
    const splitStart = Date.now();
    const splitText = Array.from({length: 10000}, (_, i) => `word${i}`).join(' ');
    let splitResults = [];
    for (let i = 0; i < 100; i++) {
        const words = splitText.split(' ');
        splitResults.push(words.length);
    }
    const splitTime = Date.now() - splitStart;

    // String case operations
    const caseStart = Date.now();
    const caseText = 'Mixed Case String With Various WORDS and Numbers123'.repeat(1000);
    let caseResults = [];
    for (let i = 0; i < 1000; i++) {
        const upper = caseText.toUpperCase();
        const lower = caseText.toLowerCase();
        caseResults.push(upper.length + lower.length);
    }
    const caseTime = Date.now() - caseStart;

    // String substring operations
    const substringStart = Date.now();
    const substringText = 'abcdefghijklmnopqrstuvwxyz0123456789'.repeat(1000);
    let substringResults = [];
    for (let i = 0; i < iterations; i++) {
        const start = i % 1000;
        const end = start + 10;
        substringResults.push(substringText.substring(start, end));
        substringResults.push(substringText.slice(start, end));
        substringResults.push(substringText.substr(start, 10));
    }
    const substringTime = Date.now() - substringStart;

    // String character access
    const charStart = Date.now();
    const charText = 'Hello World! This is a test string for character access.'.repeat(1000);
    let charSum = 0;
    for (let i = 0; i < iterations * 10; i++) {
        const index = i % charText.length;
        charSum += charText.charCodeAt(index);
        charSum += charText[index].length || 0;
    }
    const charTime = Date.now() - charStart;

    // String formatting operations
    const formatStart = Date.now();
    let formatResults = [];
    for (let i = 0; i < iterations; i++) {
        const formatted = `User ${i}: Name is ${`User${i}`}, age is ${20 + (i % 50)}, active: ${i % 2 === 0}`;
        formatResults.push(formatted);
    }
    const formatTime = Date.now() - formatStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("String Operations benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Concatenation: ${concatTime}ms (${concatResult.length} chars)`);
    console.log(`Array Join: ${joinTime}ms (${joinResult.length} chars)`);
    console.log(`Template Literal: ${templateTime}ms (${templateResult.length} chars)`);
    console.log(`String Repeat: ${repeatTime}ms (1000 operations)`);
    console.log(`String Search: ${searchTime}ms (${iterations} iterations, ${searchCount} matches)`);
    console.log(`String Replace: ${replaceTime}ms (100 operations)`);
    console.log(`String Split: ${splitTime}ms (100 operations, avg ${Math.round(splitResults.reduce((a, b) => a + b, 0) / splitResults.length)} words)`);
    console.log(`Case Operations: ${caseTime}ms (1000 operations)`);
    console.log(`Substring Ops: ${substringTime}ms (${iterations * 3} operations)`);
    console.log(`Character Access: ${charTime}ms (${iterations * 10} operations, sum=${charSum})`);
    console.log(`String Formatting: ${formatTime}ms (${iterations} operations)`);

    return {
        totalTime,
        targetLength,
        iterations,
        operations: {
            concatenation: targetLength / 10,
            arrayJoin: targetLength / 10 + 1, // push operations + join
            templateLiteral: targetLength / 10,
            stringRepeat: 1000,
            stringSearch: iterations * 3,
            stringReplace: 100 * 3,
            stringSplit: 100,
            caseOperations: 1000 * 2,
            substringOps: iterations * 3,
            characterAccess: iterations * 10 * 2,
            stringFormatting: iterations
        },
        times: {
            concatenation: concatTime,
            arrayJoin: joinTime,
            templateLiteral: templateTime,
            stringRepeat: repeatTime,
            stringSearch: searchTime,
            stringReplace: replaceTime,
            stringSplit: splitTime,
            caseOperations: caseTime,
            substringOps: substringTime,
            characterAccess: charTime,
            stringFormatting: formatTime
        },
        results: {
            concatLength: concatResult.length,
            joinLength: joinResult.length,
            templateLength: templateResult.length,
            repeatLength: repeatResult.length,
            searchMatches: searchCount,
            replaceCount: replaceResults.length,
            avgWordsPerSplit: Math.round(splitResults.reduce((a, b) => a + b, 0) / splitResults.length),
            caseResults: caseResults.length,
            substringResults: substringResults.length,
            charSum: charSum % 1000000, // Modulo to keep reasonable
            formatResults: formatResults.length
        },
        opsPerSecond: {
            concatenation: Math.round((targetLength / 10) / (concatTime / 1000)),
            arrayJoin: Math.round((targetLength / 10 + 1) / (joinTime / 1000)),
            templateLiteral: Math.round((targetLength / 10) / (templateTime / 1000)),
            stringRepeat: Math.round(1000 / (repeatTime / 1000)),
            stringSearch: Math.round((iterations * 3) / (searchTime / 1000)),
            stringReplace: Math.round((100 * 3) / (replaceTime / 1000)),
            stringSplit: Math.round(100 / (splitTime / 1000)),
            caseOperations: Math.round((1000 * 2) / (caseTime / 1000)),
            substringOps: Math.round((iterations * 3) / (substringTime / 1000)),
            characterAccess: Math.round((iterations * 10 * 2) / (charTime / 1000)),
            stringFormatting: Math.round(iterations / (formatTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkStringOperations();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkStringOperations;
}