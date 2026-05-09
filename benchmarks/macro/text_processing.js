// Macro-Benchmark 4: Text Processing
// Tests regular expressions, string manipulation, tokenization, and parsing

// Generate a large text document for processing
function generateTextDocument() {
    const words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "and", "runs",
        "through", "forest", "under", "moonlight", "while", "singing", "beautiful", "song",
        "about", "ancient", "legends", "told", "by", "wise", "elders", "from", "distant",
        "lands", "where", "magic", "flows", "like", "river", "bringing", "hope", "to",
        "those", "who", "believe", "in", "power", "of", "dreams", "and", "courage",
        "JavaScript", "engine", "performance", "optimization", "benchmark", "testing",
        "algorithms", "data", "structures", "recursive", "functions", "object", "oriented",
        "programming", "functional", "programming", "web", "development", "modern",
        "software", "engineering", "best", "practices", "code", "quality", "maintainability"
    ];

    const sentences = [];
    for (let i = 0; i < 500; i++) {
        const sentenceLength = 8 + Math.floor(Math.random() * 12);
        const sentence = [];

        for (let j = 0; j < sentenceLength; j++) {
            const word = words[Math.floor(Math.random() * words.length)];
            sentence.push(j === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word);
        }

        sentences.push(sentence.join(" ") + ".");
    }

    // Add some structured content
    const structuredSections = [
        "\n\n# Chapter 1: Introduction\n",
        "This chapter introduces the fundamental concepts of text processing and analysis.",
        "\n\n## Section 1.1: Tokenization\n",
        "Tokenization is the process of breaking text into individual tokens or words.",
        "\n\n## Section 1.2: Regular Expressions\n",
        "Regular expressions provide powerful pattern matching capabilities.",
        "\n\n# Chapter 2: Advanced Processing\n",
        "Advanced text processing techniques include sentiment analysis and entity extraction.",
        "\n\n## Section 2.1: Pattern Recognition\n",
        "Pattern recognition helps identify recurring structures in text.",
        "\n\n## Section 2.2: Data Extraction\n",
        "Data extraction involves pulling structured information from unstructured text.",
        "\n\n# Conclusion\n",
        "Text processing is a fundamental skill in modern software development."
    ];

    let document = sentences.slice(0, 100).join(" ");
    document += structuredSections.join("\n");
    document += "\n\n" + sentences.slice(100).join(" ");

    // Add some special patterns for regex testing
    document += "\n\nContact Information:\n";
    document += "Email: john.doe@example.com, jane.smith@company.org\n";
    document += "Phone: (555) 123-4567, +1-800-555-0199\n";
    document += "URLs: https://www.example.com, http://api.service.io/v1/data\n";
    document += "Dates: 2024-01-15, 12/25/2023, January 1st, 2024\n";
    document += "Numbers: $1,234.56, €999.99, 42%, 3.14159\n";

    return document;
}

class TextTokenizer {
    constructor() {
        this.tokenPatterns = {
            words: /\b\w+\b/g,
            sentences: /[.!?]+/g,
            paragraphs: /\n\s*\n/g,
            whitespace: /\s+/g,
            punctuation: /[.,;:!?()[\]{}'"]/g,
            numbers: /\b\d+(?:\.\d+)?\b/g,
            emails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            urls: /https?:\/\/[^\s]+/g,
            phone: /(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g
        };
        this.stopWords = new Set([
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were", "be", "been", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should"
        ]);
    }

    tokenize(text, type = 'words') {
        if (!this.tokenPatterns[type]) {
            throw new Error(`Unknown token type: ${type}`);
        }
        return text.match(this.tokenPatterns[type]) || [];
    }

    tokenizeAdvanced(text) {
        const results = {};
        for (const [type, pattern] of Object.entries(this.tokenPatterns)) {
            results[type] = this.tokenize(text, type);
        }
        return results;
    }

    extractKeywords(text, minLength = 3) {
        const words = this.tokenize(text.toLowerCase(), 'words');
        const wordCounts = {};

        for (const word of words) {
            if (word.length >= minLength && !this.stopWords.has(word)) {
                wordCounts[word] = (wordCounts[word] || 0) + 1;
            }
        }

        return Object.entries(wordCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([word, count]) => ({ word, count }));
    }
}

class TextAnalyzer {
    constructor() {
        this.patterns = {
            // Common text patterns
            capitalizedWords: /\b[A-Z][a-z]+\b/g,
            allCaps: /\b[A-Z]{2,}\b/g,
            acronyms: /\b[A-Z]{2,}(?:\.[A-Z]{2,})*\b/g,

            // Data patterns
            dates: /\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})\b/gi,
            currencies: /[$€£¥]\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|dollars?|euros?|pounds?|yen)\b/gi,
            percentages: /\b\d+(?:\.\d+)?%\b/g,

            // Code patterns
            htmlTags: /<\/?[a-zA-Z][^>]*>/g,
            cssSelectors: /[.#]?[a-zA-Z][\w-]*\s*{[^}]*}/g,
            functions: /\b\w+\s*\([^)]*\)/g
        };
    }

    analyze(text) {
        const analysis = {
            basicStats: this.getBasicStats(text),
            patterns: {},
            readability: this.calculateReadability(text),
            structure: this.analyzeStructure(text)
        };

        // Extract all patterns
        for (const [name, pattern] of Object.entries(this.patterns)) {
            const matches = text.match(pattern) || [];
            analysis.patterns[name] = {
                count: matches.length,
                examples: matches.slice(0, 5), // First 5 examples
                unique: new Set(matches).size
            };
        }

        return analysis;
    }

    getBasicStats(text) {
        return {
            characters: text.length,
            charactersNoSpaces: text.replace(/\s/g, '').length,
            words: (text.match(/\b\w+\b/g) || []).length,
            sentences: (text.match(/[.!?]+/g) || []).length,
            paragraphs: text.split(/\n\s*\n/).length,
            lines: text.split('\n').length
        };
    }

    calculateReadability(text) {
        const stats = this.getBasicStats(text);
        const avgWordsPerSentence = stats.words / Math.max(stats.sentences, 1);
        const avgCharsPerWord = stats.charactersNoSpaces / Math.max(stats.words, 1);

        // Simple readability metrics
        return {
            avgWordsPerSentence: Math.round(avgWordsPerSentence * 100) / 100,
            avgCharsPerWord: Math.round(avgCharsPerWord * 100) / 100,
            complexity: avgWordsPerSentence > 20 ? 'high' : avgWordsPerSentence > 15 ? 'medium' : 'low'
        };
    }

    analyzeStructure(text) {
        const headers = text.match(/^#{1,6}\s+.+$/gm) || [];
        const sections = text.split(/^#{1,6}\s+/gm).filter(s => s.trim());

        return {
            headers: headers.length,
            sections: sections.length,
            avgSectionLength: sections.length > 0 ? Math.round(sections.reduce((sum, s) => sum + s.length, 0) / sections.length) : 0
        };
    }
}

class RegexProcessor {
    constructor() {
        this.compiledPatterns = new Map();
    }

    // Benchmark regex compilation and execution
    testRegexPerformance(text, patterns) {
        const results = {};

        for (const [name, pattern] of Object.entries(patterns)) {
            const startTime = Date.now();

            // Compile regex
            const compiledRegex = new RegExp(pattern.source || pattern, pattern.flags || 'g');
            this.compiledPatterns.set(name, compiledRegex);

            const compileTime = Date.now() - startTime;

            // Execute regex
            const execStart = Date.now();
            const matches = [];
            let match;

            compiledRegex.lastIndex = 0; // Reset
            while ((match = compiledRegex.exec(text)) !== null) {
                matches.push({
                    match: match[0],
                    index: match.index,
                    groups: match.slice(1)
                });

                // Prevent infinite loop on zero-width matches
                if (match.index === compiledRegex.lastIndex) {
                    compiledRegex.lastIndex++;
                }
            }

            const execTime = Date.now() - execStart;

            results[name] = {
                compileTime,
                execTime,
                totalTime: compileTime + execTime,
                matchCount: matches.length,
                matches: matches.slice(0, 3) // First 3 matches as examples
            };
        }

        return results;
    }

    // Advanced text replacement with callbacks
    advancedReplace(text) {
        const operations = [];
        let result = text;

        // Replace emails with masked versions
        const emailStart = Date.now();
        result = result.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, (match) => {
            return match.replace(/^(.{2})[^@]*(@.{2})[^.]*(\..*)$/, '$1***$2***$3');
        });
        operations.push({ operation: 'email_masking', time: Date.now() - emailStart });

        // Replace numbers with spelled out versions (for small numbers)
        const numberStart = Date.now();
        const numberMap = { '0': 'zero', '1': 'one', '2': 'two', '3': 'three', '4': 'four', '5': 'five' };
        result = result.replace(/\b[0-5]\b/g, (match) => numberMap[match] || match);
        operations.push({ operation: 'number_spelling', time: Date.now() - numberStart });

        // Normalize whitespace
        const whitespaceStart = Date.now();
        result = result.replace(/\s+/g, ' ').replace(/\n\s*\n/g, '\n\n');
        operations.push({ operation: 'whitespace_normalization', time: Date.now() - whitespaceStart });

        return { result, operations };
    }
}

function benchmarkTextProcessing() {
    console.log("Starting Text Processing benchmark...");
    const startTime = Date.now();

    // Step 1: Generate test document
    console.log("Step 1: Generating text document...");
    const document = generateTextDocument();
    console.log(`Generated document: ${document.length} characters`);

    // Step 2: Tokenization
    console.log("Step 2: Text tokenization...");
    const tokenizeStart = Date.now();
    const tokenizer = new TextTokenizer();

    const basicTokens = tokenizer.tokenize(document, 'words');
    const advancedTokens = tokenizer.tokenizeAdvanced(document);
    const keywords = tokenizer.extractKeywords(document);

    const tokenizeTime = Date.now() - tokenizeStart;

    // Step 3: Text analysis
    console.log("Step 3: Text analysis...");
    const analysisStart = Date.now();
    const analyzer = new TextAnalyzer();
    const analysis = analyzer.analyze(document);
    const analysisTime = Date.now() - analysisStart;

    // Step 4: Regular expression processing
    console.log("Step 4: Regular expression processing...");
    const regexStart = Date.now();
    const regexProcessor = new RegexProcessor();

    const testPatterns = {
        emails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi,
        phones: /(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g,
        urls: /https?:\/\/[^\s]+/gi,
        dates: /\b\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b/g,
        currencies: /[$€£]\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?/g,
        words: /\b\w+\b/g,
        sentences: /[^.!?]*[.!?]/g
    };

    const regexResults = regexProcessor.testRegexPerformance(document, testPatterns);
    const regexTime = Date.now() - regexStart;

    // Step 5: Advanced text replacement
    console.log("Step 5: Advanced text replacement...");
    const replaceStart = Date.now();
    const replacementResult = regexProcessor.advancedReplace(document);
    const replaceTime = Date.now() - replaceStart;

    // Step 6: String manipulation stress test
    console.log("Step 6: String manipulation stress test...");
    const stringStart = Date.now();

    let testString = document;
    const manipulations = [];

    // Multiple string operations
    testString = testString.toUpperCase();
    manipulations.push('toUpperCase');

    testString = testString.toLowerCase();
    manipulations.push('toLowerCase');

    const words = testString.split(/\s+/);
    manipulations.push('split');

    const reversed = words.reverse().join(' ');
    manipulations.push('reverse_join');

    const substring = testString.substring(100, 1000);
    manipulations.push('substring');

    const indexOf = testString.indexOf('the');
    manipulations.push('indexOf');

    const stringTime = Date.now() - stringStart;

    const endTime = Date.now();
    const duration = endTime - startTime;

    // Results summary
    console.log("Text Processing benchmark completed");
    console.log(`Total duration: ${duration}ms`);
    console.log(`Document size: ${document.length} characters, ${basicTokens.length} words`);
    console.log(`Tokenization: ${tokenizeTime}ms (${advancedTokens.words.length} words, ${keywords.length} keywords)`);
    console.log(`Analysis: ${analysisTime}ms (${analysis.basicStats.sentences} sentences, ${analysis.structure.headers} headers)`);
    console.log(`Regex processing: ${regexTime}ms (${Object.keys(regexResults).length} patterns tested)`);
    console.log(`Text replacement: ${replaceTime}ms (${replacementResult.operations.length} operations)`);
    console.log(`String manipulation: ${stringTime}ms (${manipulations.length} operations)`);

    if (keywords.length > 0) {
        console.log(`Top keyword: "${keywords[0].word}" (${keywords[0].count} occurrences)`);
    }

    return {
        duration,
        documentSize: document.length,
        operations: {
            tokenization: 1,
            textAnalysis: 1,
            regexProcessing: Object.keys(testPatterns).length,
            textReplacement: replacementResult.operations.length,
            stringManipulation: manipulations.length
        },
        results: {
            tokenization: {
                time: tokenizeTime,
                wordCount: basicTokens.length,
                keywordCount: keywords.length,
                topKeyword: keywords[0]
            },
            analysis: {
                time: analysisTime,
                stats: analysis.basicStats,
                readability: analysis.readability,
                structure: analysis.structure
            },
            regex: {
                time: regexTime,
                patterns: Object.keys(regexResults).map(name => ({
                    name,
                    matchCount: regexResults[name].matchCount,
                    totalTime: regexResults[name].totalTime
                }))
            },
            replacement: {
                time: replaceTime,
                operations: replacementResult.operations,
                outputSize: replacementResult.result.length
            },
            stringManipulation: {
                time: stringTime,
                operations: manipulations,
                finalSize: reversed.length
            }
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkTextProcessing();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkTextProcessing;
}
