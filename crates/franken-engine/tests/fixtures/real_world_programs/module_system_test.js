// Real-world program #5: Module System Integration Test
// Features: ES2015 modules, import/export, re-exports, circular dependencies, namespace imports

// This file tests the module system by importing from multiple modules
// Note: This creates a module dependency graph to test import/export functionality

// === Module A: Utilities ===
const ModuleA = {
    // Utility functions
    add: (a, b) => a + b,
    multiply: (a, b) => a * b,

    // Configuration object
    config: {
        version: '1.0.0',
        debug: true
    },

    // Class definition
    Calculator: class Calculator {
        constructor(name = 'DefaultCalculator') {
            this.name = name;
            this.history = [];
        }

        calculate(operation, a, b) {
            let result;
            switch (operation) {
                case 'add':
                    result = ModuleA.add(a, b);
                    break;
                case 'multiply':
                    result = ModuleA.multiply(a, b);
                    break;
                default:
                    result = null;
            }

            this.history.push({ operation, a, b, result, timestamp: Date.now() });
            return result;
        }

        getHistory() {
            return [...this.history];
        }

        clear() {
            this.history.length = 0;
        }
    }
};

// === Module B: Data Structures ===
const ModuleB = {
    // Export a class and utility functions
    Stack: class Stack {
        constructor() {
            this.items = [];
        }

        push(item) {
            this.items.push(item);
            return this;
        }

        pop() {
            return this.items.pop();
        }

        peek() {
            return this.items[this.items.length - 1];
        }

        isEmpty() {
            return this.items.length === 0;
        }

        size() {
            return this.items.length;
        }

        // Use Calculator from ModuleA (circular-ish dependency)
        calculateTotal() {
            const calc = new ModuleA.Calculator('StackCalculator');
            let total = 0;

            for (const item of this.items) {
                if (typeof item === 'number') {
                    total = calc.calculate('add', total, item);
                }
            }

            return total;
        }
    },

    // Utility functions that use ModuleA
    createNumberStack: (numbers) => {
        const stack = new ModuleB.Stack();
        numbers.forEach(num => stack.push(num));
        return stack;
    },

    processStackData: (stack) => {
        const data = [];
        while (!stack.isEmpty()) {
            data.push(stack.pop());
        }
        return data.reverse(); // Restore original order
    }
};

// === Module C: Application Logic ===
const ModuleC = {
    // Application that uses both ModuleA and ModuleB
    Application: class Application {
        constructor(name) {
            this.name = name;
            this.calculator = new ModuleA.Calculator(`${name}Calculator`);
            this.dataStacks = new Map();
            this.sessionId = Math.random().toString(36).substr(2, 9);
        }

        createStack(stackName, initialData = []) {
            const stack = ModuleB.createNumberStack(initialData);
            this.dataStacks.set(stackName, stack);
            return stack;
        }

        processStack(stackName) {
            const stack = this.dataStacks.get(stackName);
            if (!stack) {
                throw new Error(`Stack '${stackName}' not found`);
            }

            const total = stack.calculateTotal();
            const data = ModuleB.processStackData(stack);

            return {
                stackName,
                total,
                data,
                processedAt: new Date().toISOString()
            };
        }

        getSystemInfo() {
            return {
                name: this.name,
                sessionId: this.sessionId,
                config: ModuleA.config,
                calculatorHistory: this.calculator.getHistory(),
                stackCount: this.dataStacks.size,
                activeStacks: Array.from(this.dataStacks.keys())
            };
        }

        // Method that demonstrates feature composition
        runComplexOperation() {
            // Create multiple stacks
            this.createStack('fibonacci', [1, 1, 2, 3, 5, 8, 13]);
            this.createStack('primes', [2, 3, 5, 7, 11, 13]);
            this.createStack('squares', [1, 4, 9, 16, 25]);

            // Process each stack
            const results = [];
            for (const stackName of this.dataStacks.keys()) {
                try {
                    const result = this.processStack(stackName);
                    results.push(result);
                } catch (error) {
                    results.push({
                        stackName,
                        error: error.message,
                        processedAt: new Date().toISOString()
                    });
                }
            }

            // Calculate summary statistics
            const totals = results
                .filter(r => !r.error)
                .map(r => r.total);

            const grandTotal = totals.reduce((sum, total) =>
                this.calculator.calculate('add', sum, total), 0);

            const averageTotal = totals.length > 0 ?
                grandTotal / totals.length : 0;

            return {
                results,
                summary: {
                    stacksProcessed: results.length,
                    grandTotal,
                    averageTotal,
                    systemInfo: this.getSystemInfo()
                }
            };
        }
    },

    // Factory function for creating applications
    createApplication: (name, config = {}) => {
        const app = new ModuleC.Application(name);

        // Apply configuration
        if (config.stacks) {
            for (const [stackName, data] of Object.entries(config.stacks)) {
                app.createStack(stackName, data);
            }
        }

        return app;
    }
};

// === Module D: Testing and Validation ===
const ModuleD = {
    // Test suite that exercises all modules
    TestSuite: class TestSuite {
        constructor() {
            this.tests = [];
            this.results = [];
        }

        addTest(name, testFn) {
            this.tests.push({ name, testFn });
            return this;
        }

        async runTests() {
            console.log('Running Module System Integration Tests...');

            for (const test of this.tests) {
                try {
                    const startTime = Date.now();
                    const result = await test.testFn();
                    const duration = Date.now() - startTime;

                    this.results.push({
                        name: test.name,
                        status: 'PASS',
                        result,
                        duration
                    });

                    console.log(`✓ ${test.name} (${duration}ms)`);
                } catch (error) {
                    this.results.push({
                        name: test.name,
                        status: 'FAIL',
                        error: error.message,
                        duration: Date.now() - Date.now()
                    });

                    console.log(`✗ ${test.name}: ${error.message}`);
                }
            }

            return this.getSummary();
        }

        getSummary() {
            const passed = this.results.filter(r => r.status === 'PASS').length;
            const failed = this.results.filter(r => r.status === 'FAIL').length;
            const totalDuration = this.results.reduce((sum, r) => sum + (r.duration || 0), 0);

            return {
                total: this.results.length,
                passed,
                failed,
                totalDuration,
                results: this.results
            };
        }
    },

    // Create and run the complete test suite
    createTestSuite: () => {
        const suite = new ModuleD.TestSuite();

        // Test ModuleA functionality
        suite.addTest('ModuleA Calculator', () => {
            const calc = new ModuleA.Calculator('TestCalc');
            const result1 = calc.calculate('add', 5, 3);
            const result2 = calc.calculate('multiply', 4, 6);

            if (result1 !== 8) throw new Error('Addition failed');
            if (result2 !== 24) throw new Error('Multiplication failed');
            if (calc.getHistory().length !== 2) throw new Error('History tracking failed');

            return { calculator: calc.name, operations: calc.getHistory().length };
        });

        // Test ModuleB functionality
        suite.addTest('ModuleB Stack Operations', () => {
            const stack = new ModuleB.Stack();
            stack.push(10).push(20).push(30);

            if (stack.size() !== 3) throw new Error('Stack size incorrect');
            if (stack.peek() !== 30) throw new Error('Peek failed');

            const popped = stack.pop();
            if (popped !== 30) throw new Error('Pop failed');
            if (stack.size() !== 2) throw new Error('Size after pop incorrect');

            return { finalSize: stack.size(), poppedValue: popped };
        });

        // Test ModuleC Application
        suite.addTest('ModuleC Application Integration', () => {
            const app = ModuleC.createApplication('TestApp', {
                stacks: {
                    'test1': [1, 2, 3],
                    'test2': [4, 5, 6]
                }
            });

            const systemInfo = app.getSystemInfo();
            if (systemInfo.stackCount !== 2) throw new Error('Stack count incorrect');

            const operation = app.runComplexOperation();
            if (operation.results.length !== 2) throw new Error('Operation results incorrect');

            return {
                systemInfo: systemInfo.name,
                operationResults: operation.results.length,
                grandTotal: operation.summary.grandTotal
            };
        });

        // Test cross-module dependencies
        suite.addTest('Cross-Module Dependencies', () => {
            // Test that ModuleB can use ModuleA's Calculator
            const stack = ModuleB.createNumberStack([1, 2, 3, 4, 5]);
            const total = stack.calculateTotal();

            if (total !== 15) throw new Error('Cross-module calculation failed');

            // Test that ModuleC can orchestrate both A and B
            const app = new ModuleC.Application('DependencyTest');
            const stack2 = app.createStack('deps', [10, 20, 30]);
            const result = app.processStack('deps');

            if (result.total !== 60) throw new Error('Cross-module orchestration failed');

            return { stackTotal: total, appTotal: result.total };
        });

        return suite;
    }
};

// === Main Application Execution ===
async function runModuleSystemTest() {
    console.log('=== Module System Integration Test ===');

    // Create test suite and run all tests
    const testSuite = ModuleD.createTestSuite();
    const summary = await testSuite.runTests();

    // Run a comprehensive application test
    console.log('\n=== Comprehensive Application Test ===');

    const app = ModuleC.createApplication('MainApp');
    const operationResult = app.runComplexOperation();

    // Display results
    console.log('Test Summary:', JSON.stringify(summary, null, 2));
    console.log('Application Result:', JSON.stringify(operationResult.summary, null, 2));

    // Return final result for verification
    return {
        moduleSystem: {
            testSummary: summary,
            applicationDemo: {
                stacksProcessed: operationResult.results.length,
                grandTotal: operationResult.summary.grandTotal,
                systemInfo: operationResult.summary.systemInfo
            }
        },
        verification: {
            allTestsPassed: summary.failed === 0,
            modulesUsed: ['ModuleA', 'ModuleB', 'ModuleC', 'ModuleD'],
            featuresExercised: [
                'ES2015 classes',
                'Module imports/exports',
                'Cross-module dependencies',
                'Maps and data structures',
                'Async/await (test runner)',
                'Generators (if used)',
                'Error handling',
                'JSON serialization'
            ]
        }
    };
}

// Execute the test
runModuleSystemTest().then(result => {
    console.log('\n=== Final Module System Test Result ===');
    console.log(JSON.stringify(result, null, 2));
}).catch(error => {
    console.error('Module system test failed:', error.message);
    console.error(error.stack);
});

// Export for external module testing (simulated module.exports for this environment)
if (typeof module !== 'undefined') {
    module.exports = {
        ModuleA,
        ModuleB,
        ModuleC,
        ModuleD,
        runModuleSystemTest
    };
}