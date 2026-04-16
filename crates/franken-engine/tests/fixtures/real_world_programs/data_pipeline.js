// Real-world program #4: Data Processing Pipeline
// Features: ES2015 classes, generators, arrow functions, Map, destructuring, method chaining

class DataSource {
    constructor(data) {
        this.data = Array.isArray(data) ? data : [];
        this.metadata = {
            created: Date.now(),
            processed: false,
            recordCount: this.data.length
        };
    }

    // Generator for streaming data
    *stream() {
        for (const item of this.data) {
            yield {
                record: item,
                timestamp: Date.now(),
                source: 'DataSource'
            };
        }
    }

    // Static factory methods
    static fromJSON(jsonString) {
        try {
            const parsed = JSON.parse(jsonString);
            return new DataSource(parsed);
        } catch (error) {
            throw new Error('Invalid JSON data: ' + error.message);
        }
    }

    static fromCSV(csvString, delimiter = ',') {
        const lines = csvString.trim().split('\n');
        if (lines.length === 0) return new DataSource([]);

        const headers = lines[0].split(delimiter);
        const data = lines.slice(1).map(line => {
            const values = line.split(delimiter);
            const obj = {};
            headers.forEach((header, index) => {
                obj[header.trim()] = values[index] ? values[index].trim() : null;
            });
            return obj;
        });

        return new DataSource(data);
    }
}

class DataTransformer {
    constructor() {
        this.transformations = [];
        this.stats = {
            recordsProcessed: 0,
            transformationsApplied: 0,
            errors: 0
        };
    }

    // Add transformation function
    addTransform(name, transformFn) {
        if (typeof transformFn !== 'function') {
            throw new Error('Transform must be a function');
        }

        this.transformations.push({ name, transformFn });
        return this;
    }

    // Transform a single record
    transformRecord(record) {
        let transformedRecord = { ...record };

        for (const { name, transformFn } of this.transformations) {
            try {
                transformedRecord = transformFn(transformedRecord);
                this.stats.transformationsApplied++;
            } catch (error) {
                console.error(`Transformation '${name}' failed:`, error.message);
                this.stats.errors++;
            }
        }

        this.stats.recordsProcessed++;
        return transformedRecord;
    }

    // Process data stream with transformations
    *processStream(dataStream) {
        for (const item of dataStream) {
            try {
                const transformed = this.transformRecord(item.record);
                yield {
                    ...item,
                    record: transformed,
                    transformedAt: Date.now()
                };
            } catch (error) {
                console.error('Failed to process record:', error.message);
                this.stats.errors++;
            }
        }
    }

    // Convenience methods for common transformations
    addFieldCalculation(fieldName, calculationFn) {
        return this.addTransform(`calculate_${fieldName}`, (record) => ({
            ...record,
            [fieldName]: calculationFn(record)
        }));
    }

    addFieldMapping(mappings) {
        return this.addTransform('field_mapping', (record) => {
            const mapped = { ...record };
            for (const [oldKey, newKey] of Object.entries(mappings)) {
                if (oldKey in mapped) {
                    mapped[newKey] = mapped[oldKey];
                    delete mapped[oldKey];
                }
            }
            return mapped;
        });
    }

    addValidation(validationFn, defaultValue = null) {
        return this.addTransform('validation', (record) => {
            return validationFn(record) ? record : defaultValue;
        });
    }
}

class DataAggregator {
    constructor() {
        this.aggregations = new Map();
        this.groupers = new Map();
    }

    // Add aggregation function
    addAggregation(name, initialValue, aggregateFn) {
        this.aggregations.set(name, {
            value: initialValue,
            fn: aggregateFn
        });
        return this;
    }

    // Add grouping function
    addGroupBy(keyFn, aggregationName = 'default') {
        this.groupers.set(aggregationName, keyFn);
        return this;
    }

    // Process stream and aggregate results
    processStream(dataStream) {
        const results = new Map();
        let recordCount = 0;

        for (const item of dataStream) {
            if (!item.record) continue;

            recordCount++;
            const record = item.record;

            // Process each grouper
            for (const [groupName, keyFn] of this.groupers) {
                const groupKey = keyFn(record);

                if (!results.has(groupName)) {
                    results.set(groupName, new Map());
                }

                const groupResults = results.get(groupName);

                if (!groupResults.has(groupKey)) {
                    // Initialize aggregations for this group
                    const groupData = {};
                    for (const [aggName, aggConfig] of this.aggregations) {
                        groupData[aggName] = aggConfig.value;
                    }
                    groupResults.set(groupKey, groupData);
                }

                // Apply aggregations
                const groupData = groupResults.get(groupKey);
                for (const [aggName, aggConfig] of this.aggregations) {
                    groupData[aggName] = aggConfig.fn(groupData[aggName], record);
                }
            }
        }

        return {
            recordCount,
            groups: Object.fromEntries(
                Array.from(results.entries()).map(([groupName, groupMap]) => [
                    groupName,
                    Object.fromEntries(groupMap.entries())
                ])
            )
        };
    }

    // Convenience methods for common aggregations
    static sum(field) {
        return {
            initialValue: 0,
            fn: (acc, record) => acc + (parseFloat(record[field]) || 0)
        };
    }

    static count() {
        return {
            initialValue: 0,
            fn: (acc, record) => acc + 1
        };
    }

    static average(field) {
        return {
            initialValue: { sum: 0, count: 0 },
            fn: (acc, record) => ({
                sum: acc.sum + (parseFloat(record[field]) || 0),
                count: acc.count + 1
            })
        };
    }

    static collect(field) {
        return {
            initialValue: [],
            fn: (acc, record) => {
                acc.push(record[field]);
                return acc;
            }
        };
    }
}

class DataPipeline {
    constructor(source) {
        this.source = source;
        this.transformers = [];
        this.aggregator = null;
        this.filters = [];
        this.output = null;
    }

    // Add transformer to pipeline
    addTransformer(transformer) {
        if (!(transformer instanceof DataTransformer)) {
            throw new Error('Must be a DataTransformer instance');
        }
        this.transformers.push(transformer);
        return this;
    }

    // Add aggregator to pipeline
    setAggregator(aggregator) {
        if (!(aggregator instanceof DataAggregator)) {
            throw new Error('Must be a DataAggregator instance');
        }
        this.aggregator = aggregator;
        return this;
    }

    // Add filter to pipeline
    addFilter(filterFn) {
        if (typeof filterFn !== 'function') {
            throw new Error('Filter must be a function');
        }
        this.filters.push(filterFn);
        return this;
    }

    // Execute the pipeline
    execute() {
        let dataStream = this.source.stream();

        // Apply transformers
        for (const transformer of this.transformers) {
            dataStream = transformer.processStream(dataStream);
        }

        // Apply filters
        if (this.filters.length > 0) {
            dataStream = this._applyFilters(dataStream);
        }

        // Apply aggregation if configured
        if (this.aggregator) {
            this.output = this.aggregator.processStream(dataStream);
        } else {
            // Collect all records
            this.output = Array.from(dataStream);
        }

        return this.output;
    }

    // Internal filter application
    *_applyFilters(dataStream) {
        for (const item of dataStream) {
            let shouldInclude = true;

            for (const filterFn of this.filters) {
                if (!filterFn(item.record)) {
                    shouldInclude = false;
                    break;
                }
            }

            if (shouldInclude) {
                yield item;
            }
        }
    }

    // Get pipeline statistics
    getStats() {
        const stats = {
            source: this.source.metadata,
            transformers: this.transformers.map(t => t.stats),
            filtersCount: this.filters.length,
            hasAggregator: !!this.aggregator
        };

        return stats;
    }
}

// Test the data pipeline system
function testDataPipeline() {
    console.log('Testing Data Processing Pipeline...');

    // Create sample data
    const salesData = [
        { product: 'Widget A', category: 'Electronics', price: 29.99, quantity: 10, region: 'North' },
        { product: 'Widget B', category: 'Electronics', price: 39.99, quantity: 5, region: 'South' },
        { product: 'Gadget X', category: 'Electronics', price: 199.99, quantity: 3, region: 'North' },
        { product: 'Tool Y', category: 'Hardware', price: 89.99, quantity: 7, region: 'East' },
        { product: 'Part Z', category: 'Hardware', price: 15.50, quantity: 20, region: 'West' },
        { product: 'Service A', category: 'Services', price: 49.99, quantity: 12, region: 'North' },
    ];

    // Create data source
    const source = new DataSource(salesData);

    // Create transformer
    const transformer = new DataTransformer()
        .addFieldCalculation('total', record => record.price * record.quantity)
        .addFieldMapping({ quantity: 'qty' })
        .addValidation(record => record.price > 0);

    // Create aggregator
    const aggregator = new DataAggregator()
        .addGroupBy(record => record.category, 'byCategory')
        .addGroupBy(record => record.region, 'byRegion')
        .addAggregation('totalSales', 0, (acc, record) => acc + (record.total || 0))
        .addAggregation('itemCount', 0, (acc, record) => acc + (record.qty || 0))
        .addAggregation('avgPrice', { sum: 0, count: 0 }, (acc, record) => ({
            sum: acc.sum + record.price,
            count: acc.count + 1
        }));

    // Create and execute pipeline
    const pipeline = new DataPipeline(source)
        .addTransformer(transformer)
        .addFilter(record => record.category !== 'Services') // Exclude services
        .setAggregator(aggregator);

    const results = pipeline.execute();

    console.log('Pipeline Results:');
    console.log(JSON.stringify(results, null, 2));

    // Test CSV parsing
    const csvData = `name,age,city
John,30,New York
Jane,25,Los Angeles
Bob,35,Chicago`;

    const csvSource = DataSource.fromCSV(csvData);
    const csvTransformer = new DataTransformer()
        .addFieldCalculation('ageGroup', record => {
            const age = parseInt(record.age);
            if (age < 30) return 'Young';
            if (age < 40) return 'Middle';
            return 'Senior';
        });

    const csvPipeline = new DataPipeline(csvSource)
        .addTransformer(csvTransformer);

    const csvResults = csvPipeline.execute();

    return {
        salesAnalysis: results,
        csvProcessing: csvResults.map(item => item.record),
        pipelineStats: pipeline.getStats()
    };
}

// Execute the test
const result = testDataPipeline();
console.log('\nFinal result:', JSON.stringify(result, null, 2));

// Export for module testing
if (typeof module !== 'undefined') {
    module.exports = { DataSource, DataTransformer, DataAggregator, DataPipeline };
}