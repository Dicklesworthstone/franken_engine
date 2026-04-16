// Real-world program #7: Validation Library with Regex and Builder Pattern
// Features: Regular expressions, ES2015 classes, builder pattern, error accumulation, Map/Set

class ValidationError {
    constructor(field, value, rule, message) {
        this.field = field;
        this.value = value;
        this.rule = rule;
        this.message = message;
        this.timestamp = new Date().toISOString();
    }

    toString() {
        return `ValidationError: ${this.field} - ${this.message}`;
    }

    toJSON() {
        return {
            field: this.field,
            value: this.value,
            rule: this.rule,
            message: this.message,
            timestamp: this.timestamp
        };
    }
}

class ValidationRule {
    constructor(name, pattern, message, options = {}) {
        this.name = name;
        this.pattern = pattern instanceof RegExp ? pattern : new RegExp(pattern);
        this.message = message;
        this.options = {
            required: false,
            allowEmpty: false,
            caseSensitive: true,
            ...options
        };
    }

    test(value, field = 'unknown') {
        // Handle null/undefined
        if (value == null) {
            if (this.options.required) {
                return new ValidationError(field, value, this.name, 'This field is required');
            }
            return null; // Valid if not required
        }

        // Convert to string for testing
        const stringValue = String(value);

        // Handle empty strings
        if (stringValue === '') {
            if (this.options.required) {
                return new ValidationError(field, value, this.name, 'This field cannot be empty');
            }
            if (!this.options.allowEmpty) {
                return new ValidationError(field, value, this.name, 'Empty values are not allowed');
            }
            return null; // Valid empty
        }

        // Apply case sensitivity
        const testValue = this.options.caseSensitive ?
            stringValue : stringValue.toLowerCase();

        // Test against pattern
        const testPattern = this.options.caseSensitive ?
            this.pattern : new RegExp(this.pattern.source, this.pattern.flags + 'i');

        if (!testPattern.test(testValue)) {
            return new ValidationError(field, value, this.name, this.message);
        }

        return null; // Valid
    }

    clone() {
        return new ValidationRule(this.name, this.pattern, this.message, { ...this.options });
    }
}

// Pre-built validation rules
class CommonValidators {
    static email() {
        return new ValidationRule(
            'email',
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            'Must be a valid email address'
        );
    }

    static phone() {
        return new ValidationRule(
            'phone',
            /^\+?[\d\s\-\(\)]{10,}$/,
            'Must be a valid phone number'
        );
    }

    static url() {
        return new ValidationRule(
            'url',
            /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/,
            'Must be a valid URL'
        );
    }

    static password(minLength = 8) {
        return new ValidationRule(
            'password',
            new RegExp(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{${minLength},}$`),
            `Must be at least ${minLength} characters with uppercase, lowercase, number, and special character`
        );
    }

    static alphanumeric() {
        return new ValidationRule(
            'alphanumeric',
            /^[a-zA-Z0-9]+$/,
            'Must contain only letters and numbers'
        );
    }

    static numeric() {
        return new ValidationRule(
            'numeric',
            /^[\d.]+$/,
            'Must be a number'
        );
    }

    static integer() {
        return new ValidationRule(
            'integer',
            /^-?\d+$/,
            'Must be an integer'
        );
    }

    static creditCard() {
        return new ValidationRule(
            'creditCard',
            /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$/,
            'Must be a valid credit card number'
        );
    }

    static zipCode() {
        return new ValidationRule(
            'zipCode',
            /^\d{5}(-\d{4})?$/,
            'Must be a valid ZIP code (12345 or 12345-6789)'
        );
    }

    static ipAddress() {
        return new ValidationRule(
            'ipAddress',
            /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
            'Must be a valid IP address'
        );
    }

    static hexColor() {
        return new ValidationRule(
            'hexColor',
            /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
            'Must be a valid hex color (#RGB or #RRGGBB)'
        );
    }

    static length(min, max = Infinity) {
        return new ValidationRule(
            'length',
            new RegExp(`^.{${min},${max === Infinity ? '' : max}}$`),
            `Must be between ${min} and ${max === Infinity ? 'unlimited' : max} characters`
        );
    }
}

class FieldValidator {
    constructor(fieldName) {
        this.fieldName = fieldName;
        this.rules = [];
        this.customValidators = [];
        this.transformers = [];
    }

    // Add validation rule
    addRule(rule) {
        if (!(rule instanceof ValidationRule)) {
            throw new Error('Rule must be a ValidationRule instance');
        }
        this.rules.push(rule);
        return this;
    }

    // Add custom validator function
    addCustomValidator(name, validatorFn, message) {
        this.customValidators.push({
            name,
            validate: validatorFn,
            message
        });
        return this;
    }

    // Add value transformer
    addTransformer(transformerFn) {
        this.transformers.push(transformerFn);
        return this;
    }

    // Convenience methods for common rules
    required() {
        const rule = new ValidationRule('required', /.*/, 'This field is required');
        rule.options.required = true;
        return this.addRule(rule);
    }

    email() {
        return this.addRule(CommonValidators.email());
    }

    phone() {
        return this.addRule(CommonValidators.phone());
    }

    url() {
        return this.addRule(CommonValidators.url());
    }

    password(minLength) {
        return this.addRule(CommonValidators.password(minLength));
    }

    length(min, max) {
        return this.addRule(CommonValidators.length(min, max));
    }

    pattern(regex, message) {
        return this.addRule(new ValidationRule('custom', regex, message));
    }

    // Custom validation methods
    matches(otherField, message = 'Fields must match') {
        return this.addCustomValidator('matches', (value, allData) => {
            return value === allData[otherField];
        }, message);
    }

    oneOf(allowedValues, message = 'Value not in allowed list') {
        return this.addCustomValidator('oneOf', (value) => {
            return allowedValues.includes(value);
        }, message);
    }

    range(min, max, message = `Value must be between ${min} and ${max}`) {
        return this.addCustomValidator('range', (value) => {
            const num = parseFloat(value);
            return !isNaN(num) && num >= min && num <= max;
        }, message);
    }

    // Validate a value
    validate(value, allData = {}) {
        const errors = [];

        // Apply transformers
        let transformedValue = value;
        for (const transformer of this.transformers) {
            try {
                transformedValue = transformer(transformedValue);
            } catch (error) {
                errors.push(new ValidationError(
                    this.fieldName,
                    value,
                    'transformer',
                    `Transformation failed: ${error.message}`
                ));
                break;
            }
        }

        // Test validation rules
        for (const rule of this.rules) {
            const error = rule.test(transformedValue, this.fieldName);
            if (error) {
                errors.push(error);
            }
        }

        // Test custom validators
        for (const validator of this.customValidators) {
            try {
                if (!validator.validate(transformedValue, allData)) {
                    errors.push(new ValidationError(
                        this.fieldName,
                        transformedValue,
                        validator.name,
                        validator.message
                    ));
                }
            } catch (error) {
                errors.push(new ValidationError(
                    this.fieldName,
                    transformedValue,
                    validator.name,
                    `Validation failed: ${error.message}`
                ));
            }
        }

        return {
            value: transformedValue,
            errors,
            isValid: errors.length === 0
        };
    }
}

class SchemaValidator {
    constructor() {
        this.fields = new Map();
        this.globalValidators = [];
        this.options = {
            stopOnFirstError: false,
            allowUnknownFields: true,
            stripUnknownFields: false
        };
    }

    // Configure validation options
    configure(options) {
        this.options = { ...this.options, ...options };
        return this;
    }

    // Add field validator
    field(fieldName) {
        const validator = new FieldValidator(fieldName);
        this.fields.set(fieldName, validator);
        return validator;
    }

    // Add global validator (validates entire object)
    addGlobalValidator(name, validatorFn, message) {
        this.globalValidators.push({
            name,
            validate: validatorFn,
            message
        });
        return this;
    }

    // Get field validator
    getField(fieldName) {
        return this.fields.get(fieldName);
    }

    // Remove field validator
    removeField(fieldName) {
        this.fields.delete(fieldName);
        return this;
    }

    // Validate an object
    validate(data) {
        const result = {
            isValid: true,
            errors: [],
            fieldErrors: new Map(),
            globalErrors: [],
            validatedData: {},
            summary: {
                totalFields: 0,
                validFields: 0,
                invalidFields: 0,
                totalErrors: 0
            }
        };

        // Validate each defined field
        for (const [fieldName, validator] of this.fields) {
            result.summary.totalFields++;

            const fieldResult = validator.validate(data[fieldName], data);
            result.validatedData[fieldName] = fieldResult.value;

            if (!fieldResult.isValid) {
                result.isValid = false;
                result.summary.invalidFields++;
                result.summary.totalErrors += fieldResult.errors.length;

                result.fieldErrors.set(fieldName, fieldResult.errors);
                result.errors.push(...fieldResult.errors);

                if (this.options.stopOnFirstError) {
                    break;
                }
            } else {
                result.summary.validFields++;
            }
        }

        // Handle unknown fields
        if (!this.options.allowUnknownFields || this.options.stripUnknownFields) {
            for (const fieldName in data) {
                if (!this.fields.has(fieldName)) {
                    if (!this.options.allowUnknownFields) {
                        result.isValid = false;
                        const error = new ValidationError(
                            fieldName,
                            data[fieldName],
                            'unknown',
                            'Unknown field not allowed'
                        );
                        result.errors.push(error);
                        result.summary.totalErrors++;
                    }

                    if (!this.options.stripUnknownFields) {
                        result.validatedData[fieldName] = data[fieldName];
                    }
                }
            }
        } else {
            // Include all fields in validated data
            for (const fieldName in data) {
                if (!this.fields.has(fieldName)) {
                    result.validatedData[fieldName] = data[fieldName];
                }
            }
        }

        // Run global validators
        for (const validator of this.globalValidators) {
            try {
                if (!validator.validate(result.validatedData)) {
                    result.isValid = false;
                    const error = new ValidationError(
                        'global',
                        result.validatedData,
                        validator.name,
                        validator.message
                    );
                    result.globalErrors.push(error);
                    result.errors.push(error);
                    result.summary.totalErrors++;
                }
            } catch (error) {
                result.isValid = false;
                const validationError = new ValidationError(
                    'global',
                    result.validatedData,
                    validator.name,
                    `Global validation failed: ${error.message}`
                );
                result.globalErrors.push(validationError);
                result.errors.push(validationError);
                result.summary.totalErrors++;
            }
        }

        return result;
    }

    // Create a schema from a configuration object
    static fromConfig(config) {
        const schema = new SchemaValidator();

        for (const [fieldName, fieldConfig] of Object.entries(config)) {
            const field = schema.field(fieldName);

            for (const [ruleName, ruleConfig] of Object.entries(fieldConfig)) {
                switch (ruleName) {
                    case 'required':
                        if (ruleConfig) field.required();
                        break;
                    case 'email':
                        if (ruleConfig) field.email();
                        break;
                    case 'phone':
                        if (ruleConfig) field.phone();
                        break;
                    case 'url':
                        if (ruleConfig) field.url();
                        break;
                    case 'password':
                        field.password(ruleConfig.minLength || 8);
                        break;
                    case 'length':
                        field.length(ruleConfig.min || 0, ruleConfig.max);
                        break;
                    case 'pattern':
                        field.pattern(new RegExp(ruleConfig.regex), ruleConfig.message);
                        break;
                    case 'oneOf':
                        field.oneOf(ruleConfig.values, ruleConfig.message);
                        break;
                    case 'range':
                        field.range(ruleConfig.min, ruleConfig.max, ruleConfig.message);
                        break;
                }
            }
        }

        return schema;
    }
}

// Test the validation library
function testValidationLibrary() {
    console.log('Testing Validation Library with Regex and Builder Pattern...');

    // Test individual validators
    const emailValidator = CommonValidators.email();
    const phoneValidator = CommonValidators.phone();
    const passwordValidator = CommonValidators.password();

    const testCases = [
        { validator: emailValidator, value: 'user@example.com', shouldPass: true },
        { validator: emailValidator, value: 'invalid-email', shouldPass: false },
        { validator: phoneValidator, value: '+1-555-123-4567', shouldPass: true },
        { validator: phoneValidator, value: '123', shouldPass: false },
        { validator: passwordValidator, value: 'StrongPass123!', shouldPass: true },
        { validator: passwordValidator, value: 'weak', shouldPass: false },
    ];

    const validatorResults = testCases.map(({ validator, value, shouldPass }) => {
        const error = validator.test(value, 'test');
        const passed = error === null;
        return {
            validator: validator.name,
            value,
            expectedPass: shouldPass,
            actuallyPassed: passed,
            correct: passed === shouldPass,
            error: error ? error.message : null
        };
    });

    // Test schema validation
    const userSchema = new SchemaValidator();

    userSchema.field('email')
        .required()
        .email();

    userSchema.field('password')
        .required()
        .password(8);

    userSchema.field('confirmPassword')
        .required()
        .matches('password');

    userSchema.field('age')
        .required()
        .range(18, 120);

    userSchema.field('username')
        .required()
        .length(3, 20)
        .pattern(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores');

    userSchema.field('website')
        .url();

    userSchema.addGlobalValidator('passwordSecure', (data) => {
        return data.password && data.password !== data.username;
    }, 'Password cannot be the same as username');

    // Test data sets
    const validUser = {
        email: 'john@example.com',
        password: 'SecurePass123!',
        confirmPassword: 'SecurePass123!',
        age: 25,
        username: 'john_doe',
        website: 'https://johndoe.com'
    };

    const invalidUser = {
        email: 'invalid-email',
        password: 'weak',
        confirmPassword: 'different',
        age: 15,
        username: 'jo',
        website: 'not-a-url',
        unexpectedField: 'value'
    };

    const validResult = userSchema.validate(validUser);
    const invalidResult = userSchema.validate(invalidUser);

    // Test configuration-based schema
    const configSchema = SchemaValidator.fromConfig({
        title: {
            required: true,
            length: { min: 5, max: 100 }
        },
        description: {
            required: true,
            length: { min: 10 }
        },
        category: {
            required: true,
            oneOf: { values: ['tech', 'science', 'art'], message: 'Must be a valid category' }
        },
        priority: {
            required: true,
            range: { min: 1, max: 10 }
        }
    });

    const configTestData = {
        title: 'Test Article Title',
        description: 'This is a test article description that is long enough.',
        category: 'tech',
        priority: 5
    };

    const configResult = configSchema.validate(configTestData);

    return {
        individualValidators: {
            testCases: validatorResults,
            correctCount: validatorResults.filter(r => r.correct).length,
            totalCount: validatorResults.length
        },
        schemaValidation: {
            validUser: {
                isValid: validResult.isValid,
                errorCount: validResult.errors.length,
                summary: validResult.summary
            },
            invalidUser: {
                isValid: invalidResult.isValid,
                errorCount: invalidResult.errors.length,
                fieldErrorCount: invalidResult.fieldErrors.size,
                globalErrorCount: invalidResult.globalErrors.length,
                summary: invalidResult.summary,
                sampleErrors: invalidResult.errors.slice(0, 3).map(e => ({
                    field: e.field,
                    rule: e.rule,
                    message: e.message
                }))
            }
        },
        configBasedValidation: {
            isValid: configResult.isValid,
            errorCount: configResult.errors.length,
            summary: configResult.summary
        },
        verification: {
            allValidatorTestsPassed: validatorResults.every(r => r.correct),
            validUserPassed: validResult.isValid,
            invalidUserFailed: !invalidResult.isValid,
            configValidationWorked: configResult.isValid
        }
    };
}

// Execute the test
const result = testValidationLibrary();
console.log('\nValidation Library Test Results:');
console.log(JSON.stringify(result, null, 2));

// Export for module testing
if (typeof module !== 'undefined') {
    module.exports = {
        ValidationError,
        ValidationRule,
        CommonValidators,
        FieldValidator,
        SchemaValidator
    };
}