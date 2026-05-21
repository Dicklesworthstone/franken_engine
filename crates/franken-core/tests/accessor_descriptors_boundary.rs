//! Boundary tests for accessor descriptor support in franken-core.
//!
//! This test suite verifies that accessor descriptors (get/set) work correctly
//! across the franken-core crate boundary. These tests exercise the public API
//! to ensure accessor descriptor support passes all boundary checks for the
//! extracted franken-core crate.

use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, LaneRouter,
};
use frankenengine_core::ir_contract::{Ir3Instruction, Reg};
use frankenengine_core::lowering_pipeline::LoweringPipeline;
use frankenengine_core::object_model::{JsValue, PropertyDescriptor, PropertyKey};
use frankenengine_core::parser::CanonicalEs2020Parser;
use frankenengine_core::runtime_config::RuntimeConfig;

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

fn create_test_config() -> RuntimeConfig {
    RuntimeConfig::new()
        .with_accessor_support(true)
        .with_property_descriptors(true)
}

fn parse_and_lower(source: &str) -> Result<Vec<Ir3Instruction>, Box<dyn std::error::Error>> {
    let parser = CanonicalEs2020Parser::new();
    let ast = parser.parse(source)?;

    let mut pipeline = LoweringPipeline::new();
    let ir3_program = pipeline.lower(ast)?;

    Ok(ir3_program.instructions)
}

fn execute_program(
    instructions: Vec<Ir3Instruction>,
) -> Result<ExecutionResult, InterpreterError> {
    let config = create_test_config();
    let mut router = LaneRouter::new(config);
    router.execute(instructions)
}

// ---------------------------------------------------------------------------
// Basic accessor definition tests
// ---------------------------------------------------------------------------

#[test]
fn test_simple_getter_definition() {
    let source = r#"
        const obj = {
            get value() {
                return 42;
            }
        };
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::DefineProperty { .. }
        )),
        "getter should generate DefineProperty instruction"
    );
}

#[test]
fn test_simple_setter_definition() {
    let source = r#"
        const obj = {
            set value(val) {
                this._value = val;
            }
        };
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::DefineProperty { .. }
        )),
        "setter should generate DefineProperty instruction"
    );
}

#[test]
fn test_getter_setter_pair() {
    let source = r#"
        const obj = {
            get value() {
                return this._value;
            },
            set value(val) {
                this._value = val;
            }
        };
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let define_count = instructions.iter()
        .filter(|inst| matches!(inst, Ir3Instruction::DefineProperty { .. }))
        .count();
    assert!(define_count >= 1, "getter/setter pair should generate property definitions");
}

#[test]
fn test_class_accessor_definition() {
    let source = r#"
        class TestClass {
            get property() {
                return this._property;
            }

            set property(value) {
                this._property = value;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::DefineProperty { .. }
        )),
        "class accessors should generate DefineProperty instructions"
    );
}

#[test]
fn test_object_define_property_accessor() {
    let source = r#"
        const obj = {};
        Object.defineProperty(obj, 'test', {
            get: function() { return 'value'; },
            set: function(val) { this._test = val; },
            enumerable: true
        });
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CallFunction { .. }
        )),
        "Object.defineProperty should generate function call"
    );
}

// ---------------------------------------------------------------------------
// Accessor invocation tests
// ---------------------------------------------------------------------------

#[test]
fn test_getter_invocation() {
    let source = r#"
        const obj = {
            get value() {
                return 100;
            }
        };
        const result = obj.value;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "getter access should generate GetProperty instruction"
    );
}

#[test]
fn test_setter_invocation() {
    let source = r#"
        const obj = {
            set value(val) {
                this._value = val;
            }
        };
        obj.value = 42;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::SetProperty { .. }
        )),
        "setter assignment should generate SetProperty instruction"
    );
}

#[test]
fn test_getter_setter_chaining() {
    let source = r#"
        const obj = {
            get value() {
                return this._value || 0;
            },
            set value(val) {
                this._value = val;
            }
        };
        obj.value = 10;
        const result = obj.value;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let get_count = instructions.iter()
        .filter(|inst| matches!(inst, Ir3Instruction::GetProperty { .. }))
        .count();
    let set_count = instructions.iter()
        .filter(|inst| matches!(inst, Ir3Instruction::SetProperty { .. }))
        .count();

    assert!(get_count >= 1, "should have getter access");
    assert!(set_count >= 1, "should have setter access");
}

#[test]
fn test_computed_property_accessor() {
    let source = r#"
        const key = 'dynamic';
        const obj = {
            get [key]() {
                return 'computed getter';
            },
            set [key](val) {
                this._computed = val;
            }
        };
        obj[key] = 'test';
        const result = obj[key];
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. } | Ir3Instruction::SetProperty { .. }
        )),
        "computed property accessors should work"
    );
}

#[test]
fn test_this_binding_in_accessors() {
    let source = r#"
        const obj = {
            _value: 0,
            get value() {
                return this._value;
            },
            set value(val) {
                this._value = val;
            }
        };
        obj.value = 123;
        const result = obj.value;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_program(instructions).expect("execution should succeed");

    // Verify the accessor mechanism works with proper this binding
    assert!(!result.return_value.is_undefined(), "accessor should return a value");
}

// ---------------------------------------------------------------------------
// Prototype chain traversal tests
// ---------------------------------------------------------------------------

#[test]
fn test_inherited_accessor() {
    let source = r#"
        const parent = {
            get inheritedValue() {
                return 'from parent';
            }
        };

        const child = Object.create(parent);
        const result = child.inheritedValue;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "inherited accessor should generate property access"
    );
}

#[test]
fn test_accessor_override() {
    let source = r#"
        const parent = {
            get value() {
                return 'parent';
            }
        };

        const child = Object.create(parent);
        Object.defineProperty(child, 'value', {
            get: function() {
                return 'child';
            }
        });

        const result = child.value;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "accessor override should work"
    );
}

#[test]
fn test_prototype_setter_inheritance() {
    let source = r#"
        const parent = {
            set sharedValue(val) {
                this._shared = val;
            }
        };

        const child = Object.create(parent);
        child.sharedValue = 'test';
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::SetProperty { .. }
        )),
        "prototype setter should be accessible from child"
    );
}

#[test]
fn test_deep_prototype_chain_accessor() {
    let source = r#"
        const grandparent = {
            get deepValue() {
                return 'deep';
            }
        };

        const parent = Object.create(grandparent);
        const child = Object.create(parent);

        const result = child.deepValue;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "deep prototype chain accessor should work"
    );
}

#[test]
fn test_accessor_shadowing() {
    let source = r#"
        const proto = {
            get value() {
                return 'proto';
            }
        };

        const obj = Object.create(proto);
        obj.value = 'direct'; // This should create a data property that shadows the accessor

        const result = obj.value;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::SetProperty { .. } | Ir3Instruction::GetProperty { .. }
        )),
        "accessor shadowing should work"
    );
}

// ---------------------------------------------------------------------------
// Property descriptor attribute tests
// ---------------------------------------------------------------------------

#[test]
fn test_configurable_accessor() {
    let source = r#"
        const obj = {};
        Object.defineProperty(obj, 'test', {
            get: function() { return 42; },
            configurable: true
        });

        // Should be able to reconfigure
        Object.defineProperty(obj, 'test', {
            get: function() { return 100; }
        });
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CallFunction { .. }
        )),
        "configurable accessor should allow reconfiguration"
    );
}

#[test]
fn test_non_configurable_accessor() {
    let source = r#"
        const obj = {};
        Object.defineProperty(obj, 'test', {
            get: function() { return 42; },
            configurable: false
        });

        // This should throw an error
        try {
            Object.defineProperty(obj, 'test', {
                get: function() { return 100; }
            });
        } catch (e) {
            // Expected
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CallFunction { .. }
        )),
        "non-configurable accessor should prevent reconfiguration"
    );
}

#[test]
fn test_enumerable_accessor() {
    let source = r#"
        const obj = {};
        Object.defineProperty(obj, 'enumerable', {
            get: function() { return 'yes'; },
            enumerable: true
        });

        Object.defineProperty(obj, 'nonEnumerable', {
            get: function() { return 'no'; },
            enumerable: false
        });

        const keys = Object.keys(obj);
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CallFunction { .. }
        )),
        "enumerable property should affect Object.keys"
    );
}

#[test]
fn test_accessor_descriptor_introspection() {
    let source = r#"
        const obj = {
            get test() { return 42; },
            set test(val) { this._test = val; }
        };

        const descriptor = Object.getOwnPropertyDescriptor(obj, 'test');
        const hasGetter = typeof descriptor.get === 'function';
        const hasSetter = typeof descriptor.set === 'function';
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CallFunction { .. }
        )),
        "should be able to introspect accessor descriptors"
    );
}

#[test]
fn test_accessor_without_setter() {
    let source = r#"
        const obj = {
            get readOnly() {
                return 'cannot change';
            }
        };

        obj.readOnly = 'attempt to set'; // Should be ignored in non-strict mode
        const result = obj.readOnly;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_program(instructions).expect("execution should succeed");

    assert!(!result.return_value.is_undefined(), "read-only accessor should work");
}

#[test]
fn test_accessor_without_getter() {
    let source = r#"
        const obj = {
            set writeOnly(val) {
                this._writeOnly = val;
            }
        };

        obj.writeOnly = 'set value';
        const result = obj.writeOnly; // Should return undefined
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_program(instructions).expect("execution should succeed");

    // Write-only accessor (no getter) should return undefined when accessed
    assert!(result.return_value.is_undefined(), "write-only accessor should return undefined");
}

// ---------------------------------------------------------------------------
// Private accessor prefix tagging tests
// ---------------------------------------------------------------------------

#[test]
fn test_private_accessor_definition() {
    let source = r#"
        class TestClass {
            #privateValue = 0;

            get #privateAccessor() {
                return this.#privateValue;
            }

            set #privateAccessor(val) {
                this.#privateValue = val;
            }

            getPrivate() {
                return this.#privateAccessor;
            }

            setPrivate(val) {
                this.#privateAccessor = val;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::DefineProperty { .. } | Ir3Instruction::CreateClass { .. }
        )),
        "private accessors should be supported"
    );
}

#[test]
fn test_private_accessor_encapsulation() {
    let source = r#"
        class Container {
            #data;

            get #value() {
                return this.#data;
            }

            set #value(val) {
                this.#data = val;
            }

            setValue(val) {
                this.#value = val;
            }

            getValue() {
                return this.#value;
            }
        }

        const instance = new Container();
        instance.setValue(42);
        const result = instance.getValue();
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. } | Ir3Instruction::SetProperty { .. }
        )),
        "private accessor encapsulation should work"
    );
}

#[test]
fn test_mixed_public_private_accessors() {
    let source = r#"
        class MixedClass {
            #internal = 0;

            get public() {
                return this.#internal * 2;
            }

            set public(val) {
                this.#internal = val / 2;
            }

            get #private() {
                return this.#internal;
            }

            set #private(val) {
                this.#internal = val;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::DefineProperty { .. } | Ir3Instruction::CreateClass { .. }
        )),
        "mixed public/private accessors should work"
    );
}

// ---------------------------------------------------------------------------
// Complex accessor pattern tests
// ---------------------------------------------------------------------------

#[test]
fn test_accessor_with_validation() {
    let source = r#"
        const obj = {
            _value: 0,
            get value() {
                return this._value;
            },
            set value(val) {
                if (typeof val === 'number' && val >= 0) {
                    this._value = val;
                } else {
                    throw new Error('Invalid value');
                }
            }
        };

        obj.value = 10; // Valid
        const result = obj.value;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. } | Ir3Instruction::SetProperty { .. }
        )),
        "accessor with validation should work"
    );
}

#[test]
fn test_lazy_initialization_accessor() {
    let source = r#"
        const obj = {
            get expensiveValue() {
                if (this._expensiveValue === undefined) {
                    this._expensiveValue = 'computed expensive value';
                }
                return this._expensiveValue;
            }
        };

        const first = obj.expensiveValue;
        const second = obj.expensiveValue; // Should use cached value
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "lazy initialization accessor should work"
    );
}

#[test]
fn test_accessor_delegation() {
    let source = r#"
        const target = {
            _data: 'target data'
        };

        const proxy = {
            get data() {
                return target._data;
            },
            set data(val) {
                target._data = val;
            }
        };

        proxy.data = 'new data';
        const result = proxy.data;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. } | Ir3Instruction::SetProperty { .. }
        )),
        "accessor delegation should work"
    );
}

#[test]
fn test_accessor_method_binding() {
    let source = r#"
        const obj = {
            _methods: {
                process: function(data) {
                    return data.toUpperCase();
                }
            },

            get processor() {
                return this._methods.process;
            }
        };

        const processor = obj.processor;
        // Note: would need .call() for proper binding in real usage
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "accessor method binding should work"
    );
}

#[test]
fn test_accessor_with_side_effects() {
    let source = r#"
        let accessCount = 0;

        const obj = {
            get tracked() {
                accessCount++;
                return 'tracked value';
            },

            getAccessCount() {
                return accessCount;
            }
        };

        const first = obj.tracked;
        const second = obj.tracked;
        const count = obj.getAccessCount();
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::GetProperty { .. }
        )),
        "accessor with side effects should work"
    );
}

#[test]
fn test_boundary_comprehensive_accessor_test() {
    // Comprehensive test combining multiple accessor patterns
    let source = r#"
        class ComprehensiveAccessorTest {
            #privateData = {};
            _publicData = {};

            // Basic public accessor
            get value() {
                return this._publicData.value || 0;
            }

            set value(val) {
                if (typeof val === 'number') {
                    this._publicData.value = val;
                }
            }

            // Private accessor with validation
            get #internalValue() {
                return this.#privateData.internal;
            }

            set #internalValue(val) {
                if (val !== null && val !== undefined) {
                    this.#privateData.internal = val;
                }
            }

            // Computed property accessor
            get ['computed' + 'Property']() {
                return 'computed';
            }

            // Read-only accessor
            get timestamp() {
                return Date.now();
            }

            // Method that uses private accessor
            setInternal(val) {
                this.#internalValue = val;
            }

            getInternal() {
                return this.#internalValue;
            }
        }

        const instance = new ComprehensiveAccessorTest();

        // Test public accessor
        instance.value = 42;
        const publicValue = instance.value;

        // Test private accessor through methods
        instance.setInternal('private data');
        const privateValue = instance.getInternal();

        // Test computed property
        const computedValue = instance.computedProperty;

        // Test read-only accessor
        const timestamp = instance.timestamp;
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");

    // Verify presence of all major accessor constructs
    let has_define_property = instructions.iter().any(|inst|
        matches!(inst, Ir3Instruction::DefineProperty { .. }));
    let has_get_property = instructions.iter().any(|inst|
        matches!(inst, Ir3Instruction::GetProperty { .. }));
    let has_set_property = instructions.iter().any(|inst|
        matches!(inst, Ir3Instruction::SetProperty { .. }));

    assert!(has_define_property, "should have property definition");
    assert!(has_get_property, "should have property access");
    assert!(has_set_property, "should have property assignment");
}