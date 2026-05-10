#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== Class Semantics E2E Test Suite ==="

RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${CLASS_SEMANTICS_E2E_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_class_semantics_$(date +%s)_$$}"
LOG="artifacts/test_classes_$(date +%s).jsonl"
mkdir -p artifacts

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "Required rch binary not found: $RCH_BIN" >&2
    exit 2
fi

run_frankenctl() {
    local step_name="$1"
    shift

    local output_file="artifacts/test_classes_${step_name}.rch.log"

    "$RCH_BIN" exec -- env \
        "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
        "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
        "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
        cargo run --bin frankenctl -- "$@" 2>&1 | tee "$output_file"
    local status=${PIPESTATUS[0]}

    if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$output_file"; then
        echo "rch reported local fallback for $step_name; refusing local execution" >&2
        return 125
    fi

    return "$status"
}

function run_test() {
    local test_name="$1"
    local test_file="$2"
    local expected_output="$3"

    echo "Running test: $test_name"
    local start_time
    start_time=$(date +%s.%N)

    if run_frankenctl "$test_name" run --input "$test_file" --out /tmp/fe_result.json; then
        local exit_code=0
        local result
        result=$(jq -r .execution_value /tmp/fe_result.json 2>/dev/null || echo "parse_error")
        if [[ "$result" == "$expected_output" ]]; then
            echo "✓ $test_name PASSED"
            local status="pass"
        else
            echo "✗ $test_name FAILED: expected '$expected_output', got '$result'"
            local status="fail"
        fi
    else
        local exit_code=$?
        echo "✗ $test_name FAILED: exit code $exit_code"
        local status="fail"
        local result="execution_error"
    fi

    local end_time
    end_time=$(date +%s.%N)
    local duration
    duration=$(echo "$end_time - $start_time" | bc -l)

    # Log to JSONL
    echo "{\"test\":\"$test_name\",\"exit\":$exit_code,\"time\":$duration,\"status\":\"$status\",\"result\":\"$result\",\"expected\":\"$expected_output\"}" >> "$LOG"
}

# Test 1: Basic class declaration and construction
cat > /tmp/fe_class_test1.js << 'EOF'
class Animal {
  constructor(name) {
    this.name = name;
  }
  speak() {
    return this.name + ' makes a sound';
  }
}
const a = new Animal('Dog');
a.speak();
EOF
run_test "basic_class_declaration" "/tmp/fe_class_test1.js" "Dog makes a sound"

# Test 2: Static methods
cat > /tmp/fe_class_test2.js << 'EOF'
class Animal {
  static getType() {
    return 'animal';
  }
}
Animal.getType();
EOF
run_test "static_methods" "/tmp/fe_class_test2.js" "animal"

# Test 3: Class inheritance with extends
cat > /tmp/fe_class_test3.js << 'EOF'
class Animal {
  constructor(name) {
    this.name = name;
  }
  speak() {
    return this.name + ' makes a sound';
  }
}
class Dog extends Animal {
  speak() {
    return this.name + ' barks';
  }
}
const d = new Dog('Buddy');
d.speak();
EOF
run_test "inheritance_extends" "/tmp/fe_class_test3.js" "Buddy barks"

# Test 4: Super constructor call
cat > /tmp/fe_class_test4.js << 'EOF'
class Animal {
  constructor(name) {
    this.name = name;
  }
}
class Dog extends Animal {
  constructor(name, breed) {
    super(name);
    this.breed = breed;
  }
  getInfo() {
    return this.name + ' is a ' + this.breed;
  }
}
const d = new Dog('Buddy', 'Golden Retriever');
d.getInfo();
EOF
run_test "super_constructor" "/tmp/fe_class_test4.js" "Buddy is a Golden Retriever"

# Test 5: Super method call
cat > /tmp/fe_class_test5.js << 'EOF'
class Animal {
  speak() {
    return 'Animal sound';
  }
}
class Dog extends Animal {
  speak() {
    return super.speak() + ' - but actually barks';
  }
}
const d = new Dog();
d.speak();
EOF
run_test "super_method" "/tmp/fe_class_test5.js" "Animal sound - but actually barks"

# Test 6: instanceof with inheritance
cat > /tmp/fe_class_test6.js << 'EOF'
class Animal {}
class Dog extends Animal {}
const d = new Dog();
d instanceof Dog && d instanceof Animal && d instanceof Object;
EOF
run_test "instanceof_inheritance" "/tmp/fe_class_test6.js" "true"

# Test 7: Getter methods
cat > /tmp/fe_class_test7.js << 'EOF'
class Person {
  constructor(firstName, lastName) {
    this.firstName = firstName;
    this.lastName = lastName;
  }
  get fullName() {
    return this.firstName + ' ' + this.lastName;
  }
}
const p = new Person('John', 'Doe');
p.fullName;
EOF
run_test "getter_methods" "/tmp/fe_class_test7.js" "John Doe"

# Test 8: Setter methods
cat > /tmp/fe_class_test8.js << 'EOF'
class Person {
  constructor() {
    this._name = '';
  }
  set name(value) {
    this._name = value.toUpperCase();
  }
  get name() {
    return this._name;
  }
}
const p = new Person();
p.name = 'john';
p.name;
EOF
run_test "setter_methods" "/tmp/fe_class_test8.js" "JOHN"

# Test 9: Computed method names
cat > /tmp/fe_class_test9.js << 'EOF'
class MyClass {
  ['computed' + 'Method']() {
    return 'computed result';
  }
}
const obj = new MyClass();
obj.computedMethod();
EOF
run_test "computed_method_names" "/tmp/fe_class_test9.js" "computed result"

# Test 10: Class expression
cat > /tmp/fe_class_test10.js << 'EOF'
const Animal = class {
  constructor(name) {
    this.name = name;
  }
  speak() {
    return this.name + ' speaks';
  }
};
const a = new Animal('Cat');
a.speak();
EOF
run_test "class_expression" "/tmp/fe_class_test10.js" "Cat speaks"

# Test 11: Constructor return value (object)
cat > /tmp/fe_class_test11.js << 'EOF'
class MyClass {
  constructor() {
    return { custom: 'object' };
  }
}
const obj = new MyClass();
obj.custom;
EOF
run_test "constructor_return_object" "/tmp/fe_class_test11.js" "object"

# Test 12: Constructor return value (primitive - should be ignored)
cat > /tmp/fe_class_test12.js << 'EOF'
class MyClass {
  constructor() {
    this.value = 'instance';
    return 'primitive'; // Should be ignored
  }
}
const obj = new MyClass();
obj.value;
EOF
run_test "constructor_return_primitive" "/tmp/fe_class_test12.js" "instance"

# Test 13: Three-level inheritance
cat > /tmp/fe_class_test13.js << 'EOF'
class Animal {
  getType() { return 'animal'; }
}
class Mammal extends Animal {
  getType() { return 'mammal'; }
}
class Dog extends Mammal {
  getType() { return 'dog'; }
}
const d = new Dog();
d instanceof Dog && d instanceof Mammal && d instanceof Animal;
EOF
run_test "three_level_inheritance" "/tmp/fe_class_test13.js" "true"

echo "=== Test Summary ==="
total_tests=$(wc -l < "$LOG")
passed_tests=$(jq -r 'select(.status == "pass")' "$LOG" | wc -l)
failed_tests=$((total_tests - passed_tests))

echo "Total tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

if [[ $failed_tests -eq 0 ]]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ $failed_tests tests failed"
    echo "See $LOG for details"
    exit 1
fi
