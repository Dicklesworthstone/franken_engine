# Property-Based Testing Manifest

## Document Metadata

- **Document ID**: PROP-TEST-V1
- **Version**: 1.0
- **Date**: 2026-04-20
- **Status**: Active
- **Purpose**: Define property-based testing framework for FrankenEngine correctness validation

## Overview

This manifest establishes a comprehensive property-based testing framework for FrankenEngine, employing systematic property verification, automated test case generation, and intelligent counterexample discovery. The framework ensures correctness through mathematical properties rather than exhaustive example-based testing.

## Property Catalog

### Core JavaScript Properties

#### Arithmetic Properties
```rust
// Associativity: (a + b) + c = a + (b + c)
#[proptest]
fn arithmetic_associativity(a: f64, b: f64, c: f64) {
    let left = engine.eval(&format!("({} + {}) + {}", a, b, c))?;
    let right = engine.eval(&format!("{} + ({} + {})", a, b, c))?;
    prop_assert_eq!(left, right, "Addition associativity violated");
}

// Commutativity: a + b = b + a
#[proptest]
fn arithmetic_commutativity(a: f64, b: f64) {
    let left = engine.eval(&format!("{} + {}", a, b))?;
    let right = engine.eval(&format!("{} + {}", b, a))?;
    prop_assert_eq!(left, right, "Addition commutativity violated");
}

// Identity: a + 0 = a
#[proptest]
fn arithmetic_identity(a: f64) {
    let result = engine.eval(&format!("{} + 0", a))?;
    prop_assert_eq!(result, a, "Addition identity violated");
}
```

#### Array Method Properties
```rust
// Map preserves length: arr.map(f).length === arr.length
#[proptest]
fn array_map_preserves_length(arr: Vec<i32>) {
    let original_len = arr.len();
    let result = engine.eval(&format!("{:?}.map(x => x * 2)", arr))?;
    let result_len = result.get_property("length")?;
    prop_assert_eq!(result_len, original_len, "Map length preservation violated");
}

// Filter reduces or maintains length: arr.filter(p).length <= arr.length
#[proptest]
fn array_filter_length_monotonic(arr: Vec<i32>) {
    let original_len = arr.len();
    let result = engine.eval(&format!("{:?}.filter(x => x > 0)", arr))?;
    let result_len = result.get_property("length")?;
    prop_assert!(result_len <= original_len, "Filter length monotonicity violated");
}

// Reduce composition: arr.reduce(f, init) consistency
#[proptest]
fn array_reduce_composition(arr: Vec<i32>, init: i32) {
    let direct = engine.eval(&format!("{:?}.reduce((acc, x) => acc + x, {})", arr, init))?;
    let manual = arr.iter().fold(init, |acc, &x| acc + x);
    prop_assert_eq!(direct, manual, "Reduce composition violated");
}
```

#### String Properties
```rust
// String concatenation associativity: (a + b) + c = a + (b + c)
#[proptest]
fn string_concat_associativity(a: String, b: String, c: String) {
    let left = engine.eval(&format!("({:?} + {:?}) + {:?}", a, b, c))?;
    let right = engine.eval(&format!("{:?} + ({:?} + {:?})", a, b, c))?;
    prop_assert_eq!(left, right, "String concatenation associativity violated");
}

// String length additivity: (a + b).length = a.length + b.length
#[proptest]
fn string_length_additivity(a: String, b: String) {
    let concat_len = engine.eval(&format!("({:?} + {:?}).length", a, b))?;
    let sum_len = a.len() + b.len();
    prop_assert_eq!(concat_len, sum_len, "String length additivity violated");
}
```

### Security Properties

#### Containment Invariants
```rust
// Capability monotonicity: capabilities can only be revoked, never gained
#[proptest]
fn capability_monotonicity(initial_caps: CapabilitySet, operations: Vec<SecurityOperation>) {
    let mut current_caps = initial_caps.clone();
    let mut engine_caps = engine.get_capabilities()?;
    
    for op in operations {
        engine.execute_security_operation(&op)?;
        let new_engine_caps = engine.get_capabilities()?;
        let new_expected_caps = apply_operation(&current_caps, &op);
        
        // Engine capabilities should never exceed expected capabilities
        prop_assert!(new_engine_caps.is_subset_of(&new_expected_caps), 
                    "Capability monotonicity violated: gained unexpected capabilities");
        
        current_caps = new_expected_caps;
        engine_caps = new_engine_caps;
    }
}

// Information flow: no data leakage across security boundaries
#[proptest]
fn information_flow_preservation(
    high_security_data: SecureData, 
    low_security_context: ExecutionContext
) {
    let result = engine.execute_in_context(&low_security_context, |engine| {
        // Attempt to access high security data
        engine.eval(&format!("globalThis.highSecData = {:?}", high_security_data))?;
        engine.eval("typeof globalThis.highSecData")?
    })?;
    
    prop_assert_eq!(result, "undefined", 
                   "Information flow violation: high security data accessible in low context");
}
```

#### Policy Consistency
```rust
// Policy decision determinism: same input -> same decision
#[proptest]
fn policy_decision_determinism(request: CapabilityRequest) {
    let decision1 = engine.evaluate_capability_request(&request)?;
    let decision2 = engine.evaluate_capability_request(&request)?;
    prop_assert_eq!(decision1, decision2, "Policy decision non-determinism detected");
}

// Policy transitivity: if A allows B and B allows C, then A allows C
#[proptest]
fn policy_transitivity(
    context_a: SecurityContext,
    context_b: SecurityContext, 
    context_c: SecurityContext,
    capability: Capability
) {
    let a_allows_b = engine.check_delegation(&context_a, &context_b, &capability)?;
    let b_allows_c = engine.check_delegation(&context_b, &context_c, &capability)?;
    
    if a_allows_b && b_allows_c {
        let a_allows_c = engine.check_delegation(&context_a, &context_c, &capability)?;
        prop_assert!(a_allows_c, "Policy transitivity violated");
    }
}
```

### Performance Properties

#### Asymptotic Complexity Bounds
```rust
// Array access should be O(1)
#[proptest]
fn array_access_constant_time(size: usize) {
    prop_assume!(size > 0 && size < 10_000);
    
    let arr = vec![42; size];
    let start = Instant::now();
    let _result = engine.eval(&format!("{}[{}]", arr, size / 2))?;
    let duration = start.elapsed();
    
    // Constant time should be under 1ms regardless of array size
    prop_assert!(duration < Duration::from_millis(1), 
                "Array access not constant time: {:?} for size {}", duration, size);
}

// Object property lookup should be O(log n) or better
#[proptest]
fn object_property_lookup_sublinear(properties: BTreeMap<String, i32>) {
    prop_assume!(properties.len() > 100);
    
    let obj_literal = format_object_literal(&properties);
    let random_key = properties.keys().nth(properties.len() / 2).unwrap();
    
    let start = Instant::now();
    let _result = engine.eval(&format!("({}).{}", obj_literal, random_key))?;
    let duration = start.elapsed();
    
    // Should be sublinear in number of properties
    let max_time = Duration::from_nanos((properties.len() as f64).log2() as u64 * 1000);
    prop_assert!(duration < max_time, 
                "Object property lookup not sublinear: {:?} for {} properties", 
                duration, properties.len());
}
```

## Arbitrary Generators

### Primitive Generators

#### JavaScript Value Generator
```rust
pub struct JSValueGenerator;

impl Arbitrary for JSValue {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            // Primitive values
            any::<bool>().prop_map(JSValue::Boolean),
            any::<i32>().prop_map(JSValue::Number),
            any::<f64>().prop_map(JSValue::Number),
            ".*".prop_map(JSValue::String),
            Just(JSValue::Null),
            Just(JSValue::Undefined),
            
            // Complex values (limited depth to prevent infinite recursion)
            prop::collection::vec(any::<JSValue>(), 0..10).prop_map(JSValue::Array),
            prop::collection::btree_map(".*", any::<JSValue>(), 0..10).prop_map(JSValue::Object),
        ].boxed()
    }
}
```

#### JavaScript AST Generator
```rust
#[derive(Debug, Clone)]
pub enum JSExpression {
    Literal(JSValue),
    Identifier(String),
    BinaryOp { left: Box<JSExpression>, op: BinaryOperator, right: Box<JSExpression> },
    UnaryOp { op: UnaryOperator, operand: Box<JSExpression> },
    CallExpression { callee: Box<JSExpression>, args: Vec<JSExpression> },
    MemberExpression { object: Box<JSExpression>, property: String },
}

impl Arbitrary for JSExpression {
    type Parameters = u32; // depth limit
    type Strategy = BoxedStrategy<Self>;
    
    fn arbitrary_with(depth: Self::Parameters) -> Self::Strategy {
        if depth == 0 {
            prop_oneof![
                any::<JSValue>().prop_map(JSExpression::Literal),
                "[a-zA-Z_][a-zA-Z0-9_]*".prop_map(JSExpression::Identifier),
            ].boxed()
        } else {
            prop_oneof![
                any::<JSValue>().prop_map(JSExpression::Literal),
                "[a-zA-Z_][a-zA-Z0-9_]*".prop_map(JSExpression::Identifier),
                (any::<JSExpression>().prop_recursive(depth, depth - 1, 5, |inner| {
                    (inner.clone(), any::<BinaryOperator>(), inner)
                        .prop_map(|(left, op, right)| JSExpression::BinaryOp {
                            left: Box::new(left),
                            op,
                            right: Box::new(right),
                        })
                })),
            ].boxed()
        }
    }
}
```

### Domain-Specific Generators

#### Security Context Generator
```rust
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub origin: String,
    pub capabilities: CapabilitySet,
    pub trust_level: TrustLevel,
    pub isolation_boundary: IsolationBoundary,
}

impl Arbitrary for SecurityContext {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            prop_oneof![
                "https://[a-z]{3,10}\\.com",
                "file://.*",
                "chrome-extension://[a-f0-9]{32}",
            ],
            any::<CapabilitySet>(),
            any::<TrustLevel>(),
            any::<IsolationBoundary>(),
        )
        .prop_map(|(origin, capabilities, trust_level, isolation_boundary)| {
            SecurityContext {
                origin,
                capabilities,
                trust_level,
                isolation_boundary,
            }
        })
        .boxed()
    }
}
```

#### Capability Request Generator
```rust
impl Arbitrary for CapabilityRequest {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<SecurityContext>(),
            prop_oneof![
                Just(Capability::FileSystemRead),
                Just(Capability::FileSystemWrite),
                Just(Capability::NetworkAccess),
                Just(Capability::ProcessSpawn),
                prop::collection::vec(any::<String>(), 1..5)
                    .prop_map(|paths| Capability::FileSystemReadPaths(paths)),
            ],
            prop::option::of(any::<String>()), // optional delegation token
        )
        .prop_map(|(context, capability, delegation_token)| {
            CapabilityRequest {
                context,
                capability,
                delegation_token,
            }
        })
        .boxed()
    }
}
```

## Shrinkers

### Value Shrinkers

#### JavaScript Value Shrinker
```rust
impl Shrink for JSValue {
    type Strategy = BoxedStrategy<Self>;
    
    fn shrink(&self) -> Self::Strategy {
        match self {
            JSValue::Boolean(b) => {
                if *b { 
                    Just(JSValue::Boolean(false)).boxed() 
                } else { 
                    prop::strategy::empty().boxed() 
                }
            }
            JSValue::Number(n) => {
                if n.fract() != 0.0 {
                    // Shrink to integer first
                    Just(JSValue::Number(n.trunc())).boxed()
                } else if *n != 0.0 {
                    // Shrink toward zero
                    Just(JSValue::Number(n / 2.0)).boxed()
                } else {
                    prop::strategy::empty().boxed()
                }
            }
            JSValue::String(s) => {
                if s.is_empty() {
                    prop::strategy::empty().boxed()
                } else if s.len() == 1 {
                    Just(JSValue::String(String::new())).boxed()
                } else {
                    prop_oneof![
                        Just(JSValue::String(s[..s.len()/2].to_string())),
                        Just(JSValue::String(s[s.len()/2..].to_string())),
                        Just(JSValue::String(String::new())),
                    ].boxed()
                }
            }
            JSValue::Array(arr) => {
                if arr.is_empty() {
                    prop::strategy::empty().boxed()
                } else {
                    prop_oneof![
                        // Remove elements
                        Just(JSValue::Array(arr[..arr.len()-1].to_vec())),
                        Just(JSValue::Array(arr[1..].to_vec())),
                        Just(JSValue::Array(vec![])),
                        // Shrink elements
                        prop::collection::vec(
                            any::<usize>().prop_ind_flat_map(|i| {
                                arr.get(i % arr.len()).unwrap_or(&JSValue::Undefined).shrink()
                            }), 
                            arr.len()
                        ).prop_map(JSValue::Array),
                    ].boxed()
                }
            }
            JSValue::Object(obj) => {
                if obj.is_empty() {
                    prop::strategy::empty().boxed()
                } else {
                    prop_oneof![
                        // Remove properties
                        Just(JSValue::Object(
                            obj.iter().take(obj.len() - 1).map(|(k, v)| (k.clone(), v.clone())).collect()
                        )),
                        Just(JSValue::Object(BTreeMap::new())),
                        // Shrink values
                        prop::collection::btree_map(
                            any::<String>(),
                            any::<String>().prop_ind_flat_map(|key| {
                                obj.get(&key).unwrap_or(&JSValue::Undefined).shrink()
                            }),
                            obj.len()
                        ).prop_map(JSValue::Object),
                    ].boxed()
                }
            }
            _ => prop::strategy::empty().boxed(),
        }
    }
}
```

### AST Shrinkers

#### Expression Shrinker
```rust
impl Shrink for JSExpression {
    type Strategy = BoxedStrategy<Self>;
    
    fn shrink(&self) -> Self::Strategy {
        match self {
            JSExpression::BinaryOp { left, op: _, right } => {
                prop_oneof![
                    // Shrink to operands
                    left.shrink(),
                    right.shrink(),
                    Just((**left).clone()),
                    Just((**right).clone()),
                    // Shrink to literals
                    Just(JSExpression::Literal(JSValue::Number(0.0))),
                    Just(JSExpression::Literal(JSValue::Number(1.0))),
                ].boxed()
            }
            JSExpression::UnaryOp { op: _, operand } => {
                prop_oneof![
                    operand.shrink(),
                    Just((**operand).clone()),
                    Just(JSExpression::Literal(JSValue::Number(0.0))),
                ].boxed()
            }
            JSExpression::CallExpression { callee, args } => {
                if args.is_empty() {
                    callee.shrink()
                } else {
                    prop_oneof![
                        callee.shrink(),
                        Just((**callee).clone()),
                        // Remove arguments
                        Just(JSExpression::CallExpression {
                            callee: callee.clone(),
                            args: args[..args.len()-1].to_vec(),
                        }),
                        // Shrink to first argument
                        Just(args[0].clone()),
                    ].boxed()
                }
            }
            JSExpression::MemberExpression { object, property: _ } => {
                prop_oneof![
                    object.shrink(),
                    Just((**object).clone()),
                    Just(JSExpression::Literal(JSValue::Undefined)),
                ].boxed()
            }
            _ => prop::strategy::empty().boxed(),
        }
    }
}
```

## Counterexample Minimization

### Delta Debugging Algorithm

#### Minimization Strategy
```rust
pub struct CounterexampleMinimizer {
    pub engine: Box<dyn JSEngine>,
    pub property_checker: Box<dyn Fn(&JSValue) -> bool>,
}

impl CounterexampleMinimizer {
    pub fn minimize_value(&self, failing_value: JSValue) -> Result<JSValue, MinimizationError> {
        let mut current = failing_value;
        let mut made_progress = true;
        
        while made_progress {
            made_progress = false;
            let candidates = self.generate_smaller_candidates(&current)?;
            
            for candidate in candidates {
                if self.check_property_violation(&candidate)? {
                    current = candidate;
                    made_progress = true;
                    break;
                }
            }
        }
        
        Ok(current)
    }
    
    fn generate_smaller_candidates(&self, value: &JSValue) -> Result<Vec<JSValue>, MinimizationError> {
        match value {
            JSValue::Array(arr) => {
                let mut candidates = Vec::new();
                
                // Remove elements (delta debugging)
                if arr.len() > 1 {
                    let half = arr.len() / 2;
                    candidates.push(JSValue::Array(arr[..half].to_vec()));
                    candidates.push(JSValue::Array(arr[half..].to_vec()));
                    
                    // Remove individual elements
                    for i in 0..arr.len() {
                        let mut smaller = arr.clone();
                        smaller.remove(i);
                        candidates.push(JSValue::Array(smaller));
                    }
                }
                
                // Recursively minimize elements
                for (i, element) in arr.iter().enumerate() {
                    for smaller_element in self.generate_smaller_candidates(element)? {
                        let mut smaller_array = arr.clone();
                        smaller_array[i] = smaller_element;
                        candidates.push(JSValue::Array(smaller_array));
                    }
                }
                
                Ok(candidates)
            }
            JSValue::String(s) => {
                let mut candidates = Vec::new();
                
                if !s.is_empty() {
                    // Binary search approach
                    if s.len() > 1 {
                        let half = s.len() / 2;
                        candidates.push(JSValue::String(s[..half].to_string()));
                        candidates.push(JSValue::String(s[half..].to_string()));
                    }
                    
                    // Character removal
                    for i in 0..s.len() {
                        let mut chars: Vec<char> = s.chars().collect();
                        chars.remove(i);
                        candidates.push(JSValue::String(chars.into_iter().collect()));
                    }
                    
                    // Common minimal strings
                    candidates.extend(vec![
                        JSValue::String("".to_string()),
                        JSValue::String("0".to_string()),
                        JSValue::String("1".to_string()),
                        JSValue::String("a".to_string()),
                    ]);
                }
                
                Ok(candidates)
            }
            JSValue::Number(n) => {
                let mut candidates = Vec::new();
                
                if *n != 0.0 {
                    candidates.push(JSValue::Number(0.0));
                    candidates.push(JSValue::Number(n / 2.0));
                    candidates.push(JSValue::Number(n.trunc()));
                    
                    if n.is_sign_positive() {
                        candidates.push(JSValue::Number(1.0));
                    } else {
                        candidates.push(JSValue::Number(-1.0));
                    }
                }
                
                Ok(candidates)
            }
            _ => Ok(Vec::new()),
        }
    }
    
    fn check_property_violation(&self, value: &JSValue) -> Result<bool, MinimizationError> {
        Ok(!(self.property_checker)(value))
    }
}
```

### Hierarchical Minimization

#### Multi-Level Reduction
```rust
pub struct HierarchicalMinimizer {
    levels: Vec<Box<dyn MinimizationLevel>>,
}

impl HierarchicalMinimizer {
    pub fn new() -> Self {
        Self {
            levels: vec![
                Box::new(StructuralLevel),      // Remove/reduce structure
                Box::new(SyntacticLevel),       // Simplify syntax
                Box::new(SemanticLevel),        // Preserve semantics while minimizing
                Box::new(LiteralLevel),         // Minimize literal values
            ],
        }
    }
    
    pub fn minimize(&self, input: JSExpression, property: &dyn PropertyChecker) -> JSExpression {
        let mut current = input;
        
        for level in &self.levels {
            current = level.minimize(current, property);
        }
        
        current
    }
}

trait MinimizationLevel {
    fn minimize(&self, input: JSExpression, property: &dyn PropertyChecker) -> JSExpression;
}

struct StructuralLevel;
impl MinimizationLevel for StructuralLevel {
    fn minimize(&self, input: JSExpression, property: &dyn PropertyChecker) -> JSExpression {
        match input {
            JSExpression::CallExpression { callee, args } => {
                // Try removing arguments one by one
                for i in (0..args.len()).rev() {
                    let mut reduced_args = args.clone();
                    reduced_args.remove(i);
                    
                    let candidate = JSExpression::CallExpression {
                        callee: callee.clone(),
                        args: reduced_args,
                    };
                    
                    if property.check(&candidate) {
                        return self.minimize(candidate, property);
                    }
                }
                
                // Try reducing to just the callee
                if property.check(&callee) {
                    return self.minimize(*callee, property);
                }
                
                input
            }
            _ => input,
        }
    }
}
```

## Bayesian Coverage Targeting

### Coverage-Guided Generation

#### Feedback-Directed Strategy
```rust
pub struct BayesianCoverageTargeter {
    pub coverage_database: CoverageDatabase,
    pub generator_weights: BTreeMap<GeneratorType, f64>,
    pub exploration_rate: f64,
    pub exploitation_rate: f64,
}

impl BayesianCoverageTargeter {
    pub fn generate_targeted_input(&mut self) -> Result<JSValue, GenerationError> {
        // Update generator weights based on coverage feedback
        self.update_weights_from_coverage()?;
        
        // Choose generator based on weighted random selection
        let generator_type = self.select_generator()?;
        
        // Generate input with coverage-guided parameters
        self.generate_with_coverage_bias(generator_type)
    }
    
    fn update_weights_from_coverage(&mut self) -> Result<(), GenerationError> {
        for (generator_type, weight) in &mut self.generator_weights {
            let recent_coverage = self.coverage_database
                .get_recent_coverage_for_generator(generator_type)?;
            
            let coverage_ratio = recent_coverage.new_branches as f64 / 
                                recent_coverage.total_branches as f64;
            
            // Bayesian update: higher coverage -> higher weight
            *weight = *weight * (1.0 + coverage_ratio * self.exploration_rate) + 
                     coverage_ratio * self.exploitation_rate;
        }
        
        // Normalize weights
        let total_weight: f64 = self.generator_weights.values().sum();
        for weight in self.generator_weights.values_mut() {
            *weight /= total_weight;
        }
        
        Ok(())
    }
    
    fn select_generator(&self) -> Result<GeneratorType, GenerationError> {
        let mut rng = thread_rng();
        let random_value: f64 = rng.gen();
        let mut cumulative_weight = 0.0;
        
        for (generator_type, weight) in &self.generator_weights {
            cumulative_weight += weight;
            if random_value <= cumulative_weight {
                return Ok(*generator_type);
            }
        }
        
        // Fallback to uniform random selection
        Ok(*self.generator_weights.keys().nth(
            rng.gen_range(0..self.generator_weights.len())
        ).unwrap())
    }
    
    fn generate_with_coverage_bias(&self, generator_type: GeneratorType) -> Result<JSValue, GenerationError> {
        match generator_type {
            GeneratorType::Array => {
                let uncovered_array_methods = self.coverage_database
                    .get_uncovered_branches_for_feature("array_methods")?;
                
                // Bias toward generating inputs that exercise uncovered array methods
                let size = if uncovered_array_methods.contains("sparse_arrays") {
                    // Generate sparse arrays more frequently
                    thread_rng().gen_range(10..100)
                } else {
                    thread_rng().gen_range(1..10)
                };
                
                Ok(JSValue::Array(
                    (0..size).map(|_| self.generate_biased_element(&uncovered_array_methods))
                             .collect::<Result<Vec<_>, _>>()?
                ))
            }
            GeneratorType::Object => {
                let uncovered_object_features = self.coverage_database
                    .get_uncovered_branches_for_feature("object_properties")?;
                
                let mut properties = BTreeMap::new();
                
                // Bias toward properties that exercise uncovered features
                if uncovered_object_features.contains("prototype_chain") {
                    properties.insert("__proto__".to_string(), JSValue::Object(BTreeMap::new()));
                }
                
                if uncovered_object_features.contains("accessor_properties") {
                    properties.insert("get".to_string(), JSValue::String("getter".to_string()));
                    properties.insert("set".to_string(), JSValue::String("setter".to_string()));
                }
                
                Ok(JSValue::Object(properties))
            }
            _ => Ok(JSValue::Undefined),
        }
    }
    
    fn generate_biased_element(&self, uncovered_features: &HashSet<String>) -> Result<JSValue, GenerationError> {
        if uncovered_features.contains("bigint_values") {
            Ok(JSValue::BigInt(thread_rng().gen::<i64>()))
        } else if uncovered_features.contains("symbol_values") {
            Ok(JSValue::Symbol("Symbol(test)".to_string()))
        } else {
            Ok(JSValue::Number(thread_rng().gen()))
        }
    }
}
```

### Multi-Objective Optimization

#### Pareto-Optimal Test Generation
```rust
pub struct MultiObjectiveTester {
    pub objectives: Vec<Box<dyn TestObjective>>,
    pub pareto_front: Vec<TestCase>,
    pub generation_budget: usize,
}

impl MultiObjectiveTester {
    pub fn evolve_test_suite(&mut self) -> Result<Vec<TestCase>, EvolutionError> {
        let mut population = self.initialize_population()?;
        
        for generation in 0..self.generation_budget {
            // Evaluate all objectives for each test case
            let evaluated_population = population
                .into_iter()
                .map(|test_case| self.evaluate_objectives(test_case))
                .collect::<Result<Vec<_>, _>>()?;
            
            // Update Pareto front
            self.update_pareto_front(&evaluated_population)?;
            
            // Select parents based on Pareto dominance
            let parents = self.select_parents(&evaluated_population)?;
            
            // Generate offspring through crossover and mutation
            population = self.generate_offspring(&parents)?;
        }
        
        Ok(self.pareto_front.clone())
    }
    
    fn evaluate_objectives(&self, test_case: TestCase) -> Result<EvaluatedTestCase, EvolutionError> {
        let mut objective_scores = Vec::new();
        
        for objective in &self.objectives {
            let score = objective.evaluate(&test_case)?;
            objective_scores.push(score);
        }
        
        Ok(EvaluatedTestCase {
            test_case,
            objective_scores,
        })
    }
    
    fn update_pareto_front(&mut self, population: &[EvaluatedTestCase]) -> Result<(), EvolutionError> {
        for candidate in population {
            let mut is_dominated = false;
            let mut dominates_existing = Vec::new();
            
            for (i, existing) in self.pareto_front.iter().enumerate() {
                let existing_eval = self.evaluate_objectives(existing.clone())?;
                
                if self.dominates(&existing_eval, candidate) {
                    is_dominated = true;
                    break;
                } else if self.dominates(candidate, &existing_eval) {
                    dominates_existing.push(i);
                }
            }
            
            if !is_dominated {
                // Remove dominated solutions
                for &i in dominates_existing.iter().rev() {
                    self.pareto_front.remove(i);
                }
                
                // Add non-dominated solution
                self.pareto_front.push(candidate.test_case.clone());
            }
        }
        
        Ok(())
    }
    
    fn dominates(&self, a: &EvaluatedTestCase, b: &EvaluatedTestCase) -> bool {
        let mut a_better_or_equal = true;
        let mut a_strictly_better = false;
        
        for (a_score, b_score) in a.objective_scores.iter().zip(&b.objective_scores) {
            if a_score < b_score {
                a_better_or_equal = false;
                break;
            } else if a_score > b_score {
                a_strictly_better = true;
            }
        }
        
        a_better_or_equal && a_strictly_better
    }
}

trait TestObjective {
    fn evaluate(&self, test_case: &TestCase) -> Result<f64, EvolutionError>;
    fn name(&self) -> &str;
}

struct BranchCoverageObjective;
impl TestObjective for BranchCoverageObjective {
    fn evaluate(&self, test_case: &TestCase) -> Result<f64, EvolutionError> {
        let coverage = execute_with_coverage_tracking(test_case)?;
        Ok(coverage.branch_coverage_ratio())
    }
    
    fn name(&self) -> &str { "branch_coverage" }
}

struct PropertyViolationObjective;
impl TestObjective for PropertyViolationObjective {
    fn evaluate(&self, test_case: &TestCase) -> Result<f64, EvolutionError> {
        let violations = count_property_violations(test_case)?;
        Ok(violations as f64)
    }
    
    fn name(&self) -> &str { "property_violations" }
}
```

---

## Implementation Roadmap

### Phase 1: Property Discovery (Month 1)
- [ ] Catalog fundamental JavaScript properties
- [ ] Implement basic property checkers
- [ ] Create primitive value generators
- [ ] Establish property violation tracking

### Phase 2: Generator Infrastructure (Month 2)
- [ ] Implement arbitrary generators for all JS types
- [ ] Create domain-specific security generators
- [ ] Build hierarchical shrinking algorithms
- [ ] Integrate with existing test infrastructure

### Phase 3: Coverage Optimization (Month 3)
- [ ] Deploy Bayesian coverage targeting
- [ ] Implement multi-objective optimization
- [ ] Create feedback-directed test generation
- [ ] Establish continuous property monitoring

### Phase 4: Advanced Minimization (Month 4)
- [ ] Build delta debugging framework
- [ ] Implement semantic-preserving reduction
- [ ] Create automated counterexample analysis
- [ ] Integrate with CI/CD pipeline

---

## References

1. [QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs](https://www.cs.tufts.edu/~nr/cs257/archive/john-hughes/quick.pdf)
2. [Property-Based Testing with PropEr, Erlang, and Elixir](https://pragprog.com/titles/fhproper/property-based-testing-with-proper-erlang-and-elixir/)
3. [Generating Good Generators for Inductive Relations](https://dl.acm.org/doi/10.1145/3158133)
4. [Coverage-Guided Fuzzing](https://llvm.org/docs/LibFuzzer.html)
5. [Delta Debugging: Simplifying and Isolating Failure-Inducing Input](https://www.st.cs.uni-saarland.de/dd/)

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
