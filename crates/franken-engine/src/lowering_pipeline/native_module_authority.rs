//! Selected authority of the engine's first-class Events exports.
//!
//! Initializing a module does not execute its exported functions. Follow the
//! private loader's result through IR bindings and property reads, then account
//! for the actual exported body when its value is called. Escapes and dynamic
//! selection conservatively retain possible native authority; they cannot erase
//! it. This is a capability summary only and changes no information-flow facts.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{
    AssignmentOperator, BinaryOperator, BindingId, BindingKind, Ir1Literal, Ir1Module, Ir1Op,
    Ir1PropertyKey, JsString, ScopeKind, UnaryOperator, classify_ir1_op,
    collect_immediately_invoked_capabilities, global_object_capture_name, parse_capture_cell_name,
};
use crate::capability::hostcall_registry_row;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Value {
    loader: bool,
    namespace: bool,
    receiver_inert: bool,
    bind_factory: bool,
    capabilities: BTreeSet<String>,
    captures: BTreeSet<BindingId>,
    key: Option<JsString>,
}

impl Value {
    fn join(&mut self, other: &Self) {
        self.loader |= other.loader;
        self.namespace |= other.namespace;
        self.receiver_inert &= other.receiver_inert;
        self.bind_factory &= other.bind_factory;
        self.capabilities.extend(other.capabilities.iter().cloned());
        self.captures.extend(&other.captures);
        if self.key != other.key {
            self.key = None;
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    stack: Vec<Value>,
    bindings: BTreeMap<BindingId, Value>,
    properties: BTreeMap<JsString, Value>,
    unknown_property: Option<Value>,
    callable_properties_opaque: bool,
    escaped_captures: BTreeSet<BindingId>,
    handlers: Vec<BTreeSet<u32>>,
}

impl State {
    fn pop(&mut self) -> Value {
        self.stack.pop().unwrap_or_default()
    }

    fn join(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.stack
            .resize(self.stack.len().max(other.stack.len()), Value::default());
        for (left, right) in self.stack.iter_mut().zip(&other.stack) {
            left.join(right);
        }
        for (binding, value) in &other.bindings {
            if let Some(previous) = self.bindings.get_mut(binding) {
                previous.join(value);
            } else {
                self.bindings.insert(*binding, value.clone());
            }
        }
        for (key, value) in &other.properties {
            if let Some(previous) = self.properties.get_mut(key) {
                previous.join(value);
            } else {
                self.properties.insert(key.clone(), value.clone());
            }
        }
        if let Some(value) = &other.unknown_property {
            if let Some(previous) = &mut self.unknown_property {
                previous.join(value);
            } else {
                self.unknown_property = Some(value.clone());
            }
        }
        self.callable_properties_opaque |= other.callable_properties_opaque;
        self.escaped_captures.extend(&other.escaped_captures);
        self.handlers
            .resize_with(self.handlers.len().max(other.handlers.len()), BTreeSet::new);
        for (left, right) in self.handlers.iter_mut().zip(&other.handlers) {
            left.extend(right);
        }
        *self != before
    }
}

struct Exports {
    loader_store: usize,
    loader_binding: BindingId,
    cache_calls: BTreeSet<usize>,
    global_bindings: BTreeMap<String, BindingId>,
    properties: BTreeMap<JsString, Value>,
    initialization: BTreeSet<String>,
    constructor: BTreeSet<String>,
    escaped: BTreeSet<String>,
}

fn body_capabilities(ops: &[Ir1Op]) -> BTreeSet<String> {
    let mut capabilities = BTreeSet::new();
    for op in ops {
        if let (_, Some(capability), _) = classify_ir1_op(op) {
            capabilities.insert(capability.0);
        }
    }
    collect_immediately_invoked_capabilities(ops, &mut capabilities);
    // Some builtin-named operations require a distinct runtime grant (for
    // example QueueMicrotask requires Timer). Use the same registry as dispatch
    // rather than treating the tag's textual prefix as its authority.
    let authority: Vec<_> = capabilities
        .iter()
        .filter_map(|tag| hostcall_registry_row(tag).and_then(|row| row.authority))
        .map(|capability| capability.to_string())
        .collect();
    capabilities.extend(authority);
    capabilities
}

fn function_value(op: &Ir1Op) -> Option<Value> {
    let (body_ops, is_generator) = match op {
        Ir1Op::CreateFunction {
            body_ops,
            is_generator,
            ..
        }
        | Ir1Op::DeclareFunction {
            body_ops,
            is_generator,
            ..
        } => (body_ops, is_generator),
        _ => return None,
    };
    Some(Value {
        receiver_inert: true,
        capabilities: if *is_generator {
            BTreeSet::new()
        } else {
            body_capabilities(body_ops)
        },
        ..Value::default()
    })
}

/// Authenticate the reserved loader and the constructor returned by its actual
/// initializer. Neither a guest object with a similarly named property nor a
/// lexical binding called `events` supplies this proof.
fn exports(ir1: &Ir1Module) -> Option<Exports> {
    let global_bindings = ir1
        .scopes
        .iter()
        .filter(|scope| matches!(scope.kind, ScopeKind::Global | ScopeKind::StrictGlobal))
        .flat_map(|scope| &scope.bindings)
        .filter(|binding| matches!(binding.kind, BindingKind::Var | BindingKind::FunctionDecl))
        .map(|binding| (binding.name.clone(), binding.binding_id))
        .collect();
    let module_bindings: BTreeSet<_> = ir1
        .scopes
        .iter()
        .flat_map(|scope| &scope.bindings)
        .filter(|binding| super::util_module::is_module_binding(&binding.name))
        .map(|binding| binding.binding_id)
        .collect();
    let cache_calls = ir1
        .ops
        .windows(4)
        .enumerate()
        .filter_map(|(index, ops)| {
            let [
                Ir1Op::CreateFunction { .. },
                Ir1Op::CreateFunction { .. },
                Ir1Op::Call { arg_count: 1 },
                Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id },
            ] = ops
            else {
                return None;
            };
            module_bindings.contains(binding_id).then_some(index + 2)
        })
        .collect();
    let loader_binding = ir1
        .scopes
        .iter()
        .flat_map(|scope| &scope.bindings)
        .find(|binding| binding.name == "%events_module")?
        .binding_id;
    let (loader_store, thunk) = ir1.ops.windows(4).enumerate().find_map(|(index, ops)| {
        let [
            Ir1Op::CreateFunction { .. },
            Ir1Op::CreateFunction {
                body_ops,
                is_generator: false,
                ..
            },
            Ir1Op::Call { arg_count: 1 },
            Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id },
        ] = ops
        else {
            return None;
        };
        (*binding_id == loader_binding).then_some((index + 3, body_ops.as_slice()))
    })?;
    let [
        Ir1Op::CreateFunction {
            body_ops,
            is_generator: false,
            ..
        },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::Return,
    ] = thunk
    else {
        return None;
    };
    let (constructor_binding, constructor) = body_ops.windows(2).find_map(|ops| {
        let [
            call @ Ir1Op::HostCall { capability, .. },
            Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id },
        ] = ops
        else {
            return None;
        };
        (capability == "builtin:EventEmitterConstructorRef")
            .then(|| (*binding_id, body_capabilities(std::slice::from_ref(call))))
    })?;
    if !matches!(body_ops.last_chunk::<2>(), Some([Ir1Op::LoadBinding { binding_id }, Ir1Op::Return]) if *binding_id == constructor_binding)
    {
        return None;
    }
    let functions: BTreeMap<_, _> = body_ops
        .iter()
        .filter_map(|op| {
            let Ir1Op::DeclareFunction { binding_id, .. } = op else {
                return None;
            };
            function_value(op).map(|value| (*binding_id, value))
        })
        .collect();
    let mut properties = BTreeMap::new();
    for ops in body_ops.windows(3) {
        let [
            Ir1Op::LoadBinding { binding_id },
            value,
            Ir1Op::SetProperty {
                key: Ir1PropertyKey::Static(key),
                ..
            },
        ] = ops
        else {
            continue;
        };
        if *binding_id != constructor_binding {
            continue;
        }
        let value = if let Ir1Op::LoadBinding { binding_id } = value {
            if *binding_id == constructor_binding {
                Value {
                    namespace: true,
                    receiver_inert: true,
                    ..Value::default()
                }
            } else {
                functions.get(binding_id).cloned().unwrap_or_default()
            }
        } else {
            function_value(value).unwrap_or_default()
        };
        properties.insert(key.clone(), value);
    }
    let initialization = body_capabilities(thunk);
    let mut escaped = initialization.clone();
    escaped.extend(constructor.iter().cloned());
    for value in properties.values() {
        escaped.extend(value.capabilities.iter().cloned());
    }
    Some(Exports {
        loader_store,
        loader_binding,
        cache_calls,
        global_bindings,
        properties,
        initialization,
        constructor,
        escaped,
    })
}

fn expose(value: &Value, state: &mut State, exports: &Exports, required: &mut BTreeSet<String>) {
    let mut pending = vec![value.clone()];
    let mut visited = BTreeSet::new();
    while let Some(value) = pending.pop() {
        required.extend(value.capabilities.iter().cloned());
        if value.namespace || value.loader {
            required.extend(exports.escaped.iter().cloned());
        }
        for binding in &value.captures {
            // Closures retain live cells. A callback may escape before a later
            // assignment places a native helper or namespace in that cell.
            state.escaped_captures.insert(*binding);
            if visited.insert(*binding)
                && let Some(value) = state.bindings.get(binding)
            {
                pending.push(value.clone());
            }
        }
    }
}

fn property_key(
    key: &Ir1PropertyKey,
    state: &mut State,
    exports: &Exports,
    required: &mut BTreeSet<String>,
) -> Option<JsString> {
    match key {
        Ir1PropertyKey::Static(key) => Some(key.clone()),
        Ir1PropertyKey::Dynamic => {
            let value = state.pop();
            // Get/Set/Delete/Define perform ToPropertyKey on this operand.
            // Its conversion hook may call a retained native helper before
            // the property operation itself, even if that operation throws.
            expose(&value, state, exports, required);
            value.key
        }
    }
}

fn transfer(
    index: usize,
    op: &Ir1Op,
    state: &mut State,
    exports: &Exports,
    required: &mut BTreeSet<String>,
) {
    if exports.cache_calls.contains(&index) {
        // The authenticated cache factory retains its initializer without
        // invoking it. In particular, a Stream initializer capturing Events
        // is not an escape of the Events namespace at prelude construction.
        state.pop();
        state.pop();
        state.stack.push(Value::default());
        return;
    }
    match op {
        Ir1Op::LoadBinding { binding_id } => state
            .stack
            .push(state.bindings.get(binding_id).cloned().unwrap_or_default()),
        Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id } => {
            let mut value = state.pop();
            if index == exports.loader_store && *binding_id == exports.loader_binding {
                value.loader = true;
            }
            state.bindings.insert(*binding_id, value.clone());
            if state.escaped_captures.contains(binding_id) {
                expose(&value, state, exports, required);
            }
            state.stack.push(value);
        }
        Ir1Op::AssignOp {
            binding_id,
            operator,
            ..
        } => {
            let value = state.pop();
            let value = match operator {
                AssignmentOperator::Assign => value,
                AssignmentOperator::LogicalAndAssign
                | AssignmentOperator::LogicalOrAssign
                | AssignmentOperator::NullishCoalescingAssign => {
                    let mut selected = state.bindings.get(binding_id).cloned().unwrap_or_default();
                    selected.join(&value);
                    selected
                }
                _ => {
                    // Arithmetic compound assignments coerce both operands;
                    // ++/-- coerce the target binding, not their literal RHS.
                    let previous = state.bindings.get(binding_id).cloned().unwrap_or_default();
                    expose(&previous, state, exports, required);
                    expose(&value, state, exports, required);
                    Value::default()
                }
            };
            state.bindings.insert(*binding_id, value.clone());
            if state.escaped_captures.contains(binding_id) {
                expose(&value, state, exports, required);
            }
            state.stack.push(value);
        }
        Ir1Op::CreateFunction {
            free_vars,
            body_ops,
            ..
        }
        | Ir1Op::DeclareFunction {
            free_vars,
            body_ops,
            ..
        } => {
            let value = Value {
                receiver_inert: !body_ops.iter().any(|op| matches!(op, Ir1Op::LoadThis)),
                captures: free_vars
                    .iter()
                    .filter_map(|name| {
                        parse_capture_cell_name(name).map(|(id, _)| id).or_else(|| {
                            global_object_capture_name(name)
                                .and_then(|name| exports.global_bindings.get(name).copied())
                        })
                    })
                    .collect(),
                ..Value::default()
            };
            if let Ir1Op::DeclareFunction { binding_id, .. } = op {
                state.bindings.insert(*binding_id, value.clone());
                if state.escaped_captures.contains(binding_id) {
                    expose(&value, state, exports, required);
                }
            } else {
                state.stack.push(value);
            }
        }
        Ir1Op::LoadLiteral { value } => state.stack.push(Value {
            key: if let Ir1Literal::String(key) = value {
                Some(key.clone())
            } else {
                None
            },
            ..Value::default()
        }),
        Ir1Op::LoadName { .. }
        | Ir1Op::LoadThis
        | Ir1Op::LoadSuper
        | Ir1Op::LoadNewTarget
        | Ir1Op::DeleteName { .. } => state.stack.push(Value::default()),
        Ir1Op::GetProperty { key } => {
            let key = property_key(key, state, exports, required);
            let object = state.pop();
            let mut value = Value::default();
            if object.namespace {
                if let Some(key) = key {
                    value = state.properties.get(&key).cloned().unwrap_or_default();
                } else {
                    for property in state.properties.values() {
                        value.join(property);
                    }
                }
                if let Some(unknown_property) = &state.unknown_property {
                    value.join(unknown_property);
                }
            } else {
                // Calling .call/.apply invokes the target. Calling an intact
                // .bind only creates another callable retaining that target.
                value = object;
                value.bind_factory = key.as_ref().is_some_and(|key| key == "bind")
                    && !state.callable_properties_opaque;
                value.key = None;
            }
            state.stack.push(value);
        }
        Ir1Op::SetProperty { key, .. }
        | Ir1Op::DefineAccessor { key, .. }
        | Ir1Op::DefineMethod { key } => {
            state.callable_properties_opaque = true;
            let value = state.pop();
            let key = property_key(key, state, exports, required);
            let object = state.pop();
            if object.namespace {
                if let Some(key) = key {
                    state.properties.insert(key, value.clone());
                } else if let Some(unknown_property) = &mut state.unknown_property {
                    unknown_property.join(&value);
                } else {
                    state.unknown_property = Some(value.clone());
                }
            } else {
                expose(&value, state, exports, required);
            }
            if matches!(op, Ir1Op::SetProperty { .. }) {
                state.stack.push(value);
            } else {
                state.stack.push(object);
            }
        }
        Ir1Op::DeleteProperty { key } => {
            state.callable_properties_opaque = true;
            let key = property_key(key, state, exports, required);
            let object = state.pop();
            if object.namespace
                && let Some(key) = key
            {
                state.properties.insert(key, Value::default());
            }
            state.stack.push(Value::default());
        }
        Ir1Op::Call { arg_count }
        | Ir1Op::CallMethod { arg_count }
        | Ir1Op::Construct { arg_count } => {
            let arguments: Vec<_> = (0..*arg_count).map(|_| state.pop()).collect();
            let receiver = if matches!(op, Ir1Op::CallMethod { .. }) {
                state.pop()
            } else {
                Value::default()
            };
            let callee = state.pop();
            if callee.bind_factory && !state.callable_properties_opaque {
                let mut result = receiver;
                result.bind_factory = false;
                // Bound arguments can themselves carry callable authority.
                // Retain it in the result without exercising it at bind time.
                let mut bound_arguments = state.clone();
                for argument in arguments {
                    expose(
                        &argument,
                        &mut bound_arguments,
                        exports,
                        &mut result.capabilities,
                    );
                    result.captures.extend(argument.captures);
                }
                state.stack.push(result);
                return;
            }
            required.extend(callee.capabilities.iter().cloned());
            if callee.namespace {
                required.extend(exports.constructor.iter().cloned());
            }
            let captured = Value {
                captures: callee.captures.clone(),
                ..Value::default()
            };
            expose(&captured, state, exports, required);
            if !callee.receiver_inert && !callee.namespace {
                expose(&receiver, state, exports, required);
            }
            for argument in arguments {
                expose(&argument, state, exports, required);
            }
            let mut result = Value::default();
            if callee.loader {
                required.extend(exports.initialization.iter().cloned());
                result.namespace = true;
            } else {
                // Guest callbacks or coercions may mutate Function.prototype
                // or a helper's own properties during an ordinary invocation.
                state.callable_properties_opaque = true;
            }
            state.stack.push(result);
        }
        Ir1Op::HostCall {
            capability,
            arg_count,
        } => {
            let arguments: Vec<_> = (0..*arg_count).map(|_| state.pop()).collect();
            // Destructuring's coercibility check returns its original object.
            if capability == "builtin:RequireObjectCoercible" {
                state
                    .stack
                    .push(arguments.into_iter().next().unwrap_or_default());
            } else {
                state.callable_properties_opaque = true;
                for argument in arguments {
                    expose(&argument, state, exports, required);
                }
                state.stack.push(Value::default());
            }
        }
        Ir1Op::Pop
        | Ir1Op::Discard
        | Ir1Op::JumpIfFalsyConsume { .. }
        | Ir1Op::JumpIfTruthy { .. }
        | Ir1Op::JumpIfNullish { .. } => {
            state.pop();
        }
        Ir1Op::PutName { .. } | Ir1Op::PutNameWithStatus { .. } | Ir1Op::Return | Ir1Op::Throw => {
            if let Some(value) = state.stack.last().cloned() {
                expose(&value, state, exports, required);
            }
        }
        Ir1Op::NewArray { count } | Ir1Op::NewObject { count } => {
            let count = if matches!(op, Ir1Op::NewObject { .. }) {
                count.saturating_mul(2)
            } else {
                *count
            };
            for _ in 0..count {
                let value = state.pop();
                expose(&value, state, exports, required);
            }
            state.stack.push(Value::default());
        }
        Ir1Op::BinaryOp { operator } => {
            let right = state.pop();
            let mut left = state.pop();
            let result = match operator {
                BinaryOperator::StrictEqual | BinaryOperator::StrictNotEqual => Value::default(),
                BinaryOperator::LogicalAnd
                | BinaryOperator::LogicalOr
                | BinaryOperator::NullishCoalescing => {
                    left.join(&right);
                    left
                }
                BinaryOperator::In => {
                    // Only the key is coerced; the proven Events namespace is
                    // an ordinary native function object, not a Proxy trap.
                    expose(&left, state, exports, required);
                    Value::default()
                }
                _ => {
                    // ToPrimitive and @@hasInstance can invoke a native helper
                    // installed as a coercion hook, including a bound helper.
                    expose(&left, state, exports, required);
                    expose(&right, state, exports, required);
                    Value::default()
                }
            };
            state.stack.push(result);
        }
        Ir1Op::UnaryOp { operator } => {
            let value = state.pop();
            if matches!(
                operator,
                UnaryOperator::Negate
                    | UnaryOperator::BitwiseNot
                    | UnaryOperator::UnaryPlus
                    | UnaryOperator::Increment
                    | UnaryOperator::Decrement
            ) {
                expose(&value, state, exports, required);
            }
            state.stack.push(Value::default());
        }
        Ir1Op::BeginTry { catch_label, .. } => {
            state.handlers.push(BTreeSet::from([*catch_label]));
        }
        Ir1Op::EndTry => {
            state.handlers.pop();
        }
        Ir1Op::Label { .. }
        | Ir1Op::Jump { .. }
        | Ir1Op::JumpIfFalsy { .. }
        | Ir1Op::EnterFinally
        | Ir1Op::EndFinally
        | Ir1Op::DiscardAbruptCompletion
        | Ir1Op::Nop
        | Ir1Op::ResolveNameStatus { .. } => {}
        Ir1Op::ExportBinding { binding_id, .. } => {
            if let Some(value) = state.bindings.get(binding_id).cloned() {
                expose(&value, state, exports, required);
            }
        }
        _ => {
            // Unsupported carriers may expose any live stack operand. Do not
            // discard a possible native call merely because this small summary
            // does not model an iterator, spread or derived constructor.
            for value in state.stack.clone() {
                expose(&value, state, exports, required);
            }
            state.stack.clear();
        }
    }
}

/// Add selected native export authority, retaining conservative authority for
/// dynamic selection and opaque escapes. Ordinary unused imports stay uncharged.
pub(super) fn collect(ir1: &Ir1Module, required: &mut BTreeSet<String>) {
    let Some(exports) = exports(ir1) else {
        return;
    };
    let labels: BTreeMap<_, _> = ir1
        .ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| {
            if let Ir1Op::Label { id } = op {
                Some((*id, index))
            } else {
                None
            }
        })
        .collect();
    let mut states = vec![None; ir1.ops.len()];
    states[0] = Some(State {
        properties: exports.properties.clone(),
        ..State::default()
    });
    let joins: BTreeSet<_> = labels.values().copied().chain([0]).collect();
    let mut pending = VecDeque::from([0usize]);
    while let Some(index) = pending.pop_front() {
        // Retain fixed-point state only at block entries. Straight-line states
        // can be consumed, avoiding a copy of every binding at every IR op.
        let state = if joins.contains(&index) {
            states[index].clone()
        } else {
            states[index].take()
        };
        let Some(mut state) = state else {
            continue;
        };
        transfer(index, &ir1.ops[index], &mut state, &exports, required);
        let mut successors = Vec::new();
        let mut fallthrough = true;
        match &ir1.ops[index] {
            Ir1Op::Jump { label_id } => {
                successors.extend(labels.get(label_id).copied());
                fallthrough = false;
            }
            Ir1Op::JumpIfFalsy { label_id }
            | Ir1Op::JumpIfFalsyConsume { label_id }
            | Ir1Op::JumpIfTruthy { label_id }
            | Ir1Op::JumpIfNullish { label_id } => successors.extend(labels.get(label_id).copied()),
            Ir1Op::ForInNext { done_label } | Ir1Op::ForOfNext { done_label } => {
                successors.extend(labels.get(done_label).copied());
            }
            Ir1Op::Return | Ir1Op::Throw => fallthrough = false,
            _ => {}
        }
        if fallthrough && index + 1 < ir1.ops.len() {
            successors.push(index + 1);
        }
        for next in successors {
            let changed = if let Some(previous) = &mut states[next] {
                previous.join(&state)
            } else {
                states[next] = Some(state.clone());
                true
            };
            if changed {
                pending.push_back(next);
            }
        }
        if let Some(handlers) = state.handlers.pop() {
            // Handler scopes follow executed CFG edges. Linear source-order
            // matching would pop the same try repeatedly across alternate
            // break/continue forwarders, losing its exceptional successors.
            for next in handlers
                .iter()
                .filter_map(|label| labels.get(label))
                .copied()
            {
                let mut exceptional = state.clone();
                exceptional.stack.clear();
                exceptional.stack.push(Value::default());
                let changed = if let Some(previous) = &mut states[next] {
                    previous.join(&exceptional)
                } else {
                    states[next] = Some(exceptional);
                    true
                };
                if changed {
                    pending.push_back(next);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ir_contract::Ir0Module, parser_api_stability::parse_script};

    fn capabilities(source: &str) -> BTreeSet<String> {
        let tree = parse_script(source).expect("regression source parses");
        let ir0 = Ir0Module::from_syntax_tree(tree, "native-events-authority.js");
        let ir1 = super::super::lower_ir0_to_ir1(&ir0)
            .expect("native Events source lowers")
            .module;
        let mut capabilities = BTreeSet::new();
        collect(&ir1, &mut capabilities);
        capabilities
    }

    #[test]
    fn selected_add_abort_listener_carries_its_real_timer_authority() {
        for source in [
            "require('events').addAbortListener(signal, listener);",
            "const events=require('node:events');events.addAbortListener(signal,listener);",
            "const {addAbortListener:add}=require('events');add(signal,listener);",
            "const events=require('events');const alias=events;const add=alias.addAbortListener;add(signal,listener);",
            "const events=require('events');events['addAbortListener'](signal,listener);",
            "const events=require('events');let add; if(flag){add=events.addAbortListener;}else{add=function(){};}add(signal,listener);",
            "const events=require('events');const add=events.addAbortListener;events.addAbortListener=function(){};add(signal,listener);",
            "const events=require('events');consume(events.addAbortListener);",
            "const events=require('events');events[method](signal,listener);",
            "const events=require('events');const add=events.addAbortListener.bind(null);add(signal,listener);",
            "const events=require('events');const add=events.addAbortListener;add.call(null,signal,listener);",
            "const events=require('events');events[key]=events.addAbortListener;events.extra(signal,listener);",
            "const events=require('events');for(const value of values){}events.addAbortListener(signal,listener);",
            "const events=require('events');function invoke(){events.addAbortListener(signal,listener);}invoke();",
            "var events=require('events');function invoke(){events.addAbortListener(signal,listener);}invoke();",
            "let events;const invoke=()=>events.addAbortListener(signal,listener);consume(invoke);events=require('events');",
            "var events;function invoke(){events.addAbortListener(signal,listener);}consume(invoke);events=require('events');",
            "let events;try{for(const value of values){try{break;}finally{}}events=require('events');throw 1;}catch(error){events.addAbortListener(signal,listener);}",
            "const events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;+events;",
            "const events=require('events');events[Symbol.toPrimitive]=function(){events.addAbortListener(signal,listener);return 1;};+events;",
            "const events=require('events');events[Symbol.toPrimitive]=function(){events.addAbortListener(signal,listener);return 1;};events+1;",
            "let events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;events+=1;",
            "let events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;++events;",
            "let events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;events++;",
            "const events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;({})[events];",
            "const events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;const target={};target[events]=1;",
            "const events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;const target={};delete target[events];",
            "const events=require('events');events[Symbol.toPrimitive]=function(){events.addAbortListener(signal,listener);return 'key';};({})[events];",
        ] {
            let actual = capabilities(source);
            assert!(
                actual.contains("timer"),
                "missing selected helper authority: {source}: {actual:?}"
            );
        }
    }

    #[test]
    fn unused_shadowed_reassigned_and_once_helpers_do_not_claim_timer() {
        for source in [
            "const {addAbortListener}=require('events');",
            "const events=require('events');const add=events.addAbortListener;",
            "const {addAbortListener}=require('events');{const addAbortListener=function(){};addAbortListener(signal,listener);}",
            "const events=require('events');let add=events.addAbortListener;add=function(){};add(signal,listener);",
            "const events=require('events');events.addAbortListener=function(){};events.addAbortListener(signal,listener);",
            "const events=require('events');events.once(emitter,'ready');",
            "const {once}=require('events');once(emitter,'ready');",
            "const events={addAbortListener:function(){}};events.addAbortListener(signal,listener);",
            "const events=require('events');const add=events.addAbortListener.bind(null);",
            "const events=require('events');function unused(){events.addAbortListener(signal,listener);}",
            "var events=require('events');function unused(){events.addAbortListener(signal,listener);}",
            "let events;const noop=function(){};const bound=noop.bind(null,()=>events.addAbortListener(signal,listener));events=require('events');",
            "const events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;typeof events;!events;void events;",
            "const events=require('events');const run=events.addAbortListener.bind(null,signal,listener);events[Symbol.toPrimitive]=run;events===events;events!==null;'once' in events;",
            "const events=require('events');const key='once';events[key];",
            "const events=require('events');events[Symbol.toPrimitive];const target={};target[Symbol.iterator]=1;delete target[Symbol.iterator];",
        ] {
            let actual = capabilities(source);
            assert!(
                !actual.contains("timer"),
                "unselected helper was charged: {source}: {actual:?}"
            );
        }
    }
}
