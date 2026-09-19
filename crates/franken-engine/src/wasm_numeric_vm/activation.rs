//! Heap-backed guest activations. Guest calls never recurse on the Rust stack.
//!
//! A suspended frame owns its locals, operands, control labels and continuation
//! offset. Host calls still use the existing authorized import boundary. All
//! frames share one meter, including a live-value ceiling across suspended
//! operands and locals; this is not a sandbox for trusted native callbacks.
//! Tail calls release the current activation before admitting its replacement,
//! retaining only the older suspended callers and their accounted values.

use super::*;
use std::borrow::Cow;
use std::num::NonZeroU64;

struct Activation<'vm> {
    function: u32,
    body: &'vm FunctionBody,
    signature: &'vm FunctionType,
    locals: Vec<WasmBoundaryValue>,
    stack: Vec<WasmBoundaryValue>,
    reader: CodeReader<'vm>,
    controls: Vec<control::Frame>,
}

enum Transfer {
    Call { function: u32, arguments: Vec<WasmBoundaryValue>, tail: bool },
    Return,
    Yield,
}

fn allocation<T>(count: usize) -> WasmNumericVmError {
    WasmStateError::AllocationFailed {
        bytes: (count as u64).saturating_mul(std::mem::size_of::<T>() as u64),
    }.into()
}

fn add_base(meter: &mut ExecutionMeter<'_>, count: usize) -> Result<(), WasmNumericVmError> {
    let actual = meter.live_value_base.checked_add(count)
        .ok_or(WasmNumericVmError::LiveValueLimitExceeded {
            actual: usize::MAX, max: meter.limits.max_live_values,
        })?;
    if actual > meter.limits.max_live_values {
        return Err(WasmNumericVmError::LiveValueLimitExceeded {
            actual, max: meter.limits.max_live_values,
        });
    }
    meter.live_value_base = actual;
    Ok(())
}

fn remove_base(meter: &mut ExecutionMeter<'_>, count: usize) -> Result<(), WasmNumericVmError> {
    meter.live_value_base = meter.live_value_base.checked_sub(count)
        .ok_or_else(|| WasmNumericVmError::InvalidModule {
            detail: "inconsistent live activation accounting".into(),
        })?;
    Ok(())
}

impl<'vm> Activation<'vm> {
    fn new(
        vm: &'vm WasmNumericVm,
        function: u32,
        arguments: Cow<'_, [WasmBoundaryValue]>,
        meter: &mut ExecutionMeter<'_>,
    ) -> Result<Self, WasmNumericVmError> {
        let index = (function as usize).checked_sub(vm.imports.len())
            .ok_or(WasmNumericVmError::UnknownFunction { function_index: function })?;
        let body = vm.functions.get(index)
            .ok_or(WasmNumericVmError::UnknownFunction { function_index: function })?;
        let signature = vm.function_type(body.type_index)?;
        validate_arguments(function, signature, &arguments)?;
        let local_count = arguments.len().checked_add(body.locals.len())
            .ok_or(WasmNumericVmError::LocalLimitExceeded {
                actual: usize::MAX, max: vm.limits.max_locals_per_call,
            })?;
        if local_count > vm.limits.max_locals_per_call {
            return Err(WasmNumericVmError::LocalLimitExceeded {
                actual: local_count, max: vm.limits.max_locals_per_call,
            });
        }
        // Admission happens before copying arguments or allocating locals.
        add_base(meter, local_count)?;
        // Small-frame setup is covered by dispatch. Charge each additional
        // group of 64 values before allocation/zeroing, so a large-local call
        // cannot amplify a single opcode into unmetered native work.
        meter.charge_work((local_count.saturating_sub(64) as u64).div_ceil(64))?;
        let mut locals = match arguments {
            Cow::Owned(arguments) => arguments,
            Cow::Borrowed(arguments) => {
                let mut owned = Vec::new();
                owned.try_reserve_exact(local_count)
                    .map_err(|_| allocation::<WasmBoundaryValue>(local_count))?;
                owned.extend_from_slice(arguments);
                owned
            }
        };
        locals.try_reserve_exact(body.locals.len())
            .map_err(|_| allocation::<WasmBoundaryValue>(local_count))?;
        locals.extend(body.locals.iter().copied().map(zero_value));
        let mut controls = Vec::new();
        controls.try_reserve_exact(1).map_err(|_| allocation::<control::Frame>(1))?;
        controls.push(control::Frame::function(signature.results.len(), body.code.len() - 1));
        Ok(Self {
            function, body, signature, locals, stack: Vec::new(),
            reader: CodeReader::new(&body.code), controls,
        })
    }

    fn run(
        &mut self,
        vm: &WasmNumericVm,
        meter: &mut ExecutionMeter<'_>,
        state: &mut state::InstanceState,
        slice: Option<Slice>,
    ) -> Result<Transfer, WasmNumericVmError> {
        let function = self.function;
        while !self.reader.finished() {
            // Guest-only loops may never reach a host callback. Poll before
            // the opcode and its work/effects; completed instructions remain
            // committed when this invocation unwinds its flat frame vector.
            state.check_execution_cancellation()?;
            // Never consume an opcode/immediate until this slice can start it.
            if slice.is_some_and(|slice| slice.exhausted(meter)) { return Ok(Transfer::Yield); }
            let offset = self.reader.offset();
            let opcode = self.reader.read_u8(function)?;
            meter.tick()?;
            match opcode {
                0x00..=0x05 | 0x0b..=0x0f => {
                    if control::execute(
                        opcode, &self.body.control, &mut self.controls, &mut self.stack,
                        &mut self.reader, meter, function,
                    )? {
                        self.validate_results()?;
                        return Ok(Transfer::Return);
                    }
                }
                0x1a => { pop_value(&mut self.stack, function, opcode)?; }
                0x1b => execute_select(&mut self.stack, function, opcode)?,
                0x20 => {
                    let index = self.reader.read_u32_leb(function)?;
                    let value = self.locals.get(index as usize).cloned()
                        .ok_or(WasmNumericVmError::InvalidLocal {
                            function_index: function, local_index: index,
                        })?;
                    push_value(&mut self.stack, value, meter)?;
                }
                0x21 | 0x22 => {
                    let index = self.reader.read_u32_leb(function)?;
                    let value = if opcode == 0x21 {
                        pop_value(&mut self.stack, function, opcode)?
                    } else {
                        self.stack.last().cloned().ok_or(WasmNumericVmError::StackUnderflow {
                            function_index: function, opcode,
                        })?
                    };
                    let slot = self.locals.get_mut(index as usize)
                        .ok_or(WasmNumericVmError::InvalidLocal {
                            function_index: function, local_index: index,
                        })?;
                    ensure_same_type(function, index as usize, slot.value_type(), value.value_type())?;
                    *slot = value;
                }
                0x10..=0x13 => {
                    let index = self.reader.read_u32_leb(function)?;
                    let callee = if matches!(opcode, 0x10 | 0x12) {
                        index
                    } else {
                        let table = self.reader.read_u32_leb(function)?;
                        let element = expect_i32(pop_value(&mut self.stack, function, opcode)?, function, 0)? as u32;
                        state.indirect_callee(vm, index, table, element, meter)?
                    };
                    let signature = vm.function_signature(callee)?;
                    let count = signature.params.len();
                    let begin = self.stack.len().checked_sub(count)
                        .ok_or(WasmNumericVmError::StackUnderflow { function_index: function, opcode })?;
                    let mut arguments = Vec::new();
                    arguments.try_reserve_exact(count)
                        .map_err(|_| allocation::<WasmBoundaryValue>(count))?;
                    // Move in ABI order, retaining only the caller's prefix.
                    arguments.extend(self.stack.drain(begin..));
                    validate_arguments(callee, signature, &arguments)?;
                    return Ok(Transfer::Call { function: callee, arguments, tail: opcode >= 0x12 });
                }
                0x23..=0x40 | 0xfc => {
                    state.execute(opcode, &mut self.reader, &mut self.stack, meter, function)?;
                }
                0x41 => {
                    let value = WasmBoundaryValue::I32(self.reader.read_i32_leb(function)?);
                    push_value(&mut self.stack, value, meter)?;
                }
                0x42 => {
                    let value = WasmBoundaryValue::I64(self.reader.read_i64_leb(function)?);
                    push_value(&mut self.stack, value, meter)?;
                }
                0x43 => {
                    let value = WasmBoundaryValue::F32Bits(self.reader.read_u32_le(function)?);
                    push_value(&mut self.stack, value, meter)?;
                }
                0x44 => {
                    let value = WasmBoundaryValue::F64Bits(self.reader.read_u64_le(function)?);
                    push_value(&mut self.stack, value, meter)?;
                }
                0x45..=0xc4 => control::execute_numeric(opcode, &mut self.stack, function)?,
                _ => return Err(WasmNumericVmError::UnsupportedOpcode {
                    function_index: function, opcode, offset,
                }),
            }
        }
        Err(WasmNumericVmError::InvalidModule {
            detail: format!("function {function} did not terminate with end"),
        })
    }

    fn validate_results(&self) -> Result<(), WasmNumericVmError> {
        if self.stack.len() != self.signature.results.len() {
            return Err(WasmNumericVmError::ResultStackMismatch {
                function_index: self.function,
                expected: self.signature.results.len(), actual: self.stack.len(),
            });
        }
        for (index, (expected, value)) in self.signature.results.iter().zip(&self.stack).enumerate() {
            ensure_same_type(self.function, index, *expected, value.value_type())?;
        }
        Ok(())
    }
}

fn resume(
    frames: &mut [Activation<'_>],
    results: Vec<WasmBoundaryValue>,
    meter: &mut ExecutionMeter<'_>,
) -> Result<Option<Vec<WasmBoundaryValue>>, WasmNumericVmError> {
    let Some(caller) = frames.last_mut() else { return Ok(Some(results)); };
    // These operands become active again; observe_stack counts them on each
    // result push, rather than counting the suspended prefix twice.
    remove_base(meter, caller.stack.len())?;
    for value in results { push_value(&mut caller.stack, value, meter)?; }
    Ok(None)
}

/// One cooperative slice. Subtraction avoids overflow near u64::MAX and never
/// turns a depleted *invocation* budget into an endlessly yielding continuation.
#[derive(Clone, Copy)]
struct Slice {
    start: u64,
    work: NonZeroU64,
}

impl Slice {
    fn exhausted(self, meter: &ExecutionMeter<'_>) -> bool {
        meter.instructions.saturating_sub(self.start) >= self.work.get()
    }
}

struct Machine<'vm, 'args> {
    frames: Vec<Activation<'vm>>,
    pending: Option<(u32, Cow<'args, [WasmBoundaryValue]>)>,
    depth: u32,
}

impl<'vm, 'args> Machine<'vm, 'args> {
    fn new(function: u32, arguments: Cow<'args, [WasmBoundaryValue]>, depth: u32) -> Self {
        Self { frames: Vec::new(), pending: Some((function, arguments)), depth }
    }

    /// None means a suspension BEFORE the next opcode or pending callee.
    /// All stack/label accounting stays in place until this invocation ends.
    fn run(
        &mut self,
        vm: &'vm WasmNumericVm,
        meter: &mut ExecutionMeter<'_>,
        state: &mut state::InstanceState,
        slice: Option<Slice>,
    ) -> Result<Option<Vec<WasmBoundaryValue>>, WasmNumericVmError> {
        loop {
            state.check_execution_cancellation()?;
            if slice.is_some_and(|slice| slice.exhausted(meter)) { return Ok(None); }
            if let Some((callee, arguments)) = self.pending.take() {
                let call_depth = u32::try_from(self.frames.len()).ok()
                    .and_then(|nested| self.depth.checked_add(nested))
                    .ok_or(WasmNumericVmError::CallDepthExceeded { max: vm.limits.max_call_depth })?;
                meter.enter_call(call_depth)?;
                if (callee as usize) < vm.imports.len() {
                    add_base(meter, arguments.len())?;
                    let results = state.invoke_import(vm, callee, &arguments, meter);
                    remove_base(meter, arguments.len())?;
                    if let Some(results) = resume(&mut self.frames, results?, meter)? {
                        return Ok(Some(results));
                    }
                } else {
                    self.frames.try_reserve(1)
                        .map_err(|_| allocation::<Activation<'_>>(self.frames.len() + 1))?;
                    self.frames.push(Activation::new(vm, callee, arguments, meter)?);
                }
            }
            let transfer = self.frames.last_mut().ok_or_else(|| WasmNumericVmError::InvalidModule {
                detail: "missing guest activation".into(),
            })?.run(vm, meter, state, slice)?;
            match transfer {
                Transfer::Call { function, arguments, tail } => {
                    if tail {
                        // Validation has checked the enclosing result contract;
                        // indirect dispatch has also checked the actual target.
                        // The active operands are not in live_value_base. Only
                        // this frame's locals need releasing; older suspended
                        // prefixes remain charged until their own continuation.
                        let frame = self.frames.pop().expect("tail-calling guest activation");
                        remove_base(meter, frame.locals.len())?;
                        drop(frame);
                    } else {
                        let frame = self.frames.last().expect("suspending guest activation");
                        add_base(meter, frame.stack.len())?;
                    }
                    // With the tail caller removed, ordinary admission computes
                    // the same depth and checks the replacement's own live-value
                    // and setup-work costs. Host tails use this same pending path.
                    self.pending = Some((function, Cow::Owned(arguments)));
                }
                Transfer::Return => {
                    let frame = self.frames.pop().expect("returning guest activation");
                    remove_base(meter, frame.locals.len())?;
                    let results = frame.stack;
                    // Locals and control labels are dropped before the caller
                    // resumes. No frame owns another frame, even on an error.
                    drop(frame.locals);
                    drop(frame.controls);
                    if let Some(results) = resume(&mut self.frames, results, meter)? {
                        return Ok(Some(results));
                    }
                }
                Transfer::Yield => return Ok(None),
            }
        }
    }
}

pub(super) fn invoke(
    vm: &WasmNumericVm,
    function: u32,
    arguments: &[WasmBoundaryValue],
    depth: u32,
    meter: &mut ExecutionMeter<'_>,
    state: &mut state::InstanceState,
) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> {
    let previous_base = meter.live_value_base;
    let mut machine = Machine::new(function, Cow::Borrowed(arguments), depth);
    let outcome = machine.run(vm, meter, state, None).and_then(|result| {
        result.ok_or_else(|| WasmNumericVmError::InvalidModule {
            detail: "unbounded invocation unexpectedly yielded".into(),
        })
    });
    // Failure drops the flat frames, not already completed guest/host effects.
    meter.live_value_base = previous_base;
    match outcome {
        Ok(results) => {
            state.check_execution_cancellation()?;
            Ok(results)
        }
        // Do not replace the first budget, validation or host failure with a
        // request that arrived while cleaning up the rejected invocation.
        Err(error) => Err(error),
    }
}

/// A single export invocation borrowing its instance exclusively until it
/// completes, traps or is dropped. Locals, labels, pending calls and the original
/// invocation meter survive every yield. There is no clone/serialization path
/// that could fork an invocation or repeat a completed host effect.
///
/// Dropping this handle cancels only the unfinished computation. It releases
/// the instance for later calls and does NOT roll back completed writes or I/O.
/// Instance startup has already run; this handle never reruns startup.
#[must_use = "resume the call or explicitly drop it to cancel"]
pub struct WasmCall<'call, 'vm> {
    vm: &'vm WasmNumericVm,
    state: &'call mut state::InstanceState,
    machine: Machine<'vm, 'static>,
    meter: ExecutionMeter<'vm>,
}

impl fmt::Debug for WasmCall<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmCall")
            .field("instructions_executed", &self.meter.instructions)
            .field("peak_stack_values", &self.meter.peak_stack_values)
            .field("max_call_depth", &self.meter.max_call_depth)
            .finish_non_exhaustive()
    }
}

/// The continuation is returned only for a genuine suspension. Completion and
/// errors consume it, so retrying either cannot execute the call a second time.
#[derive(Debug)]
#[must_use = "retain a pending continuation or drop it to cancel"]
pub enum WasmCallStep<'call, 'vm> {
    Pending(WasmCall<'call, 'vm>),
    Complete(WasmNumericExecution),
}

impl<'call, 'vm> WasmCall<'call, 'vm> {
    pub(super) fn new_export(
        vm: &'vm WasmNumericVm,
        state: &'call mut state::InstanceState,
        name: &str,
        arguments: &[WasmBoundaryValue],
    ) -> Result<Self, WasmNumericVmError> {
        if let Some(kind) = vm.state.export_kind(name) {
            return Err(WasmNumericVmError::ExportIsNotFunction { name: name.into(), kind });
        }
        let function = vm.exports.get(name)
            .ok_or_else(|| WasmNumericVmError::UnknownExport { name: name.into() })?
            .function_index;
        validate_arguments(function, vm.function_signature(function)?, arguments)?;
        // The continuation owns its arguments. Bound this allocation even if
        // it is cancelled before the first resume/activation admission.
        if arguments.len() > vm.limits.max_live_values {
            return Err(WasmNumericVmError::LiveValueLimitExceeded {
                actual: arguments.len(), max: vm.limits.max_live_values,
            });
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(arguments.len())
            .map_err(|_| allocation::<WasmBoundaryValue>(arguments.len()))?;
        owned.extend_from_slice(arguments);
        Ok(Self {
            vm, state, machine: Machine::new(function, Cow::Owned(owned), 1),
            meter: ExecutionMeter::new(&vm.limits),
        })
    }

    /// Run until completion or the first dispatch boundary after `work` units
    /// have been charged. A slice is a SOFT scheduling quantum, not a fresh hard
    /// budget: one bulk instruction, callee setup or trusted host callback can
    /// exceed it. The original max_instructions still refuses work atomically.
    /// No callback, bulk operation or memory write is split or restarted.
    ///
    /// This is cooperative scheduling, not preemption of blocking native code.
    /// An execution error consumes the continuation and preserves completed
    /// effects just like synchronous call_export. A zero quantum is unrepresentable.
    pub fn resume(mut self, work: NonZeroU64) -> Result<WasmCallStep<'call, 'vm>, WasmNumericVmError> {
        let slice = Slice { start: self.meter.instructions, work };
        let outcome = self.machine.run(self.vm, &mut self.meter, self.state, Some(slice))?;
        // Preserve the synchronous path's completion check. An execution error
        // above retains precedence over a later cancellation request.
        self.state.check_execution_cancellation()?;
        match outcome {
            Some(results) => Ok(WasmCallStep::Complete(WasmNumericExecution {
                results,
                instructions_executed: self.meter.instructions,
                peak_stack_values: self.meter.peak_stack_values,
                max_call_depth: self.meter.max_call_depth,
            })),
            None => Ok(WasmCallStep::Pending(self)),
        }
    }

    /// Cumulative work across all slices, including host/bulk/setup charges.
    pub fn instructions_executed(&self) -> u64 { self.meter.instructions }

    pub fn peak_stack_values(&self) -> usize { self.meter.peak_stack_values }

    pub fn max_call_depth(&self) -> u32 { self.meter.max_call_depth }

    /// Release this invocation's frames and exclusive borrow, keeping effects
    /// completed before cancellation. Dropping the handle has the same effect.
    pub fn cancel(self) {}
}
