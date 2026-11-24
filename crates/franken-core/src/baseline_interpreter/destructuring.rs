//! Private adapters for iterator-based array binding initialization.
//!
//! Keep the record in the existing iterator arena so callbacks, generator
//! resumes, memory accounting and exact thrown values use the ordinary paths.

use super::*;
use crate::ifc_artifacts::Label;

impl InterpreterCore {
    pub(super) fn dispatch_destructuring(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        operation: &str,
    ) -> Result<(Value, Label), InterpreterError> {
        let mut label = Label::Public;
        let result = (|| {
            let expected_count = match operation {
                "builtin:DestructureIteratorInit"
                | "builtin:DestructureIteratorNext"
                | "builtin:DestructureIteratorElide" => 1,
                "builtin:DestructureIteratorDone" | "builtin:DestructureValue" => 2,
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "known destructuring operation".into(),
                        got: operation.into(),
                    });
                }
            };
            if args.count != expected_count {
                return Err(InterpreterError::TypeError {
                    expected: format!("{expected_count} destructuring operands"),
                    got: format!("{} operands", args.count),
                });
            }
            let (input, input_label) = self.promise_hostcall_argument(args, 0)?;
            label = label.join(&input_label);
            if expected_count == 2 {
                let (_, source_label) = self.promise_hostcall_argument(args, 1)?;
                label = label.join(&source_label);
            }
            let retained_bytes = Self::estimate_timer_value_bytes(&input)
                .saturating_add(Self::estimate_label_bytes(&label));
            self.with_array_method_temporary(retained_bytes, |core| {
                match operation {
                    "builtin:DestructureValue" => Ok(input),
                    "builtin:DestructureIteratorInit" => {
                        core.init_for_of_iterator(module, input, &mut label)
                    }
                    "builtin:DestructureIteratorDone" => {
                        let handle = core.expect_iterator_handle(input)?;
                        label = label.join(&core.for_of_iterator_label(handle)?);
                        match core.iterator_state_mut(handle)? {
                            RuntimeIteratorState::ForOf(state) => {
                                Ok(Value::Bool(state.done || state.closed))
                            }
                            RuntimeIteratorState::ForIn(_) => unreachable!("validated for-of record"),
                        }
                    }
                    "builtin:DestructureIteratorNext" | "builtin:DestructureIteratorElide" => {
                        let handle = core.expect_iterator_handle(input.clone())?;
                        // Validate the record before interpreting an abrupt step
                        // as the completion of an array pattern's own iterator.
                        label = label.join(&core.for_of_iterator_label(handle)?);
                        let step = core.advance_for_of_iterator_with_value_read(
                            module,
                            input,
                            &mut label,
                            operation == "builtin:DestructureIteratorNext",
                        );
                        if step.is_err()
                            && let RuntimeIteratorState::ForOf(state) =
                                core.iterator_state_mut(handle)?
                        {
                            // IteratorStep/IteratorValue failures do not call
                            // return; a default or target write failure does.
                            state.done = true;
                        }
                        Ok(step?.unwrap_or(Value::Undefined))
                    }
                    _ => unreachable!("validated destructuring operation"),
                }
            })
        })();
        self.finish_native_builtin_call(result, label)
    }
}
