use super::*;

impl InterpreterCore {
    pub(super) fn allocate_readable_with_state(
        &mut self,
        state: ReadableFromState,
        object_properties: &[(&str, Value)],
        schedule_pump: bool,
    ) -> Result<Value, InterpreterError> {
        let state_bytes = Self::estimate_readable_from_state_bytes(&state);
        let pump_bytes = if schedule_pump {
            self.readable_pump_retained_bytes()
        } else {
            0
        };
        let mut projected_object = HeapObject::new();
        for (key, value) in object_properties {
            projected_object
                .properties
                .insert((*key).to_string(), value.clone());
        }
        projected_object.brand = Some(Box::new(JsString::from(READABLE_BRAND)));
        let object_bytes = Self::estimate_heap_object_bytes(&projected_object);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(state_bytes)
            .saturating_add(object_bytes)
            .saturating_add(pump_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(
                requested_bytes,
                self.heap_object_count_u32().saturating_add(1),
            ));
        }
        let previous_total = self.estimated_memory_bytes;
        let previous_heap_len = self.heap.len();
        self.apply_memory_component_delta(0, state_bytes)?;

        let object_id = match self.alloc_branded_object(READABLE_BRAND, object_properties) {
            Ok(object_id) => object_id,
            Err(error) => {
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(state_bytes);
                return Err(error);
            }
        };
        self.readable_from_streams.insert(object_id, state);
        if schedule_pump && let Err(error) = self.schedule_readable_from_pump(object_id) {
            self.readable_from_streams.remove(&object_id);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }
        Ok(Value::Object(object_id))
    }

    pub(super) fn readable_object_properties(
        object_mode: bool,
        high_water_mark: i64,
    ) -> [(&'static str, Value); 9] {
        [
            ("__maxListeners", Value::Int(10)),
            ("readable", Value::Bool(true)),
            ("readableEnded", Value::Bool(false)),
            ("readableFlowing", Value::Null),
            ("readableLength", Value::Int(0)),
            ("readableObjectMode", Value::Bool(object_mode)),
            ("readableHighWaterMark", Value::Int(high_water_mark)),
            ("destroyed", Value::Bool(false)),
            ("closed", Value::Bool(false)),
        ]
    }

    pub(super) fn readable_pump_registration_bytes(&self) -> u64 {
        self.event_loop
            .projected_io_completion_memory_bytes(&Label::Public)
            .saturating_sub(self.event_loop.estimated_memory_bytes())
    }

    pub(super) fn readable_pump_retained_bytes(&self) -> u64 {
        self.readable_pump_registration_bytes()
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
    }

    pub(super) fn estimate_readable_pump_reservation_bytes(
        reservation: &ReadablePumpReservation,
    ) -> u64 {
        reservation
            .bytes
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
    }

    pub(super) fn pending_readable_pumps_memory_bytes(&self) -> u64 {
        u64::try_from(self.pending_readable_from_pumps.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
    }

    pub(super) fn readable_pump_reservations_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.readable_pump_reservations
                .values()
                .map(Self::estimate_readable_pump_reservation_bytes),
        )
    }

    pub(super) fn remove_pending_readable_pump(&mut self, registration: u64) -> Option<ObjectId> {
        let object_id = self.pending_readable_from_pumps.remove(&registration)?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        Some(object_id)
    }

    pub(super) fn has_pending_readable_pump(&self, object_id: ObjectId) -> bool {
        self.pending_readable_from_pumps
            .values()
            .any(|pending| *pending == object_id)
    }

    /// Queue one future pump turn, suppressing duplicate schedules created by
    /// re-entrant listener registration. A refused logical-memory charge rolls
    /// the task and deterministic sequence back before either becomes visible.
    pub(super) fn schedule_readable_from_pump(
        &mut self,
        object_id: ObjectId,
    ) -> Result<bool, InterpreterError> {
        if !self.readable_from_streams.contains_key(&object_id) {
            return Ok(false);
        }
        self.schedule_readable_pump_registration(object_id)
    }

    pub(super) fn schedule_readable_pump_registration(
        &mut self,
        object_id: ObjectId,
    ) -> Result<bool, InterpreterError> {
        if self.has_pending_readable_pump(object_id) {
            return Ok(false);
        }
        if let Some(reservation) = self.readable_pump_reservations.get_mut(&object_id) {
            reservation.requested = true;
            return Ok(false);
        }
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let seq = self
            .event_loop
            .schedule_io_completion(crate::closure_model::ClosureHandle(0), Label::Public);
        let next_component_bytes = self
            .promise_runtime_memory_bytes()
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        if let Err(error) =
            self.apply_memory_component_delta(previous_promise_bytes, next_component_bytes)
        {
            self.event_loop.rollback_last_scheduled(seq);
            return Err(error);
        }
        let previous = self.pending_readable_from_pumps.insert(seq, object_id);
        debug_assert!(
            previous.is_none(),
            "EventLoop registration sequences are unique"
        );
        Ok(true)
    }

    /// Precharge a successor pump without assigning its sequence yet. The
    /// reservation suppresses re-entrant duplicates until the surrounding
    /// callback returns and the caller converts it into a real task.
    pub(super) fn reserve_readable_pump(
        &mut self,
        object_id: ObjectId,
    ) -> Result<bool, InterpreterError> {
        if !self.readable_from_streams.contains_key(&object_id)
            || self.has_pending_readable_pump(object_id)
            || self.readable_pump_reservations.contains_key(&object_id)
        {
            return Ok(false);
        }
        let reserved_bytes = self.readable_pump_registration_bytes();
        let reservation = ReadablePumpReservation {
            bytes: reserved_bytes,
            requested: false,
        };
        self.apply_memory_component_delta(
            0,
            Self::estimate_readable_pump_reservation_bytes(&reservation),
        )?;
        let previous = self
            .readable_pump_reservations
            .insert(object_id, reservation);
        debug_assert!(previous.is_none(), "duplicate reservations are suppressed");
        Ok(true)
    }

    pub(super) fn release_readable_pump_reservation(&mut self, object_id: ObjectId) {
        if let Some(reservation) = self.readable_pump_reservations.remove(&object_id) {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_readable_pump_reservation_bytes(&reservation));
        }
    }

    pub(super) fn remove_readable_pipe_link(
        &mut self,
        source: ObjectId,
    ) -> Option<ReadablePipeLink> {
        let removed = self.readable_pipe_links.remove(&source)?;
        let reverse_removed = self.readable_pipe_sources.remove(&removed.destination);
        debug_assert_eq!(reverse_removed, Some(source));
        let removed_entries = 1u64.saturating_add(u64::from(reverse_removed.is_some()));
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_mul(removed_entries));
        Some(removed)
    }

    pub(super) fn clear_readable_pipe_links(&mut self) {
        while let Some((source, link)) = self
            .readable_pipe_links
            .iter()
            .next()
            .map(|(source, link)| (*source, *link))
        {
            self.remove_readable_pipe_link(source);
            self.remove_readable_pipe_listener_records(
                source,
                "end",
                BuiltinFunctionKind::StreamReadablePipeEnd,
                link.destination,
                link.token,
            );
            self.remove_readable_pipe_listener_records(
                source,
                "data",
                BuiltinFunctionKind::StreamReadablePipeData,
                link.destination,
                link.token,
            );
            self.remove_readable_pipe_listener_records(
                link.destination,
                "drain",
                BuiltinFunctionKind::StreamReadablePipeDrain,
                source,
                link.token,
            );
        }
        debug_assert!(self.readable_pipe_sources.is_empty());
    }

    /// Writable terminalization owns the inverse edge of every pipe link.
    /// The reverse edge avoids an uncharged scan across unrelated sources.
    pub(super) fn detach_readable_pipes_to_destination(&mut self, destination: ObjectId) {
        if let Some(source) = self.readable_pipe_sources.get(&destination).copied()
            && let Some(link) = self.readable_pipe_links.get(&source).copied()
        {
            self.detach_readable_pipe(source, destination, link.token);
        }
    }

    pub(super) fn detach_current_readable_pipe(&mut self, source: ObjectId) {
        if let Some(link) = self.readable_pipe_links.get(&source).copied() {
            self.detach_readable_pipe(source, link.destination, link.token);
        }
    }

    /// Removing an internal callback retires the entire authenticated edge.
    /// Drain callbacks belong to the Writable rather than the Readable.
    pub(super) fn detach_readable_pipe_listener(&mut self, target: ObjectId, listener: &Value) {
        if matches!(listener, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::StreamReadablePipeDrain)
        {
            self.detach_readable_pipes_to_destination(target);
        } else {
            self.detach_current_readable_pipe(target);
        }
    }

    /// Finish an operation that no longer needs its unconditional successor
    /// reservation. Re-entrant guest work may already have requested a pump;
    /// preserve that request even when the surrounding operation returns an
    /// error, otherwise committed callback mutations can be stranded forever.
    pub(super) fn settle_readable_pump_reservation(
        &mut self,
        object_id: ObjectId,
        reserved: bool,
    ) -> Result<(), InterpreterError> {
        if !reserved {
            return Ok(());
        }
        let requested = self
            .readable_pump_reservations
            .get(&object_id)
            .is_some_and(|reservation| reservation.requested);
        if requested && self.readable_from_streams.contains_key(&object_id) {
            if let Err(error) = self.convert_readable_pump_reservation(object_id) {
                self.release_readable_pump_reservation(object_id);
                return Err(error);
            }
        } else {
            self.release_readable_pump_reservation(object_id);
        }
        Ok(())
    }

    pub(super) fn readable_error_after_reservation<T>(
        &mut self,
        object_id: ObjectId,
        reserved: bool,
        error: InterpreterError,
    ) -> Result<T, InterpreterError> {
        self.settle_readable_pump_reservation(object_id, reserved)?;
        Err(error)
    }

    /// Replace a precharged reservation with the real event-loop task while
    /// keeping the total charge continuous. Projection and materialization are
    /// checked against the same estimator; a future mismatch fails closed and
    /// restores both the reservation and deterministic sequence.
    pub(super) fn convert_readable_pump_reservation(
        &mut self,
        object_id: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let Some(reservation) = self.readable_pump_reservations.remove(&object_id) else {
            return self.schedule_readable_from_pump(object_id);
        };
        let reserved_bytes = reservation.bytes;
        let reserved_total = Self::estimate_readable_pump_reservation_bytes(&reservation);
        if !self.readable_from_streams.contains_key(&object_id) {
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(reserved_total);
            return Ok(false);
        }

        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let seq = self
            .event_loop
            .schedule_io_completion(crate::closure_model::ClosureHandle(0), Label::Public);
        let actual_bytes = self
            .promise_runtime_memory_bytes()
            .saturating_sub(previous_promise_bytes);
        let actual_total = actual_bytes.saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        if let Err(error) = self.apply_memory_component_delta(reserved_total, actual_total) {
            self.event_loop.rollback_last_scheduled(seq);
            self.readable_pump_reservations
                .insert(object_id, reservation);
            return Err(error);
        }
        debug_assert_eq!(reserved_bytes, actual_bytes);
        debug_assert_eq!(reserved_total, actual_total);
        let previous = self.pending_readable_from_pumps.insert(seq, object_id);
        debug_assert!(
            previous.is_none(),
            "EventLoop registration sequences are unique"
        );
        Ok(true)
    }

    pub(super) fn finish_readable_pump_after_emission(
        &mut self,
        object_id: ObjectId,
        reserved: bool,
        emission: Result<bool, InterpreterError>,
    ) -> Result<(), InterpreterError> {
        let scheduling = if reserved {
            self.convert_readable_pump_reservation(object_id)
        } else {
            self.schedule_readable_from_pump(object_id)
        };
        if let Err(error) = scheduling {
            if reserved {
                self.release_readable_pump_reservation(object_id);
            }
            return Err(error);
        }
        emission?;
        Ok(())
    }

    /// Release only the failed Readable's engine-owned lifecycle state before
    /// an asynchronous listener exception escapes the evaluation boundary.
    ///
    /// `finish_readable_pump_after_emission` admits the successor before guest
    /// code can fail. Returning that failure directly from the event-loop turn
    /// used to strand the successor, queue, listener table, and pipe edges.
    /// Continuing the ordinary event loop would be worse: unrelated callbacks
    /// could run after an uncaught exception. Cancel just this Readable's
    /// successor and terminalize it without invoking any more guest listeners.
    /// The original exception remains the result of the failed turn (bd-tc2iu).
    pub(super) fn abort_readable_after_async_failure(&mut self, object_id: ObjectId) {
        while let Some(registration) = self
            .pending_readable_from_pumps
            .iter()
            .find_map(|(registration, pending)| (*pending == object_id).then_some(*registration))
        {
            self.remove_pending_readable_pump(registration);
            let previous_promise_bytes = self.promise_runtime_memory_bytes();
            let _ = self.event_loop.cancel_registration(registration);
            let released_promise_bytes =
                previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(released_promise_bytes);
        }
        self.release_readable_pump_reservation(object_id);

        self.mirror_readable_bool(object_id, "destroyed", true);
        self.mirror_readable_bool(object_id, "closed", true);
        self.mirror_readable_bool(object_id, "readable", false);
        self.detach_current_readable_pipe(object_id);
        self.clear_event_listeners(object_id, None);
        self.clear_event_promise_waiters_for_target(object_id);

        let Some(mut state) = self.readable_from_streams.remove(&object_id) else {
            return;
        };
        let state_bytes = Self::estimate_readable_from_state_bytes(&state);
        let terminal = ReadableTerminalState {
            lifecycle_label: std::mem::replace(&mut state.lifecycle_label, Label::Public),
        };
        let terminal_bytes = Self::estimate_readable_terminal_state_bytes(&terminal);
        let previous = self.readable_terminal_states.insert(object_id, terminal);
        debug_assert!(previous.is_none());
        let previous_terminal_bytes = previous
            .as_ref()
            .map(Self::estimate_readable_terminal_state_bytes)
            .unwrap_or(0);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(state_bytes)
            .saturating_sub(previous_terminal_bytes)
            .saturating_add(terminal_bytes);
    }

    /// A `data` observer puts a Readable into flowing mode; a `readable`
    /// observer selects paused/pull mode. Both are engine-owned internal-slot
    /// transitions. Mirror the decision into the existing public property
    /// without a fallible guest write after a listener/waiter record has been
    /// committed. If guest code deleted that mirror, preserve the deletion.
    pub(super) fn readable_activation_applies(&self, object_id: ObjectId, event: &str) -> bool {
        if !matches!(event, "data" | "readable") {
            return false;
        }
        let Some(state) = self.readable_from_streams.get(&object_id) else {
            return false;
        };
        state.phase != ReadableFromPumpPhase::SettleToArray && (event != "data" || !state.paused)
    }

    pub(super) fn has_readable_pull_observer(&self, object_id: ObjectId) -> bool {
        self.event_listeners
            .get(&object_id)
            .and_then(|events| events.get(&RuntimePropertyKey::from("readable")))
            .is_some_and(|records| !records.is_empty())
            || self
                .event_promise_waiters
                .get(&object_id)
                .and_then(|events| events.get(&RuntimePropertyKey::from("readable")))
                .is_some_and(|waiters| !waiters.is_empty())
    }

    pub(super) fn reserve_readable_activation_pump(
        &mut self,
        object_id: ObjectId,
        event: &str,
    ) -> Result<bool, InterpreterError> {
        if !self.readable_activation_applies(object_id, event) {
            return Ok(false);
        }
        self.reserve_readable_pump(object_id)
    }

    pub(super) fn activate_readable_from_data_flow_with_reservation(
        &mut self,
        object_id: ObjectId,
        event: &str,
        reserved: bool,
    ) -> Result<(), InterpreterError> {
        if !self.readable_activation_applies(object_id, event) {
            self.settle_readable_pump_reservation(object_id, reserved)?;
            return Ok(());
        }
        let flowing = event == "data";
        let paused = event == "readable";
        self.set_readable_flow_and_schedule_with_reservation(object_id, flowing, paused, reserved)
    }

    pub(super) fn set_readable_flow_and_schedule_with_reservation(
        &mut self,
        object_id: ObjectId,
        flowing: bool,
        paused: bool,
        reserved: bool,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.readable_from_streams.get_mut(&object_id) else {
            self.settle_readable_pump_reservation(object_id, reserved)?;
            return Ok(());
        };
        let previous_flowing = state.flowing;
        let previous_paused = state.paused;
        state.flowing = flowing;
        state.paused = paused;
        let scheduled = if reserved {
            self.convert_readable_pump_reservation(object_id)
        } else {
            self.schedule_readable_from_pump(object_id)
        };
        if let Err(error) = scheduled {
            if let Some(state) = self.readable_from_streams.get_mut(&object_id) {
                state.flowing = previous_flowing;
                state.paused = previous_paused;
            }
            if reserved {
                self.release_readable_pump_reservation(object_id);
            }
            return Err(error);
        }
        let key = "readableFlowing";
        let previous_bytes = self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key))
            .map(|value| Self::estimate_property_entry_bytes(key, value));
        self.mutate_heap(|heap| {
            if let Some(flowing_slot) = heap
                .get_mut(object_id.0 as usize)
                .and_then(|object| object.properties.get_mut(key))
            {
                *flowing_slot = Value::Bool(flowing);
            }
        });
        if let Some(previous_bytes) = previous_bytes {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(Self::estimate_property_entry_bytes(
                    key,
                    &Value::Bool(flowing),
                ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn activate_readable_from_data_flow(
        &mut self,
        object_id: ObjectId,
        event: &str,
    ) -> Result<(), InterpreterError> {
        let reserved = self.reserve_readable_activation_pump(object_id, event)?;
        self.activate_readable_from_data_flow_with_reservation(object_id, event, reserved)
    }

    pub(super) fn readable_receiver_id(
        &self,
        receiver: Value,
    ) -> Result<ObjectId, InterpreterError> {
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: "Readable receiver".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        let is_readable = self
            .readable_from_streams
            .get(&object_id)
            .is_some_and(|state| state.phase != ReadableFromPumpPhase::SettleToArray);
        if !is_readable {
            return Err(InterpreterError::TypeError {
                expected: "Readable receiver".to_string(),
                got: "non-Readable object".to_string(),
            });
        }
        Ok(object_id)
    }

    pub(super) fn readable_pause(&mut self, receiver: Value) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        self.set_object_property(object_id, "readableFlowing".to_string(), Value::Bool(false))?;
        if let Some(state) = self.readable_from_streams.get_mut(&object_id) {
            state.flowing = false;
            state.paused = true;
        }
        Ok(Value::Object(object_id))
    }

    pub(super) fn readable_resume(&mut self, receiver: Value) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        let previous = self
            .readable_from_streams
            .get(&object_id)
            .map(|state| (state.flowing, state.paused));
        if let Some(state) = self.readable_from_streams.get_mut(&object_id) {
            state.flowing = true;
            state.paused = false;
        }
        if let Err(error) = self.schedule_readable_pump_registration(object_id) {
            if let (Some(state), Some((flowing, paused))) =
                (self.readable_from_streams.get_mut(&object_id), previous)
            {
                state.flowing = flowing;
                state.paused = paused;
            }
            return Err(error);
        }
        self.mirror_readable_bool(object_id, "readableFlowing", true);
        Ok(Value::Object(object_id))
    }

    /// Attach one engine-owned Writable to a Readable without exposing a
    /// forgeable pipe-link object. Data/end and drain builtin listeners
    /// reuse the ordinary EventEmitter table, so registration memory, IFC
    /// dispatch, re-entrant snapshots, and source-close cleanup all follow the
    /// existing audited paths.
    pub(super) fn readable_pipe(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count > 2 {
            return Err(InterpreterError::TypeError {
                expected: "Readable.pipe(destination[, options])".to_string(),
                got: format!("{} arguments", args.count),
            });
        }
        let source_id = self.readable_receiver_id(receiver)?;
        let destination =
            self.builtin_arg(args, 0)?
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "live Writable pipe destination".to_string(),
                    got: "missing argument".to_string(),
                })?;
        let destination_id = self.writable_receiver_id(destination.clone())?;
        // Only literal false suppresses automatic end. The option is an
        // ordinary Get (including inherited accessors and Proxy traps), read
        // once before registering listeners or emitting `pipe`. Falsy options
        // use the default, and unrelated properties are never inspected.
        let end_destination = match self.builtin_arg(args, 1)? {
            Some(options) if options.is_truthy() => {
                let option_register = args.start.checked_add(1).ok_or(
                    InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    },
                )?;
                let observation = self.begin_property_observation([option_register])?;
                let outcome = self
                    .get_v(module, &options, &RuntimePropertyKey::from("end"))
                    .map(|end| !matches!(end, Value::Bool(false)));
                self.finish_property_read_observation(observation, outcome)?
            }
            _ => true,
        };

        // The Get above may re-enter the runtime and end/destroy either
        // stream or install a different link. All state checks and resource
        // preflights below therefore use the state AFTER that observation.
        let destination_live = self
            .writable_streams
            .get(&destination_id)
            .is_some_and(|state| {
                !state.end_requested && !state.destroy_requested && !state.finished
            });
        if !destination_live {
            return Err(InterpreterError::TypeError {
                expected: "live Writable pipe destination".to_string(),
                got: "ended or destroyed Writable".to_string(),
            });
        }

        if self.readable_pipe_links.contains_key(&source_id) {
            return Err(InterpreterError::TypeError {
                expected: "Readable without an existing pipe destination".to_string(),
                got: "multiple destinations are outside the bounded pipe subset".to_string(),
            });
        }
        if self.readable_pipe_sources.contains_key(&destination_id) {
            return Err(InterpreterError::TypeError {
                expected: "Writable without an existing pipe source".to_string(),
                got: "multiple sources are outside the bounded pipe subset".to_string(),
            });
        }

        let token = self.next_readable_pipe_token;
        let next_token = token
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Readable.pipe authentication token space exhausted".to_string(),
            })?;
        let pump_bytes = if self.has_pending_readable_pump(source_id)
            || self.readable_pump_reservations.contains_key(&source_id)
        {
            0
        } else {
            self.readable_pump_retained_bytes()
        };
        let pipe_listener_value_bytes = Self::estimate_string_bytes("");
        let data_record_bytes = MEMORY_ESTIMATE_EVENT_LISTENER_BASE_BYTES
            .saturating_add(Self::estimate_string_bytes("data"))
            .saturating_add(pipe_listener_value_bytes);
        let end_record_bytes = MEMORY_ESTIMATE_EVENT_LISTENER_BASE_BYTES
            .saturating_add(Self::estimate_string_bytes("end"))
            .saturating_add(pipe_listener_value_bytes);
        let drain_record_bytes = MEMORY_ESTIMATE_EVENT_LISTENER_BASE_BYTES
            .saturating_add(Self::estimate_string_bytes("drain"))
            .saturating_add(pipe_listener_value_bytes);
        let listener_values_bytes = pipe_listener_value_bytes.saturating_mul(3);
        let data_scan_len = self
            .event_listeners
            .get(&source_id)
            .and_then(|by_event| by_event.get(&RuntimePropertyKey::from("data")))
            .map(Vec::len)
            .unwrap_or(0)
            .saturating_add(1);
        let end_scan_len = self
            .event_listeners
            .get(&source_id)
            .and_then(|by_event| by_event.get(&RuntimePropertyKey::from("end")))
            .map(Vec::len)
            .unwrap_or(0)
            .saturating_add(1);
        let drain_scan_len = self
            .event_listeners
            .get(&destination_id)
            .and_then(|by_event| by_event.get(&RuntimePropertyKey::from("drain")))
            .map(Vec::len)
            .unwrap_or(0)
            .saturating_add(1);
        // Reserve synchronous postvalidation and eventual teardown scans.
        // Source data/end registration stays bounded while linked. Later
        // destination drain registrations precharge their added scan work.
        let pipe_scan_cost = u64::try_from(
            data_scan_len
                .saturating_add(end_scan_len)
                .saturating_add(drain_scan_len),
        )
        .unwrap_or(u64::MAX)
        .saturating_mul(2);
        let instructions_before_pipe = self.instructions_executed;
        let instructions_after_pipe = instructions_before_pipe.saturating_add(pipe_scan_cost);
        if instructions_after_pipe > self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: instructions_before_pipe,
                budget: self.config.instruction_budget,
            });
        }

        // Find the final provenance winner entirely through borrowed labels.
        // The aggregate physical-peak check must happen before cloning either
        // the attacker-sized Readable projection or a Custom label name.
        let (
            projected,
            original_bytes,
            projected_bytes,
            pipe_label,
            data_listener,
            end_listener,
            drain_listener,
        ) = {
            let Some(current) = self.readable_from_streams.get(&source_id) else {
                return Err(InterpreterError::TypeError {
                    expected: "live Readable pipe source".to_string(),
                    got: "closed Readable".to_string(),
                });
            };
            if current.destroy_requested {
                return Err(InterpreterError::TypeError {
                    expected: "live Readable pipe source".to_string(),
                    got: "destroyed Readable".to_string(),
                });
            }
            let mut winner = &current.lifecycle_label;
            for index in 0..args.count {
                let register =
                    args.start
                        .checked_add(index)
                        .ok_or(InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: u32::MAX,
                        })?;
                let candidate = self.get_register_label(register)?;
                if candidate > winner {
                    winner = candidate;
                }
            }
            if let Some(destination_label) = self.stream_state_label_ref(destination_id)
                && destination_label > winner
            {
                winner = destination_label;
            }
            if let Some(context_label) = self.active_execution_context_label()
                && context_label > winner
            {
                winner = context_label;
            }
            if let Some(option_label) = self.pending_hostcall_result_label.as_ref()
                && option_label > winner
            {
                // Reading `end` selects a later lifecycle effect. Retain its
                // shape, descriptor and callback provenance after the caller
                // frame and the options object have disappeared.
                winner = option_label;
            }

            let original_bytes = Self::estimate_readable_from_state_bytes(current);
            let current_label_bytes = Self::estimate_label_bytes(&current.lifecycle_label);
            let pipe_label_bytes = Self::estimate_label_bytes(winner);
            let projected_upper_bytes = original_bytes
                .saturating_sub(current_label_bytes)
                .saturating_add(pipe_label_bytes);
            let retained_delta_upper = projected_upper_bytes
                .saturating_sub(original_bytes)
                .saturating_add(pump_bytes)
                .saturating_add(data_record_bytes)
                .saturating_add(end_record_bytes)
                .saturating_add(drain_record_bytes)
                .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_mul(2));
            let preclone_temporary = listener_values_bytes
                .saturating_add(original_bytes)
                .saturating_add(pipe_label_bytes);
            let precommit_temporary = listener_values_bytes
                .saturating_add(projected_upper_bytes)
                .saturating_add(pipe_label_bytes);
            let committed_temporary = original_bytes
                .saturating_add(pipe_label_bytes)
                .saturating_add(listener_values_bytes);
            self.check_temporary_memory_budget(
                preclone_temporary
                    .max(precommit_temporary)
                    .max(retained_delta_upper.saturating_add(committed_temporary)),
            )?;

            let data_listener = Value::BuiltinFunction(BuiltinFunction::readable_pipe_listener(
                BuiltinFunctionKind::StreamReadablePipeData,
                destination_id,
                token,
            ));
            let end_listener = Value::BuiltinFunction(BuiltinFunction::readable_pipe_listener(
                BuiltinFunctionKind::StreamReadablePipeEnd,
                destination_id,
                token,
            ));
            let drain_listener = Value::BuiltinFunction(BuiltinFunction::readable_pipe_listener(
                BuiltinFunctionKind::StreamReadablePipeDrain,
                source_id,
                token,
            ));
            let final_label = winner.clone();
            let mut projected = self.try_clone_readable_state(current)?;
            drop(std::mem::replace(
                &mut projected.lifecycle_label,
                final_label,
            ));
            projected.flowing = true;
            projected.paused = false;
            let projected_bytes = Self::estimate_readable_from_state_bytes(&projected);
            debug_assert!(projected_bytes <= projected_upper_bytes);
            let pipe_label = projected.lifecycle_label.clone();
            (
                projected,
                original_bytes,
                projected_bytes,
                pipe_label,
                data_listener,
                end_listener,
                drain_listener,
            )
        };
        self.instructions_executed = instructions_after_pipe;
        let pump_reserved = match self.reserve_readable_pump(source_id) {
            Ok(reserved) => reserved,
            Err(error) => {
                self.instructions_executed = instructions_before_pipe;
                return Err(error);
            }
        };
        let original = self
            .readable_from_streams
            .remove(&source_id)
            .expect("readable source was cloned from live state");

        if let Err(error) = self.apply_memory_component_delta(original_bytes, projected_bytes) {
            self.readable_from_streams.insert(source_id, original);
            if pump_reserved {
                self.release_readable_pump_reservation(source_id);
            }
            self.instructions_executed = instructions_before_pipe;
            return Err(error);
        }
        self.readable_from_streams.insert(source_id, projected);
        if let Err(error) = self.insert_event_listener(
            source_id,
            "data",
            EventListenerRecord {
                listener: data_listener.clone(),
                once: false,
            },
            false,
        ) {
            self.restore_readable_pipe_state(source_id, original);
            let result = self.readable_error_after_reservation(source_id, pump_reserved, error);
            self.instructions_executed = instructions_before_pipe;
            return result;
        }
        if let Err(error) = self.insert_event_listener(
            source_id,
            "end",
            EventListenerRecord {
                listener: end_listener.clone(),
                once: true,
            },
            false,
        ) {
            self.rollback_inserted_event_listener(source_id, "data", false);
            self.restore_readable_pipe_state(source_id, original);
            let result = self.readable_error_after_reservation(source_id, pump_reserved, error);
            self.instructions_executed = instructions_before_pipe;
            return result;
        }
        if let Err(error) = self.insert_event_listener(
            destination_id,
            "drain",
            EventListenerRecord {
                listener: drain_listener.clone(),
                once: false,
            },
            false,
        ) {
            self.rollback_inserted_event_listener(source_id, "end", false);
            self.rollback_inserted_event_listener(source_id, "data", false);
            self.restore_readable_pipe_state(source_id, original);
            let result = self.readable_error_after_reservation(source_id, pump_reserved, error);
            self.instructions_executed = instructions_before_pipe;
            return result;
        }
        drop(data_listener);
        drop(end_listener);
        drop(drain_listener);
        if let Err(error) =
            self.apply_memory_component_delta(0, MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_mul(2))
        {
            self.rollback_inserted_event_listener(destination_id, "drain", false);
            self.rollback_inserted_event_listener(source_id, "end", false);
            self.rollback_inserted_event_listener(source_id, "data", false);
            self.restore_readable_pipe_state(source_id, original);
            let result = self.readable_error_after_reservation(source_id, pump_reserved, error);
            self.instructions_executed = instructions_before_pipe;
            return result;
        }
        self.readable_pipe_links.insert(
            source_id,
            ReadablePipeLink {
                destination: destination_id,
                token,
                end_destination,
                awaiting_drain: false,
            },
        );
        self.readable_pipe_sources.insert(destination_id, source_id);

        if let Err(error) = self.set_readable_flow_and_schedule_with_reservation(
            source_id,
            true,
            false,
            pump_reserved,
        ) {
            self.remove_readable_pipe_link(source_id);
            self.rollback_inserted_event_listener(destination_id, "drain", false);
            self.rollback_inserted_event_listener(source_id, "end", false);
            self.rollback_inserted_event_listener(source_id, "data", false);
            self.restore_readable_pipe_state(source_id, original);
            self.instructions_executed = instructions_before_pipe;
            return Err(error);
        }
        self.next_readable_pipe_token = next_token;
        drop(original);

        self.emit_event_listener_records(
            module,
            destination_id,
            "pipe",
            vec![Value::Object(source_id)],
            pipe_label,
        )?;
        let link_remains_live = self
            .readable_pipe_links
            .get(&source_id)
            .is_some_and(|link| link.destination == destination_id && link.token == token)
            && self.readable_pipe_sources.get(&destination_id) == Some(&source_id)
            && self
                .readable_from_streams
                .get(&source_id)
                .is_some_and(|state| !state.destroy_requested)
            && self
                .writable_streams
                .get(&destination_id)
                .is_some_and(|state| {
                    !state.end_requested && !state.destroy_requested && !state.finished
                })
            && self.matching_readable_pipe_listener_count(
                source_id,
                "data",
                BuiltinFunctionKind::StreamReadablePipeData,
                destination_id,
                token,
            ) == 1
            && self.matching_readable_pipe_listener_count(
                source_id,
                "end",
                BuiltinFunctionKind::StreamReadablePipeEnd,
                destination_id,
                token,
            ) == 1
            && self.matching_readable_pipe_listener_count(
                destination_id,
                "drain",
                BuiltinFunctionKind::StreamReadablePipeDrain,
                source_id,
                token,
            ) == 1;
        if !link_remains_live {
            if self
                .readable_pipe_links
                .get(&source_id)
                .is_some_and(|link| link.destination == destination_id && link.token == token)
            {
                self.detach_readable_pipe(source_id, destination_id, token);
            }
            return Err(InterpreterError::TypeError {
                expected: "one live Readable.pipe listener set after pipe event".to_string(),
                got: "source, destination, or internal listener edge changed during pipe event"
                    .to_string(),
            });
        }
        Ok(destination)
    }

    /// Detach exactly the currently authenticated pipe edge. Teardown happens
    /// before the destination's synchronous `unpipe` event so a re-entrant
    /// listener may safely establish a fresh edge; the retired token makes any
    /// retained data/end/drain builtin from the old edge a no-op (bd-fw7zd.10).
    pub(super) fn readable_unpipe(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count > 1 {
            return Err(InterpreterError::TypeError {
                expected: "Readable.unpipe([destination])".to_string(),
                got: format!("{} arguments", args.count),
            });
        }
        let source_id = self.readable_receiver_id(receiver.clone())?;
        let requested_destination = match self.builtin_arg(args, 0)? {
            None | Some(Value::Undefined) => None,
            Some(Value::Object(object_id))
                if self.writable_streams.contains_key(&object_id)
                    || self.writable_terminal_states.contains_key(&object_id) =>
            {
                Some(object_id)
            }
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "Writable unpipe destination".to_string(),
                    got: value.type_name().to_string(),
                });
            }
        };
        let Some(link) = self.readable_pipe_links.get(&source_id).copied() else {
            return Ok(receiver);
        };
        if requested_destination.is_some_and(|destination| destination != link.destination) {
            return Ok(receiver);
        }

        let mut emission_label = self.writable_invocation_label(args)?;
        let temporary = Self::estimate_label_bytes(&emission_label);
        let source_label = self.stream_state_label_with_temporary_budget(source_id, temporary)?;
        emission_label =
            self.join_owned_label_with_temporary_budget(emission_label, &source_label)?;
        let destination_label = self.stream_state_label_with_temporary_budget(
            link.destination,
            Self::estimate_label_bytes(&emission_label),
        )?;
        emission_label =
            self.join_owned_label_with_temporary_budget(emission_label, &destination_label)?;

        self.detach_readable_pipe(source_id, link.destination, link.token);
        self.emit_event_listener_records(
            module,
            link.destination,
            "unpipe",
            vec![Value::Object(source_id)],
            emission_label,
        )?;
        Ok(receiver)
    }

    pub(super) fn detach_readable_pipe(
        &mut self,
        source: ObjectId,
        destination: ObjectId,
        token: u32,
    ) {
        // A write callback may unpipe and establish a replacement before an
        // older invocation reports an error. Retiring its old token must not
        // remove or pause the replacement edge.
        if !self
            .readable_pipe_links
            .get(&source)
            .is_some_and(|link| link.destination == destination && link.token == token)
        {
            return;
        }
        self.remove_readable_pipe_link(source);
        self.remove_readable_pipe_listener_records(
            source,
            "end",
            BuiltinFunctionKind::StreamReadablePipeEnd,
            destination,
            token,
        );
        self.remove_readable_pipe_listener_records(
            source,
            "data",
            BuiltinFunctionKind::StreamReadablePipeData,
            destination,
            token,
        );
        self.remove_readable_pipe_listener_records(
            destination,
            "drain",
            BuiltinFunctionKind::StreamReadablePipeDrain,
            source,
            token,
        );
        let paused = if let Some(state) = self.readable_from_streams.get_mut(&source)
            && !state.destroy_requested
        {
            state.flowing = false;
            state.paused = true;
            true
        } else {
            false
        };
        if paused {
            self.mirror_readable_bool(source, "readableFlowing", false);
        }
    }

    pub(super) fn restore_readable_pipe_state(
        &mut self,
        source: ObjectId,
        original: ReadableFromState,
    ) {
        let previous_bytes = self
            .readable_from_streams
            .get(&source)
            .map(Self::estimate_readable_from_state_bytes)
            .unwrap_or(0);
        let original_bytes = Self::estimate_readable_from_state_bytes(&original);
        self.readable_from_streams.insert(source, original);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(original_bytes);
    }

    pub(super) fn readable_pipe_destination(
        &mut self,
        receiver: Value,
        builtin: &BuiltinFunction,
    ) -> Result<Option<(ObjectId, ObjectId, u32)>, InterpreterError> {
        let source = self.readable_receiver_id(receiver)?;
        let destination =
            builtin
                .bound_object
                .map(ObjectId)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "destination-bound Readable.pipe listener".to_string(),
                    got: "missing Writable destination".to_string(),
                })?;
        let token = builtin
            .iterator_handle
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "authenticated Readable.pipe listener".to_string(),
                got: "missing pipe token".to_string(),
            })?;
        let authenticated = self
            .readable_pipe_links
            .get(&source)
            .is_some_and(|link| link.destination == destination && link.token == token);
        let source_live = self
            .readable_from_streams
            .get(&source)
            .is_some_and(|state| !state.destroy_requested);
        let destination_live = self
            .writable_streams
            .get(&destination)
            .is_some_and(|state| {
                !state.end_requested && !state.destroy_requested && !state.finished
            });
        if authenticated && (!source_live || !destination_live) {
            self.detach_readable_pipe(source, destination, token);
        }
        if !authenticated || !source_live || !destination_live {
            return Ok(None);
        }
        Ok(Some((source, destination, token)))
    }

    pub(super) fn readable_pipe_data(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some((source, destination, token)) =
            self.readable_pipe_destination(receiver, builtin)?
        else {
            return Ok(Value::Undefined);
        };
        let result = match self.writable_write(module, Value::Object(destination), args) {
            Ok(result) => result,
            Err(error) => {
                self.detach_readable_pipe(source, destination, token);
                return Err(error);
            }
        };
        if matches!(result, Value::Bool(false)) {
            // write(false) accepted the chunk. Preserve the authenticated edge
            // and pause until its destination actually drains. The write may
            // have re-entered guest code and replaced or destroyed the pipe.
            if let Some(link) = self.readable_pipe_links.get_mut(&source)
                && link.destination == destination
                && link.token == token
                && self.writable_streams.get(&destination).is_some_and(|state| {
                    state.need_drain
                        && !state.destroy_requested
                        && !state.end_requested
                        && !state.finished
                })
                && let Some(state) = self.readable_from_streams.get_mut(&source)
                && !state.destroy_requested
            {
                link.awaiting_drain = true;
                state.flowing = false;
                state.paused = true;
                self.mirror_readable_bool(source, "readableFlowing", false);
            }
        }
        Ok(result)
    }

    /// Resume only the still-live edge that acquired the backpressure
    /// obligation. EventEmitter snapshots can retain this callback after
    /// unpipe, and guest emit("drain") or public mirror writes cannot discharge
    /// the destination's authoritative outstanding write state.
    pub(super) fn readable_pipe_drain(
        &mut self,
        receiver: Value,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Value::Object(destination) = receiver else {
            return Ok(Value::Undefined);
        };
        let (Some(source), Some(token)) = (builtin.bound_object, builtin.iterator_handle) else {
            return Ok(Value::Undefined);
        };
        let source = ObjectId(source);
        let authenticated = self.readable_pipe_links.get(&source).is_some_and(|link| {
            link.destination == destination && link.token == token && link.awaiting_drain
        }) && self.readable_pipe_sources.get(&destination) == Some(&source);
        if !authenticated {
            return Ok(Value::Undefined);
        }
        let source_live = self
            .readable_from_streams
            .get(&source)
            .is_some_and(|state| !state.destroy_requested);
        let destination_live = self.writable_streams.get(&destination).is_some_and(|state| {
            !state.destroy_requested && !state.end_requested && !state.finished
        });
        if !source_live || !destination_live {
            self.detach_readable_pipe(source, destination, token);
            return Ok(Value::Undefined);
        }
        let destination_state = &self.writable_streams[&destination];
        if destination_state.need_drain
            || destination_state.buffered_length != 0
            || !destination_state.writes.is_empty()
        {
            return Ok(Value::Undefined);
        }

        // Draining is a control dependency of the source's later emissions.
        // Carry both stream labels and the event's context through the resume,
        // preflighting the label copy and successor pump before changing flow.
        let mut label = self.writable_invocation_label(args)?;
        label = self.join_owned_label_with_temporary_budget(
            label,
            &self.readable_from_streams[&source].lifecycle_label,
        )?;
        label = self.join_owned_label_with_temporary_budget(
            label,
            &self.writable_streams[&destination].lifecycle_label,
        )?;
        let previous_label_bytes =
            Self::estimate_label_bytes(&self.readable_from_streams[&source].lifecycle_label);
        let next_label_bytes = Self::estimate_label_bytes(&label);
        let pump_bytes = if self.has_pending_readable_pump(source)
            || self.readable_pump_reservations.contains_key(&source)
        {
            0
        } else {
            self.readable_pump_retained_bytes()
        };
        self.check_temporary_memory_budget(next_label_bytes.saturating_add(pump_bytes))?;
        let reserved = self.reserve_readable_pump(source)?;
        if let Err(error) = self.apply_memory_component_delta(previous_label_bytes, next_label_bytes) {
            if reserved {
                self.release_readable_pump_reservation(source);
            }
            return Err(error);
        }
        let previous_label = std::mem::replace(
            &mut self
                .readable_from_streams
                .get_mut(&source)
                .expect("authenticated source remains live without guest re-entry")
                .lifecycle_label,
            label,
        );
        if let Err(error) =
            self.set_readable_flow_and_schedule_with_reservation(source, true, false, reserved)
        {
            self.readable_from_streams
                .get_mut(&source)
                .expect("failed scheduling preserves its source")
                .lifecycle_label = previous_label;
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(next_label_bytes)
                .saturating_add(previous_label_bytes);
            return Err(error);
        }
        self.readable_pipe_links
            .get_mut(&source)
            .expect("resume cannot re-enter guest code")
            .awaiting_drain = false;
        Ok(Value::Undefined)
    }

    pub(super) fn readable_pipe_end(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some((source, destination, token)) =
            self.readable_pipe_destination(receiver, builtin)?
        else {
            return Ok(Value::Undefined);
        };
        if !self.readable_pipe_links[&source].end_destination {
            // EOF retires the edge even when it leaves the Writable open.
            // Preflight provenance before detaching, then notify after all
            // internal listeners are gone so `unpipe` can connect a successor.
            let mut emission_label = self.writable_invocation_label(args)?;
            let source_label = self.stream_state_label_with_temporary_budget(
                source,
                Self::estimate_label_bytes(&emission_label),
            )?;
            emission_label = emission_label.max(source_label);
            let destination_label = self.stream_state_label_with_temporary_budget(
                destination,
                Self::estimate_label_bytes(&emission_label),
            )?;
            emission_label = emission_label.max(destination_label);
            self.detach_readable_pipe(source, destination, token);
            self.emit_event_listener_records(
                module,
                destination,
                "unpipe",
                vec![Value::Object(source)],
                emission_label,
            )?;
            return Ok(Value::Undefined);
        }
        self.detach_readable_pipe(source, destination, token);
        self.writable_end(module, Value::Object(destination), args)
    }

    pub(super) fn stream_pipeline_state_bytes(state: &StreamPipelineState) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(
                u64::try_from(state.stages.capacity())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<ObjectId>() as u64),
            )
            .saturating_add(
                u64::try_from(state.pending_close.capacity())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<ObjectId>() as u64),
            )
            .saturating_add(match &state.completion {
                StreamPipelineCompletion::Callback(callback) => {
                    Self::estimate_value_bytes(callback)
                }
                StreamPipelineCompletion::Promise(_) => 0,
            })
            .saturating_add(Self::estimate_label_bytes(&state.registration_label))
            .saturating_add(state.first_error.as_ref().map_or(0, |(error, label)| {
                Self::estimate_value_bytes(error).saturating_add(Self::estimate_label_bytes(label))
            }))
    }

    /// Relinquish every engine-owned artifact of a pipeline that cannot be
    /// published or is crossing an execution-reset boundary. Promise handles
    /// are removed before the authenticated state disappears so a failure can
    /// never leave an unreachable pending Promise behind.
    pub(super) fn abandon_stream_pipeline(&mut self, token: u32) -> Result<(), InterpreterError> {
        let Some(state) = self.stream_pipelines.get(&token) else {
            return Ok(());
        };
        if let StreamPipelineCompletion::Promise(promise) = state.completion {
            self.remove_pending_promise_at_execution_boundary(promise)?;
        }
        let state = self
            .stream_pipelines
            .remove(&token)
            .expect("validated pipeline remains owned until abandonment commits");
        self.remove_stream_pipeline_listener_records(token, &state.stages);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::stream_pipeline_state_bytes(&state));
        Ok(())
    }

    pub(super) fn construct_stream_pipeline(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        promise_mode: bool,
    ) -> Result<Value, InterpreterError> {
        let stage_count = if promise_mode {
            args.count
        } else {
            args.count.saturating_sub(1)
        };
        if stage_count < 2 || (!promise_mode && args.count < 3) {
            return Err(InterpreterError::TypeError {
                expected: "stream.pipeline(source, destination[, ...], completion)".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let stage_capacity =
            usize::try_from(stage_count).map_err(|_| InterpreterError::RangeError {
                message: "stream.pipeline stage count exceeds host address space".to_string(),
            })?;
        let one_stage_vector_bytes = u64::try_from(stage_capacity)
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<ObjectId>() as u64);
        let stage_vector_peak_bytes = one_stage_vector_bytes.saturating_mul(3);
        self.check_temporary_memory_budget(stage_vector_peak_bytes)?;
        let vector_allocation_error = || {
            self.memory_budget_error(
                self.estimated_memory_bytes
                    .saturating_add(stage_vector_peak_bytes),
                self.heap_object_count_u32(),
            )
        };
        let mut stages = Vec::new();
        stages
            .try_reserve_exact(stage_capacity)
            .map_err(|_| vector_allocation_error())?;
        for index in 0..stage_count {
            let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
            let Value::Object(object_id) = value else {
                return Err(InterpreterError::TypeError {
                    expected: "engine-owned stream pipeline stage".to_string(),
                    got: value.type_name().to_string(),
                });
            };
            stages.push(object_id);
        }
        for (index, stage) in stages.iter().copied().enumerate() {
            if index + 1 < stages.len() && !self.readable_from_streams.contains_key(&stage) {
                return Err(InterpreterError::TypeError {
                    expected: "Readable pipeline source stage".to_string(),
                    got: "non-Readable object".to_string(),
                });
            }
            if index > 0 && !self.writable_streams.contains_key(&stage) {
                return Err(InterpreterError::TypeError {
                    expected: "Writable pipeline destination stage".to_string(),
                    got: "non-Writable object".to_string(),
                });
            }
        }
        let callback = if promise_mode {
            None
        } else {
            let value = self
                .builtin_arg(args, stage_count)?
                .unwrap_or(Value::Undefined);
            if !value.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: "callable stream.pipeline completion".to_string(),
                    got: value.type_name().to_string(),
                });
            }
            Some(value)
        };
        let mut retained_stages = Vec::new();
        retained_stages
            .try_reserve_exact(stage_capacity)
            .map_err(|_| vector_allocation_error())?;
        retained_stages.extend(stages.iter().copied());
        let mut pending_close = Vec::new();
        pending_close
            .try_reserve_exact(stage_capacity)
            .map_err(|_| vector_allocation_error())?;
        pending_close.extend(stages.iter().copied());
        let next_token = self
            .next_stream_pipeline_token
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "stream.pipeline token space exhausted".to_string(),
            })?;
        let registration_label = self.join_arg_range_label(args)?;
        let promise = if promise_mode {
            Some(self.create_promise()?)
        } else {
            None
        };
        let completion = match (callback, promise) {
            (Some(callback), None) => StreamPipelineCompletion::Callback(callback),
            (None, Some(promise)) => StreamPipelineCompletion::Promise(promise),
            _ => unreachable!("pipeline completion mode was validated"),
        };
        let state = StreamPipelineState {
            stages: retained_stages,
            pending_close,
            completion,
            registration_label,
            first_error: None,
            phase: StreamPipelinePhase::Running,
        };
        let state_bytes = Self::stream_pipeline_state_bytes(&state);
        if let Err(error) = self.apply_memory_component_delta(0, state_bytes) {
            if let StreamPipelineCompletion::Promise(promise) = state.completion {
                self.rollback_fresh_promise(promise);
            }
            return Err(error);
        }
        let token = self.next_stream_pipeline_token;
        self.next_stream_pipeline_token = next_token;
        self.stream_pipelines.insert(token, state);

        for stage in &stages {
            let error_listener = EventListenerRecord {
                listener: Value::BuiltinFunction(BuiltinFunction::stream_pipeline_listener(
                    BuiltinFunctionKind::StreamPipelineError,
                    token,
                    *stage,
                )),
                once: false,
            };
            if let Err(error) = self.insert_event_listener(*stage, "error", error_listener, false) {
                self.abandon_stream_pipeline(token)?;
                return Err(error);
            }
        }
        for stage in &stages {
            let close_listener = EventListenerRecord {
                listener: Value::BuiltinFunction(BuiltinFunction::stream_pipeline_listener(
                    BuiltinFunctionKind::StreamPipelineFinish,
                    token,
                    *stage,
                )),
                once: true,
            };
            if let Err(error) = self.insert_event_listener(*stage, "close", close_listener, false) {
                self.abandon_stream_pipeline(token)?;
                return Err(error);
            }
        }
        let sink = *stages.last().expect("validated pipeline has a sink");

        for index in (0..stages.len() - 1).rev() {
            let destination_register = args
                .start
                .checked_add(u32::try_from(index + 1).unwrap_or(u32::MAX))
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
            if let Err(error) = self.readable_pipe(
                module,
                Value::Object(stages[index]),
                RegRange {
                    start: destination_register,
                    count: 1,
                },
            ) {
                for source in stages.iter().copied() {
                    if let Some(link) = self.readable_pipe_links.get(&source).copied() {
                        self.detach_readable_pipe(source, link.destination, link.token);
                    }
                }
                self.abandon_stream_pipeline(token)?;
                return Err(error);
            }
        }
        Ok(
            match self
                .stream_pipelines
                .get(&token)
                .map(|state| &state.completion)
            {
                Some(StreamPipelineCompletion::Promise(promise)) => Value::Promise(promise.0),
                _ => Value::Object(sink),
            },
        )
    }

    pub(super) fn destroy_stream_pipeline_stage(
        &mut self,
        stage: ObjectId,
        error: &Value,
        error_label: &Label,
    ) -> Result<(), InterpreterError> {
        let readable = self.readable_from_streams.contains_key(&stage);
        let writable = self.writable_streams.contains_key(&stage);
        match (readable, writable) {
            (true, true) => {
                if self
                    .writable_streams
                    .get(&stage)
                    .is_some_and(|state| state.destroy_requested)
                {
                    return Ok(());
                }
                self.record_dual_stream_failure(
                    stage,
                    error.clone(),
                    error_label.clone(),
                    WritableErrorOrigin::Write,
                    false,
                )
            }
            (true, false) => {
                let Some(lifecycle_label) = self
                    .readable_from_streams
                    .get(&stage)
                    .filter(|state| !state.destroy_requested)
                    .map(|state| {
                        self.clone_dominant_label_with_temporary_budget(
                            &state.lifecycle_label,
                            error_label,
                            Self::estimate_label_bytes(error_label),
                        )
                    })
                    .transpose()?
                else {
                    return Ok(());
                };
                self.commit_readable_destroy(
                    stage,
                    Value::Object(stage),
                    Some(error.clone()),
                    lifecycle_label,
                )?;
                Ok(())
            }
            (false, true) => {
                if self
                    .writable_streams
                    .get(&stage)
                    .is_some_and(|state| state.destroy_requested)
                {
                    return Ok(());
                }
                self.record_writable_terminal_error(
                    stage,
                    error.clone(),
                    error_label.clone(),
                    WritableErrorOrigin::Destroy,
                    false,
                )?;
                self.writable_destroy_with_trigger(
                    Value::Object(stage),
                    None,
                    error_label.clone(),
                )?;
                Ok(())
            }
            (false, false) => Ok(()),
        }
    }

    /// Admit the complete first-error transition before mutating any stage.
    /// Every per-stage kernel below performs the same exact check again, but
    /// this aggregate upper bound prevents a later stage's memory refusal from
    /// leaving an earlier stage destroyed and the pipeline permanently split.
    pub(super) fn preflight_stream_pipeline_error_teardown(
        &self,
        token: u32,
        error: &Value,
        error_label: &Label,
        retained_pipeline_bytes: u64,
    ) -> Result<(), InterpreterError> {
        let Some(pipeline) = self.stream_pipelines.get(&token) else {
            return Ok(());
        };
        let mut positive_delta = retained_pipeline_bytes;
        for stage in &pipeline.stages {
            if let Some(readable) = self
                .readable_from_streams
                .get(stage)
                .filter(|state| !state.destroy_requested)
            {
                let lifecycle_label = if &readable.lifecycle_label >= error_label {
                    &readable.lifecycle_label
                } else {
                    error_label
                };
                if let Some((previous, destroyed, pump)) =
                    self.readable_destroy_memory_projection(*stage, Some(error), lifecycle_label)
                {
                    positive_delta = positive_delta
                        .saturating_add(destroyed.saturating_add(pump).saturating_sub(previous));
                }
            }
            if let Some(writable) = self
                .writable_streams
                .get(stage)
                .filter(|state| !state.destroy_requested)
            {
                let old_dynamic = Self::estimate_writable_error_dynamic_bytes(writable);
                let lifecycle_label = if &writable.lifecycle_label >= error_label {
                    &writable.lifecycle_label
                } else {
                    error_label
                };
                let next_dynamic = Self::estimate_label_bytes(lifecycle_label)
                    .saturating_add(Self::estimate_writable_value_bytes(error))
                    .saturating_add(Self::estimate_label_bytes(error_label));
                positive_delta =
                    positive_delta.saturating_add(next_dynamic.saturating_sub(old_dynamic));
            }
        }
        let requested_bytes = self.estimated_memory_bytes.saturating_add(positive_delta);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        Ok(())
    }

    pub(super) fn settle_stream_pipeline(
        &mut self,
        module: &Ir3Module,
        token: u32,
        close_label: Label,
    ) -> Result<Value, InterpreterError> {
        let settlement_label = {
            let Some(state) = self.stream_pipelines.get(&token) else {
                return Ok(Value::Undefined);
            };
            let terminal_label = state
                .first_error
                .as_ref()
                .map_or(&close_label, |(_, label)| label);
            self.clone_dominant_label_with_temporary_budget(
                &state.registration_label,
                terminal_label,
                0,
            )?
        };
        let Some(state) = self.stream_pipelines.remove(&token) else {
            return Ok(Value::Undefined);
        };
        let state_bytes = Self::stream_pipeline_state_bytes(&state);
        self.remove_stream_pipeline_listener_records(token, &state.stages);
        for source in state.stages.iter().copied() {
            if let Some(link) = self.readable_pipe_links.get(&source).copied() {
                self.detach_readable_pipe(source, link.destination, link.token);
            }
        }
        let error = state.first_error.map(|(error, _)| error);
        let result = match (state.completion, error) {
            (StreamPipelineCompletion::Callback(callback), error) => {
                let arguments = error.map_or_else(Vec::new, |error| vec![error]);
                self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    callback,
                    Value::Undefined,
                    arguments,
                    Some(settlement_label),
                )
                .map(|_| ())
            }
            (StreamPipelineCompletion::Promise(promise), error) => {
                if let Some(error) = error {
                    let reason = self.promise_value(&error)?;
                    self.reject_promise(promise, reason, settlement_label)
                } else {
                    self.fulfill_promise(
                        promise,
                        crate::object_model::JsValue::Undefined,
                        settlement_label,
                    )
                }
            }
        };
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(state_bytes);
        result?;
        Ok(Value::Undefined)
    }

    pub(super) fn stream_pipeline_listener_settle(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        builtin: &BuiltinFunction,
        is_error: bool,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some(token) = builtin.iterator_handle else {
            return Ok(Value::Undefined);
        };
        let Value::Object(stage) = receiver else {
            return Ok(Value::Undefined);
        };
        if builtin.bound_object != Some(stage.0)
            || self.stream_pipelines.get(&token).is_none_or(|state| {
                state.phase == StreamPipelinePhase::Settling || !state.stages.contains(&stage)
            })
        {
            return Ok(Value::Undefined);
        }

        if is_error {
            if self
                .stream_pipelines
                .get(&token)
                .is_none_or(|state| state.phase != StreamPipelinePhase::Running)
            {
                return Ok(Value::Undefined);
            }
            let error = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            let error_label = self.writable_invocation_label(args)?;
            let retained_bytes = Self::estimate_value_bytes(&error)
                .saturating_add(Self::estimate_label_bytes(&error_label));
            self.preflight_stream_pipeline_error_teardown(
                token,
                &error,
                &error_label,
                retained_bytes,
            )?;
            self.apply_memory_component_delta(0, retained_bytes)?;
            let stage_count = {
                let state = self
                    .stream_pipelines
                    .get_mut(&token)
                    .expect("authenticated pipeline retained its state");
                state.first_error = Some((error.clone(), error_label.clone()));
                state.phase = StreamPipelinePhase::Destroying;
                state.stages.len()
            };
            for index in 0..stage_count {
                let source = self
                    .stream_pipelines
                    .get(&token)
                    .and_then(|state| state.stages.get(index))
                    .copied()
                    .expect("pipeline stage survived authenticated error transition");
                if let Some(link) = self.readable_pipe_links.get(&source).copied() {
                    self.detach_readable_pipe(source, link.destination, link.token);
                }
            }
            for index in 0..stage_count {
                let stage = self
                    .stream_pipelines
                    .get(&token)
                    .and_then(|state| state.stages.get(index))
                    .copied()
                    .expect("pipeline stage survived authenticated error transition");
                self.destroy_stream_pipeline_stage(stage, &error, &error_label)?;
            }
            return Ok(Value::Undefined);
        }

        let close_label = self.writable_invocation_label(args)?;
        let ready = {
            let state = self
                .stream_pipelines
                .get_mut(&token)
                .expect("authenticated pipeline retained its state");
            state.pending_close.retain(|pending| *pending != stage);
            if state.pending_close.is_empty() {
                state.phase = StreamPipelinePhase::Settling;
                true
            } else {
                false
            }
        };
        if ready {
            self.settle_stream_pipeline(module, token, close_label)
        } else {
            Ok(Value::Undefined)
        }
    }

    pub(super) fn readable_is_paused(&self, receiver: Value) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        let paused = self
            .readable_from_streams
            .get(&object_id)
            .is_some_and(|state| state.paused);
        Ok(Value::Bool(paused))
    }

    pub(super) fn commit_readable_state(
        &mut self,
        object_id: ObjectId,
        projected: ReadableFromState,
    ) -> Result<(), InterpreterError> {
        let previous_bytes = self
            .readable_from_streams
            .get(&object_id)
            .map(Self::estimate_readable_from_state_bytes)
            .unwrap_or(0);
        let new_bytes = Self::estimate_readable_from_state_bytes(&projected);
        // Until the replacement is published, both the authoritative state
        // and its projected copy are live. Refuse that physical peak rather
        // than checking only the smaller retained delta.
        self.check_temporary_memory_budget(new_bytes)?;
        self.apply_memory_component_delta(previous_bytes, new_bytes)?;
        let readable_length = projected.buffered_length;
        self.readable_from_streams.insert(object_id, projected);
        self.mirror_readable_length(object_id, readable_length);
        Ok(())
    }

    /// Commit one projected state together with its successor pump. Scheduler
    /// refusal restores the owned previous state, public length mirror, exact
    /// memory total, task queue, and registration sequence as one transaction.
    pub(super) fn commit_readable_state_and_schedule(
        &mut self,
        object_id: ObjectId,
        projected: ReadableFromState,
    ) -> Result<(), InterpreterError> {
        let previous_total = self.estimated_memory_bytes;
        let next_bytes = Self::estimate_readable_from_state_bytes(&projected);
        let pump_bytes = if self.has_pending_readable_pump(object_id)
            || self.readable_pump_reservations.contains_key(&object_id)
        {
            0
        } else {
            self.readable_pump_retained_bytes()
        };
        // `previous` remains owned for rollback until scheduling succeeds, so
        // the real transaction peak is old state + projection + successor.
        self.check_temporary_memory_budget(next_bytes.saturating_add(pump_bytes))?;
        let previous = self.readable_from_streams.remove(&object_id);
        let previous_bytes = previous
            .as_ref()
            .map(Self::estimate_readable_from_state_bytes)
            .unwrap_or(0);
        if let Err(error) = self.apply_memory_component_delta(previous_bytes, next_bytes) {
            if let Some(previous) = previous {
                self.readable_from_streams.insert(object_id, previous);
            }
            return Err(error);
        }

        let next_length = projected.buffered_length;
        self.readable_from_streams.insert(object_id, projected);
        if let Err(error) = self.schedule_readable_from_pump(object_id) {
            self.readable_from_streams.remove(&object_id);
            if let Some(previous) = previous {
                self.readable_from_streams.insert(object_id, previous);
            }
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }
        self.mirror_readable_length(object_id, next_length);
        Ok(())
    }

    /// Fallibly clone the allocation-bearing portions of one Readable state.
    /// Values are shared handles, but the queue and decoder storage are real
    /// host allocations and must never use their infallible `Clone` paths on
    /// guest-controlled lengths.
    pub(super) fn try_clone_readable_state(
        &self,
        state: &ReadableFromState,
    ) -> Result<ReadableFromState, InterpreterError> {
        let projected_upper = Self::estimate_readable_from_state_bytes(state);
        self.check_temporary_memory_budget(projected_upper)?;

        let mut buffer = VecDeque::new();
        buffer
            .try_reserve_exact(state.buffer.capacity())
            .map_err(|_| {
                self.memory_budget_error(
                    self.estimated_memory_bytes.saturating_add(projected_upper),
                    self.heap_object_count_u32(),
                )
            })?;
        buffer.extend(state.buffer.iter().cloned());

        let mut utf8_pending = Vec::new();
        utf8_pending
            .try_reserve_exact(state.utf8_pending.capacity())
            .map_err(|_| {
                self.memory_budget_error(
                    self.estimated_memory_bytes.saturating_add(projected_upper),
                    self.heap_object_count_u32(),
                )
            })?;
        utf8_pending.extend_from_slice(&state.utf8_pending);

        let projected = ReadableFromState {
            source: state.source.clone(),
            push_only: state.push_only,
            object_mode: state.object_mode,
            high_water_mark: state.high_water_mark,
            read_callback: state.read_callback.clone(),
            buffer,
            buffered_length: state.buffered_length,
            eof_requested: state.eof_requested,
            data_readable_pending: state.data_readable_pending,
            eof_readable_pending: state.eof_readable_pending,
            read_callback_active: state.read_callback_active,
            decode_utf8: state.decode_utf8,
            utf8_pending,
            destroy_requested: state.destroy_requested,
            destroy_error: state.destroy_error.clone(),
            next_index: state.next_index,
            phase: state.phase,
            flowing: state.flowing,
            paused: state.paused,
            nonflowing_read_consumed: state.nonflowing_read_consumed,
            lifecycle_label: state.lifecycle_label.clone(),
            to_array_waiter: state.to_array_waiter.clone(),
        };
        // Allocator rounding is implementation-defined. Recheck the actual
        // capacities before exposing the projection to a transaction.
        self.check_temporary_memory_budget(Self::estimate_readable_from_state_bytes(&projected))?;
        Ok(projected)
    }

    /// Clone engine-owned stream state only after charging the temporary copy
    /// against the interpreter budget. Stream transitions intentionally work
    /// on a projection so a fallible operation cannot partially mutate the
    /// live queue; this preflight keeps that transactional copy honest.
    pub(super) fn clone_readable_state_with_budget(
        &self,
        object_id: ObjectId,
    ) -> Result<Option<ReadableFromState>, InterpreterError> {
        let Some(state) = self.readable_from_streams.get(&object_id) else {
            return Ok(None);
        };
        self.try_clone_readable_state(state).map(Some)
    }

    /// Update the existing public length mirror after the internal transition
    /// has been preflighted. A guest-deleted mirror stays deleted.
    pub(super) fn mirror_readable_length(&mut self, object_id: ObjectId, length: usize) {
        let key = "readableLength";
        let value = Value::Int(i64::try_from(length).unwrap_or(i64::MAX));
        let previous_bytes = self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key))
            .map(|previous| Self::estimate_property_entry_bytes(key, previous));
        self.mutate_heap(|heap| {
            if let Some(slot) = heap
                .get_mut(object_id.0 as usize)
                .and_then(|object| object.properties.get_mut(key))
            {
                *slot = value.clone();
            }
        });
        if let Some(previous_bytes) = previous_bytes {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(Self::estimate_property_entry_bytes(key, &value));
        }
    }

    /// Update an existing public boolean mirror after its authoritative
    /// engine-owned state transition has committed. Guest deletion remains
    /// deletion, and no fallible property insertion can split the transition.
    pub(super) fn mirror_readable_bool(
        &mut self,
        object_id: ObjectId,
        key: &'static str,
        value: bool,
    ) {
        let value = Value::Bool(value);
        let previous_bytes = self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key))
            .map(|previous| Self::estimate_property_entry_bytes(key, previous));
        self.mutate_heap(|heap| {
            if let Some(slot) = heap
                .get_mut(object_id.0 as usize)
                .and_then(|object| object.properties.get_mut(key))
            {
                *slot = value.clone();
            }
        });
        if let Some(previous_bytes) = previous_bytes {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(Self::estimate_property_entry_bytes(key, &value));
        }
    }

    pub(super) fn readable_decode_utf8_bytes(
        &self,
        pending: &mut Vec<u8>,
        bytes: &[u8],
        additional_temporary_bytes: u64,
    ) -> Result<Option<Value>, InterpreterError> {
        let combined_len =
            pending
                .len()
                .checked_add(bytes.len())
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Readable UTF-8 decoder buffer overflows host address space"
                        .to_string(),
                })?;
        let maximum_output_bytes = combined_len.saturating_mul(3);
        let decoder_temporary_bytes =
            u64::try_from(combined_len.saturating_add(maximum_output_bytes)).unwrap_or(u64::MAX);
        self.check_temporary_memory_budget(
            additional_temporary_bytes.saturating_add(decoder_temporary_bytes),
        )?;
        pending.try_reserve(bytes.len()).map_err(|_| {
            self.memory_budget_error(
                self.estimated_memory_bytes
                    .saturating_add(additional_temporary_bytes)
                    .saturating_add(u64::try_from(combined_len).unwrap_or(u64::MAX)),
                self.heap_object_count_u32(),
            )
        })?;
        pending.extend_from_slice(bytes);
        let mut decoded = String::new();
        decoded.try_reserve(maximum_output_bytes).map_err(|_| {
            self.memory_budget_error(
                self.estimated_memory_bytes
                    .saturating_add(additional_temporary_bytes)
                    .saturating_add(
                        u64::try_from(combined_len.saturating_add(maximum_output_bytes))
                            .unwrap_or(u64::MAX),
                    ),
                self.heap_object_count_u32(),
            )
        })?;
        let mut cursor = 0usize;
        let mut incomplete_suffix = None;
        while cursor < pending.len() {
            match std::str::from_utf8(&pending[cursor..]) {
                Ok(text) => {
                    decoded.push_str(text);
                    cursor = pending.len();
                }
                Err(error) => {
                    let valid_end = cursor.saturating_add(error.valid_up_to());
                    if valid_end > cursor {
                        decoded.push_str(
                            std::str::from_utf8(&pending[cursor..valid_end])
                                .expect("valid_up_to is guaranteed UTF-8"),
                        );
                    }
                    if let Some(invalid_len) = error.error_len() {
                        decoded.push('\u{fffd}');
                        cursor = valid_end.saturating_add(invalid_len);
                    } else {
                        incomplete_suffix = Some(valid_end);
                        break;
                    }
                }
            }
        }
        if let Some(suffix_start) = incomplete_suffix {
            pending.drain(..suffix_start);
        } else {
            pending.clear();
        }
        Ok((!decoded.is_empty()).then(|| Value::str(decoded)))
    }

    pub(super) fn readable_normalize_push_value(
        &self,
        state: &mut ReadableFromState,
        value: Value,
        additional_temporary_bytes: u64,
    ) -> Result<Option<(Value, usize)>, InterpreterError> {
        if state.object_mode {
            return Ok(Some((value, 1)));
        }
        if state.decode_utf8
            && state.utf8_pending.is_empty()
            && let Value::Str(text) = &value
        {
            // A JavaScript string is already decoded. Preserve its exact
            // UTF-16 code units (including a lone surrogate returned by a
            // preceding read(n)) instead of round-tripping through the lossy
            // UTF-8 projection used for byte inputs.
            return Ok(Some((value.clone(), text.utf16_len())));
        }
        let bytes: Cow<'_, [u8]> = match &value {
            Value::Str(text) => Cow::Borrowed(text.as_bytes()),
            Value::Object(_) => {
                let view = self.buffer_like_view(&value)?;
                Cow::Borrowed(self.typed_array_view_bytes(&view)?)
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "string, Buffer, or Uint8Array byte chunk".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if state.decode_utf8 {
            let decoded = self.readable_decode_utf8_bytes(
                &mut state.utf8_pending,
                &bytes,
                additional_temporary_bytes,
            )?;
            return Ok(decoded.map(|decoded| {
                let units = match &decoded {
                    Value::Str(text) => text.utf16_len(),
                    _ => 0,
                };
                (decoded, units)
            }));
        }
        let units = bytes.len();
        drop(bytes);
        Ok(Some((value, units)))
    }

    pub(super) fn readable_enqueue_value(
        &mut self,
        object_id: ObjectId,
        value: Value,
        label: Label,
    ) -> Result<bool, InterpreterError> {
        let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
            return Ok(false);
        };
        if projected.phase != ReadableFromPumpPhase::Data || projected.eof_requested {
            return Ok(false);
        }
        let lifecycle_label = projected.lifecycle_label.join(&label);
        projected.lifecycle_label = lifecycle_label.clone();
        let projection_bytes = Self::estimate_readable_from_state_bytes(&projected);
        let Some((value, units)) =
            self.readable_normalize_push_value(&mut projected, value, projection_bytes)?
        else {
            // Every byte went to an incomplete UTF-8 sequence. That is still
            // progress: the stream asks `_read` for more, as Node does, or a
            // character split across pushes would park the stream forever.
            self.commit_readable_state_and_schedule(object_id, projected)?;
            return Ok(true);
        };
        let buffered_length = projected
            .buffered_length
            .checked_add(units)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Readable buffered length overflows host address space".to_string(),
            })?;
        projected
            .buffer
            .try_reserve(1)
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        projected.buffer.push_back(ReadableBufferedChunk {
            value,
            label: lifecycle_label,
            units,
        });
        projected.buffered_length = buffered_length;
        projected.data_readable_pending = true;
        let below_high_water_mark = buffered_length < projected.high_water_mark;
        self.commit_readable_state_and_schedule(object_id, projected)?;
        Ok(below_high_water_mark)
    }

    pub(super) fn readable_request_eof(
        &mut self,
        object_id: ObjectId,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        self.readable_request_eof_with_flow_commitment(object_id, label, false)
    }

    pub(super) fn readable_request_eof_with_flow_commitment(
        &mut self,
        object_id: ObjectId,
        label: Label,
        flow_committed: bool,
    ) -> Result<Value, InterpreterError> {
        let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
            return Ok(Value::Bool(false));
        };
        if projected.phase != ReadableFromPumpPhase::Data || projected.eof_requested {
            return Ok(Value::Bool(false));
        }
        projected.lifecycle_label = projected.lifecycle_label.join(&label);
        if projected.decode_utf8 && !projected.utf8_pending.is_empty() {
            let replacement =
                Value::str(String::from_utf8_lossy(&projected.utf8_pending).into_owned());
            let units = match &replacement {
                Value::Str(text) => text.len(),
                _ => 0,
            };
            projected
                .buffer
                .try_reserve(1)
                .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
            projected.buffer.push_back(ReadableBufferedChunk {
                value: replacement,
                label: projected.lifecycle_label.clone(),
                units,
            });
            projected.buffered_length =
                projected
                    .buffered_length
                    .checked_add(units)
                    .ok_or_else(|| InterpreterError::RangeError {
                        message: "Readable buffered length overflows host address space"
                            .to_string(),
                    })?;
            projected.data_readable_pending = true;
            projected.utf8_pending.clear();
        }
        projected.eof_requested = true;
        if (projected.flowing || flow_committed) && projected.buffer.is_empty() {
            projected.phase = ReadableFromPumpPhase::End;
            projected.data_readable_pending = false;
        } else {
            projected.eof_readable_pending = true;
        }
        self.commit_readable_state_and_schedule(object_id, projected)?;
        Ok(Value::Bool(false))
    }

    pub(super) fn readable_push(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let trigger_label = if args.count > 0 {
            self.get_register_label(args.start)?
                .clone()
                .join(&match &value {
                    Value::Object(object_id) => self.binary_storage_label(*object_id),
                    _ => Label::Public,
                })
        } else {
            Label::Public
        };
        if value == Value::Null {
            return self.readable_request_eof(object_id, trigger_label);
        }
        let rejected_during_dual_final =
            self.readable_from_streams
                .get(&object_id)
                .is_some_and(|state| {
                    matches!(
                        state.phase,
                        ReadableFromPumpPhase::Data | ReadableFromPumpPhase::End
                    ) && state.eof_requested
                })
                && self.writable_streams.get(&object_id).is_some_and(|state| {
                    state.end_requested
                        && matches!(
                            state.flavor,
                            WritableStreamFlavor::PassThrough | WritableStreamFlavor::Transform
                        )
                        && matches!(
                            state.final_status,
                            WritableFinalStatus::Active(_) | WritableFinalStatus::Done
                        )
                });
        if rejected_during_dual_final {
            let error =
                self.stream_error_value("ERR_STREAM_PUSH_AFTER_EOF", "stream.push() after EOF")?;
            self.record_dual_stream_failure(
                object_id,
                error,
                trigger_label,
                WritableErrorOrigin::Final,
                false,
            )?;
            return Ok(Value::Bool(false));
        }
        Ok(Value::Bool(self.readable_enqueue_value(
            object_id,
            value,
            trigger_label,
        )?))
    }

    pub(super) fn stream_error_value(
        &mut self,
        code: &'static str,
        message: &'static str,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("Error")?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error_id, "Error", message.to_string())?;
        self.set_object_property(error_id, "code".to_string(), Value::str(code))?;
        Ok(Value::Object(error_id))
    }

    /// Internal `_write` for the bounded PassThrough identity. Forwarding is
    /// deliberately synchronous for one readable pump turn: Node makes a
    /// piped destination observe `source.write(chunk)` before a following
    /// `source.unpipe(destination)` in the same turn (bd-fw7zd.10).
    pub(super) fn stream_passthrough_write(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count != 3 {
            return Err(InterpreterError::TypeError {
                expected: "internal PassThrough._write(chunk, encoding, callback)".to_string(),
                got: format!("{} arguments", args.count),
            });
        }
        let object_id = self.readable_receiver_id(receiver.clone())?;
        let writable_id = self.writable_receiver_id(receiver.clone())?;
        if object_id != writable_id {
            return Err(InterpreterError::InternalError {
                details: "PassThrough readable/writable identity split".to_string(),
            });
        }
        if self
            .readable_from_streams
            .get(&object_id)
            .is_none_or(|state| state.phase != ReadableFromPumpPhase::Data || state.eof_requested)
        {
            return Err(InterpreterError::TypeError {
                expected: "live PassThrough readable half before EOF".to_string(),
                got: "closed PassThrough readable half".to_string(),
            });
        }
        let chunk = self.read_reg(args.start)?;
        let mut chunk_label = self.writable_invocation_label(RegRange {
            start: args.start,
            count: 1,
        })?;
        if let Value::Object(chunk_id) = &chunk {
            let storage_label = self.binary_storage_label(*chunk_id);
            chunk_label =
                self.join_owned_label_with_temporary_budget(chunk_label, &storage_label)?;
        }
        let completion = self.read_reg(args.start.saturating_add(2))?;
        let Value::BuiltinFunction(completion) = completion else {
            return Err(InterpreterError::TypeError {
                expected: "authenticated PassThrough write completion".to_string(),
                got: completion.type_name().to_string(),
            });
        };
        let (completion_object, token) = Self::writable_bound_completion(&completion)?;
        if completion.kind != BuiltinFunctionKind::StreamWritableWriteDone
            || completion_object != object_id
            || !self
                .writable_streams
                .get(&object_id)
                .is_some_and(|state| state.writes.has_active_token(token))
        {
            return Err(InterpreterError::InternalError {
                details: "PassThrough write completion authentication failed".to_string(),
            });
        }
        if self
            .writable_streams
            .get(&object_id)
            .is_some_and(|state| state.tick_sequence.is_none())
        {
            self.next_writable_tick_sequence
                .checked_add(1)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Writable tick sequence space exhausted".to_string(),
                })?;
        }
        self.readable_enqueue_value(object_id, chunk, chunk_label)?;
        if self
            .readable_from_streams
            .get(&object_id)
            .is_some_and(|state| state.flowing && !state.buffer.is_empty())
        {
            self.drive_readable_from_pump(object_id, Some(module))?;
        }
        self.writable_write_done(module, &completion, RegRange { start: 0, count: 0 })?;
        Ok(Value::Undefined)
    }

    /// Internal `_final` commits readable EOF before authenticated `prefinish`.
    /// The final tick is reserved before guest reentrancy. Flowing/full pull
    /// drains consume it after `end`; passive/partial pull consumes it after
    /// the EOF-readable notice; all other paused lanes finish immediately.
    pub(super) fn stream_passthrough_final(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count != 1 {
            return Err(InterpreterError::TypeError {
                expected: "internal PassThrough._final(callback)".to_string(),
                got: format!("{} arguments", args.count),
            });
        }
        let object_id = self.readable_receiver_id(receiver.clone())?;
        let writable_id = self.writable_receiver_id(receiver.clone())?;
        if object_id != writable_id {
            return Err(InterpreterError::InternalError {
                details: "PassThrough readable/writable identity split".to_string(),
            });
        }
        if self
            .readable_from_streams
            .get(&object_id)
            .is_none_or(|state| state.phase != ReadableFromPumpPhase::Data || state.eof_requested)
        {
            return Err(InterpreterError::TypeError {
                expected: "live PassThrough readable half before EOF".to_string(),
                got: "closed PassThrough readable half".to_string(),
            });
        }
        let completion = self.read_reg(args.start)?;
        let Value::BuiltinFunction(completion) = completion else {
            return Err(InterpreterError::TypeError {
                expected: "authenticated PassThrough final completion".to_string(),
                got: completion.type_name().to_string(),
            });
        };
        let (completion_object, token) = Self::writable_bound_completion(&completion)?;
        if completion.kind != BuiltinFunctionKind::StreamWritableFinalDone
            || completion_object != object_id
            || !self
                .writable_streams
                .get(&object_id)
                .is_some_and(|state| state.final_status == WritableFinalStatus::Active(token))
        {
            return Err(InterpreterError::InternalError {
                details: "PassThrough final completion authentication failed".to_string(),
            });
        }
        let lifecycle_label = self.writable_invocation_label(args)?;
        let has_pull_observer = self.has_readable_pull_observer(object_id);
        let (
            flowing_end_commitment,
            pull_end_commitment,
            defer_final_until_readable,
            defer_prefinish_until_readable,
        ) = self.readable_from_streams.get(&object_id).map_or(
            (false, false, false, false),
            |state| {
                let flowing_end = !state.destroy_requested && state.flowing && !state.paused;
                let pull_end = !state.destroy_requested
                    && state.nonflowing_read_consumed
                    && state.buffer.is_empty();
                let empty_pull_notice = !state.destroy_requested
                    && !flowing_end
                    && !pull_end
                    && has_pull_observer
                    && state.paused
                    && state.buffer.is_empty();
                let until_readable = !state.destroy_requested
                    && !flowing_end
                    && !pull_end
                    && has_pull_observer
                    && state.paused
                    && (!state.buffer.is_empty() || empty_pull_notice);
                (flowing_end, pull_end, until_readable, empty_pull_notice)
            },
        );
        let defer_final_until_end = flowing_end_commitment || pull_end_commitment;
        if self
            .writable_streams
            .get(&object_id)
            .is_some_and(|state| state.deferred_final_tick_sequence.is_none())
        {
            let sequence = self.next_writable_tick_sequence;
            let next_sequence =
                sequence
                    .checked_add(1)
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "Writable tick sequence space exhausted".to_string(),
                    })?;
            self.writable_streams
                .get_mut(&object_id)
                .expect("authenticated PassThrough final retained its Writable state")
                .deferred_final_tick_sequence = Some(sequence);
            self.next_writable_tick_sequence = next_sequence;
        }
        // EOF is an engine-owned commitment before `prefinish` guest code:
        // a re-entrant push/write must fail like Node/Bun instead of extending
        // the readable queue and stranding the already-reserved final tick.
        // The pre-listener flow/pull snapshot still fixes end-vs-finish order.
        self.readable_request_eof_with_flow_commitment(
            object_id,
            lifecycle_label,
            flowing_end_commitment,
        )?;
        if !defer_prefinish_until_readable {
            self.emit_writable_prefinish_with_tick(object_id, module, false)?;
        }
        if !defer_final_until_end && !defer_final_until_readable {
            self.writable_final_done(module, &completion, RegRange { start: 0, count: 0 })?;
        }
        Ok(Value::Undefined)
    }

    pub(super) fn stream_transform_publish_completion_value(
        &mut self,
        module: &Ir3Module,
        object_id: ObjectId,
        token: u32,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        if self.writable_completion_error_register(args)?.is_some() || args.count < 2 {
            return Ok(());
        }
        let Some(value) = self.builtin_arg(args, 1)? else {
            return Ok(());
        };
        if matches!(value, Value::Undefined | Value::Null) {
            return Ok(());
        }
        let original_label = self
            .writable_streams
            .get(&object_id)
            .and_then(|state| {
                state
                    .writes
                    .active_label(token)
                    .cloned()
                    .or_else(|| Some(state.lifecycle_label.clone()))
            })
            .unwrap_or(Label::Public);
        let callback_label = self.writable_invocation_label(args)?;
        let mut label =
            self.join_owned_label_with_temporary_budget(original_label, &callback_label)?;
        if let Value::Object(value_id) = &value {
            let storage_label = self.binary_storage_label(*value_id);
            label = self.join_owned_label_with_temporary_budget(label, &storage_label)?;
        }
        self.readable_enqueue_value(object_id, value, label)?;
        if self
            .readable_from_streams
            .get(&object_id)
            .is_some_and(|state| state.flowing && !state.buffer.is_empty())
        {
            self.drive_readable_from_pump(object_id, Some(module))?;
        }
        Ok(())
    }

    /// Transform callbacks receive a distinct authenticated completion. A
    /// successful second argument is published synchronously before the
    /// Writable record completes, preserving transform/write alternation.
    pub(super) fn stream_transform_write_done(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (object_id, token) = Self::writable_bound_completion(builtin)?;
        let authenticated = self.writable_streams.get(&object_id).is_some_and(|state| {
            state.flavor == WritableStreamFlavor::Transform && state.writes.has_active_token(token)
        });
        if !authenticated {
            return Ok(Value::Undefined);
        }
        let has_error = self.writable_completion_error_register(args)?.is_some();
        if self
            .writable_streams
            .get(&object_id)
            .is_some_and(|state| state.tick_sequence.is_none())
        {
            self.next_writable_tick_sequence
                .checked_add(1)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Writable tick sequence space exhausted".to_string(),
                })?;
        }
        self.stream_transform_publish_completion_value(module, object_id, token, args)?;
        let completion_args = RegRange {
            start: args.start,
            count: u32::from(args.count > 0),
        };
        let result = self.writable_write_done(module, builtin, completion_args)?;
        if has_error {
            self.destroy_dual_stream_after_writable_error(object_id)?;
        }
        Ok(result)
    }

    /// Default Transform `_final` when no guest `flush` hook exists.
    pub(super) fn stream_transform_final(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.writable_receiver_id(receiver)?;
        if self
            .writable_streams
            .get(&object_id)
            .is_none_or(|state| state.flavor != WritableStreamFlavor::Transform)
        {
            return Err(InterpreterError::TypeError {
                expected: "Transform receiver".to_string(),
                got: "non-Transform Writable".to_string(),
            });
        }
        let completion = self.read_reg(args.start)?;
        let Value::BuiltinFunction(completion) = completion else {
            return Err(InterpreterError::TypeError {
                expected: "authenticated Transform final completion".to_string(),
                got: completion.type_name().to_string(),
            });
        };
        self.stream_transform_final_done(module, &completion, RegRange { start: 0, count: 0 })
    }

    pub(super) fn stream_transform_final_done(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (object_id, token) = Self::writable_bound_completion(builtin)?;
        let authenticated = self.writable_streams.get(&object_id).is_some_and(|state| {
            state.flavor == WritableStreamFlavor::Transform
                && state.final_status == WritableFinalStatus::Active(token)
        });
        if !authenticated {
            return Ok(Value::Undefined);
        }
        let has_error = self.writable_completion_error_register(args)?.is_some();
        if has_error {
            let completion_args = RegRange {
                start: args.start,
                count: u32::from(args.count > 0),
            };
            let result = self.writable_final_done(module, builtin, completion_args)?;
            self.destroy_dual_stream_after_writable_error(object_id)?;
            return Ok(result);
        }

        let lifecycle_label = self.writable_invocation_label(args)?;
        let defer_final_until_end = self
            .readable_from_streams
            .get(&object_id)
            .is_some_and(|state| state.flowing && !state.paused && !state.destroy_requested);
        if self
            .writable_streams
            .get(&object_id)
            .is_some_and(|state| state.deferred_final_tick_sequence.is_none())
        {
            let sequence = self.next_writable_tick_sequence;
            let next_sequence =
                sequence
                    .checked_add(1)
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "Writable tick sequence space exhausted".to_string(),
                    })?;
            self.writable_streams
                .get_mut(&object_id)
                .expect("authenticated Transform final retained its Writable state")
                .deferred_final_tick_sequence = Some(sequence);
            self.next_writable_tick_sequence = next_sequence;
        }
        self.stream_transform_publish_completion_value(module, object_id, token, args)?;
        self.emit_writable_prefinish_with_tick(object_id, module, false)?;
        self.readable_request_eof_with_flow_commitment(
            object_id,
            lifecycle_label,
            defer_final_until_end,
        )?;
        if !defer_final_until_end {
            self.writable_final_done(module, builtin, RegRange { start: 0, count: 0 })?;
        }
        Ok(Value::Undefined)
    }

    /// Consume a dual stream's engine-owned final token after its committed
    /// readable boundary: either End for a flowing/full pull drain, or the
    /// EOF-readable notification that leaves passive/partial data queued.
    pub(super) fn complete_deferred_dual_stream_final(
        &mut self,
        object_id: ObjectId,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        let Some(token) = self.writable_streams.get(&object_id).and_then(|state| {
            let authenticated_internal_final = matches!(
                state.flavor,
                WritableStreamFlavor::PassThrough | WritableStreamFlavor::Transform
            );
            match state.final_status {
                WritableFinalStatus::Active(token) if authenticated_internal_final => Some(token),
                _ => None,
            }
        }) else {
            return Ok(());
        };
        let completion = BuiltinFunction::writable_completion(
            BuiltinFunctionKind::StreamWritableFinalDone,
            object_id,
            token,
        );
        self.writable_final_done(module, &completion, RegRange { start: 0, count: 0 })?;
        Ok(())
    }

    /// An asynchronous Readable callback/scheduling failure escapes the
    /// evaluation boundary, so no later checkpoint may be relied on. Consume
    /// the already-reserved dual final token without replacing the original
    /// error. No later checkpoint is reliable after the exception, so convert
    /// the live Writable directly to its accounted terminal tombstone instead
    /// of allocating a cleanup tick that could itself strand at sequence
    /// exhaustion. The ordinary readable abort then releases its half.
    pub(super) fn terminalize_deferred_dual_final_after_readable_failure(
        &mut self,
        object_id: ObjectId,
    ) {
        let Some(state) = self.writable_streams.get(&object_id) else {
            return;
        };
        if !matches!(
            state.flavor,
            WritableStreamFlavor::PassThrough | WritableStreamFlavor::Transform
        ) {
            return;
        }
        let previous_bytes = Self::estimate_writable_state_bytes(state);
        let mut state = self
            .writable_streams
            .remove(&object_id)
            .expect("authenticated dual Writable state survived terminalization");
        let lifecycle_label = std::mem::replace(&mut state.lifecycle_label, Label::Public);
        let terminal = WritableTerminalState {
            object_mode: state.object_mode,
            high_water_mark: state.high_water_mark,
            end_requested: state.end_requested,
            finished: state.finished,
            buffered_length: state.buffered_length,
            cork_depth: state.cork_depth,
            accepts_late_end_callback: state.finished || state.terminal_error.is_some(),
            callbacks: LinkedList::new(),
            tick_sequence: None,
            lifecycle_label,
        };
        let terminal_bytes = Self::estimate_writable_terminal_state_bytes(&terminal);
        let previous = self.writable_terminal_states.insert(object_id, terminal);
        debug_assert!(previous.is_none());
        let previous_terminal_bytes = previous
            .as_ref()
            .map(Self::estimate_writable_terminal_state_bytes)
            .unwrap_or(0);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_sub(previous_terminal_bytes)
            .saturating_add(terminal_bytes);
    }

    pub(super) fn stream_passthrough_destroy(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver.clone())?;
        let writable_id = self.writable_receiver_id(receiver.clone())?;
        if object_id != writable_id {
            return Err(InterpreterError::InternalError {
                details: "PassThrough readable/writable identity split".to_string(),
            });
        }

        let error_register = self.writable_completion_error_register(args)?;
        let error = match self.builtin_arg(args, 0)? {
            None | Some(Value::Undefined | Value::Null) => None,
            Some(error) => Some(error),
        };
        let mut trigger_label = self.writable_invocation_label(args)?;
        if let Some(Value::Object(error_id)) = &error {
            let storage_label = self.binary_storage_label(*error_id);
            trigger_label =
                self.join_owned_label_with_temporary_budget(trigger_label, &storage_label)?;
        }
        let readable_lifecycle_label = self
            .readable_from_streams
            .get(&object_id)
            .filter(|state| !state.destroy_requested)
            .map(|state| {
                self.clone_dominant_label_with_temporary_budget(
                    &state.lifecycle_label,
                    &trigger_label,
                    Self::estimate_label_bytes(&trigger_label),
                )
            })
            .transpose()?;
        let readable_reservation = readable_lifecycle_label
            .as_ref()
            .and_then(|label| {
                self.readable_destroy_memory_projection(object_id, error.as_ref(), label)
            })
            .map(|(previous, destroyed, pump)| {
                destroyed.saturating_add(pump).saturating_sub(previous)
            })
            .unwrap_or(0);

        // Reserve the readable half's positive delta while the Writable
        // teardown performs its own exact admission. This turns the two
        // existing atomic kernels into one aggregate transaction without
        // exposing a half-destroyed identity at a tight memory ceiling.
        self.apply_memory_component_delta(0, readable_reservation)?;
        let writable_result =
            self.writable_destroy_with_trigger(receiver.clone(), error_register, trigger_label);
        if let Err(error) = writable_result {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(readable_reservation);
            return Err(error);
        }
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            // The readable half is the sole shared EventEmitter owner. Keep
            // the exact destroy error for pending Writable callbacks, but do
            // not emit a second shared `error` event from the Writable phase.
            state.terminal_error_emitted = true;
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(readable_reservation);
        if let Some(lifecycle_label) = readable_lifecycle_label {
            self.commit_readable_destroy(object_id, receiver.clone(), error, lifecycle_label)?;
        }
        Ok(receiver)
    }

    pub(super) fn readable_pull_source_chunk(
        &mut self,
        object_id: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
            return Ok(false);
        };
        if projected.push_only
            || projected.phase != ReadableFromPumpPhase::Data
            || projected.eof_requested
        {
            return Ok(false);
        }
        let next_value = match &projected.source {
            Value::Str(text) if projected.next_index == 0 => {
                Some((Value::Str(text.clone()), Label::Public))
            }
            Value::Str(_) => None,
            Value::Object(source_id) => {
                let length = self.array_like_length(*source_id)?;
                if projected.next_index < length {
                    let key = RuntimePropertyKey::String(JsString::from(
                        projected.next_index.to_string(),
                    ));
                    Some((
                        self.array_index_value(*source_id, projected.next_index)?
                            .unwrap_or(Value::Undefined),
                        self.runtime_property_label(*source_id, &key),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some((value, value_label)) = next_value {
            let chunk_label = projected.lifecycle_label.join(&value_label);
            projected.lifecycle_label = chunk_label.clone();
            projected
                .buffer
                .try_reserve(1)
                .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
            projected.buffer.push_back(ReadableBufferedChunk {
                value,
                label: chunk_label,
                units: 1,
            });
            projected.next_index = projected.next_index.saturating_add(1);
            projected.buffered_length = projected.buffered_length.saturating_add(1);
            projected.data_readable_pending = true;
            self.commit_readable_state_and_schedule(object_id, projected)?;
            Ok(true)
        } else {
            projected.eof_requested = true;
            projected.eof_readable_pending = true;
            self.commit_readable_state_and_schedule(object_id, projected)?;
            Ok(false)
        }
    }

    pub(super) fn readable_materialize_byte_chunk(
        &mut self,
        value: Value,
        object_mode: bool,
        decoded_utf8: bool,
    ) -> Result<Value, InterpreterError> {
        if object_mode || decoded_utf8 {
            return Ok(value);
        }
        match value {
            Value::Str(text) => Ok(Value::Object(
                self.alloc_buffer_from_bytes(text.as_bytes())?,
            )),
            Value::Object(_) => Ok(value),
            other => Err(InterpreterError::TypeError {
                expected: "buffered byte chunk".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn readable_read(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        let requested_size = self.readable_requested_size(args)?;
        let should_pull = self
            .readable_from_streams
            .get(&object_id)
            .is_some_and(|state| {
                state.buffer.is_empty()
                    && !state.push_only
                    && !state.eof_requested
                    && state.phase == ReadableFromPumpPhase::Data
            });
        if should_pull {
            let _ = self.readable_pull_source_chunk(object_id)?;
        }
        let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
            return Ok(Value::Null);
        };
        if projected.buffer.is_empty() {
            self.schedule_readable_from_pump(object_id)?;
            return Ok(Value::Null);
        }
        if requested_size == Some(0) {
            return Ok(Value::Null);
        }
        if !projected.object_mode
            && requested_size.is_some_and(|size| size > projected.buffered_length)
            && !projected.eof_requested
        {
            self.schedule_readable_from_pump(object_id)?;
            return Ok(Value::Null);
        }

        let mut raw_allocation_checkpoint = None;
        let result = if projected.object_mode {
            let chunk = projected
                .buffer
                .pop_front()
                .expect("non-empty Readable queue");
            projected.buffered_length = projected.buffered_length.saturating_sub(chunk.units);
            chunk.value
        } else if projected.decode_utf8 {
            let unit_bytes = u64::try_from(projected.buffered_length)
                .unwrap_or(u64::MAX)
                .saturating_mul(2);
            // `from_code_units` may transiently own both its intermediate
            // three-byte-per-unit UTF-8 replacement String and the copied
            // Arc<str>, plus a two-byte-per-unit exact-unit Arc. Account the
            // worst sequential result/remainder peak together with the
            // already-live transactional state clone and Vec<u16>, before any
            // of those infallible host allocations.
            let string_bytes = u64::try_from(projected.buffered_length)
                .unwrap_or(u64::MAX)
                .saturating_mul(10)
                .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_mul(6));
            let temporary_bytes = Self::estimate_readable_from_state_bytes(&projected)
                .saturating_add(unit_bytes)
                .saturating_add(string_bytes);
            self.check_temporary_memory_budget(temporary_bytes)?;
            let mut units = Vec::new();
            units
                .try_reserve_exact(projected.buffered_length)
                .map_err(|_| {
                    self.memory_budget_error(
                        self.estimated_memory_bytes.saturating_add(temporary_bytes),
                        self.heap_object_count_u32(),
                    )
                })?;
            for chunk in &projected.buffer {
                let Value::Str(value) = &chunk.value else {
                    return Err(InterpreterError::TypeError {
                        expected: "decoded Readable string chunk".to_string(),
                        got: chunk.value.type_name().to_string(),
                    });
                };
                units.extend(value.encode_utf16());
            }
            let consumed = requested_size.unwrap_or(units.len()).min(units.len());
            let result = Value::Str(JsString::from_code_units(&units[..consumed]));
            let remainder = &units[consumed..];
            projected.buffer.clear();
            projected.buffered_length = remainder.len();
            if !remainder.is_empty() {
                projected.buffer.push_back(ReadableBufferedChunk {
                    value: Value::Str(JsString::from_code_units(remainder)),
                    label: projected.lifecycle_label.clone(),
                    units: remainder.len(),
                });
            }
            result
        } else {
            let single_buffer = projected
                .buffer
                .front()
                .and_then(|chunk| match chunk.value {
                    Value::Object(buffer_id)
                        if projected.buffer.len() == 1
                            && requested_size
                                .is_none_or(|size| size >= projected.buffered_length)
                            && self.is_buffer_object(buffer_id) =>
                    {
                        Some(buffer_id)
                    }
                    _ => None,
                });
            if let Some(buffer_id) = single_buffer {
                projected.buffer.clear();
                projected.buffered_length = 0;
                Value::Object(buffer_id)
            } else {
                let projection_peak_bytes = Self::estimate_readable_from_state_bytes(&projected);
                self.check_temporary_memory_budget(
                    projection_peak_bytes.saturating_add(
                        u64::try_from(projected.buffered_length).unwrap_or(u64::MAX),
                    ),
                )?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(projected.buffered_length)
                    .map_err(|_| {
                        self.memory_budget_error(
                            self.estimated_memory_bytes.saturating_add(
                                u64::try_from(projected.buffered_length).unwrap_or(u64::MAX),
                            ),
                            self.heap_object_count_u32(),
                        )
                    })?;
                let coalescing_temporary_bytes = projection_peak_bytes
                    .saturating_add(u64::try_from(bytes.capacity()).unwrap_or(u64::MAX));
                self.check_temporary_memory_budget(coalescing_temporary_bytes)?;
                for chunk in &projected.buffer {
                    match &chunk.value {
                        Value::Str(value) => bytes.extend_from_slice(value.as_bytes()),
                        value @ Value::Object(_) => {
                            let view = self.buffer_like_view(value)?;
                            bytes.extend_from_slice(self.typed_array_view_bytes(&view)?);
                        }
                        value => {
                            return Err(InterpreterError::TypeError {
                                expected: "buffered byte chunk".to_string(),
                                got: value.type_name().to_string(),
                            });
                        }
                    }
                }
                let consumed = requested_size.unwrap_or(bytes.len()).min(bytes.len());
                let checkpoint = (self.heap.len(), self.estimated_memory_bytes);
                let result = match self.alloc_buffer_from_bytes_with_temporary(
                    &bytes[..consumed],
                    coalescing_temporary_bytes,
                ) {
                    Ok(result) => Value::Object(result),
                    Err(error) => {
                        self.rollback_heap_to_len(checkpoint.0);
                        self.estimated_memory_bytes = checkpoint.1;
                        return Err(error);
                    }
                };
                let remainder = &bytes[consumed..];
                projected.buffer.clear();
                projected.buffered_length = remainder.len();
                if !remainder.is_empty() {
                    let remainder_len = remainder.len();
                    let remainder_buffer = match self.alloc_buffer_from_bytes_with_temporary(
                        remainder,
                        coalescing_temporary_bytes,
                    ) {
                        Ok(remainder) => remainder,
                        Err(error) => {
                            self.rollback_heap_to_len(checkpoint.0);
                            self.estimated_memory_bytes = checkpoint.1;
                            return Err(error);
                        }
                    };
                    projected.buffer.push_back(ReadableBufferedChunk {
                        value: Value::Object(remainder_buffer),
                        label: projected.lifecycle_label.clone(),
                        units: remainder_len,
                    });
                }
                raw_allocation_checkpoint = Some(checkpoint);
                result
            }
        };
        if !projected.flowing && self.active_readable_listener_target == Some(object_id) {
            projected.nonflowing_read_consumed = true;
        }
        let should_prefetch = !projected.push_only
            && projected.buffer.is_empty()
            && !projected.eof_requested
            && projected.phase == ReadableFromPumpPhase::Data;
        if let Err(error) = self.commit_readable_state_and_schedule(object_id, projected) {
            if let Some((heap_len, estimated_memory_bytes)) = raw_allocation_checkpoint {
                self.rollback_heap_to_len(heap_len);
                self.estimated_memory_bytes = estimated_memory_bytes;
            }
            return Err(error);
        }
        if should_prefetch {
            let _ = self.readable_pull_source_chunk(object_id)?;
        }
        Ok(result)
    }

    pub(super) fn readable_requested_size(
        &self,
        args: RegRange,
    ) -> Result<Option<usize>, InterpreterError> {
        let Some(value) = self.builtin_arg(args, 0)? else {
            return Ok(None);
        };
        let numeric = match value {
            Value::Undefined => return Ok(None),
            Value::Int(value) => {
                return Ok(Some(usize::try_from(value.max(0)).unwrap_or(usize::MAX)));
            }
            Value::Float(value) if value.inner().is_finite() => value.inner().trunc(),
            Value::Str(value) => return Ok(Self::readable_string_size_prefix(&value)),
            _ => return Ok(None),
        };
        if numeric <= 0.0 {
            return Ok(Some(0));
        }
        if numeric >= usize::MAX as f64 {
            return Ok(Some(usize::MAX));
        }
        Ok(Some(numeric as usize))
    }

    /// Node's stream implementation uses a leading base-10 integer scan for
    /// string read sizes rather than ECMAScript `Number(...)`: `"2tail"`
    /// requests two units, `"1e2"` requests one, and a string without a
    /// decimal prefix falls back to an unsized read.
    pub(super) fn readable_string_size_prefix(value: &JsString) -> Option<usize> {
        let text = value.as_utf8_projection().trim_start();
        let bytes = text.as_bytes();
        let (negative, start) = match bytes.first() {
            Some(b'-') => (true, 1),
            Some(b'+') => (false, 1),
            _ => (false, 0),
        };
        let mut saw_digit = false;
        let mut size = 0usize;
        for byte in bytes.iter().skip(start) {
            if !byte.is_ascii_digit() {
                break;
            }
            saw_digit = true;
            size = size
                .saturating_mul(10)
                .saturating_add(usize::from(*byte - b'0'));
        }
        if !saw_digit {
            None
        } else if negative {
            Some(0)
        } else {
            Some(size)
        }
    }

    pub(super) fn readable_unshift(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let trigger_label = if args.count > 0 {
            self.get_register_label(args.start)?
                .clone()
                .join(&match &value {
                    Value::Object(object_id) => self.binary_storage_label(*object_id),
                    _ => Label::Public,
                })
        } else {
            Label::Public
        };
        let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
            return Ok(Value::Bool(false));
        };
        if projected.phase != ReadableFromPumpPhase::Data || projected.destroy_requested {
            return Ok(Value::Bool(false));
        }
        let before_eof = !projected.eof_requested;
        if value == Value::Null {
            return Ok(Value::Bool(false));
        }
        let empty_byte_chunk = !projected.object_mode
            && match &value {
                Value::Undefined => true,
                Value::Str(text) => text.utf16_len() == 0,
                Value::Object(_) => self
                    .buffer_like_view(&value)
                    .is_ok_and(|view| view.byte_length == 0),
                _ => false,
            };
        if empty_byte_chunk {
            return Ok(Value::Bool(before_eof));
        }
        projected.lifecycle_label = projected.lifecycle_label.join(&trigger_label);
        let projection_bytes = Self::estimate_readable_from_state_bytes(&projected);
        let Some((value, units)) =
            self.readable_normalize_push_value(&mut projected, value, projection_bytes)?
        else {
            self.commit_readable_state(object_id, projected)?;
            return Ok(Value::Bool(
                !self
                    .readable_from_streams
                    .get(&object_id)
                    .is_some_and(|state| state.eof_requested),
            ));
        };
        let buffered_length = projected
            .buffered_length
            .checked_add(units)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Readable buffered length overflows host address space".to_string(),
            })?;
        projected
            .buffer
            .try_reserve(1)
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        projected.buffer.push_front(ReadableBufferedChunk {
            value,
            label: projected.lifecycle_label.clone(),
            units,
        });
        projected.buffered_length = buffered_length;
        projected.data_readable_pending = true;
        self.commit_readable_state_and_schedule(object_id, projected)?;
        Ok(Value::Bool(before_eof))
    }

    pub(super) fn readable_set_encoding(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver.clone())?;
        let encoding_label = if args.count > 0 {
            self.get_register_label(args.start)?.clone()
        } else {
            Label::Public
        };
        let encoding = match self.builtin_arg(args, 0)? {
            Some(Value::Str(encoding)) => encoding.to_ascii_lowercase(),
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "Readable encoding string".to_string(),
                    got: value.type_name().to_string(),
                });
            }
            None => "utf8".to_string(),
        };
        if !matches!(encoding.as_str(), "utf8" | "utf-8") {
            return Err(InterpreterError::TypeError {
                expected: "utf8 or utf-8 Readable encoding".to_string(),
                got: encoding,
            });
        }
        let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
            return Ok(receiver);
        };
        if projected.object_mode {
            return Err(InterpreterError::TypeError {
                expected: "byte-mode Readable for setEncoding".to_string(),
                got: "object-mode Readable".to_string(),
            });
        }
        projected.lifecycle_label = projected.lifecycle_label.join(&encoding_label);
        if projected.decode_utf8 {
            self.commit_readable_state(object_id, projected)?;
            return Ok(receiver);
        }
        projected.decode_utf8 = true;
        let buffered = std::mem::take(&mut projected.buffer);
        let mut decoded = VecDeque::new();
        decoded
            .try_reserve_exact(buffered.capacity())
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        self.check_temporary_memory_budget(
            Self::estimate_readable_from_state_bytes(&projected)
                .saturating_add(Self::estimate_readable_buffer_bytes(&buffered))
                .saturating_add(Self::estimate_readable_buffer_bytes(&decoded)),
        )?;
        projected.buffered_length = 0;
        let mut buffered = buffered;
        while let Some(chunk) = buffered.pop_front() {
            let transaction_bytes = Self::estimate_readable_from_state_bytes(&projected)
                .saturating_add(Self::estimate_readable_buffer_bytes(&buffered))
                .saturating_add(Self::estimate_readable_buffer_bytes(&decoded))
                .saturating_add(Self::estimate_value_bytes(&chunk.value))
                .saturating_add(Self::estimate_label_bytes(&chunk.label));
            let chunk_label = chunk.label.join(&encoding_label);
            if let Some((value, units)) =
                self.readable_normalize_push_value(&mut projected, chunk.value, transaction_bytes)?
            {
                self.check_temporary_memory_budget(
                    Self::estimate_readable_from_state_bytes(&projected)
                        .saturating_add(Self::estimate_readable_buffer_bytes(&buffered))
                        .saturating_add(Self::estimate_readable_buffer_bytes(&decoded))
                        .saturating_add(Self::estimate_value_bytes(&value))
                        .saturating_add(Self::estimate_label_bytes(&chunk_label)),
                )?;
                projected.buffered_length = projected
                    .buffered_length
                    .checked_add(units)
                    .ok_or_else(|| InterpreterError::RangeError {
                        message: "Readable buffered length overflows host address space"
                            .to_string(),
                    })?;
                decoded.push_back(ReadableBufferedChunk {
                    value,
                    label: chunk_label,
                    units,
                });
            }
        }
        drop(buffered);
        projected.buffer = decoded;
        projected.data_readable_pending = !projected.buffer.is_empty();
        self.commit_readable_state_and_schedule(object_id, projected)?;
        Ok(receiver)
    }

    pub(super) fn readable_destroy(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver.clone())?;
        let error = match self.builtin_arg(args, 0)? {
            None | Some(Value::Undefined | Value::Null) => None,
            Some(error) => Some(error),
        };
        let trigger_label = if args.count > 0 {
            self.get_register_label(args.start)?
                .clone()
                .join(&match &error {
                    Some(Value::Object(error_id)) => self.binary_storage_label(*error_id),
                    _ => Label::Public,
                })
        } else {
            Label::Public
        };
        let Some(current) = self.readable_from_streams.get(&object_id) else {
            return Ok(receiver);
        };
        if current.destroy_requested {
            return Ok(receiver);
        }

        let lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            &current.lifecycle_label,
            &trigger_label,
            Self::estimate_label_bytes(&trigger_label),
        )?;
        self.commit_readable_destroy(object_id, receiver, error, lifecycle_label)
    }

    pub(super) fn readable_destroy_memory_projection(
        &self,
        object_id: ObjectId,
        error: Option<&Value>,
        lifecycle_label: &Label,
    ) -> Option<(u64, u64, u64)> {
        let current = self.readable_from_streams.get(&object_id)?;
        let label_bytes = match &lifecycle_label {
            Label::Custom { name, .. } => Self::estimate_string_bytes(name),
            _ => 0,
        };
        let previous_bytes = Self::estimate_readable_from_state_bytes(current);
        let destroyed_state_bytes = MEMORY_ESTIMATE_READABLE_FROM_BASE_BYTES
            .saturating_add(error.map(Self::estimate_value_bytes).unwrap_or(0))
            .saturating_add(label_bytes)
            .saturating_add(
                current
                    .to_array_waiter
                    .as_ref()
                    .map(|waiter| Self::estimate_readable_to_array_waiter_bytes(&waiter.label))
                    .unwrap_or(0),
            );
        let pump_bytes = if self.has_pending_readable_pump(object_id)
            || self.readable_pump_reservations.contains_key(&object_id)
        {
            0
        } else {
            self.readable_pump_retained_bytes()
        };
        Some((previous_bytes, destroyed_state_bytes, pump_bytes))
    }

    pub(super) fn commit_readable_destroy(
        &mut self,
        object_id: ObjectId,
        receiver: Value,
        error: Option<Value>,
        lifecycle_label: Label,
    ) -> Result<Value, InterpreterError> {
        let Some((previous_bytes, destroyed_state_bytes, pump_bytes)) =
            self.readable_destroy_memory_projection(object_id, error.as_ref(), &lifecycle_label)
        else {
            return Ok(receiver);
        };
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(destroyed_state_bytes)
            .saturating_add(pump_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let previous_total = self.estimated_memory_bytes;
        let mut projected = self
            .readable_from_streams
            .remove(&object_id)
            .expect("live Readable state was checked before owned teardown");
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(previous_bytes);
        if let Err(error) = self.schedule_readable_pump_registration(object_id) {
            self.readable_from_streams.insert(object_id, projected);
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }

        projected.destroy_requested = true;
        projected.lifecycle_label = lifecycle_label;
        projected.destroy_error = error;
        projected.phase = if projected.destroy_error.is_some() {
            ReadableFromPumpPhase::DestroyError
        } else {
            ReadableFromPumpPhase::Close
        };
        projected.source = Value::Undefined;
        projected.read_callback = None;
        projected.buffer = VecDeque::new();
        projected.buffered_length = 0;
        projected.utf8_pending = Vec::new();
        projected.eof_requested = true;
        projected.data_readable_pending = false;
        projected.eof_readable_pending = false;
        projected.read_callback_active = false;
        debug_assert_eq!(
            Self::estimate_readable_from_state_bytes(&projected),
            destroyed_state_bytes
        );
        self.estimated_memory_bytes = requested_bytes;
        self.readable_from_streams.insert(object_id, projected);

        self.mirror_readable_bool(object_id, "destroyed", true);
        self.mirror_readable_bool(object_id, "closed", true);
        self.mirror_readable_bool(object_id, "readable", false);
        Ok(receiver)
    }

    pub(super) fn readable_to_array(&mut self, receiver: Value) -> Result<Value, InterpreterError> {
        let object_id = self.readable_receiver_id(receiver)?;
        let Some(snapshot) = self.clone_readable_state_with_budget(object_id)? else {
            return Err(InterpreterError::TypeError {
                expected: "live finite Readable.from receiver".to_string(),
                got: "closed Readable".to_string(),
            });
        };
        let mut projected = snapshot;
        let next_index = projected.next_index;
        let phase = projected.phase;
        let push_only = projected.push_only;
        let already_waiting = projected.to_array_waiter.is_some();
        if push_only || already_waiting || phase != ReadableFromPumpPhase::Data {
            return Err(InterpreterError::TypeError {
                expected: "one pre-terminal toArray consumption on Readable.from".to_string(),
                got: if push_only {
                    "generic Readable".to_string()
                } else if phase != ReadableFromPumpPhase::Data {
                    "terminating Readable".to_string()
                } else {
                    "duplicate toArray".to_string()
                },
            });
        }

        let source_length = match &projected.source {
            Value::Str(_) => 1,
            Value::Object(source_id) => self.array_like_length(*source_id)?,
            _ => 0,
        };
        let remaining = source_length.saturating_sub(next_index);
        let result_length = projected
            .buffer
            .len()
            .checked_add(remaining)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Readable toArray result length overflows host address space".to_string(),
            })?;
        let waiter_bytes =
            Self::estimate_readable_to_array_waiter_bytes(&projected.lifecycle_label);
        let projected_state_bytes = Self::estimate_readable_from_state_bytes(&projected);
        let projected_buffer_bytes = Self::estimate_readable_buffer_bytes(&projected.buffer);
        let final_state_bytes = projected_state_bytes
            .saturating_sub(projected_buffer_bytes)
            .saturating_add(waiter_bytes);
        let promise_bytes = self
            .promise_store
            .projected_create_memory_bytes()
            .saturating_sub(self.promise_store.estimated_memory_bytes());
        let pump_bytes = if self.has_pending_readable_pump(object_id)
            || self.readable_pump_reservations.contains_key(&object_id)
        {
            0
        } else {
            self.readable_pump_retained_bytes()
        };
        let mut projected_empty_array = HeapObject::new();
        projected_empty_array.is_array = true;
        projected_empty_array.cached_dense_length = Some(0);
        projected_empty_array
            .properties
            .insert("length".to_string(), Value::Int(0));
        let fixed_result_bytes = Self::estimate_heap_object_bytes(&projected_empty_array);
        let minimum_element_bytes = Self::estimate_property_entry_bytes("0", &Value::Undefined);
        let minimum_result_bytes = fixed_result_bytes.saturating_add(
            u64::try_from(result_length)
                .unwrap_or(u64::MAX)
                .saturating_mul(minimum_element_bytes),
        );
        let minimum_values_bytes = u64::try_from(result_length)
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Value>() as u64);
        let minimum_materialization_peak = projected_state_bytes
            .saturating_add(minimum_values_bytes)
            .saturating_add(promise_bytes)
            .saturating_add(minimum_result_bytes);
        let minimum_commit_peak = final_state_bytes
            .saturating_add(promise_bytes)
            .saturating_add(minimum_result_bytes)
            .saturating_add(pump_bytes);
        let minimum_requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(minimum_materialization_peak.max(minimum_commit_peak));
        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if self.memory_request_exceeds_budget(
            minimum_requested_bytes,
            self.config.max_total_memory_bytes,
        ) || requested_heap_objects > self.config.max_heap_objects
        {
            return Err(self.memory_budget_error(minimum_requested_bytes, requested_heap_objects));
        }

        let mut values = Vec::new();
        values.try_reserve_exact(result_length).map_err(|_| {
            self.memory_budget_error(minimum_requested_bytes, requested_heap_objects)
        })?;
        values.extend(projected.buffer.iter().map(|chunk| chunk.value.clone()));
        match &projected.source {
            Value::Str(text) if next_index == 0 => values.push(Value::Str(text.clone())),
            Value::Str(_) => {}
            Value::Object(source_id) => {
                for index in next_index..source_length {
                    values.push(
                        self.array_index_value(*source_id, index)?
                            .unwrap_or(Value::Undefined),
                    );
                }
            }
            _ => {}
        }

        let result_bytes = fixed_result_bytes.saturating_add(
            values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    Self::estimate_property_entry_bytes(&index.to_string(), value)
                })
                .sum::<u64>(),
        );
        let values_bytes = u64::try_from(values.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Value>() as u64)
            .saturating_add(Self::saturating_sum(
                values.iter().map(Self::estimate_value_bytes),
            ));
        let materialization_peak = projected_state_bytes
            .saturating_add(values_bytes)
            .saturating_add(promise_bytes)
            .saturating_add(result_bytes);
        let commit_peak = final_state_bytes
            .saturating_add(promise_bytes)
            .saturating_add(result_bytes)
            .saturating_add(pump_bytes);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(materialization_peak.max(commit_peak));
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(
                requested_bytes,
                self.heap_object_count_u32().saturating_add(1),
            ));
        }

        let previous_estimated_bytes = self.estimated_memory_bytes;
        let previous_heap_len = self.heap.len();
        let promise = self.create_promise()?;
        let result = match self.alloc_array_from_values(&values) {
            Ok(result) => result,
            Err(error) => {
                self.rollback_fresh_promise(promise);
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_estimated_bytes;
                return Err(error);
            }
        };
        drop(values);
        projected.next_index = source_length;
        projected.buffer = VecDeque::new();
        projected.buffered_length = 0;
        projected.data_readable_pending = false;
        projected.eof_readable_pending = false;
        projected.eof_requested = true;
        projected.phase = ReadableFromPumpPhase::End;
        projected.to_array_waiter = Some(ReadableToArrayWaiter {
            promise,
            result,
            label: projected.lifecycle_label.clone(),
        });
        if let Err(error) = self.commit_readable_state_and_schedule(object_id, projected) {
            self.rollback_fresh_promise(promise);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return Err(error);
        }
        Ok(Value::Promise(promise.0))
    }

    pub(super) fn settle_readable_to_array_after_close(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        if self.readable_terminal_states.contains_key(&object_id)
            && self.readable_from_streams.contains_key(&object_id)
        {
            return Err(InterpreterError::InternalError {
                details: "Readable terminalization found live state beside an existing tombstone"
                    .to_string(),
            });
        }
        let Some(mut state) = self.readable_from_streams.remove(&object_id) else {
            return Ok(());
        };
        debug_assert_eq!(state.phase, ReadableFromPumpPhase::SettleToArray);
        let previous_total = self.estimated_memory_bytes;
        let state_bytes = Self::estimate_readable_from_state_bytes(&state);
        let terminal_bytes = MEMORY_ESTIMATE_READABLE_TERMINAL_BASE_BYTES
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label));
        debug_assert!(terminal_bytes <= state_bytes);
        // Releasing a live kernel must keep making progress even when the
        // caller lowers the configured ceiling below already-resident state.
        // Account the smaller tombstone before Promise settlement so nested
        // admission observes the retained terminal provenance.
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(state_bytes)
            .saturating_add(terminal_bytes);

        let settlement = if let Some(waiter) = state.to_array_waiter.as_ref() {
            if state.destroy_requested {
                self.reject_promise(
                    waiter.promise,
                    state.destroy_error.as_ref().map_or_else(
                        || Self::value_to_js_value(&Value::str("Premature close")),
                        Self::value_to_js_value,
                    ),
                    state.lifecycle_label.join(&waiter.label),
                )
            } else {
                self.fulfill_promise(
                    waiter.promise,
                    Self::value_to_js_value(&Value::Object(waiter.result)),
                    waiter.label.clone(),
                )
            }
        } else {
            Ok(())
        };

        if let Err(error) = settlement {
            self.estimated_memory_bytes = previous_total;
            let previous = self.readable_from_streams.insert(object_id, state);
            debug_assert!(previous.is_none());
            debug_assert_eq!(
                self.estimated_memory_bytes,
                self.recompute_base_estimated_memory_bytes()
            );
            return Err(error);
        }
        let terminal = ReadableTerminalState {
            lifecycle_label: std::mem::replace(&mut state.lifecycle_label, Label::Public),
        };
        debug_assert_eq!(
            Self::estimate_readable_terminal_state_bytes(&terminal),
            terminal_bytes
        );
        let previous = self.readable_terminal_states.insert(object_id, terminal);
        debug_assert!(previous.is_none());
        drop(state);
        Ok(())
    }

    /// Execute one finite-readable phase without holding the stream-state or
    /// listener-table borrow across user callback re-entrancy.
    pub(super) fn drive_readable_read_callback(
        &mut self,
        object_id: ObjectId,
        module: &Ir3Module,
        mut projected: ReadableFromState,
    ) -> Result<bool, InterpreterError> {
        let Some(read_callback) = projected.read_callback.as_ref() else {
            return Ok(false);
        };
        if !projected.push_only
            || projected.eof_requested
            || projected.phase != ReadableFromPumpPhase::Data
            || projected.read_callback_active
        {
            return Ok(false);
        }
        let pump_bytes = if self.has_pending_readable_pump(object_id)
            || self.readable_pump_reservations.contains_key(&object_id)
        {
            0
        } else {
            self.readable_pump_retained_bytes()
        };
        self.preflight_inline_method_call_with_argument_label_and_temporary(
            Some(module),
            read_callback,
            1,
            Some(&projected.lifecycle_label),
            Self::estimate_readable_from_state_bytes(&projected)
                .saturating_add(Self::estimate_value_bytes(read_callback))
                .saturating_add(pump_bytes),
        )?;
        let read_callback = read_callback.clone();
        let lifecycle_label = projected.lifecycle_label.clone();
        let high_water_mark = projected.high_water_mark;
        let flowing_before = projected.flowing;
        let paused_before = projected.paused;
        projected.read_callback_active = true;
        let pump_reserved = self.reserve_readable_pump(object_id)?;
        if let Err(error) = self.commit_readable_state(object_id, projected) {
            if pump_reserved {
                self.release_readable_pump_reservation(object_id);
            }
            return Err(error);
        }
        let invocation = self.invoke_inline_method_call_with_argument_label_preflighted(
            Some(module),
            read_callback,
            Value::Object(object_id),
            vec![Value::Int(
                i64::try_from(high_water_mark).unwrap_or(i64::MAX),
            )],
            Some(lifecycle_label),
        );
        let mut made_progress = false;
        if let Some(state) = self.readable_from_streams.get_mut(&object_id) {
            state.read_callback_active = false;
            made_progress = state.flowing != flowing_before || state.paused != paused_before;
        }
        let reschedule_requested = self
            .readable_pump_reservations
            .get(&object_id)
            .is_some_and(|reservation| reservation.requested);
        made_progress |= reschedule_requested;
        let scheduling = if made_progress && pump_reserved {
            self.convert_readable_pump_reservation(object_id)
        } else if made_progress {
            self.schedule_readable_from_pump(object_id)
        } else {
            if pump_reserved {
                self.release_readable_pump_reservation(object_id);
            }
            Ok(false)
        };
        if let Err(error) = scheduling {
            if pump_reserved {
                self.release_readable_pump_reservation(object_id);
            }
            return Err(error);
        }
        invocation?;
        Ok(true)
    }

    pub(super) fn drive_readable_from_pump(
        &mut self,
        object_id: ObjectId,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module context for Readable.from pump".to_string(),
            got: "missing module context".to_string(),
        })?;
        let Some(phase) = self
            .readable_from_streams
            .get(&object_id)
            .map(|state| state.phase)
        else {
            return Ok(());
        };

        match phase {
            ReadableFromPumpPhase::Data => {
                let Some(snapshot) = self.clone_readable_state_with_budget(object_id)? else {
                    return Ok(());
                };
                if !snapshot.flowing {
                    let mut pull_pump_reserved = false;
                    let should_pull = snapshot.buffer.is_empty()
                        && !snapshot.push_only
                        && !snapshot.eof_requested;
                    let mut projected = if should_pull {
                        drop(snapshot);
                        pull_pump_reserved = self.reserve_readable_pump(object_id)?;
                        if let Err(error) = self.readable_pull_source_chunk(object_id) {
                            return self.readable_error_after_reservation(
                                object_id,
                                pull_pump_reserved,
                                error,
                            );
                        }
                        let projected_result = self.clone_readable_state_with_budget(object_id);
                        let Some(projected) = (match projected_result {
                            Ok(projected) => projected,
                            Err(error) => {
                                return self.readable_error_after_reservation(
                                    object_id,
                                    pull_pump_reserved,
                                    error,
                                );
                            }
                        }) else {
                            self.settle_readable_pump_reservation(object_id, pull_pump_reserved)?;
                            return Ok(());
                        };
                        projected
                    } else {
                        snapshot
                    };
                    let (emit_readable, eof_notification) = if projected.data_readable_pending {
                        projected.data_readable_pending = false;
                        (true, false)
                    } else if projected.eof_readable_pending {
                        projected.eof_readable_pending = false;
                        (true, true)
                    } else {
                        (false, false)
                    };
                    if emit_readable {
                        let lifecycle_label = projected.lifecycle_label.clone();
                        let pump_reserved = if pull_pump_reserved {
                            true
                        } else {
                            self.reserve_readable_pump(object_id)?
                        };
                        if let Err(error) = self.commit_readable_state(object_id, projected) {
                            if pump_reserved {
                                self.release_readable_pump_reservation(object_id);
                            }
                            return Err(error);
                        }
                        let previous_readable_listener =
                            self.active_readable_listener_target.replace(object_id);
                        let emission = self.emit_event_listener_records(
                            module,
                            object_id,
                            "readable",
                            Vec::new(),
                            lifecycle_label,
                        );
                        self.active_readable_listener_target = previous_readable_listener;
                        let readable_result = match emission {
                            Err(listener_error) => {
                                let _ = self.finish_readable_pump_after_emission(
                                    object_id,
                                    pump_reserved,
                                    Ok(false),
                                );
                                self.terminalize_deferred_dual_final_after_readable_failure(
                                    object_id,
                                );
                                return Err(listener_error);
                            }
                            Ok(emitted) => self.finish_readable_pump_after_emission(
                                object_id,
                                pump_reserved,
                                Ok(emitted),
                            ),
                        };
                        if let Err(error) = readable_result {
                            self.terminalize_deferred_dual_final_after_readable_failure(object_id);
                            return Err(error);
                        }
                        if !eof_notification {
                            // Pull-mode PassThrough/Transform finalization is
                            // held until the queued data-readable notification
                            // has run. Starting it here preserves the reference
                            // `readable -> prefinish -> EOF-readable` sequence.
                            if let Err(error) = self.drive_writable(object_id, module) {
                                self.terminalize_deferred_dual_final_after_readable_failure(
                                    object_id,
                                );
                                return Err(error);
                            }
                        }
                        let finish_after_eof_notification = eof_notification
                            && self
                                .readable_from_streams
                                .get(&object_id)
                                .is_some_and(|state| {
                                    state.phase == ReadableFromPumpPhase::Data
                                        && state.eof_requested
                                        && (!state.buffer.is_empty()
                                            || !state.nonflowing_read_consumed)
                                })
                            && self.writable_streams.get(&object_id).is_some_and(|state| {
                                matches!(
                                    state.flavor,
                                    WritableStreamFlavor::PassThrough
                                        | WritableStreamFlavor::Transform
                                ) && matches!(state.final_status, WritableFinalStatus::Active(_))
                            });
                        if finish_after_eof_notification {
                            // A passive/partial pull listener has observed the
                            // EOF-readable notification but left bytes queued,
                            // or an initially-empty pull listener has observed
                            // its sole readable notice. Consume the reserved
                            // final tick now. A listener that drained buffered
                            // data instead reaches End first.
                            self.complete_deferred_dual_stream_final(object_id, module)?;
                        }
                        return Ok(());
                    }
                    self.settle_readable_pump_reservation(object_id, pull_pump_reserved)?;
                    if projected.push_only
                        && !projected.eof_requested
                        && projected.buffered_length < projected.high_water_mark
                        && projected.read_callback.is_some()
                    {
                        let _ = self.drive_readable_read_callback(object_id, module, projected)?;
                        return Ok(());
                    }
                    if projected.eof_requested && projected.buffer.is_empty() {
                        projected.phase = ReadableFromPumpPhase::End;
                        self.commit_readable_state_and_schedule(object_id, projected)?;
                    }
                    return Ok(());
                }

                if !snapshot.buffer.is_empty() {
                    let mut projected = snapshot;
                    let projection_temporary_bytes =
                        Self::estimate_readable_from_state_bytes(&projected);
                    let chunk = projected
                        .buffer
                        .pop_front()
                        .expect("non-empty flowing Readable queue");
                    projected.buffered_length =
                        projected.buffered_length.saturating_sub(chunk.units);
                    projected.data_readable_pending = false;
                    if projected.buffer.is_empty() && projected.eof_requested {
                        projected.phase = ReadableFromPumpPhase::End;
                        projected.eof_readable_pending = false;
                    }
                    let object_mode = projected.object_mode;
                    let decoded_utf8 = projected.decode_utf8;
                    let allocation_checkpoint = (self.heap.len(), self.estimated_memory_bytes);
                    let pump_reserved = self.reserve_readable_pump(object_id)?;
                    let emitted_value = match self.readable_materialize_byte_chunk(
                        chunk.value,
                        object_mode,
                        decoded_utf8,
                    ) {
                        Ok(value) => value,
                        Err(error) => {
                            if pump_reserved {
                                self.release_readable_pump_reservation(object_id);
                            }
                            self.rollback_heap_to_len(allocation_checkpoint.0);
                            self.estimated_memory_bytes = allocation_checkpoint.1;
                            return Err(error);
                        }
                    };
                    // A chunk may have been prefetched before a classified
                    // drain resumed this source. Its emission depends on the
                    // latest lifecycle label even when its payload is Public.
                    // Reuse the owned chunk label when it already dominates;
                    // otherwise account the full projection plus the new copy
                    // before committing either the queue or its emission.
                    let emission_label = if chunk.label >= projected.lifecycle_label {
                        chunk.label
                    } else {
                        match self.clone_dominant_label_with_temporary_budget(
                            &chunk.label,
                            &projected.lifecycle_label,
                            projection_temporary_bytes,
                        ) {
                            Ok(label) => label,
                            Err(error) => {
                                if pump_reserved {
                                    self.release_readable_pump_reservation(object_id);
                                }
                                self.rollback_heap_to_len(allocation_checkpoint.0);
                                self.estimated_memory_bytes = allocation_checkpoint.1;
                                return Err(error);
                            }
                        }
                    };
                    if let Err(error) = self.commit_readable_state(object_id, projected) {
                        if pump_reserved {
                            self.release_readable_pump_reservation(object_id);
                        }
                        self.rollback_heap_to_len(allocation_checkpoint.0);
                        self.estimated_memory_bytes = allocation_checkpoint.1;
                        return Err(error);
                    }
                    let emission = self.emit_event_listener_records(
                        module,
                        object_id,
                        "data",
                        vec![emitted_value],
                        emission_label,
                    );
                    self.finish_readable_pump_after_emission(object_id, pump_reserved, emission)?;
                    return Ok(());
                }

                if snapshot.eof_requested {
                    let mut projected = snapshot;
                    projected.phase = ReadableFromPumpPhase::End;
                    projected.data_readable_pending = false;
                    projected.eof_readable_pending = false;
                    self.commit_readable_state_and_schedule(object_id, projected)?;
                    return Ok(());
                }

                if snapshot.push_only {
                    let _ = self.drive_readable_read_callback(object_id, module, snapshot)?;
                    return Ok(());
                }

                let source = snapshot.source;
                let next_index = snapshot.next_index;
                let lifecycle_label = snapshot.lifecycle_label;
                let next_value = match source {
                    Value::Str(text) if next_index == 0 => Some(Value::Str(text)),
                    Value::Str(_) => None,
                    Value::Object(source_id) => {
                        let length = self.array_like_length(source_id)?;
                        if next_index < length {
                            Some(
                                self.array_index_value(source_id, next_index)?
                                    .unwrap_or(Value::Undefined),
                            )
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                let Some(value) = next_value else {
                    if let Some(mut state) = self.clone_readable_state_with_budget(object_id)? {
                        state.phase = ReadableFromPumpPhase::End;
                        state.eof_requested = true;
                        self.commit_readable_state_and_schedule(object_id, state)?;
                    }
                    return Ok(());
                };
                let Some(mut state) = self.clone_readable_state_with_budget(object_id)? else {
                    return Ok(());
                };
                if state.phase != ReadableFromPumpPhase::Data || state.next_index != next_index {
                    return Ok(());
                }
                state.next_index = state.next_index.saturating_add(1);
                let pump_reserved = self.reserve_readable_pump(object_id)?;
                if let Err(error) = self.commit_readable_state(object_id, state) {
                    if pump_reserved {
                        self.release_readable_pump_reservation(object_id);
                    }
                    return Err(error);
                }
                let emission = self.emit_event_listener_records(
                    module,
                    object_id,
                    "data",
                    vec![value],
                    lifecycle_label,
                );
                self.finish_readable_pump_after_emission(object_id, pump_reserved, emission)?;
            }
            ReadableFromPumpPhase::DestroyError => {
                let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
                    return Ok(());
                };
                let error = projected.destroy_error.clone();
                let lifecycle_label = projected.lifecycle_label.clone();
                projected.phase = ReadableFromPumpPhase::Close;
                let pump_reserved = self.reserve_readable_pump(object_id)?;
                if let Err(error) = self.commit_readable_state(object_id, projected) {
                    if pump_reserved {
                        self.release_readable_pump_reservation(object_id);
                    }
                    return Err(error);
                }
                let emission = if let Some(error) = error {
                    self.emit_event_listener_records(
                        module,
                        object_id,
                        "error",
                        vec![error],
                        lifecycle_label,
                    )
                } else {
                    Ok(false)
                };
                self.finish_readable_pump_after_emission(object_id, pump_reserved, emission)?;
            }
            ReadableFromPumpPhase::End => {
                let Some(mut projected) = self.clone_readable_state_with_budget(object_id)? else {
                    return Ok(());
                };
                projected.phase = ReadableFromPumpPhase::Close;
                let lifecycle_label = projected.lifecycle_label.clone();
                let pump_reserved = self.reserve_readable_pump(object_id)?;
                if let Err(error) = self.commit_readable_state(object_id, projected) {
                    if pump_reserved {
                        self.release_readable_pump_reservation(object_id);
                    }
                    return Err(error);
                }
                self.mirror_readable_bool(object_id, "readable", false);
                self.mirror_readable_bool(object_id, "readableEnded", true);
                let emission = self.emit_event_listener_records(
                    module,
                    object_id,
                    "end",
                    Vec::new(),
                    lifecycle_label,
                );
                let readable_result =
                    self.finish_readable_pump_after_emission(object_id, pump_reserved, emission);
                let writable_result = self.complete_deferred_dual_stream_final(object_id, module);
                readable_result?;
                writable_result?;
            }
            ReadableFromPumpPhase::Close => {
                self.mirror_readable_bool(object_id, "destroyed", true);
                self.mirror_readable_bool(object_id, "closed", true);
                self.detach_current_readable_pipe(object_id);
                let lifecycle_label = self
                    .readable_from_streams
                    .get(&object_id)
                    .map(|state| state.lifecycle_label.clone())
                    .unwrap_or(Label::Public);
                if let Some(state) = self.readable_from_streams.get_mut(&object_id) {
                    state.phase = ReadableFromPumpPhase::SettleToArray;
                }
                let emission = self.emit_event_listener_records(
                    module,
                    object_id,
                    "close",
                    Vec::new(),
                    lifecycle_label,
                );
                self.clear_event_listeners(object_id, None);
                // Promise reactions are enqueued only after every close
                // listener has run. Even a throwing close listener must not
                // strand the already-consumed toArray Promise.
                let settlement = self.settle_readable_to_array_after_close(object_id);
                emission?;
                settlement?;
            }
            ReadableFromPumpPhase::SettleToArray => {
                self.settle_readable_to_array_after_close(object_id)?;
            }
        }
        Ok(())
    }

    /// bd-3894s slice (2d): schedule a deferred readable-stream emission (`'data'` or
    /// `'end'`) for `object_id` on the next event-loop turn. It reuses the same
    /// `IoCompletion` macrotask phase as the response callback (a sentinel
    /// `ClosureHandle(0)` is stored — `execute_macrotask_callback` recognizes the
    /// emission by its registration sequence and dispatches it BEFORE the
    /// closure-callback path, so the sentinel is never invoked). Because it is
    /// scheduled after the response callback, it orders onto a LATER turn, by which
    /// point the callback has registered its `res.on('data'|'end', …)` listeners.
    pub(super) fn schedule_stream_emission(
        &mut self,
        object_id: ObjectId,
        phase: StreamEventPhase,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let seq = self
            .event_loop
            .schedule_io_completion(crate::closure_model::ClosureHandle(0), label);
        let next_component_bytes = self
            .promise_runtime_memory_bytes()
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        if let Err(error) =
            self.apply_memory_component_delta(previous_promise_bytes, next_component_bytes)
        {
            self.event_loop.rollback_last_scheduled(seq);
            return Err(error);
        }
        let previous = self
            .pending_stream_emissions
            .insert(seq, PendingStreamEmission { object_id, phase });
        debug_assert!(
            previous.is_none(),
            "EventLoop registration sequences are unique"
        );
        Ok(())
    }

    pub(super) fn pending_stream_emissions_memory_bytes(&self) -> u64 {
        u64::try_from(self.pending_stream_emissions.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
    }

    pub(super) fn remove_pending_stream_emission(
        &mut self,
        registration: u64,
    ) -> Option<PendingStreamEmission> {
        let emission = self.pending_stream_emissions.remove(&registration)?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        Some(emission)
    }

    /// bd-3894s slice (2d): emit one readable-stream phase for an `IncomingMessage`
    /// on the current event-loop turn. `'data'` delivers the whole response body as a
    /// single chunk (only when non-empty — Node emits no `'data'` for an empty body)
    /// to each `res.on('data', …)` listener, then schedules the `'end'` phase for the
    /// next turn; `'end'` fires each `res.on('end', …)` listener with no argument and
    /// releases the object's listener table. The listeners registered during the
    /// `'response'` callback are present because that callback ran on an earlier turn.
    pub(super) fn drive_stream_emission(
        &mut self,
        emission: PendingStreamEmission,
        module: Option<&Ir3Module>,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let PendingStreamEmission { object_id, phase } = emission;
        match phase {
            StreamEventPhase::Data => {
                let chunk = self
                    .heap
                    .get(object_id.0 as usize)
                    .and_then(|obj| obj.properties.get("body"))
                    .cloned()
                    .unwrap_or(Value::Undefined);
                let has_body = matches!(&chunk, Value::Str(s) if !s.is_empty());
                // Admit the terminal phase before exposing data callbacks so a
                // memory refusal cannot publish a response stream that never
                // reaches `end`.
                self.schedule_stream_emission(object_id, StreamEventPhase::End, label.clone())?;
                if has_body && let Some(module) = module {
                    let _ = self.emit_event_listener_records(
                        module,
                        object_id,
                        "data",
                        vec![chunk],
                        label,
                    )?;
                }
                Ok(())
            }
            StreamEventPhase::End => {
                if let Some(module) = module {
                    let _ = self.emit_event_listener_records(
                        module,
                        object_id,
                        "end",
                        Vec::new(),
                        label,
                    )?;
                }
                // The response stream is fully consumed; drop its listener table so
                // the side-table stays bounded to in-flight streams.
                self.clear_event_listeners(object_id, None);
                Ok(())
            }
        }
    }

    /// bd-3894s slice (2d): build the `Error`-shaped value delivered to a
    /// `req.on('error', …)` listener when the deferred egress is denied or fails. Node
    /// passes an `Error`; we model it as an object carrying `message` and `code` so a
    /// listener can branch on `err.code`. The denial itself is already recorded as a
    /// signed DENIED `EffectReceipt`; this only surfaces it to the request's `'error'`
    /// event (the egress never reached the network).
    pub(super) fn build_request_error_value(&mut self) -> Result<Value, InterpreterError> {
        let err_id = self.alloc_object_with_properties(&[
            ("message", Value::str("net request failed")),
            ("code", Value::str("ERR_NETWORK")),
        ])?;
        Ok(Value::Object(err_id))
    }

    /// bd-1xl17.d / bd-rul7k: map the raw bytes a successful `fs:read` host effect
    /// produced to the JS value `readFileSync` would return. Without an encoding
    /// Node yields a `Buffer` (modeled here as a `Uint8Array`-backed value); with
    /// a recognized character encoding it yields the decoded string. The
    /// bd-rul7k: resolve the character encoding for an `fs:read` (`readFileSync`)
    /// from its optional second argument. Node accepts either a bare encoding
    /// string (`readFileSync(p, 'utf8')`) or an options object
    /// (`readFileSync(p, { encoding: 'utf8' })`). Returns the encoding string when
    /// present; an options object whose own `encoding` property is absent or
    /// non-string (e.g. `{ encoding: null }`) yields `None`, matching Node's
    /// Buffer result, as does a missing second argument. Only the object's own
    /// `encoding` property is consulted (no prototype walk), mirroring how Node
    /// reads the options bag.
    pub(super) fn resolve_fs_read_encoding(&self, second_arg: Option<&Value>) -> Option<String> {
        match second_arg? {
            Value::Str(s) => Some(s.to_string()),
            Value::Object(id) => match self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.properties.get("encoding").cloned())
            {
                Some(Value::Str(s)) => Some(s.to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    /// bd-3894s slice (2): resolve the request `method`, `headers`, and `body`
    /// from a `fetch(url, init)` / `http.request(url, options)` options object so
    /// the network host effect (and its signed receipt) reflect the REAL request
    /// rather than a hardcoded bodyless GET. The options object is the call's
    /// SECOND argument, forwarded by the http/fetch lowering (`net:request`
    /// arg[1]) and retained here as `second_arg`.
    ///
    /// Node-ish parity for the recognized fields:
    /// - `method`: trimmed + upper-cased; defaults to `"GET"` when absent/blank.
    /// - `headers`: a nested `{ name: value }` object; values are coerced to
    ///   strings and emitted in ECMAScript own-key order so the recorded effect
    ///   is byte-reproducible and matches ordinary object enumeration. Non-stringable header
    ///   values are skipped rather than mis-framed.
    /// - `body`: a string (or stringified integer) becomes the request body;
    ///   anything else — including the `http.request` writable-stream form that
    ///   carries the body via `req.write`/`req.end` (a follow-up slice) — yields
    ///   no body here.
    ///
    /// A non-object second arg (the callback closure in `http.get(url, cb)`,
    /// `undefined`, etc.) yields the bodyless-GET defaults, leaving the existing
    /// slice-1 GET egress unchanged.
    pub(super) fn resolve_net_request_options(
        &self,
        second_arg: Option<&Value>,
    ) -> (String, Vec<(String, String)>, Option<Vec<u8>>) {
        let defaults = || ("GET".to_string(), Vec::new(), None);
        let Some(Value::Object(id)) = second_arg else {
            return defaults();
        };
        let Some(options) = self.heap.get(id.0 as usize) else {
            return defaults();
        };
        let method = match options.properties.get("method") {
            Some(Value::Str(s)) if !s.trim().is_empty() => s.trim().to_ascii_uppercase(),
            _ => "GET".to_string(),
        };
        let headers = match options.properties.get("headers") {
            Some(Value::Object(hid)) => self
                .heap
                .get(hid.0 as usize)
                .map(|h| {
                    h.properties
                        .iter()
                        .filter_map(|(name, value)| {
                            Self::net_header_value(value).map(|v| (name.clone(), v))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let body = match options.properties.get("body") {
            Some(Value::Str(s)) => Some(s.as_bytes().to_vec()),
            Some(Value::Int(i)) => Some(i.to_string().into_bytes()),
            _ => None,
        };
        (method, headers, body)
    }

    /// bd-3894s slice (2): coerce a single header value to its wire string. A
    /// string is emitted verbatim and an integer is stringified; anything else
    /// (object/closure/etc.) is skipped rather than mis-framed as a header value.
    pub(super) fn net_header_value(value: &Value) -> Option<String> {
        match value {
            Value::Str(s) => Some(s.to_string()),
            Value::Int(i) => Some(i.to_string()),
            _ => None,
        }
    }

    pub(super) fn client_request_chunk_len(chunk: &Value) -> Option<usize> {
        match chunk {
            Value::Str(value) => Some(value.len()),
            Value::Int(value) => Some(value.to_string().len()),
            _ => None,
        }
    }

    /// Append one supported legacy `ClientRequest` body chunk as a single
    /// bounded memory-and-provenance transaction. A refusal leaves the body,
    /// mutation label, and running memory total unchanged.
    pub(super) fn append_legacy_client_request_body(
        &mut self,
        request_id: ObjectId,
        chunk: &Value,
        chunk_label: &Label,
    ) -> Result<bool, InterpreterError> {
        let Some(chunk_len) = Self::client_request_chunk_len(chunk) else {
            return Ok(false);
        };
        if chunk_len == 0 {
            return Ok(false);
        }

        let request_index = request_id.0 as usize;
        let previous_body = match self
            .heap
            .get(request_index)
            .and_then(|request| request.properties.get("__body"))
        {
            Some(Value::Str(body)) => body.clone(),
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "string ClientRequest body state".to_string(),
                    got: value.type_name().to_string(),
                });
            }
            None => return Err(InterpreterError::ObjectNotFound { id: request_id.0 }),
        };
        let next_len = previous_body.len().checked_add(chunk_len).ok_or_else(|| {
            InterpreterError::RangeError {
                message: format!("HTTP request body exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            }
        })?;
        if next_len > MAX_HTTP_BODY_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP request body exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            });
        }

        let previous_label = self
            .object_mutation_labels
            .get(&request_id)
            .cloned()
            .unwrap_or(Label::Public);
        let temporary_bytes = u64::try_from(next_len)
            .unwrap_or(u64::MAX)
            .saturating_mul(2)
            .saturating_add(Self::estimate_label_bytes(&previous_label).saturating_mul(2))
            .saturating_add(Self::estimate_label_bytes(chunk_label).saturating_mul(2))
            .saturating_add(64 * 1024);
        self.check_temporary_memory_budget(temporary_bytes)?;

        let next_label = previous_label.join(chunk_label);
        let mut next_body = String::with_capacity(next_len);
        next_body.push_str(previous_body.as_utf8_projection());
        match chunk {
            Value::Str(value) => next_body.push_str(value.as_utf8_projection()),
            Value::Int(value) => next_body.push_str(&value.to_string()),
            // This is unreachable after `client_request_chunk_len`, but retaining
            // the ordinary no-op behavior here keeps a future shape extension
            // from turning a guest value into a production panic.
            _ => return Ok(false),
        }
        let next_body = Value::str(next_body);
        let previous_body_value = Value::Str(previous_body);
        let previous_property_bytes =
            Self::estimate_property_entry_bytes("__body", &previous_body_value);
        let next_property_bytes = Self::estimate_property_entry_bytes("__body", &next_body);
        let previous_label_bytes = if previous_label == Label::Public {
            0
        } else {
            Self::estimate_object_mutation_label_entry_bytes(&previous_label)
        };
        let next_label_bytes = if next_label == Label::Public {
            0
        } else {
            Self::estimate_object_mutation_label_entry_bytes(&next_label)
        };
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_property_bytes)
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_property_bytes)
            .saturating_add(next_label_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }

        self.mutate_heap(|heap| {
            heap[request_index]
                .properties
                .insert("__body".to_string(), next_body);
        });
        if next_label == Label::Public {
            self.object_mutation_labels.remove(&request_id);
        } else {
            self.object_mutation_labels.insert(request_id, next_label);
        }
        self.estimated_memory_bytes = requested_bytes;
        self.gc_write_barrier(request_id);
        Ok(true)
    }

    /// bd-rul7k item 3: true when `encoding` is a Node `BufferEncoding` recognized
    /// by [`Self::decode_fs_read_result`] (case-insensitive). Kept in lock-step
    /// with the decode arms below — every recognized arm there must be listed here.
    /// Used by `dispatch_host_io_hostcall` to reject an unknown `fs:read` encoding
    /// with a JS-catchable `TypeError` BEFORE the read runs, matching Node.
    pub(super) fn is_recognized_fs_encoding(encoding: &str) -> bool {
        matches!(
            encoding.to_ascii_lowercase().as_str(),
            "utf8"
                | "utf-8"
                | "utf16le"
                | "utf-16le"
                | "ucs2"
                | "ucs-2"
                | "latin1"
                | "binary"
                | "ascii"
                | "hex"
                | "base64"
                | "base64url"
        )
    }

    /// Node `BufferEncoding` values handled here: utf8/utf-8,
    /// utf16le/utf-16le/ucs2/ucs-2, latin1/binary, ascii, hex, base64, and
    /// base64url. The bare-string and options-object encoding forms are both
    /// resolved up front by [`Self::resolve_fs_read_encoding`] and validated by
    /// [`Self::is_recognized_fs_encoding`] (an unknown encoding throws `TypeError`
    /// at dispatch before this is reached, bd-rul7k item 3). A `None` encoding (no
    /// arg, or `{ encoding: null }`) yields the Buffer shape, which requires the
    /// `HeapAllocate` capability.
    pub(super) fn decode_fs_read_result(
        &mut self,
        bytes: &[u8],
        encoding: Option<&str>,
    ) -> Result<Value, InterpreterError> {
        use base64::Engine as _;
        let decoded: Option<String> = match encoding.map(str::to_ascii_lowercase).as_deref() {
            Some("utf8" | "utf-8") => Some(String::from_utf8_lossy(bytes).into_owned()),
            Some("utf16le" | "utf-16le" | "ucs2" | "ucs-2") => {
                // UTF-16LE: little-endian u16 code units. A trailing odd byte is
                // dropped by chunks_exact (Node would surface a replacement char);
                // the common even-length case is faithful.
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&units))
            }
            Some("latin1" | "binary") => Some(bytes.iter().map(|&b| char::from(b)).collect()),
            Some("ascii") => Some(bytes.iter().map(|&b| char::from(b & 0x7f)).collect()),
            Some("hex") => Some(hex::encode(bytes)),
            // base64/base64url ENCODE the raw bytes into an ASCII string (like
            // `hex`); they do not decode. `readFileSync(p, 'base64')` mirrors
            // `Buffer.from(bytes).toString('base64')`. Node's `base64` uses the
            // standard alphabet WITH padding; `base64url` uses the URL-safe
            // alphabet with NO padding.
            Some("base64") => Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            Some("base64url") => {
                Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
            }
            _ => None,
        };
        if let Some(text) = decoded {
            return Ok(Value::str(text));
        }
        let view = self.alloc_buffer_from_bytes(bytes)?;
        Ok(Value::Object(view))
    }

    /// bd-3894s slice (4): parse the raw HTTP/1.1 response bytes a `net:request`
    /// round trip read back into the JS response object `http.get`/`fetch` returns.
    /// The shape is a pragmatic blend of Node's `IncomingMessage` and the WHATWG
    /// `Response`: `{ status, statusText, ok, headers, body }`, where:
    /// - `status` is the final numeric status code, after informational replies,
    /// - `statusText` is the reason phrase,
    /// - `ok` is `true` for a 2xx status (WHATWG `Response.ok` semantics),
    /// - `headers` is a plain object of lower-cased header name -> value (the
    ///   lower-casing matches `fetch` `Headers` / Node's `res.headers`; the last
    ///   value wins on a duplicate name, which is `alloc_object_with_properties`'s
    ///   natural overwrite behavior),
    /// - `body` is the transfer-decoded body as a UTF-8 (lossy) string. Chunk
    ///   boundaries are removed before UTF-8 decoding, so a multi-byte scalar
    ///   split between chunks is not replaced by multiple U+FFFD characters.
    ///
    /// The live reader and recorded/custom-provider outcome parser share one
    /// framing implementation. Invalid or incomplete outcomes produce no
    /// response object, just as provider I/O failure does; no status-0 response
    /// is fabricated. The raw effect outcome remains available for diagnosis.
    pub(super) fn build_net_response_value(
        &mut self,
        raw: &[u8],
        method: &str,
    ) -> Result<Value, InterpreterError> {
        use frankenengine_extension_host::host_io::{
            SANDBOXED_HOST_IO_MAX_BYTES, parse_http_response,
        };

        let raw_bytes = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if raw_bytes > SANDBOXED_HOST_IO_MAX_BYTES {
            return Ok(Value::Undefined);
        }
        let parsed = match parse_http_response(raw, method) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(Value::Undefined),
        };
        // Parsing above borrows input and allocates no payload. Admit the
        // temporary decoded bytes, worst-case lossy UTF-8 expansion, strings
        // and field vectors before constructing the guest-visible objects.
        let field_vectors = parsed
            .header_count()
            .saturating_mul(
                std::mem::size_of::<(String, Value)>()
                    .saturating_add(std::mem::size_of::<(&str, Value)>()),
            )
            .saturating_mul(2);
        self.check_temporary_memory_budget(
            raw_bytes
                .saturating_mul(8)
                .saturating_add(u64::try_from(field_vectors).unwrap_or(u64::MAX)),
        )?;
        let body = parsed
            .body_bytes()
            .map_err(|error| InterpreterError::InternalError {
                details: format!("validated HTTP response decoding failed: {error}"),
            })?;
        let status = i64::from(parsed.status);
        let status_text = String::from_utf8_lossy(parsed.status_text)
            .trim()
            .to_string();

        // Collect header name/value pairs (lower-cased names, trimmed values).
        // Hold the owned strings so the `&str` keys handed to
        // `alloc_object_with_properties` stay valid for the call.
        let header_pairs: Vec<(String, Value)> = parsed
            .headers()
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name).to_ascii_lowercase(),
                    Value::str(String::from_utf8_lossy(value).as_ref()),
                )
            })
            .collect();
        let header_props: Vec<(&str, Value)> = header_pairs
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect();
        let headers_id = self.alloc_object_with_properties(&header_props)?;

        let body_str = String::from_utf8_lossy(body.as_ref()).into_owned();
        let ok = (200..300).contains(&status);
        // bd-3894s slice (2d): tag the response `IncomingMessage` so `res.on('data'|
        // 'end'|'error', …)` resolves to the shared `EventEmitter.prototype.on` via
        // the `__type` member-access path. The own data properties below
        // (`status`/`body`/`headers`/`ok`/`statusText`) still win property resolution,
        // so the tag only adds the readable-stream `.on` method — direct reads like
        // `res.status` / `res.body` are unchanged.
        let response_id = self.alloc_branded_object(
            "IncomingMessage",
            &[
                ("status", Value::Int(status)),
                ("statusText", Value::str(status_text.as_str())),
                ("ok", Value::Bool(ok)),
                ("headers", Value::Object(headers_id)),
                ("body", Value::str(body_str.as_str())),
            ],
        )?;
        Ok(Value::Object(response_id))
    }

    // ---------------------------------------------------------------------------
    // ExecutionSeed management for PERF-H2.2
    // ---------------------------------------------------------------------------

    pub(super) fn execution_seed_registry_envelope_bytes() -> u64 {
        u64::try_from(
            std::mem::size_of::<ExecutionSeedShared>()
                .saturating_add(2usize.saturating_mul(std::mem::size_of::<usize>())),
        )
        .unwrap_or(u64::MAX)
    }

    pub(super) fn pending_execution_seed_entry_bytes() -> u64 {
        Self::execution_seed_registry_envelope_bytes().saturating_add(
            u64::try_from(std::mem::size_of::<std::rc::Weak<ExecutionSeedShared>>())
                .unwrap_or(u64::MAX),
        )
    }

    #[inline]
    pub(super) fn live_execution_seed_reserved_bytes(&self) -> u64 {
        if self
            .execution_seed_reservation_ledger
            .accounting_fault
            .get()
        {
            u64::MAX
        } else {
            self.execution_seed_reservation_ledger
                .live_reserved_bytes
                .get()
        }
    }

    #[inline]
    pub(super) fn total_memory_bytes_from_base(&self, base_bytes: u64) -> u64 {
        base_bytes
            .saturating_add(self.live_execution_seed_reserved_bytes())
            .saturating_add(self.simple_callback_temporary_bytes)
            .saturating_add(self.json_parse_temporary_bytes)
            .saturating_add(self.regexp_temporary_bytes.get())
            .saturating_add(self.argument_overflow_bytes)
    }

    pub(super) fn prune_dead_pending_execution_seeds(&mut self) {
        let previous_len = self.pending_lazy_seeds.len();
        self.pending_lazy_seeds
            .retain(|seed| seed.strong_count() != 0);
        let removed = previous_len.saturating_sub(self.pending_lazy_seeds.len());
        let released_bytes = u64::try_from(removed)
            .unwrap_or(u64::MAX)
            .saturating_mul(Self::pending_execution_seed_entry_bytes());
        match self
            .execution_seed_reservation_ledger
            .live_reserved_bytes
            .get()
            .checked_sub(released_bytes)
        {
            Some(next) => self
                .execution_seed_reservation_ledger
                .live_reserved_bytes
                .set(next),
            None => {
                self.execution_seed_reservation_ledger
                    .accounting_fault
                    .set(true);
                self.execution_seed_reservation_ledger
                    .live_reserved_bytes
                    .set(u64::MAX);
            }
        }
    }

    pub(super) fn capture_execution_seed(
        &mut self,
    ) -> Result<ExecutionSeedHandle, InterpreterError> {
        self.prune_dead_pending_execution_seeds();
        if self
            .execution_seed_reservation_ledger
            .accounting_fault
            .get()
        {
            return Err(InterpreterError::InternalError {
                details: "execution-seed reservation ledger is inconsistent".to_string(),
            });
        }

        let snapshot_bytes = self.estimate_execution_seed_snapshot_bytes();
        let reserved_bytes = snapshot_bytes
            .saturating_add(u64::try_from(std::mem::size_of::<ExecutionSeed>()).unwrap_or(u64::MAX))
            .saturating_add(Self::pending_execution_seed_entry_bytes());
        let requested_base_bytes = self.estimated_memory_bytes;
        if self.memory_request_exceeds_budget(
            requested_base_bytes.saturating_add(reserved_bytes),
            self.config.max_total_memory_bytes,
        ) {
            return Err(self.memory_budget_error(
                requested_base_bytes.saturating_add(reserved_bytes),
                self.heap_object_count_u32(),
            ));
        }

        let Some(next_reserved_bytes) = self
            .execution_seed_reservation_ledger
            .live_reserved_bytes
            .get()
            .checked_add(reserved_bytes)
        else {
            self.execution_seed_reservation_ledger
                .accounting_fault
                .set(true);
            self.execution_seed_reservation_ledger
                .live_reserved_bytes
                .set(u64::MAX);
            return Err(InterpreterError::InternalError {
                details: "execution-seed reservation ledger overflowed".to_string(),
            });
        };

        let shared = std::rc::Rc::new(ExecutionSeedShared {
            state: std::cell::RefCell::new(Box::new(ExecutionSeed::Lazy {
                epoch: self.seed_epoch,
                max_regs: self.config.max_registers,
            })),
            snapshot_bytes,
            reserved_bytes: std::cell::Cell::new(reserved_bytes),
            registered: std::cell::Cell::new(true),
            reservation_ledger: std::rc::Rc::downgrade(&self.execution_seed_reservation_ledger),
        });
        self.execution_seed_reservation_ledger
            .live_reserved_bytes
            .set(next_reserved_bytes);
        self.pending_lazy_seeds
            .push(std::rc::Rc::downgrade(&shared));
        Ok(ExecutionSeedHandle(shared))
    }

    // ---- THE ONLY WAY to mutate a seed-surface field ----
    pub(crate) fn mutate_registers<R>(&mut self, f: impl FnOnce(&mut Vec<Value>) -> R) -> R {
        self.before_seed_surface_write();
        self.registers_value_bytes.set(None);
        let result = f(&mut self.registers.value);
        self.note_registers_written_to(self.registers.value.len());
        result
    }

    /// [`Self::mutate_registers`] for a write whose effect on
    /// [`Self::registers_memory_bytes`] the caller has computed: values of
    /// `released` bytes leave the file and values of `added` bytes enter it
    /// (growing it with `Undefined` adds none). A cached sum moves by that
    /// delta instead of being dropped, so the next isolated-callback or
    /// inline-call preflight does not walk the whole file.
    pub(super) fn mutate_registers_by_bytes<R>(
        &mut self,
        released: u64,
        added: u64,
        f: impl FnOnce(&mut Vec<Value>) -> R,
    ) -> R {
        let cached = self.registers_value_bytes.get();
        self.before_seed_surface_write();
        let result = f(&mut self.registers.value);
        self.registers_value_bytes
            .set(cached.map(|bytes| bytes.saturating_sub(released).saturating_add(added)));
        result
    }

    /// Install a whole register file whose [`Self::registers_memory_bytes`]
    /// is `value_bytes` when the caller knows it (a fresh file of
    /// `Undefined` is 0; a restored snapshot carries its own), else `None`.
    pub(super) fn install_register_file(
        &mut self,
        registers: Vec<Value>,
        value_bytes: Option<u64>,
    ) {
        self.note_registers_written_to(registers.len());
        self.registers = SeedTrackedField::new(registers);
        self.registers_value_bytes.set(value_bytes);
    }

    /// A write to physical register `actual_reg` (bd-9vouw.499).
    #[inline]
    pub(super) fn note_register_written(&mut self, actual_reg: usize) {
        if actual_reg >= self.register_dirty_end {
            self.register_dirty_end = actual_reg + 1;
        }
    }

    /// Writes to physical registers below `end` (bd-9vouw.499).
    #[inline]
    pub(super) fn note_registers_written_to(&mut self, end: usize) {
        self.register_dirty_end = self.register_dirty_end.max(end);
    }

    pub(crate) fn mutate_heap<R>(&mut self, f: impl FnOnce(&mut Heap) -> R) -> R {
        self.before_seed_surface_write();
        f(&mut self.heap.value)
    }

    pub(crate) fn mutate_function_prototypes<R>(
        &mut self,
        f: impl FnOnce(&mut BTreeMap<(ContentHash, u32), ObjectId>) -> R,
    ) -> R {
        self.before_seed_surface_write();
        f(&mut self.function_prototypes.value)
    }

    pub(crate) fn mutate_builtin_prototypes<R>(
        &mut self,
        f: impl FnOnce(&mut BTreeMap<String, ObjectId>) -> R,
    ) -> R {
        self.before_seed_surface_write();
        f(&mut self.builtin_prototypes.value)
    }

    pub(super) fn mutate_symbol_state<R>(
        &mut self,
        f: impl FnOnce(&mut RuntimeSymbolState) -> R,
    ) -> R {
        self.before_seed_surface_write();
        f(&mut self.symbol_state.value)
    }

    #[inline]
    pub(super) fn before_seed_surface_write(&mut self) {
        self.last_post_run_epoch = None;
        // Every register write comes through here, and almost always with no
        // lazy seed pending (bd-9vouw.124: 7.8% of an arithmetic loop).
        if !self.pending_lazy_seeds.is_empty() {
            self.materialize_pending_lazy_seeds_with_current_state();
        }
        self.seed_epoch = self.seed_epoch.wrapping_add(1);
    }

    pub(super) fn materialize_pending_lazy_seeds_with_current_state(&mut self) {
        let pending = std::mem::take(&mut self.pending_lazy_seeds);
        for weak in pending {
            let Some(strong) = weak.upgrade() else {
                let entry_bytes = Self::pending_execution_seed_entry_bytes();
                match self
                    .execution_seed_reservation_ledger
                    .live_reserved_bytes
                    .get()
                    .checked_sub(entry_bytes)
                {
                    Some(next) => self
                        .execution_seed_reservation_ledger
                        .live_reserved_bytes
                        .set(next),
                    None => {
                        self.execution_seed_reservation_ledger
                            .accounting_fault
                            .set(true);
                        self.execution_seed_reservation_ledger
                            .live_reserved_bytes
                            .set(u64::MAX);
                    }
                }
                continue;
            };
            strong.registered.set(false);
            let weak_bytes =
                u64::try_from(std::mem::size_of::<std::rc::Weak<ExecutionSeedShared>>())
                    .unwrap_or(u64::MAX);
            strong
                .reserved_bytes
                .set(strong.reserved_bytes.get().saturating_sub(weak_bytes));
            let next_live_reserved = self
                .execution_seed_reservation_ledger
                .live_reserved_bytes
                .get()
                .checked_sub(weak_bytes);
            match next_live_reserved {
                Some(next) => self
                    .execution_seed_reservation_ledger
                    .live_reserved_bytes
                    .set(next),
                None => {
                    self.execution_seed_reservation_ledger
                        .accounting_fault
                        .set(true);
                    self.execution_seed_reservation_ledger
                        .live_reserved_bytes
                        .set(u64::MAX);
                }
            }

            let mut seed = strong.state.borrow_mut();
            if let ExecutionSeed::Lazy { .. } = **seed {
                **seed = ExecutionSeed::Materialized {
                    registers: self.registers.value.clone(),
                    heap: self.heap.value.clone(),
                    function_prototypes: self.function_prototypes.value.clone(),
                    builtin_prototypes: self.builtin_prototypes.value.clone(),
                    symbol_state: self.symbol_state.value.clone(),
                    weakmap_storage: self.weakmap_storage.clone(),
                    weak_collection_labels: self
                        .weakmap_storage
                        .keys()
                        .filter_map(|owner| {
                            self.object_mutation_labels
                                .get(owner)
                                .map(|label| (*owner, label.clone()))
                        })
                        .collect(),
                };
            }
        }
    }

    pub(super) fn reset_execution_state_from_seed(
        &mut self,
        seed: &ExecutionSeedHandle,
    ) -> Result<(), InterpreterError> {
        if !seed.is_owned_by(&self.execution_seed_reservation_ledger) {
            return Err(InterpreterError::InternalError {
                details: "execution seed belongs to a different interpreter core".to_string(),
            });
        }

        let previous_seed_surface_bytes = self
            .registers_memory_bytes()
            .saturating_add(self.heap_memory_bytes())
            .saturating_add(self.symbol_state_memory_bytes())
            .saturating_add(self.weakmap_storage_memory_bytes())
            .saturating_add(self.weak_collection_labels_memory_bytes());
        let next_seed_surface_bytes = {
            let snapshot = seed.0.state.borrow();
            match &**snapshot {
                ExecutionSeed::Lazy { epoch, .. } if *epoch == self.seed_epoch => None,
                ExecutionSeed::Lazy { epoch, .. } => {
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "lazy seed survived a write (seed_epoch={}, core_epoch={}); \
                             the before_seed_surface_write chokepoint missed a write site",
                            epoch, self.seed_epoch
                        ),
                    });
                }
                ExecutionSeed::Materialized {
                    registers,
                    heap,
                    symbol_state,
                    weakmap_storage,
                    weak_collection_labels,
                    ..
                } => {
                    self.check_temporary_memory_budget(seed.0.snapshot_bytes)?;
                    symbol_state
                        .validate()
                        .map_err(|details| InterpreterError::InternalError { details })?;
                    for value in registers {
                        validate_symbol_value(symbol_state, value)
                            .map_err(|details| InterpreterError::InternalError { details })?;
                    }
                    for object in heap.iter() {
                        validate_heap_symbol_references(symbol_state, object)
                            .map_err(|details| InterpreterError::InternalError { details })?;
                    }
                    for storage in weakmap_storage.values() {
                        for value in storage
                            .entries
                            .values()
                            .chain(storage.symbol_entries.values())
                        {
                            validate_symbol_value(symbol_state, value)
                                .map_err(|details| InterpreterError::InternalError { details })?;
                        }
                        for symbol in storage.symbol_entries.keys() {
                            validate_symbol_value(symbol_state, &Value::Symbol(SymbolId(*symbol)))
                                .map_err(|details| InterpreterError::InternalError { details })?;
                        }
                    }
                    Some(Self::estimate_seed_surface_active_bytes(
                        registers,
                        heap,
                        symbol_state,
                        weakmap_storage,
                        weak_collection_labels,
                    ))
                }
            }
        };

        if let Some(next_seed_surface_bytes) = next_seed_surface_bytes {
            let projected_base_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_seed_surface_bytes)
                .saturating_add(next_seed_surface_bytes);
            if self.memory_request_exceeds_budget(
                projected_base_bytes,
                self.config.max_total_memory_bytes,
            ) {
                return Err(
                    self.memory_budget_error(projected_base_bytes, self.heap_object_count_u32())
                );
            }
        }

        // Execution-local stream state is keyed by heap ObjectId and must
        // disappear at the same authoritative boundary that restores the
        // seeded heap. Otherwise a reused id can inherit callbacks, buffered
        // chunks, pumps, listeners, or static `events.once` links from the
        // preceding execution.
        self.clear_url_execution_state();
        self.clear_cluster_execution_state();
        self.clear_crypto_execution_state();
        self.clear_stream_pipeline_execution_state()?;
        self.clear_readable_execution_state();
        self.clear_writable_execution_state();
        self.clear_http_execution_state();
        self.clear_loopback_execution_state();
        self.clear_residual_event_state()?;
        self.clear_event_once_wrapper_state();
        self.clear_object_mutation_labels();
        if let Some(context) = self.active_inline_callback_context_label.take() {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_label_bytes(&context));
        }
        let restore = if next_seed_surface_bytes.is_some() {
            let snapshot = seed.0.state.borrow();
            match &**snapshot {
                ExecutionSeed::Materialized {
                    registers,
                    heap,
                    function_prototypes,
                    builtin_prototypes,
                    symbol_state,
                    weakmap_storage,
                    weak_collection_labels,
                } => Some((
                    registers.clone(),
                    heap.clone(),
                    function_prototypes.clone(),
                    builtin_prototypes.clone(),
                    symbol_state.clone(),
                    weakmap_storage.clone(),
                    weak_collection_labels.clone(),
                )),
                ExecutionSeed::Lazy { .. } => {
                    return Err(InterpreterError::InternalError {
                        details: "materialized execution seed reverted to lazy state".to_string(),
                    });
                }
            }
        } else {
            None
        };

        if let Some((
            registers,
            heap,
            function_prototypes,
            builtin_prototypes,
            symbol_state,
            weakmap_storage,
            weak_collection_labels,
        )) = restore
        {
            self.before_seed_surface_write();
            self.note_registers_written_to(registers.len());
            self.registers.value = registers;
            self.registers_value_bytes.set(None);
            self.heap.value = heap;
            self.function_prototypes.value = function_prototypes;
            // A restored map may hold built-in backing objects, and a
            // restored heap deleted virtual properties.
            self.builtin_function_backings = true;
            self.virtual_property_deletions = true;
            self.builtin_prototypes.value = builtin_prototypes;
            self.symbol_state.value = symbol_state;
            self.weakmap_storage = weakmap_storage;
            self.object_mutation_labels = weak_collection_labels;
            let committed_seed_surface_bytes = next_seed_surface_bytes
                .expect("materialized execution seed has a projected active size");
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_seed_surface_bytes)
                .saturating_add(committed_seed_surface_bytes);
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // IFC label management
    // ---------------------------------------------------------------------------

    /// Get the IFC label for a register.
    pub fn get_register_label(&self, reg: u32) -> Result<&Label, InterpreterError> {
        if reg >= self.config.max_registers {
            return self.overflow_argument(reg).map(|(_, label)| label);
        }
        let actual_reg = self.register_base + reg as usize;
        // The error is built only on the out-of-bounds path: this runs on
        // every register read.
        match self.register_labels.get(actual_reg) {
            Some(label) => Ok(label),
            None => Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            }),
        }
    }

    /// Set the IFC label for a register.
    pub fn set_register_label(&mut self, reg: u32, label: Label) -> Result<(), InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        self.note_register_written(actual_reg);
        let Some(previous_label) = self.register_labels.get(actual_reg) else {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        };
        let previous_label_bytes = Self::estimate_label_bytes(previous_label);
        let context_dominates = self
            .active_execution_context_label()
            .is_some_and(|context| context > &label);
        let next_label_bytes = if context_dominates {
            self.active_execution_context_label()
                .map(Self::estimate_label_bytes)
                .unwrap_or(0)
        } else {
            Self::estimate_label_bytes(&label)
        };
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }

        // Refusal above is atomic. On success, release the old attacker-sized
        // name before cloning a dominant callback context so the physical peak
        // never contains both the dead destination name and its replacement.
        let previous_label =
            std::mem::replace(&mut self.register_labels[actual_reg], Label::Public);
        drop(previous_label);
        let next_label = if context_dominates {
            drop(label);
            self.active_execution_context_label()
                .expect("dominant inline callback context was checked")
                .clone()
        } else {
            label
        };
        let is_public = matches!(&next_label, Label::Public);
        self.register_labels[actual_reg] = next_label;
        if is_public {
            self.seeded_register_labels.remove(&actual_reg);
        } else {
            self.seeded_register_labels.insert(actual_reg);
            self.all_register_labels_public = false;
        }
        self.adjust_register_labels_bytes(previous_label_bytes, next_label_bytes);
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    #[inline]
    pub(super) fn seeded_register_label(&self, reg: u32) -> Option<&Label> {
        if self.seeded_register_labels.is_empty() {
            return None;
        }
        let actual_reg = self.register_base.checked_add(reg as usize)?;
        if self.seeded_register_labels.contains(&actual_reg) {
            self.register_labels.get(actual_reg)
        } else {
            None
        }
    }

    pub(super) fn array_buffer_id_for_object(&self, object_id: ObjectId) -> Option<ObjectId> {
        let object = self.heap.get(object_id.0 as usize)?;
        if object.array_buffer.is_some() {
            Some(object_id)
        } else if let Some(view) = &object.typed_array {
            Some(view.buffer)
        } else {
            object.data_view.as_ref().map(|view| view.buffer)
        }
    }

    pub(super) fn binary_storage_label_ref(&self, object_id: ObjectId) -> Option<&Label> {
        self.array_buffer_id_for_object(object_id)
            .and_then(|buffer_id| self.heap.get(buffer_id.0 as usize))
            .and_then(|object| object.array_buffer.as_deref())
            .map(|backing| &backing.label)
    }

    pub(super) fn binary_storage_label(&self, object_id: ObjectId) -> Label {
        self.binary_storage_label_ref(object_id)
            .cloned()
            .unwrap_or(Label::Public)
    }

    pub(super) fn url_state_label_ref(&self, object_id: ObjectId) -> Option<&Label> {
        self.url_objects
            .get(&object_id)
            .map(|state| &state.lifecycle_label)
            .or_else(|| {
                self.url_search_params
                    .get(&object_id)
                    .map(|state| &state.lifecycle_label)
            })
    }

    pub(super) fn url_state_label(&self, object_id: ObjectId) -> Label {
        self.url_state_label_ref(object_id)
            .cloned()
            .unwrap_or(Label::Public)
    }

    pub(super) fn cluster_state_label_ref(&self, object_id: ObjectId) -> Option<&Label> {
        self.cluster_facades
            .get(&object_id)
            .map(|state| &state.lifecycle_label)
            .or_else(|| {
                self.cluster_facades
                    .values()
                    .find(|state| state.settings == object_id)
                    .map(|state| &state.lifecycle_label)
            })
    }

    pub(super) fn cluster_state_label(&self, object_id: ObjectId) -> Label {
        self.cluster_state_label_ref(object_id)
            .cloned()
            .unwrap_or(Label::Public)
    }

    pub(super) fn stream_state_label_ref(&self, object_id: ObjectId) -> Option<&Label> {
        // Most programs own no stream, server or socket: skip the chain walk
        // that every property access would otherwise pay.
        if self.readable_from_streams.is_empty()
            && self.readable_terminal_states.is_empty()
            && self.writable_streams.is_empty()
            && self.writable_terminal_states.is_empty()
            && self.loopback_servers.is_empty()
            && self.loopback_sockets.is_empty()
        {
            return None;
        }
        let mut label: Option<&Label> = None;
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = ChainGuard::default();
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                break;
            }
            if let Some(state) = self.readable_from_streams.get(&id) {
                let candidate = &state.lifecycle_label;
                if label.is_none_or(|winner| candidate > winner) {
                    label = Some(candidate);
                }
            }
            if let Some(state) = self.readable_terminal_states.get(&id) {
                let candidate = &state.lifecycle_label;
                if label.is_none_or(|winner| candidate > winner) {
                    label = Some(candidate);
                }
            }
            if let Some(state) = self.writable_streams.get(&id) {
                let candidate = &state.lifecycle_label;
                if label.is_none_or(|winner| candidate > winner) {
                    label = Some(candidate);
                }
            }
            if let Some(state) = self.writable_terminal_states.get(&id) {
                let candidate = &state.lifecycle_label;
                if label.is_none_or(|winner| candidate > winner) {
                    label = Some(candidate);
                }
            }
            if let Some(state) = self.loopback_servers.get(&id) {
                let candidate = &state.lifecycle_label;
                if label.is_none_or(|winner| candidate > winner) {
                    label = Some(candidate);
                }
            }
            if let Some(state) = self.loopback_sockets.get(&id) {
                let candidate = &state.lifecycle_label;
                if label.is_none_or(|winner| candidate > winner) {
                    label = Some(candidate);
                }
            }
            if let Some(object) = self.heap.get(id.0 as usize) {
                let active_proxy_target = object.brand() == Some(PROXY_TYPE_TAG)
                    && !matches!(
                        object.properties.get(PROXY_REVOKED_SLOT),
                        Some(Value::Bool(true))
                    );
                current = if active_proxy_target {
                    match object.properties.get(PROXY_TARGET_SLOT) {
                        Some(Value::Object(target)) => Some(*target),
                        _ => None,
                    }
                } else {
                    object.prototype
                };
            } else {
                current = None;
            }
            depth += 1;
        }
        label
    }

    pub(super) fn stream_state_label(&self, object_id: ObjectId) -> Label {
        self.stream_state_label_ref(object_id)
            .cloned()
            .unwrap_or(Label::Public)
    }

    pub(super) fn stream_state_label_with_temporary_budget(
        &self,
        object_id: ObjectId,
        additional_temporary_bytes: u64,
    ) -> Result<Label, InterpreterError> {
        let Some(label) = self.stream_state_label_ref(object_id) else {
            return Ok(Label::Public);
        };
        self.check_temporary_memory_budget(
            additional_temporary_bytes.saturating_add(Self::estimate_label_bytes(label)),
        )?;
        Ok(label.clone())
    }

    pub(super) fn join_binary_storage_label(
        &mut self,
        object_id: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let Some(buffer_id) = self.array_buffer_id_for_object(object_id) else {
            return Ok(());
        };
        let Some(previous_label) = self
            .heap
            .get(buffer_id.0 as usize)
            .and_then(|object| object.array_buffer.as_deref())
            .map(|backing| backing.label.clone())
        else {
            return Ok(());
        };
        let next_label = previous_label.join(label);
        self.apply_memory_component_delta(
            Self::estimate_label_bytes(&previous_label),
            Self::estimate_label_bytes(&next_label),
        )?;
        self.mutate_heap(|heap| {
            if let Some(backing) = heap
                .get_mut(buffer_id.0 as usize)
                .and_then(|object| object.array_buffer.as_deref_mut())
            {
                backing.label = next_label;
            }
        });
        Ok(())
    }

    pub(super) fn propagate_builtin_binary_mutation_label(
        &mut self,
        builtin: &BuiltinFunction,
        receiver: &Value,
        args: RegRange,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        use BuiltinFunctionKind as Kind;

        let mutates_receiver = matches!(
            builtin.kind,
            Kind::DataViewSetUint8
                | Kind::DataViewSetInt32
                | Kind::DataViewSetUint32
                | Kind::TypedArraySet
                | Kind::TypedArrayFill
                | Kind::TypedArrayCopyWithin
                | Kind::BufferWriteUInt8
                | Kind::BufferWriteUInt16Le
                | Kind::BufferWriteUInt16Be
                | Kind::BufferWriteInt32Le
                | Kind::BufferWriteInt32Be
                | Kind::BufferWriteUInt32Le
                | Kind::BufferWriteUInt32Be
                | Kind::BufferSwap16
                | Kind::BufferSwap32
                | Kind::BufferSwap64
        ) || (builtin.kind == Kind::DataViewMethod
            && builtin
                .module_specifier
                .0
                .as_deref()
                .is_some_and(|name| name.starts_with("set")))
            || (builtin.kind == Kind::BufferNumericMethod
                && builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .is_some_and(|name| name.starts_with("write")))
            || (builtin.kind == Kind::TypedArrayMethod
                && matches!(
                    builtin.module_specifier.0.as_deref(),
                    Some("reverse" | "sort")
                ));
        if mutates_receiver && let Value::Object(object_id) = receiver {
            self.join_binary_storage_label(*object_id, label)?;
        }

        if builtin.kind == Kind::BufferCopy
            && args.count > 0
            && let Value::Object(target_id) = self.read_reg(args.start)?
        {
            self.join_binary_storage_label(target_id, label)?;
        }

        if matches!(
            builtin.kind,
            Kind::UrlSearchParamsAppend
                | Kind::UrlSearchParamsSort
                | Kind::UrlSearchParamsDelete
                | Kind::UrlSearchParamsSet
        ) && let Value::Object(object_id) = receiver
        {
            self.join_url_search_params_lifecycle_label(*object_id, label)?;
        }
        if matches!(
            builtin.kind,
            Kind::ArrayPush
                | Kind::ArrayPop
                | Kind::ArrayShift
                | Kind::ArrayUnshift
                | Kind::ArrayReverse
                | Kind::ArraySort
                | Kind::ArraySplice
                | Kind::ArrayFill
                | Kind::ArrayCopyWithin
        ) && let Value::Object(object_id) = receiver
        {
            self.join_object_mutation_label(*object_id, label)?;
        }
        Ok(())
    }

    pub(super) fn append_spread_array_element(
        &mut self,
        array_id: ObjectId,
        next_index: &mut u32,
        value: Value,
    ) -> Result<(), InterpreterError> {
        // One IR spread instruction can consume an arbitrarily large iterable.
        // Charge each internal step so a large Buffer cannot bypass the public
        // instruction budget while its elements are streamed.
        if self.instructions_executed >= self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        if *next_index == u32::MAX {
            return Err(InterpreterError::RangeError {
                message: "array spread exceeds the maximum array length".to_string(),
            });
        }
        self.instructions_executed += 1;
        self.set_object_property(array_id, next_index.to_string(), value)?;
        *next_index += 1;
        Ok(())
    }

    /// Apply an IR array spread as one target-array/register-label transaction.
    ///
    /// Element writes and the final `length` update are individually fallible,
    /// while the IFC label replacement can retain an attacker-sized Custom
    /// name. Reserve an exact snapshot-plus-label peak before cloning either,
    /// run all heap writes under the remaining live-state ceiling, and restore
    /// the complete target object plus the incremental accumulator on refusal.
    /// Iterator advancement and guest `next()` side effects remain observable,
    /// matching ordinary iterator semantics; only the spread target and its
    /// label form this transaction.
    pub(super) fn spread_into_array_transaction(
        &mut self,
        module: &Ir3Module,
        array: u32,
        iterable: u32,
    ) -> Result<(), InterpreterError> {
        let array_value = self.read_reg(array)?;
        let iterable_value = self.read_reg(iterable)?;
        let Value::Object(array_id) = array_value else {
            return Ok(());
        };
        let heap_index = array_id.0 as usize;
        let actual_array_register = self.register_base + array as usize;

        let (array_snapshot, final_label, previous_label_bytes, transaction_temporary_bytes) = {
            let Some(array_object) = self.heap.get(heap_index) else {
                return Ok(());
            };
            let array_label = self.get_register_label(array)?;
            let mut label_winner = array_label;
            let iterable_label = self.get_register_label(iterable)?;
            if iterable_label > label_winner {
                label_winner = iterable_label;
            }
            if let Some(context_label) = self.active_inline_callback_context_label.as_ref()
                && context_label > label_winner
            {
                label_winner = context_label;
            }
            let label_changes = label_winner != array_label;
            let previous_label_bytes = Self::estimate_label_bytes(array_label);
            let transaction_temporary_bytes = Self::estimate_heap_object_bytes(array_object)
                .saturating_add(if label_changes {
                    Self::estimate_label_bytes(label_winner)
                } else {
                    0
                });
            self.check_temporary_memory_budget(transaction_temporary_bytes)?;
            let final_label = label_changes.then(|| label_winner.clone());
            (
                array_object.clone(),
                final_label,
                previous_label_bytes,
                transaction_temporary_bytes,
            )
        };

        let target_was_remembered = self.gc_remembered_set.contains(&array_id);
        let original_memory_ceiling = self.config.max_total_memory_bytes;
        // Keep the rollback snapshot in the shared temporary ledger. Reducing
        // only the original config ceiling would lose this reservation when a
        // tighter live sandbox is applied before or during guest iteration.
        self.json_reserve_temporary(transaction_temporary_bytes)?;

        let mutation_result = (|| {
            // Length, not the highest populated index, owns the insertion
            // point: preceding elisions still occupy array positions.
            let mut next_index =
                u32::try_from(self.array_like_length(array_id)?).map_err(|_| {
                    InterpreterError::RangeError {
                        message: "array spread target length exceeds the array index range"
                            .to_string(),
                    }
                })?;

            match iterable_value {
                // `[...map]` / `[...set]`: collections iterate their entries
                // (Map: `[key, value]` pairs, Set: values) in insertion order,
                // unless @@iterator is overridden (a subclass's own generator).
                Value::Object(iterable_id)
                    if (self.collection_storage_id(iterable_id, "Map").is_some()
                        && self.collection_iterates_intrinsically(iterable_id, "Map"))
                        || (self.collection_storage_id(iterable_id, "Set").is_some()
                            && self.collection_iterates_intrinsically(iterable_id, "Set")) =>
                {
                    let values = self
                        .collection_iteration_values(iterable_id)?
                        .unwrap_or_default();
                    for value in values {
                        self.append_spread_array_element(array_id, &mut next_index, value)?;
                    }
                }
                Value::Object(iterable_id) => {
                    // GetMethod happens exactly once, including an inherited
                    // accessor or Proxy trap. An array's own @@iterator may
                    // override the intrinsic; an indexed ordinary object is
                    // not iterable merely because it has numeric properties.
                    let iterator_method = self
                        .lookup_symbol_iterator_method(
                            Some(module),
                            iterable_id,
                            Value::Object(iterable_id),
                        )?
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "callable Symbol.iterator method".to_string(),
                            got: "null or undefined Symbol.iterator".to_string(),
                        })?;
                    let intrinsic_kind = match &iterator_method {
                        Value::BuiltinFunction(builtin) => Some(&builtin.kind),
                        _ => None,
                    };
                    if matches!(intrinsic_kind, Some(BuiltinFunctionKind::TypedArrayValues)) {
                        let (_, view) =
                            self.typed_array_receiver_view(Value::Object(iterable_id), "values")?;
                        for index in 0..view.length {
                            let value = self.with_array_buffer_bytes(view.buffer, |bytes| {
                                Self::read_typed_array_element_bytes(&view, bytes, index)
                            })??;
                            self.append_spread_array_element(array_id, &mut next_index, value)?;
                        }
                    } else if matches!(intrinsic_kind, Some(BuiltinFunctionKind::ArrayValues))
                        && self
                            .heap
                            .get(iterable_id.0 as usize)
                            .is_some_and(|object| object.is_array)
                    {
                        // Stream the intrinsic instead of allocating an eager
                        // snapshot of every element. The live length and Get
                        // operations preserve holes, inherited properties,
                        // accessor effects, and changes made by those getters.
                        let initial_length = self.array_like_length(iterable_id)?;
                        let mut index = 0u32;
                        loop {
                            // Spreading an array into itself must consume the
                            // finite pre-transaction view. Reading the live
                            // target would observe our own appends forever.
                            let length = if iterable_id == array_id {
                                initial_length
                            } else {
                                self.array_like_length(iterable_id)?
                            };
                            if index as usize >= length {
                                break;
                            }
                            let value = if iterable_id == array_id {
                                let raw = array_snapshot
                                    .properties
                                    .get(&index.to_string())
                                    .cloned()
                                    .unwrap_or(Value::Undefined);
                                self.resolve_accessor_get(
                                    Some(module),
                                    raw,
                                    Value::Object(iterable_id),
                                )?
                            } else {
                                self.proxy_aware_get_property(
                                    Some(module),
                                    iterable_id,
                                    &index.to_string(),
                                    Value::Object(iterable_id),
                                    0,
                                )?
                            };
                            self.append_spread_array_element(array_id, &mut next_index, value)?;
                            index = index.checked_add(1).ok_or_else(|| {
                                InterpreterError::RangeError {
                                    message: "array spread exceeds the array index range"
                                        .to_string(),
                                }
                            })?;
                        }
                    } else {
                        let iterator_value = self.invoke_inline_method_call(
                            Some(module),
                            iterator_method,
                            Value::Object(iterable_id),
                            Vec::new(),
                        )?;
                        let init = self.prepare_custom_iterator_result(module, iterator_value)?;
                        let iterator = self.init_iterator_from_state(
                            Value::Object(iterable_id),
                            init,
                            IterationKind::ArraySpread,
                        )?;
                        while let Some(value) =
                            self.advance_for_of_iterator(Some(module), iterator.clone())?
                        {
                            self.append_spread_array_element(array_id, &mut next_index, value)?;
                        }
                    }
                }
                Value::Str(text) => {
                    for element in text.code_point_elements() {
                        self.append_spread_array_element(
                            array_id,
                            &mut next_index,
                            Value::Str(element),
                        )?;
                    }
                }
                Value::Iterator(handle) => {
                    while let Some(value) =
                        self.advance_for_of_iterator(Some(module), Value::Iterator(handle))?
                    {
                        self.append_spread_array_element(array_id, &mut next_index, value)?;
                    }
                }
                // `[...g()]`: a generator object is its own iterator; drive it
                // through the same protocol `for (x of g())` uses (bd-9vouw.3).
                generator @ Value::Generator(_) => {
                    let init = self.prepare_for_of_state(Some(module), &generator)?;
                    let iterator =
                        self.init_iterator_from_state(generator, init, IterationKind::ArraySpread)?;
                    while let Some(value) =
                        self.advance_for_of_iterator(Some(module), iterator.clone())?
                    {
                        self.append_spread_array_element(array_id, &mut next_index, value)?;
                    }
                }
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "iterable".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
            self.set_object_property(
                array_id,
                "length".to_string(),
                Value::Int(i64::from(next_index)),
            )
        })();

        self.json_release_temporary(transaction_temporary_bytes);
        if let Err(error) = mutation_result {
            self.mutate_heap(|heap| {
                if let Some(target) = heap.get_mut(heap_index) {
                    *target = array_snapshot;
                }
            });
            if !target_was_remembered {
                self.gc_remembered_set.remove(&array_id);
            }
            // A custom iterator's guest `next()` can mutate unrelated live
            // state. Keep those observable effects and re-derive accounting
            // after restoring only the transaction-owned target object.
            self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
            return Err(error);
        }

        let final_label_bytes = final_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(previous_label_bytes);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_label_bytes)
            .saturating_add(final_label_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, original_memory_ceiling) {
            self.mutate_heap(|heap| {
                if let Some(target) = heap.get_mut(heap_index) {
                    *target = array_snapshot;
                }
            });
            if !target_was_remembered {
                self.gc_remembered_set.remove(&array_id);
            }
            self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }

        if let Some(final_label) = final_label {
            self.note_register_written(actual_array_register);
            let Some(target_label) = self.register_labels.get_mut(actual_array_register) else {
                self.mutate_heap(|heap| {
                    if let Some(target) = heap.get_mut(heap_index) {
                        *target = array_snapshot;
                    }
                });
                if !target_was_remembered {
                    self.gc_remembered_set.remove(&array_id);
                }
                self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
                return Err(InterpreterError::RegisterOutOfBounds {
                    register: array,
                    max: self.config.max_registers,
                });
            };
            let is_public = matches!(&final_label, Label::Public);
            let previous_label = std::mem::replace(target_label, Label::Public);
            drop(previous_label);
            *target_label = final_label;
            if !is_public {
                self.all_register_labels_public = false;
            }
            self.adjust_register_labels_bytes(previous_label_bytes, final_label_bytes);
        }
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    /// Clone one binary-operation label winner after a strict temporary peak
    /// preflight. The caller can then commit value+label through
    /// `write_reg_with_label` as one transaction.
    #[inline(always)]
    pub(super) fn binary_operation_label(
        &self,
        lhs: u32,
        rhs: u32,
    ) -> Result<Label, InterpreterError> {
        if self.all_register_labels_public
            && lhs < self.config.max_registers
            && rhs < self.config.max_registers
            && self.register_base + (lhs.max(rhs) as usize) < self.register_labels.len()
        {
            self.check_temporary_memory_budget(0)?;
            return Ok(Label::Public);
        }
        let lhs_label = self.get_register_label(lhs)?;
        let rhs_label = self.get_register_label(rhs)?;
        let winner = if lhs_label >= rhs_label {
            lhs_label
        } else {
            rhs_label
        };
        self.check_temporary_memory_budget(Self::estimate_label_bytes(winner))?;
        Ok(winner.clone())
    }

    /// Clone one unary-operation label after a strict temporary peak preflight.
    #[inline(always)]
    pub(super) fn unary_operation_label(&self, src: u32) -> Result<Label, InterpreterError> {
        self.clone_register_label_with_temporary_budget(src)
    }

    /// Clone one register label only after charging the attacker-controlled
    /// name as a strict temporary. Isolated callback results use this helper
    /// before restoring the caller snapshot, so cleanup still runs when the
    /// clone itself is refused.
    #[inline(always)]
    pub(super) fn clone_register_label_with_temporary_budget(
        &self,
        reg: u32,
    ) -> Result<Label, InterpreterError> {
        self.clone_register_label_with_additional_temporary_budget(reg, 0)
    }

    #[inline(always)]
    pub(super) fn clone_register_label_with_additional_temporary_budget(
        &self,
        reg: u32,
        already_owned_temporary_bytes: u64,
    ) -> Result<Label, InterpreterError> {
        if self.all_register_labels_public
            && reg < self.config.max_registers
            && self.register_base + (reg as usize) < self.register_labels.len()
        {
            self.check_temporary_memory_budget(already_owned_temporary_bytes)?;
            return Ok(Label::Public);
        }
        let label = self.get_register_label(reg)?;
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes.saturating_add(Self::estimate_label_bytes(label)),
        )?;
        Ok(label.clone())
    }

    /// Dominant PC-style label for the currently executing callback or
    /// HomeObject-bound closure. A method selected through a secret definition
    /// key/prototype must taint literals, throws, and zero-argument effects in
    /// its body, not only the explicit argument registers it happens to read.
    #[inline]
    pub(super) fn active_execution_context_label(&self) -> Option<&Label> {
        let mut winner = self.active_inline_callback_context_label.as_ref();
        // bd-9vouw.72: the frames' first strict maximum, kept by the call
        // stack, instead of a scan of every frame on every call.
        if let Some(label) = self.call_stack.super_label_winner()
            && winner.is_none_or(|current| label > current)
        {
            winner = Some(label);
        }
        #[cfg(test)]
        {
            let mut scanned = self.active_inline_callback_context_label.as_ref();
            for frame in self
                .call_stack
                .iter()
                .filter(|frame| frame.super_home_object.is_some())
            {
                if scanned.is_none_or(|current| &frame.super_label > current) {
                    scanned = Some(&frame.super_label);
                }
            }
            debug_assert!(
                std::ptr::eq(
                    winner.map_or(std::ptr::null(), |label| label as *const Label),
                    scanned.map_or(std::ptr::null(), |label| label as *const Label),
                ),
                "call-stack super-label prefix drifted from the scan (bd-9vouw.72)"
            );
        }
        if let Some(pc_frame) = self.pc_label_stack.last()
            && winner.is_none_or(|current| &pc_frame.label > current)
        {
            winner = Some(&pc_frame.label);
        }
        winner
    }

    /// Read-only view of runtime IFC sink flow audit entries recorded by this core.
    pub fn ifc_runtime_flow_audit(&self) -> &[IfcRuntimeFlowAuditEntry] {
        &self.ifc_runtime_flow_audit
    }

    /// Drain runtime IFC sink flow audit entries recorded by this core.
    pub fn take_ifc_runtime_flow_audit(&mut self) -> Vec<IfcRuntimeFlowAuditEntry> {
        std::mem::take(&mut self.ifc_runtime_flow_audit)
    }

    /// Configure an explicit deterministic epoch (ms) against which runtime
    /// declassification receipts are checked for `not_before_ms`/`not_after_ms`
    /// validity (`bd-9vouw.8`).
    pub fn set_ifc_validation_epoch_ms(&mut self, epoch_ms: Option<u64>) {
        self.ifc_validation_epoch_ms = epoch_ms;
    }

    pub(super) fn compute_ipdom_table(module: &Ir3Module) -> Arc<[usize]> {
        let n = module.instructions.len();
        let exit = n;
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        let mut rev_succs: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        let mut try_handlers: Vec<usize> = Vec::new();

        let add_edge =
            |u: usize, v: usize, succs: &mut [Vec<usize>], rev_succs: &mut [Vec<usize>]| {
                let target = v.min(exit);
                if !succs[u].contains(&target) {
                    succs[u].push(target);
                    rev_succs[target].push(u);
                }
            };

        for (i, instr) in module.instructions.iter().enumerate() {
            match instr {
                Ir3Instruction::BeginTry {
                    catch_target,
                    finally_target,
                } => {
                    let handler = finally_target.unwrap_or(*catch_target) as usize;
                    try_handlers.push(handler.min(exit));
                    add_edge(i, i + 1, &mut succs, &mut rev_succs);
                }
                Ir3Instruction::EndTry => {
                    try_handlers.pop();
                    add_edge(i, i + 1, &mut succs, &mut rev_succs);
                }
                Ir3Instruction::Halt
                | Ir3Instruction::Return { .. }
                | Ir3Instruction::AsyncReturn { .. }
                | Ir3Instruction::AsyncThrow { .. }
                | Ir3Instruction::EndFinally => {
                    add_edge(i, exit, &mut succs, &mut rev_succs);
                }
                Ir3Instruction::Throw { .. } => {
                    let target = try_handlers.last().copied().unwrap_or(exit);
                    add_edge(i, target, &mut succs, &mut rev_succs);
                }
                Ir3Instruction::Jump { target } => {
                    add_edge(i, *target as usize, &mut succs, &mut rev_succs);
                }
                Ir3Instruction::JumpIf { target, .. }
                | Ir3Instruction::JumpIfNullish { target, .. }
                | Ir3Instruction::ForInNext {
                    done_target: target,
                    ..
                }
                | Ir3Instruction::ForOfNext {
                    done_target: target,
                    ..
                } => {
                    add_edge(i, i + 1, &mut succs, &mut rev_succs);
                    add_edge(i, *target as usize, &mut succs, &mut rev_succs);
                }
                _ => {
                    add_edge(i, i + 1, &mut succs, &mut rev_succs);
                }
            }
        }

        // Reverse-CFG postorder DFS rooted at `exit` so RPO index 0 is `exit`.
        let mut visited = vec![false; n + 1];
        let mut postorder = Vec::with_capacity(n + 1);
        let mut stack: Vec<(usize, usize)> = vec![(exit, 0)];
        visited[exit] = true;
        while let Some((node, next_idx)) = stack.last_mut() {
            let current = *node;
            if *next_idx < rev_succs[current].len() {
                let child = rev_succs[current][*next_idx];
                *next_idx += 1;
                if !visited[child] {
                    visited[child] = true;
                    stack.push((child, 0));
                }
            } else {
                postorder.push(current);
                stack.pop();
            }
        }

        let rpo_len = postorder.len();
        let mut rpo_nodes = Vec::with_capacity(rpo_len);
        let mut rpo_num = vec![usize::MAX; n + 1];
        for (idx, &node) in postorder.iter().rev().enumerate() {
            rpo_nodes.push(node);
            rpo_num[node] = idx;
        }

        // Cooper-Harvey-Kennedy iterative dominators on reverse CFG.
        let mut doms = vec![usize::MAX; rpo_len];
        if !doms.is_empty() {
            doms[0] = 0;
        }
        let intersect = |mut b1: usize, mut b2: usize, doms: &[usize]| -> usize {
            while b1 != b2 {
                while b1 > b2 {
                    b1 = doms[b1];
                }
                while b2 > b1 {
                    b2 = doms[b2];
                }
            }
            b1
        };

        let mut changed = true;
        while changed {
            changed = false;
            for idx in 1..rpo_len {
                let u = rpo_nodes[idx];
                let mut new_idom = usize::MAX;
                for &succ in &succs[u] {
                    let pred_rpo = rpo_num[succ];
                    if pred_rpo != usize::MAX && doms[pred_rpo] != usize::MAX {
                        new_idom = if new_idom == usize::MAX {
                            pred_rpo
                        } else {
                            intersect(pred_rpo, new_idom, &doms)
                        };
                    }
                }
                if new_idom != usize::MAX && doms[idx] != new_idom {
                    doms[idx] = new_idom;
                    changed = true;
                }
            }
        }

        let mut ipdom = vec![exit; n];
        for (u, slot) in ipdom.iter_mut().enumerate() {
            let idx = rpo_num[u];
            if idx != usize::MAX && doms[idx] != usize::MAX {
                *slot = rpo_nodes[doms[idx]];
            }
        }
        Arc::from(ipdom)
    }

    pub(super) fn ipdom_for(&mut self, module: &Ir3Module, branch_ip: usize) -> usize {
        let key = (
            module.instructions.as_ptr() as usize,
            module.instructions.len(),
        );
        let table = if let Some(cached) = self.ipdom_cache.get(&key) {
            Arc::clone(cached)
        } else {
            if self.ipdom_cache.len() >= 16 {
                self.ipdom_cache.clear();
            }
            let computed = Self::compute_ipdom_table(module);
            self.ipdom_cache.insert(key, Arc::clone(&computed));
            computed
        };
        table
            .get(branch_ip)
            .copied()
            .unwrap_or(module.instructions.len())
    }

    #[inline]
    pub(super) fn push_branch_pc_label_if_tainted(
        &mut self,
        module: &Ir3Module,
        cond_reg: u32,
    ) -> Result<(), InterpreterError> {
        if self.all_register_labels_public {
            return Ok(());
        }
        let cond_label = self.get_register_label(cond_reg)?;
        if *cond_label == Label::Public {
            return Ok(());
        }
        let joined = match self.active_execution_context_label() {
            Some(active) => active.join(cond_label),
            None => cond_label.clone(),
        };
        let reconvergence_ip = self.ipdom_for(module, self.ip);
        let call_depth = self.call_stack.len();
        if self.pc_label_stack.last().is_some_and(|top| {
            top.reconvergence_ip == reconvergence_ip
                && top.call_depth == call_depth
                && top.label == joined
        }) {
            return Ok(());
        }
        self.pc_label_stack.push(PcLabelFrame {
            reconvergence_ip,
            call_depth,
            label: joined,
        });
        Ok(())
    }

    #[inline]
    pub(super) fn push_callee_pc_label(&mut self, callee_label: Label) {
        if callee_label == Label::Public {
            return;
        }
        let joined = match self.active_execution_context_label() {
            Some(active) => active.join(&callee_label),
            None => callee_label,
        };
        let call_depth = self.call_stack.len();
        self.pc_label_stack.push(PcLabelFrame {
            reconvergence_ip: usize::MAX,
            call_depth,
            label: joined,
        });
    }

    pub(super) fn clone_active_execution_context_label(&self) -> Result<Label, InterpreterError> {
        let Some(label) = self.active_execution_context_label() else {
            return Ok(Label::Public);
        };
        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
        Ok(label.clone())
    }

    /// Join (least-upper-bound) of the IFC labels on every register in a
    /// `RegRange`. Empty range returns `Public`. Hoisted out of HostCall /
    /// Call / Apply / Construct so every call-shape that resolves to a
    /// register-range argument list uses the same join contract (bd-n2mjy).
    pub(super) fn join_arg_range_label(
        &self,
        args: crate::ir_contract::RegRange,
    ) -> Result<Label, InterpreterError> {
        let mut joined: Option<&Label> = self.active_execution_context_label();
        for i in 0..args.count {
            let reg = args
                .start
                .checked_add(i)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: u32::MAX,
                })?;
            let candidate = self.get_register_label(reg)?;
            if joined.is_none_or(|current| candidate > current) {
                joined = Some(candidate);
            }
        }
        let Some(joined) = joined else {
            return Ok(Label::Public);
        };
        // Scan borrowed labels and clone only the single winner. This turns an
        // attacker-sized N-argument join from N repeated String allocations
        // into one explicitly preflighted temporary allocation.
        self.check_temporary_memory_budget(Self::estimate_label_bytes(joined))?;
        Ok(joined.clone())
    }

    #[inline]
    pub(super) fn join_owned_label_with_temporary_budget(
        &self,
        owned: Label,
        other: &Label,
    ) -> Result<Label, InterpreterError> {
        // Public is the bottom of Label's order (level 0, before any
        // same-level Custom): `owned >= Public` always holds, so the usual
        // join with a Public operand skips the out-of-line comparison
        // (bd-9vouw.504).
        if matches!(other, Label::Public) || &owned >= other {
            return Ok(owned);
        }
        drop(owned);
        self.check_temporary_memory_budget(Self::estimate_label_bytes(other))?;
        Ok(other.clone())
    }

    pub(super) fn clone_dominant_label_with_temporary_budget(
        &self,
        left: &Label,
        right: &Label,
        already_owned_temporary_bytes: u64,
    ) -> Result<Label, InterpreterError> {
        let winner = if left >= right { left } else { right };
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes.saturating_add(Self::estimate_label_bytes(winner)),
        )?;
        Ok(winner.clone())
    }

    // ---------------------------------------------------------------------------
    // GC write barrier management
    // ---------------------------------------------------------------------------

    /// Record an object in the remembered set for generational GC.
    /// This is called when an older generation object gets a reference to a younger object.
    pub(super) fn gc_write_barrier(&mut self, object_id: ObjectId) {
        self.gc_remembered_set.insert(object_id);
    }

    /// Check if an object is in the remembered set.
    pub fn gc_is_remembered(&self, object_id: ObjectId) -> bool {
        self.gc_remembered_set.contains(&object_id)
    }

    /// Clear the remembered set (typically called after a GC cycle).
    pub fn gc_clear_remembered_set(&mut self) {
        self.gc_remembered_set.clear();
    }

    /// Get the size of the remembered set (for testing/diagnostics).
    pub fn gc_remembered_set_size(&self) -> usize {
        self.gc_remembered_set.len()
    }

    /// Get a copy of the remembered set for inspection and diagnostics.
    pub fn gc_get_remembered_set(&self) -> BTreeSet<ObjectId> {
        self.gc_remembered_set.iter().collect()
    }

    // ---------------------------------------------------------------------------
    // JIT hot path detection and tier promotion
    // ---------------------------------------------------------------------------

    /// Record a function call and check if it should be promoted to hot tier.
    pub(super) fn jit_record_function_call(&mut self, function_id: u32) -> bool {
        let count = {
            let count = self
                .jit_function_call_counts
                .entry(function_id)
                .or_insert(0);
            *count += 1;
            *count
        };

        // Check if threshold crossed for tier promotion
        if count == self.jit_hot_threshold {
            self.emit_tier_promotion_event(function_id, count);
            true // Function is now hot
        } else {
            false
        }
    }

    /// Record a loop iteration at backedge and check for hot loop promotion.
    pub(super) fn jit_record_loop_iteration(&mut self, instruction_index: usize) -> bool {
        let count = self.jit_loop_iteration_counts.increment(instruction_index);

        // Check if threshold crossed for hot loop tier promotion (edge-triggered)
        count == self.jit_hot_threshold
    }

    /// Get the current call count for a function.
    pub fn jit_get_function_call_count(&self, function_id: u32) -> u64 {
        self.jit_function_call_counts
            .get(&function_id)
            .copied()
            .unwrap_or(0)
    }

    /// Get the current iteration count for a loop backedge.
    pub fn jit_get_loop_iteration_count(&self, instruction_index: usize) -> u64 {
        self.jit_loop_iteration_counts.get(instruction_index)
    }

    /// Configure the hot threshold for tier promotion.
    pub fn jit_set_hot_threshold(&mut self, threshold: u64) {
        self.jit_hot_threshold = threshold.max(1); // Minimum threshold of 1
    }

    /// Get the current hot threshold.
    pub fn jit_get_hot_threshold(&self) -> u64 {
        self.jit_hot_threshold
    }

    /// Check if a function is considered hot (above threshold).
    pub fn jit_is_function_hot(&self, function_id: u32) -> bool {
        self.jit_get_function_call_count(function_id) >= self.jit_hot_threshold
    }

    /// Check if a loop is considered hot (above threshold).
    pub fn jit_is_loop_hot(&self, instruction_index: usize) -> bool {
        self.jit_get_loop_iteration_count(instruction_index) >= self.jit_hot_threshold
    }

    /// Evict cold functions to implement decay policy (called periodically).
    pub fn jit_evict_cold_functions(&mut self) {
        const EVICTION_FREQUENCY: u64 = 50_000; // Evict every 50k calls
        const COLD_THRESHOLD: u64 = 10; // Functions with <= 10 calls are cold

        self.jit_eviction_counter += 1;
        if self.jit_eviction_counter.is_multiple_of(EVICTION_FREQUENCY) {
            // Remove functions that haven't crossed the cold threshold
            self.jit_function_call_counts
                .retain(|_function_id, count| *count > COLD_THRESHOLD);

            // Also evict cold loops
            self.jit_loop_iteration_counts.retain_above(COLD_THRESHOLD);
        }
    }

    /// Emit a tier promotion event when a function or loop crosses the hot threshold.
    pub(super) fn emit_tier_promotion_event(&mut self, function_id: u32, call_count: u64) {
        // Emit a witness event for tier promotion. This is the correct,
        // replay-auditable telemetry channel for JIT tier-ups; the promotion
        // must NOT be written to the program's `console` stream, which is
        // observable program output (a `JIT: ...` line corrupts stdout once any
        // function or loop crosses the hot threshold and breaks cross-runtime
        // output comparison against node/bun).
        self.emit_witness(
            WitnessEventKind::HostcallDispatched, // Reuse existing event type
            Some(&format!(
                "tier_promotion:function_{}:count_{}",
                function_id, call_count
            )),
        );
    }

    /// Get JIT statistics for testing and debugging.
    pub fn jit_get_statistics(&self) -> JitStatistics {
        JitStatistics(
            self.jit_function_call_counts.len(),
            self.jit_loop_iteration_counts.len(),
            self.jit_hot_threshold,
            self.jit_eviction_counter,
            self.jit_function_call_counts.values().sum(),
        )
    }

    /// Clear all JIT counters (for testing).
    pub fn jit_clear_counters(&mut self) {
        self.jit_function_call_counts.clear();
        self.jit_loop_iteration_counts.clear();
        self.jit_eviction_counter = 0;
    }

    /// Get the captured console output entries.
    pub fn console_output(&self) -> &[ConsoleEntry] {
        &self.console_output
    }

    /// Seed a register before the next `execute()` call.
    ///
    /// This supports low-level IR harnesses that need to start from runtime
    /// values not directly materializable by current IR3 load instructions,
    /// such as opaque `Value::Function(idx)` builtin handles.
    pub fn seed_register(&mut self, reg: u32, value: Value) -> Result<(), InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        validate_symbol_value(&self.symbol_state, &value).map_err(|details| {
            InterpreterError::TypeError {
                expected: "resolved Symbol seed value".to_string(),
                got: details,
            }
        })?;

        // Seed values are live before execute captures its replay snapshot.
        // Admission must update the same incremental accounting as VM writes;
        // otherwise a seeded string is invisible until a later resync (or
        // remains uncharged when execution refuses before such a resync).
        let previous_bytes = Self::estimate_value_bytes(&self.registers[reg as usize]);
        self.apply_memory_component_delta(previous_bytes, Self::estimate_value_bytes(&value))?;
        self.last_pre_run_seed = None;
        self.last_post_run_epoch = None;
        self.note_register_written(reg as usize);
        self.mutate_registers(|r| r[reg as usize] = value);
        Ok(())
    }

    /// Retain one console entry, or fail the run when the console budget is
    /// spent. Output is never dropped silently: a truncated transcript would
    /// be a wrong answer that still exits 0.
    /// Console output under the current `console.group` indentation: two
    /// spaces per level before every line, as Node's groupIndent.
    pub(super) fn push_indented_console_output(
        &mut self,
        level: ConsoleLevel,
        message: String,
    ) -> Result<(), InterpreterError> {
        if self.console_group_depth == 0 {
            return self.push_console_output(level, message);
        }
        let indent = "  ".repeat(self.console_group_depth);
        let indented = message
            .split('\n')
            .map(|line| format!("{indent}{line}"))
            .collect::<Vec<_>>()
            .join("\n");
        self.push_console_output(level, indented)
    }

    /// `console.count` / `time` label: `${label}`, 'default' when absent or
    /// undefined.
    pub(super) fn console_label(
        &mut self,
        module: Option<&Ir3Module>,
        value: Option<Value>,
    ) -> Result<String, InterpreterError> {
        match value {
            None | Some(Value::Undefined) => Ok("default".to_string()),
            Some(value) => Ok(self
                .scoped_conversion(|this| this.conversion_to_string(module, value))?
                .to_string()),
        }
    }

    /// Record a new count/time label, charging its bytes to the console
    /// budget like output.
    pub(super) fn charge_console_label(&mut self, label: &str) -> Result<(), InterpreterError> {
        self.check_sandbox_console_allocation(
            (label.len() as u64).saturating_add(std::mem::size_of::<(String, u64)>() as u64),
        )?;
        let entries = self
            .console_counts
            .len()
            .saturating_add(self.console_timers.len())
            .saturating_add(1);
        let bytes = self.console_output_bytes.saturating_add(label.len());
        let (max_entries, max_bytes) = (
            self.config.max_console_entries,
            self.config.max_console_bytes,
        );
        if entries > max_entries || bytes > max_bytes {
            return Err(InterpreterError::ConsoleBudgetExceeded {
                entries,
                max_entries,
                bytes,
                max_bytes,
            });
        }
        self.console_output_bytes = bytes;
        Ok(())
    }

    /// The `console` methods besides log/error/warn/info (bd-9vouw.158), as
    /// Node v22.2.0 implements them: assert and trace write to stderr, the
    /// rest to stdout; warnings Node emits as process warnings are console
    /// warnings here. Timers read the deterministic performance.now() clock.
    pub(super) fn console_extra_method(
        &mut self,
        method: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let arg = |core: &Self, index: u32| core.builtin_arg(args, index);
        match method {
            // Normally routed as console:log; the same output either way.
            "debug" | "dirxml" => {
                let message = self.console_format_arguments(module, args)?;
                self.push_indented_console_output(ConsoleLevel::Log, message)?;
            }
            // util.inspect of the first argument, also for a string.
            "dir" => {
                let value = arg(self, 0)?.unwrap_or(Value::Undefined);
                let text = self.console_inspect(module, &value)?;
                self.push_indented_console_output(ConsoleLevel::Log, text)?;
            }
            "trace" => {
                let message = self.console_format_arguments(module, args)?;
                let mut text = if message.is_empty() {
                    "Trace".to_string()
                } else {
                    format!("Trace: {message}")
                };
                let frames = self.format_stack_trace();
                if !frames.is_empty() {
                    text.push('\n');
                    text.push_str(&frames);
                }
                self.push_indented_console_output(ConsoleLevel::Error, text)?;
            }
            // Never throws. A falsy assertion warns its data: a leading
            // string becomes "Assertion failed: <string>", anything else is
            // preceded by "Assertion failed".
            "assert" => {
                if arg(self, 0)?.is_some_and(|condition| condition.is_truthy()) {
                    return Ok(());
                }
                let mut values = Vec::new();
                for offset in 1..args.count {
                    values.push(arg(self, offset)?.unwrap_or(Value::Undefined));
                }
                match values.first() {
                    Some(Value::Str(first)) => {
                        values[0] = Value::str(format!("Assertion failed: {first}"));
                    }
                    _ => values.insert(0, Value::str("Assertion failed")),
                }
                let text = self.format_values(module, &values)?;
                self.push_indented_console_output(ConsoleLevel::Warn, text)?;
            }
            "count" => {
                let label = self.console_label(module, arg(self, 0)?)?;
                if !self.console_counts.contains_key(&label) {
                    self.charge_console_label(&label)?;
                }
                let count = self.console_counts.entry(label.clone()).or_insert(0);
                *count = count.saturating_add(1);
                let text = format!("{label}: {count}");
                self.push_indented_console_output(ConsoleLevel::Log, text)?;
            }
            "countReset" => {
                let label = self.console_label(module, arg(self, 0)?)?;
                if self.console_counts.remove(&label).is_none() {
                    let text = format!("Warning: Count for '{label}' does not exist");
                    self.push_indented_console_output(ConsoleLevel::Warn, text)?;
                }
            }
            "group" | "groupCollapsed" => {
                if args.count > 0 {
                    let message = self.console_format_arguments(module, args)?;
                    self.push_indented_console_output(ConsoleLevel::Log, message)?;
                }
                self.console_group_depth = self.console_group_depth.saturating_add(1);
            }
            "groupEnd" => {
                self.console_group_depth = self.console_group_depth.saturating_sub(1);
            }
            "time" => {
                let label = self.console_label(module, arg(self, 0)?)?;
                if self.console_timers.contains_key(&label) {
                    let text =
                        format!("Warning: Label '{label}' already exists for console.time()");
                    self.push_indented_console_output(ConsoleLevel::Warn, text)?;
                    return Ok(());
                }
                self.charge_console_label(&label)?;
                let now =
                    Self::coerce_to_float(&self.deterministic_performance_now()).unwrap_or(0.0);
                self.console_timers.insert(label, now);
            }
            "timeEnd" | "timeLog" => {
                let label = self.console_label(module, arg(self, 0)?)?;
                let Some(&start) = self.console_timers.get(&label) else {
                    let text = format!("Warning: No such label '{label}' for console.{method}()");
                    self.push_indented_console_output(ConsoleLevel::Warn, text)?;
                    return Ok(());
                };
                let now =
                    Self::coerce_to_float(&self.deterministic_performance_now()).unwrap_or(start);
                let mut text = format!("{label}: {}", console_elapsed_time(now - start));
                if method == "timeEnd" {
                    self.console_timers.remove(&label);
                } else if args.count > 1 {
                    let mut values = Vec::new();
                    for offset in 1..args.count {
                        values.push(arg(self, offset)?.unwrap_or(Value::Undefined));
                    }
                    text.push(' ');
                    text.push_str(&self.format_values(module, &values)?);
                }
                self.push_indented_console_output(ConsoleLevel::Log, text)?;
            }
            // Node clears only a TTY; output here is never one.
            "clear" => {}
            "table" => self.console_table(module, args)?,
            _ => {}
        }
        Ok(())
    }

    /// `console.table(data, properties)` (bd-9vouw.158), as Node v22.2.0's
    /// Console.prototype.table over internal/cli_table: a Map's entries, a
    /// Set's values, or any other object's own enumerable keys and, per key,
    /// the item (a primitive) or its own properties (an object) as columns.
    /// Anything but an object is logged.
    pub(super) fn console_table(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let data = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let properties = match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => None,
            Some(Value::Object(id)) if self.heap.get(id.0 as usize).is_some_and(|o| o.is_array) => {
                let mut names = Vec::new();
                for value in self.array_like_values(id)? {
                    names.push(
                        self.scoped_conversion(|this| this.conversion_to_string(module, value))?
                            .to_string(),
                    );
                }
                Some(names)
            }
            Some(other) => {
                return Err(InterpreterError::TypeError {
                    expected: "an Array for the \"properties\" argument of console.table"
                        .to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let (Value::Object(data_id), Some(module)) = (&data, module) else {
            let text = self.format_values(module, std::slice::from_ref(&data))?;
            return self.push_indented_console_output(ConsoleLevel::Log, text);
        };
        let brand = self
            .heap
            .get(data_id.0 as usize)
            .and_then(|object| object.brand().map(str::to_string));
        let (head, columns) = match brand.as_deref() {
            Some(kind @ ("Map" | "Set")) => {
                let items = self.promise_combinator_iterable_values(Some(module), data.clone())?;
                let mut index = Vec::with_capacity(items.len());
                let mut keys = Vec::with_capacity(items.len());
                let mut values = Vec::with_capacity(items.len());
                for (position, item) in items.into_iter().enumerate() {
                    index.push(Some(
                        self.console_table_cell(module, &Value::Int(position as i64))?,
                    ));
                    if kind == "Map" {
                        let key =
                            self.get_v(module, &item, &RuntimePropertyKey::String("0".into()))?;
                        let value =
                            self.get_v(module, &item, &RuntimePropertyKey::String("1".into()))?;
                        keys.push(Some(self.console_table_cell(module, &key)?));
                        values.push(Some(self.console_table_cell(module, &value)?));
                    } else {
                        values.push(Some(self.console_table_cell(module, &item)?));
                    }
                }
                if kind == "Map" {
                    (
                        vec![
                            "(iteration index)".to_string(),
                            "Key".to_string(),
                            "Values".to_string(),
                        ],
                        vec![index, keys, values],
                    )
                } else {
                    (
                        vec!["(iteration index)".to_string(), "Values".to_string()],
                        vec![index, values],
                    )
                }
            }
            _ => self.console_table_columns(module, &data, properties.as_deref())?,
        };
        let text = inspect::console_table_text(&head, &columns);
        self.push_indented_console_output(ConsoleLevel::Log, text)
    }

    /// The `(index)` column, one column per property in Object.keys order
    /// (array indices first), and a `Values` column for primitive items.
    pub(super) fn console_table_columns(
        &mut self,
        module: &Ir3Module,
        data: &Value,
        properties: Option<&[String]>,
    ) -> Result<ConsoleTableColumns, InterpreterError> {
        let index_keys = self.console_object_keys(module, data)?;
        let rows = index_keys.len();
        let mut columns: Vec<(String, Vec<Option<String>>)> = Vec::new();
        let mut values_column: Vec<Option<String>> = vec![None; rows];
        let mut has_primitives = false;
        for (row, index_key) in index_keys.iter().enumerate() {
            let item = self.get_v(
                module,
                data,
                &RuntimePropertyKey::String(index_key.as_str().into()),
            )?;
            let primitive = matches!(
                item,
                Value::Undefined
                    | Value::Null
                    | Value::Bool(_)
                    | Value::Int(_)
                    | Value::Float(_)
                    | Value::Str(_)
                    | Value::Symbol(_)
                    | Value::BigInt(_)
            );
            if properties.is_none() && primitive {
                has_primitives = true;
                values_column[row] = Some(self.console_table_cell(module, &item)?);
                continue;
            }
            let keys = match properties {
                Some(names) => names.to_vec(),
                None => self.console_object_keys(module, &item)?,
            };
            for key in keys {
                let cell = if primitive || !self.console_has_own_property(module, &item, &key)? {
                    String::new()
                } else {
                    let value = self.get_v(
                        module,
                        &item,
                        &RuntimePropertyKey::String(key.as_str().into()),
                    )?;
                    self.console_table_cell(module, &value)?
                };
                let position = match columns.iter().position(|(name, _)| *name == key) {
                    Some(position) => position,
                    None => {
                        columns.push((key, vec![None; rows]));
                        columns.len() - 1
                    }
                };
                columns[position].1[row] = Some(cell);
            }
        }
        // The column map is an object: array-index keys come first, in
        // numeric order, then the rest in insertion order.
        let array_index = |key: &str| {
            key.parse::<u32>()
                .ok()
                .filter(|index| *index != u32::MAX && index.to_string() == key)
        };
        columns.sort_by_key(|(key, _)| array_index(key).map_or((1, 0), |index| (0, index)));
        let mut head = vec!["(index)".to_string()];
        let mut cells = vec![index_keys.into_iter().map(Some).collect::<Vec<_>>()];
        for (key, column) in columns {
            head.push(key);
            cells.push(column);
        }
        if has_primitives {
            head.push("Values".to_string());
            cells.push(values_column);
        }
        Ok((head, cells))
    }

    /// A table cell: `util.inspect` at depth 0, or -1 for an object with
    /// more than two keys, three array entries at most, on one line.
    pub(super) fn console_table_cell(
        &mut self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<String, InterpreterError> {
        let is_array = matches!(value, Value::Object(id)
            if self.heap.get(id.0 as usize).is_some_and(|object| object.is_array));
        let depth = if matches!(value, Value::Object(_))
            && !is_array
            && self.console_object_keys(module, value)?.len() > 2
        {
            -1
        } else {
            0
        };
        self.inspect_table_cell(Some(module), value, depth)
    }

    /// `Object.keys(value)` through the builtin, so proxies, accessors and
    /// exotic objects answer as they do for guest code.
    pub(super) fn console_object_keys(
        &mut self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<Vec<String>, InterpreterError> {
        let (keys, _) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:ObjectKeys")),
            Value::Undefined,
            vec![value.clone()],
            None,
        )?;
        let Value::Object(array) = keys else {
            return Ok(Vec::new());
        };
        Ok(self
            .array_like_values(array)?
            .into_iter()
            .map(|key| self.value_to_string(&key))
            .collect())
    }

    /// `Object.prototype.hasOwnProperty.call(value, key)`.
    pub(super) fn console_has_own_property(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        let (owned, _) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            Value::BuiltinFunction(BuiltinFunction::object_has_own_property()),
            value.clone(),
            vec![Value::str(key)],
            None,
        )?;
        Ok(owned.is_truthy())
    }

    pub(super) fn push_console_output(
        &mut self,
        level: ConsoleLevel,
        message: String,
    ) -> Result<(), InterpreterError> {
        let max_entries = self.config.max_console_entries;
        if max_entries == 0 {
            return Ok(());
        }

        self.check_sandbox_console_allocation(
            (message.len() as u64).saturating_add(std::mem::size_of::<ConsoleEntry>() as u64),
        )?;

        let entries = self.console_output.len().saturating_add(1);
        let bytes = self.console_output_bytes.saturating_add(message.len());
        let max_bytes = self.config.max_console_bytes;
        if entries > max_entries || bytes > max_bytes {
            return Err(InterpreterError::ConsoleBudgetExceeded {
                entries,
                max_entries,
                bytes,
                max_bytes,
            });
        }

        self.console_output_bytes = bytes;
        self.console_output.push(ConsoleEntry {
            level,
            message,
            instruction_index: self.instructions_executed,
        });
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn take_execution_result(
        &mut self,
        completion: LabeledReturn,
        requested_hook_action: Option<HookAction>,
    ) -> ExecutionResult {
        self.take_execution_result_with_trace_handoff(
            completion,
            requested_hook_action,
            TraceHandoff::RetainInCore,
        )
    }

    pub(super) fn take_execution_result_with_trace_handoff(
        &mut self,
        completion: LabeledReturn,
        requested_hook_action: Option<HookAction>,
        trace_handoff: TraceHandoff,
    ) -> ExecutionResult {
        self.flush_sandbox_witness();
        let requested_hook_action = if self.active_sandbox.get().is_some()
            && matches!(
                requested_hook_action,
                None | Some(HookAction::Allow | HookAction::Challenge(_))
            ) {
            Some(HookAction::Sandbox)
        } else {
            requested_hook_action
        };
        self.seal_timer_callback_witness();
        self.seal_microtask_enqueue_witness();
        // Finalise the nondeterminism trace at the end-of-execution virtual
        // timestamp so the exposed copy is replay-ready: `validate_for_replay`
        // and `ReplayEngine` both require a finalised trace.
        self.nondeterminism_trace
            .finalise(self.instructions_executed);
        debug_assert_eq!(
            self.generated_code_observability_bytes,
            self.generated_code_observability_memory_bytes()
        );
        debug_assert_eq!(self.generated_code_observability_reservation_bytes, 0);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(self.generated_code_observability_bytes);
        self.generated_code_observability_bytes = 0;
        // bd-zaeeh: draining `events` releases the general structured events
        // that push_event charged; uncharge them so the estimate stays
        // consistent with a full recompute after the take below.
        debug_assert_eq!(
            self.general_event_bytes,
            self.general_interpreter_events_memory_bytes()
        );
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(self.general_event_bytes);
        self.general_event_bytes = 0;
        let nondeterminism_trace = match trace_handoff {
            TraceHandoff::RetainInCore => self.nondeterminism_trace.clone(),
            TraceHandoff::DrainEphemeralCore => std::mem::replace(
                &mut self.nondeterminism_trace,
                NondeterminismTrace::new(String::new()),
            ),
        };
        self.console_output_bytes = 0;
        self.recorded_effect_free_grants.clear();
        ExecutionResult {
            value: completion.value,
            completion_label: completion.label,
            instructions_executed: self.instructions_executed,
            tier_i_instructions_executed: self.tier_i_instructions_executed,
            tier_i_specialized_instructions_executed: self.tier_i_specialized_instructions_executed,
            requested_hook_action,
            witness_events: std::mem::take(&mut self.witness_events),
            hostcall_decisions: std::mem::take(&mut self.hostcall_decisions),
            folded_hostcall_decisions: std::mem::take(&mut self.folded_hostcall_decisions),
            events: std::mem::take(&mut self.events),
            console_output: std::mem::take(&mut self.console_output),
            iteration_traces: std::mem::take(&mut self.iteration_traces),
            nondeterminism_trace,
            generated_code_audit: std::mem::take(&mut self.generated_code_audit),
            exit_code: self.process_exit_code.take(),
        }
    }

    /// Execute an IR3 module and return the result.
    pub fn execute(&mut self, module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_trace_handoff(module, None, TraceHandoff::RetainInCore)
    }

    /// Read-only settlement state of a Promise value this core created
    /// (`Value::Promise(handle)`); `None` for an unknown handle.
    pub fn promise_state(&self, promise: u32) -> Option<crate::promise_model::PromiseState> {
        self.promise_store
            .get(crate::promise_model::PromiseHandle(promise))
            .ok()
            .map(|record| record.state.clone())
    }

    pub(super) fn execute_ephemeral(
        &mut self,
        module: &Ir3Module,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_trace_handoff(module, None, TraceHandoff::DrainEphemeralCore)
    }

    pub(super) fn execute_ephemeral_with_compact_tier1(
        &mut self,
        module: &Ir3Module,
        compact_tier1: &CompactTier1Program,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_trace_handoff(
            module,
            Some(compact_tier1),
            TraceHandoff::DrainEphemeralCore,
        )
    }

    pub(super) fn execute_with_trace_handoff(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
        trace_handoff: TraceHandoff,
    ) -> Result<ExecutionResult, InterpreterError> {
        if let Some(program) = compact_tier1 {
            program.validate_module(module)?;
        }
        crate::ir_contract::verify_ir3_specialization(module).map_err(|error| {
            InterpreterError::TypeError {
                expected: "supported, structurally valid engine IR3 module".to_string(),
                got: error.to_string(),
            }
        })?;
        self.ensure_vm_dispatch_capability()?;
        let entry_specifier = self.prepare_execution(module)?;
        self.process_exit_code = None;
        let entry_frame_widths = match compact_tier1 {
            Some(program) => Some(program.verified_function_frame_clear_widths.clone())
                .filter(|widths| !widths.is_empty()),
            None => CompactTier1Program::verified_frame_widths(module),
        };
        let previous_entry_frame_widths = std::mem::replace(
            &mut self.entry_frame_widths,
            entry_frame_widths.map(|widths| (Self::module_address(module), widths)),
        );
        let result = match self.run_top_level_execution(module, compact_tier1) {
            // `process.exit(code)` ends the program normally (bd-my9hk): the
            // run completes with that exit code rather than failing.
            Err(InterpreterError::ProcessExit { code }) => {
                self.process_exit_code = Some(code);
                Ok(LabeledReturn {
                    value: Value::Undefined,
                    label: Label::Public,
                })
            }
            other => other,
        };
        self.entry_frame_widths = previous_entry_frame_widths;
        // Final capture opportunity: a request equal to the trace's final
        // event count observes end-of-execution state (bd-fqlfw.3.5.5).
        self.check_state_capture_boundary();
        self.record_execution_outcome(&entry_specifier, &result);
        self.last_post_run_epoch = Some(self.seed_epoch);
        self.finish_execution_result_with_trace_handoff(result, trace_handoff)
    }

    /// Arm a deterministic interpreter-state capture at the given
    /// nondeterminism tick (trace event count) for the next `execute` run
    /// (bd-fqlfw.3.5.5 / E3.T5d). The capture fires at the first
    /// instruction boundary (or end of execution) where the trace's event
    /// count reaches the tick; only an exact count match produces an
    /// observation — when a single instruction emitted several events and
    /// no boundary landed on the tick, the request disarms uncaptured and
    /// the caller fails closed.
    pub fn arm_state_capture_at_tick(&mut self, tick: u64) {
        self.state_capture_tick = Some(tick);
        let released_bytes = self.state_capture_memory_bytes();
        self.state_capture_result = None;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    /// Take the observation produced by an armed state capture, if the
    /// boundary landed exactly on the requested tick.
    pub fn take_captured_state(&mut self) -> Option<CapturedInterpreterState> {
        let released_bytes = self.state_capture_memory_bytes();
        let captured = self.state_capture_result.take();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        captured
    }

    /// Number of nondeterminism events captured so far (the debugger's
    /// tick domain).
    pub fn nondeterminism_event_count(&self) -> u64 {
        self.nondeterminism_trace.event_count() as u64
    }

    /// Read-only view of the nondeterminism trace captured so far. The
    /// time-travel debugger's state producer compares a re-execution's
    /// trace against the loaded trace to fail closed when the supplied
    /// module does not correspond to the trace (bd-fqlfw.3.5.5).
    pub fn nondeterminism_trace_ref(&self) -> &NondeterminismTrace {
        &self.nondeterminism_trace
    }

    /// Instruction-boundary check for an armed state capture. O(1) when
    /// disarmed or already captured: the dispatch loop runs it before every
    /// instruction, so the disarmed check is inlined there and the rest is
    /// out of line (bd-9vouw.329).
    #[inline]
    pub(super) fn check_state_capture_boundary(&mut self) {
        if let Some(requested) = self.state_capture_tick {
            self.capture_state_at_armed_boundary(requested);
        }
    }

    #[cold]
    #[inline(never)]
    pub(super) fn capture_state_at_armed_boundary(&mut self, requested: u64) {
        let seen = self.nondeterminism_event_count();
        if seen < requested {
            return;
        }
        if seen == requested {
            let projection_working_bytes = self.capture_label_projection_working_bytes();
            if self
                .check_temporary_memory_budget(projection_working_bytes)
                .is_ok()
            {
                let heap_label_sources = self.capture_heap_label_sources();
                let captured_bytes =
                    self.estimate_projected_captured_state_bytes(&heap_label_sources);
                if self
                    .check_temporary_memory_budget(
                        captured_bytes.saturating_add(projection_working_bytes),
                    )
                    .is_ok()
                    && self.apply_memory_component_delta(0, captured_bytes).is_ok()
                {
                    let captured = self.capture_interpreter_state(seen, &heap_label_sources);
                    debug_assert_eq!(
                        captured_bytes,
                        Self::estimate_captured_state_bytes(&captured)
                    );
                    self.state_capture_result = Some(captured);
                }
            }
        }
        // seen > requested: no boundary landed exactly on the tick — stay
        // uncaptured (fail-closed). Either way the request is satisfied.
        self.state_capture_tick = None;
    }

    /// Snapshot registers (value + label) and live heap objects (with
    /// labels derived by joining, onto each object, the label of every
    /// register from whose value it is transitively reachable via property
    /// values, private collection storage and prototype links). See
    /// [`CapturedHeapState`] for why this
    /// is a projection of the register-granularity IFC state.
    pub(super) fn capture_label_projection_working_bytes(&self) -> u64 {
        u64::try_from(self.heap.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(
                (std::mem::size_of::<Option<usize>>()
                    + std::mem::size_of::<u32>()
                    + std::mem::size_of::<bool>()) as u64,
            )
    }

    /// For every heap object, identify the register whose label wins the
    /// reachability join. `Label::join` selects one operand by its full
    /// deterministic order, so retaining a source index is enough to estimate
    /// and later clone the exact result without cloning labels during preflight.
    pub(super) fn capture_heap_label_sources(&self) -> Vec<Option<usize>> {
        let mut heap_label_sources = vec![None; self.heap.len()];
        let mut frontier = Vec::with_capacity(self.heap.len());
        let mut queued = vec![false; self.heap.len()];
        for (register_index, value) in self.registers.iter().enumerate() {
            if matches!(value, Value::Undefined) {
                continue;
            }
            frontier.clear();
            queued.fill(false);
            Self::queue_object_id_from_value(value, &mut frontier, &mut queued);
            while let Some(object_index) = frontier.pop() {
                let object_id = ObjectId(object_index);
                let object_index = object_index as usize;
                if object_index >= self.heap.len() {
                    continue;
                }
                let candidate = self
                    .register_labels
                    .get(register_index)
                    .unwrap_or(&Label::Public);
                let replace = heap_label_sources[object_index].is_none_or(|existing_index| {
                    let existing = self
                        .register_labels
                        .get(existing_index)
                        .unwrap_or(&Label::Public);
                    candidate > existing
                });
                if replace {
                    heap_label_sources[object_index] = Some(register_index);
                }
                let object = &self.heap[object_index];
                for property_value in object.properties.all_data_values() {
                    Self::queue_object_id_from_value(property_value, &mut frontier, &mut queued);
                }
                if let Some(storage) = object.collection_storage.as_deref() {
                    Self::queue_object_id_from_value(
                        &Value::Object(*storage),
                        &mut frontier,
                        &mut queued,
                    );
                }
                if let Some(target) = object.weak_ref_target.as_deref() {
                    Self::queue_object_id_from_value(&target.value, &mut frontier, &mut queued);
                }
                if let Some(prototype) = object.prototype {
                    Self::queue_object_id_from_value(
                        &Value::Object(prototype),
                        &mut frontier,
                        &mut queued,
                    );
                }
                // URL.searchParams is a native authenticated edge stored
                // outside guest-visible heap properties. State captures must
                // traverse it exactly like an ordinary property so a label on
                // the URL reaches the semantically reachable params object.
                if let Some(state) = self.url_objects.get(&object_id) {
                    Self::queue_object_id_from_value(
                        &Value::Object(state.search_params),
                        &mut frontier,
                        &mut queued,
                    );
                }
            }
        }
        heap_label_sources
    }

    pub(super) fn estimate_projected_captured_state_bytes(
        &self,
        heap_label_sources: &[Option<usize>],
    ) -> u64 {
        let register_count = self
            .registers
            .iter()
            .filter(|value| !matches!(value, Value::Undefined))
            .count();
        u64::try_from(register_count)
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<CapturedRegisterState>() as u64)
            .saturating_add(Self::saturating_sum(
                self.registers
                    .iter()
                    .enumerate()
                    .filter(|(_, value)| !matches!(value, Value::Undefined))
                    .map(|(index, value)| {
                        Self::estimate_value_bytes(value).saturating_add(
                            self.register_labels
                                .get(index)
                                .map(Self::estimate_label_bytes)
                                .unwrap_or(0),
                        )
                    }),
            ))
            .saturating_add(
                u64::try_from(self.heap.live_len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<CapturedHeapState>() as u64),
            )
            .saturating_add(Self::saturating_sum(self.heap.iter_live().map(
                |(index, object)| {
                    Self::estimate_heap_object_bytes(object).saturating_add(
                        heap_label_sources
                            .get(index)
                            .and_then(|source| *source)
                            .and_then(|source| self.register_labels.get(source))
                            .map(Self::estimate_label_bytes)
                            .unwrap_or(0),
                    )
                },
            )))
            .saturating_add(Self::estimate_symbol_state_bytes(&self.symbol_state))
    }

    pub(super) fn capture_interpreter_state(
        &self,
        tick: u64,
        heap_label_sources: &[Option<usize>],
    ) -> CapturedInterpreterState {
        let registers: Vec<CapturedRegisterState> = self
            .registers
            .iter()
            .enumerate()
            .filter(|(_, value)| !matches!(value, Value::Undefined))
            .map(|(index, value)| CapturedRegisterState {
                register: index as u32,
                value: value.clone(),
                label: self
                    .register_labels
                    .get(index)
                    .cloned()
                    .unwrap_or(Label::Public),
            })
            .collect();

        let heap: Vec<CapturedHeapState> = self
            .heap
            .iter_live()
            .map(|(index, object)| CapturedHeapState {
                object_id: ObjectId(index as u32),
                object: object.clone(),
                label: heap_label_sources
                    .get(index)
                    .and_then(|source| *source)
                    .and_then(|source| self.register_labels.get(source))
                    .cloned()
                    .unwrap_or(Label::Public),
            })
            .collect();

        CapturedInterpreterState {
            tick,
            registers,
            heap,
            symbol_state: self.symbol_state.value.clone(),
        }
    }

    /// Queue one directly referenced heap object at most once per traversal.
    /// Marking on enqueue bounds the frontier by `heap.len()` even when an
    /// object exposes many properties that all reference the same target.
    pub(super) fn queue_object_id_from_value(
        value: &Value,
        out: &mut Vec<u32>,
        queued: &mut [bool],
    ) {
        if let Value::Object(object_id) = value {
            let index = object_id.0 as usize;
            if let Some(was_queued) = queued.get_mut(index)
                && !*was_queued
            {
                *was_queued = true;
                out.push(object_id.0);
            }
        }
    }

    pub(super) fn ensure_vm_dispatch_capability(&mut self) -> Result<(), InterpreterError> {
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::VmDispatch)
        {
            // Capture security violation for deterministic replay
            self.nondeterminism_trace.capture(
                NondeterminismSource::SecurityViolation,
                b"vm_dispatch_capability_denied".to_vec(),
                self.instructions_executed,
                "baseline_interpreter",
            );
            return Err(InterpreterError::CapabilityDenied {
                capability: "VmDispatch".to_string(),
            });
        }

        Ok(())
    }

    pub(super) fn prepare_execution(
        &mut self,
        module: &Ir3Module,
    ) -> Result<String, InterpreterError> {
        // Containment hooks observe EXTENSION behavior; nothing the extension
        // wrote has run yet during preparation, so engine-internal setup
        // allocations (module-namespace record, runtime globals) must not
        // trigger them. Otherwise a deny-allocation policy terminates every
        // program at instruction 0 before its first real instruction
        // (bd-gug3l). The flag is cleared on every exit path below.
        self.preparing_execution = true;
        let result = self.prepare_execution_inner(module);
        self.preparing_execution = false;
        result
    }

    pub(super) fn prepare_execution_inner(
        &mut self,
        module: &Ir3Module,
    ) -> Result<String, InterpreterError> {
        // Writes clear `last_post_run_epoch` before incrementing the epoch, so
        // equality cannot be resurrected by a wrapping counter (bd-bgq16).
        let repeat_execute =
            self.last_pre_run_seed.is_some() && self.last_post_run_epoch == Some(self.seed_epoch);
        if let Some(mut sandbox) = self.active_sandbox.get() {
            // A restriction survives into the new run, but its witness must
            // refer to this module's entry, not an instruction in the previous
            // module. Preserve the installed ceiling exactly, even when a
            // smaller restored heap would otherwise create fresh headroom.
            sandbox.instruction_index = 0;
            sandbox.timestamp_tick = if repeat_execute {
                0
            } else {
                self.instructions_executed
            };
            self.active_sandbox.set(Some(sandbox));
            self.sandbox_witness_pending.set(true);
        }
        let seed = if repeat_execute {
            self.last_pre_run_seed
                .clone()
                .expect("repeat_execute requires a previous pre-run seed")
        } else {
            self.last_pre_run_seed = None;
            self.last_post_run_epoch = None;
            self.prune_dead_pending_execution_seeds();
            self.capture_execution_seed()?
        };
        self.last_pre_run_seed = Some(seed.clone());
        self.top_level_await_resumption_contexts.clear();
        self.clear_top_level_await_outcome();
        self.rotate_generated_function_realm()?;
        self.reset_execution_state_from_seed(&seed)?;
        if repeat_execute {
            self.reset_repeat_execution_state()?;
        }
        // perf: hot path - avoid double clone of source_label
        let entry_specifier = module.header.source_label.clone();
        if let Some(installed) = &self.module_resolver
            && installed.resolver.entry_referrer() != entry_specifier
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: entry_specifier,
                error: "runtime resolver entry identity does not match executable module"
                    .to_string(),
            });
        }
        self.ensure_module_record(module, &entry_specifier)?;
        if let Some(installed) = &self.module_resolver
            && let Some(record) = self.module_state.modules.get_mut(&entry_specifier)
        {
            record.resolved_source_hash = Some(installed.entry_hash);
        }
        if let Some(ceiling) = self.entry_flow_label_ceiling.take() {
            let outcome = self.set_module_flow_label_ceiling(&entry_specifier, &ceiling);
            self.entry_flow_label_ceiling = Some(ceiling);
            outcome?;
        }
        self.entry_module_specifier = Some(entry_specifier.clone());
        self.current_module_specifier = Some(entry_specifier);
        self.active_generated_function_artifact = None;
        self.inject_runtime_globals()?;

        self.push_event("execution_started", "ok", None);

        Ok(module.header.source_label.clone())
    }

    /// Complete the repeat-execute restore contract (bd-bgq16). The seed
    /// restore in `prepare_execution_inner` rolled registers/heap/prototypes/
    /// symbols back to the previous run's pre-run state, so every piece of
    /// execution state the previous run produced — in particular every table
    /// that holds or is keyed by heap `ObjectId`s — must be dropped before
    /// `ensure_module_record` / `inject_runtime_globals` allocate again.
    /// Keeping any of it alive aliases rolled-back ids: the stale entry
    /// module record's `namespace_object` names an id past the restored heap
    /// end, and the first post-restore allocation (`process.argv`) would
    /// receive that id, letting later `ExportBinding` writes mutate `argv`
    /// through the aliased namespace.
    ///
    /// Register IFC labels are deliberately NOT reset: `set_register_label`
    /// does not advance the seed epoch, so a caller-written label is
    /// indistinguishable here from a run-written one; retaining labels can
    /// only over-taint, never under-taint.
    pub(super) fn reset_repeat_execution_state(&mut self) -> Result<(), InterpreterError> {
        // Dispatch-local state. The previous run parked `ip` on its final
        // `Halt`; without this reset a repeat execute re-halts immediately
        // and returns the stale r0 (the false positive the old repeat test
        // could not see).
        self.ip = 0;
        self.register_base = 0;
        self.register_width = self.config.max_registers as usize;
        self.call_stack.clear(&mut self.closures.cold_cells);
        self.catch_frames.clear();
        self.pending_exception = None;
        self.pending_exception_label = Label::Public;
        self.pending_hostcall_result_label = None;
        self.pending_return = None;
        self.suspended_abrupt_completions.clear();
        self.finally_frames.clear();
        self.pending_finally_entry = None;
        self.pending_captures.clear();
        self.scope_chain = ScopeChain::new();
        self.runtime_name_references.clear();
        self.module_reentrant_call_depth = 0;
        self.active_foreign_module_call_depth = 0;
        self.isolated_async_entry_pending = false;
        // A repeat run replays the previous run's budget and trace domain
        // from zero; both accumulate across `execute` calls otherwise.
        self.instructions_executed = 0;
        self.native_hole_reads.set(0);
        self.tier_i_instructions_executed = 0;
        self.tier_i_specialized_instructions_executed = 0;
        self.nondeterminism_trace = NondeterminismTrace::new(&self.trace_id);

        // Execution stores produced by the rolled-back run. The restored
        // pre-run registers and heap cannot reference these: closures,
        // iterator states, generators, promises, timers, and module records
        // only come into existence during execution, and any caller mutation
        // between runs routes through the non-repeat fresh-seed path.
        self.iterators.clear();
        for object_id in self
            .mapped_argument_bindings
            .keys()
            .copied()
            .collect::<Vec<_>>()
        {
            self.disconnect_all_mapped_arguments(object_id);
        }
        self.closures.clear();
        self.closure_method_metadata.clear();
        self.closure_lexical_super_metadata.clear();
        self.arrow_lexical_this.clear();
        self.closure_module_origins.clear();
        self.closure_generated_function_artifacts.clear();
        for generator in self.generators.iter_mut() {
            self.closures
                .replace_activation(&mut generator.execution, None);
        }
        self.generators.clear();
        self.generator_yielded = false;
        self.generator_resume_dst = None;
        self.generator_result_label = Label::Public;
        self.generator_delegation = None;
        for function in self.async_functions.iter_mut() {
            self.closures
                .replace_activation(&mut function.isolated_execution, None);
        }
        self.async_functions.clear();
        self.async_generators.clear();
        self.async_generator_runtime = AsyncGeneratorRuntime::default();
        self.async_resumption_contexts.clear();
        self.promise_store = crate::promise_model::PromiseStore::new();
        self.event_loop = crate::promise_model::EventLoop::new();
        self.promise_combinators.clear();
        self.promise_combinator_watchers.clear();
        self.promise_combinators_bytes = 0;
        self.promise_combinator_watchers_bytes = 0;
        self.array_join_stack.clear();
        self.promise_in_flight_task_bytes = 0;
        self.promise_reaction_callables.clear();
        self.next_promise_reaction_callable_id = PROMISE_REACTION_CALLABLE_BASE;
        self.next_tick_queue.clear();
        self.next_timer_id = 0;
        self.active_timers.clear();
        self.pending_timer_tasks.clear();
        self.unref_timer_ids.clear();
        self.atomics_async_waiters.clear();
        self.pending_stream_emissions.clear();

        // Weak collection entries and their owner labels were restored with
        // the seeded heap. Clearing them here would invalidate seeded owners.
        // These remaining tables are execution-local.
        self.gc_remembered_set.clear();
        self.module_state.modules.clear();
        self.module_state.retained_program_bytes = 0;
        for entry in self.module_state.live_exports.drain(..) {
            self.closures.cold_cells.release_cell(&entry.cell);
        }
        self.pending_async_module_import = None;
        self.active_cjs_context = None;

        // The clears above released many independently-charged memory
        // components; resynchronize the estimate from live state so the
        // exactness invariant (`estimated == recompute`) holds by
        // construction at this boundary.
        self.sync_estimated_memory_bytes()?;
        Ok(())
    }

    /// Drain the entry's first-tick checkpoint. A failed entry or checkpoint
    /// never admits another host task, including queued dynamic imports.
    pub(super) fn drain_after_top_level(
        &mut self,
        module: &Ir3Module,
        script_ok: bool,
    ) -> Result<(), InterpreterError> {
        // Writable completion callbacks occupy Node's internal stream-tick
        // checkpoint ahead of Promise/nextTick work and Immediate macrotasks.
        self.drain_runtime_checkpoint(Some(module))?;
        if !script_ok {
            return Ok(());
        }
        // The end of the entry's first tick: a rejection nothing handled by
        // now fails the program before any timer runs, as in Node.
        self.raise_unhandled_rejection()?;
        self.run_event_loop_until_idle_with_module(Some(module))
    }

    pub(super) fn run_top_level_execution(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<LabeledReturn, InterpreterError> {
        let result = if self.config.commonjs_entry {
            // bd-rff5g: a host-declared CommonJS entry, lowered with the
            // authenticated wrapper bindings, runs exactly like a module
            // loaded through `require`: the same wrapper environment, the
            // same `module.exports` finalization. Its completion value is not
            // observable, as in Node.
            let entry = self
                .entry_module_specifier
                .clone()
                .unwrap_or_else(|| module.header.source_label.clone());
            self.gc_set_cjs_entry_pending(true);
            let result = self.evaluate_cjs_ir3(module, &entry);
            self.gc_set_cjs_entry_pending(false);
            result.map(|()| LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            })
        } else {
            let previous_compact_tier1 = std::mem::replace(
                &mut self.top_level_compact_tier1,
                compact_tier1.map(|program| (Self::module_address(module), program.clone())),
            );
            let previous_gc_depth = self.gc_arm_top_level();
            let result = self.run_loop_labeled_with_compact_tier1(module, compact_tier1);
            self.gc_restore_safe_depth(previous_gc_depth);
            self.top_level_compact_tier1 = previous_compact_tier1;
            result
        };
        // A terminal runtime/security failure revokes guest execution, not
        // just the current stack. In particular, a queued Promise reaction,
        // nextTick, or Writable callback must not perform another host effect
        // after containment or a capability/budget denial. Return before
        // materializing scopes or draining jobs, preserving the first error.
        // Ordinary JavaScript throws retain their existing checkpoint rules.
        if result.as_ref().is_err_and(Self::stops_guest_execution) {
            return result;
        }
        if result.is_err() {
            // Tier-R leaves the failing callee's captured environment and
            // fresh local scope installed while checkpoints drain. Reify the
            // otherwise virtual leaf activation at the same boundary so
            // callbacks observe identical scope and snapshot-budget state.
            self.materialize_scope_inert_terminal_frame()?;
        }
        let suspended_at_top_level_await = !self.top_level_await_resumption_contexts.is_empty();

        // The collector may run between event-loop jobs (bd-9vouw.57). The
        // script's completion value is held in `result` across that phase.
        let completion = result
            .as_ref()
            .ok()
            .map(|completion| completion.value.clone());
        self.gc_arm_event_loop(completion);
        let script_ok = matches!(&result, Ok(_) | Err(InterpreterError::Halted));
        let drained = self.drain_after_top_level(module, script_ok);
        self.gc_disarm_event_loop();
        drained?;

        if let Some(resumed_outcome) = self.take_top_level_await_outcome() {
            return resumed_outcome;
        }

        if suspended_at_top_level_await && !self.top_level_await_resumption_contexts.is_empty() {
            let got = if self.event_loop.has_pending_work() {
                "pending module Promise after the deterministic event-loop turn limit"
            } else {
                "pending module Promise with no remaining event-loop work"
            };
            return Err(InterpreterError::TypeError {
                expected: "top-level await to settle before the event loop became idle".to_string(),
                got: got.to_string(),
            });
        }

        result
    }

    pub(super) fn record_execution_outcome(
        &mut self,
        entry_specifier: &str,
        result: &Result<LabeledReturn, InterpreterError>,
    ) {
        if let Some(record) = self.module_state.modules.get_mut(entry_specifier) {
            record.status = match result {
                Ok(_) | Err(InterpreterError::Halted) => ModuleRuntimeStatus::Evaluated,
                Err(err) => ModuleRuntimeStatus::Failed(err.to_string()),
            };
        }

        match result {
            Ok(_) => self.push_event("execution_completed", "ok", None),
            Err(InterpreterError::Halted) => {
                self.push_event("execution_halted", "ok", None);
            }
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                self.push_event(
                    "execution_contained",
                    "contained",
                    Some(&format_requested_hook_action(
                        action.as_str(),
                        reason.as_deref(),
                    )),
                );
            }
            Err(e) => {
                self.push_event("execution_failed", "fail", Some(&format!("{e}")));
            }
        }
    }

    #[cfg(test)]
    pub(super) fn finish_execution_result(
        &mut self,
        result: Result<LabeledReturn, InterpreterError>,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.finish_execution_result_with_trace_handoff(result, TraceHandoff::RetainInCore)
    }

    pub(super) fn finish_execution_result_with_trace_handoff(
        &mut self,
        result: Result<LabeledReturn, InterpreterError>,
        trace_handoff: TraceHandoff,
    ) -> Result<ExecutionResult, InterpreterError> {
        match result {
            Ok(completion) => {
                self.emit_witness(WitnessEventKind::ExecutionCompleted, None);
                Ok(self.take_execution_result_with_trace_handoff(completion, None, trace_handoff))
            }
            Err(InterpreterError::Halted) => {
                // Halt is normal termination; return whatever is in r0 with
                // the label it carries there.
                let value = self.read_reg(0).unwrap_or(Value::Undefined);
                let label = self.get_register_label(0).cloned().unwrap_or(Label::Public);
                self.emit_witness(WitnessEventKind::ExecutionCompleted, None);
                Ok(self.take_execution_result_with_trace_handoff(
                    LabeledReturn { value, label },
                    None,
                    trace_handoff,
                ))
            }
            Err(e) => Err(e),
        }
    }

    pub(super) fn module_execution_snapshot_memory_bytes(&self) -> u64 {
        // `estimate_value_vec_bytes(&self.registers)`, with the values' share
        // from the cached sum.
        u64::try_from(self.registers.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Value>() as u64)
            .saturating_add(self.registers_memory_bytes())
            .saturating_add(self.generator_delegation_memory_bytes())
            .saturating_add(
                u64::try_from(self.register_labels.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<Label>() as u64),
            )
            .saturating_add(self.register_context_labels_memory_bytes())
            .saturating_add(
                u64::try_from(self.call_stack.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<CallFrame>() as u64),
            )
            .saturating_add(self.module_snapshot_call_stack_memory_bytes())
            .saturating_add(
                u64::try_from(self.catch_frames.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<CatchFrame>() as u64),
            )
            .saturating_add(Self::estimate_scope_chain_shallow_clone_bytes(
                &self.scope_chain.frames,
            ))
            .saturating_add(
                u64::try_from(self.pending_captures.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<u32>() as u64),
            )
            .saturating_add(
                self.current_module_specifier
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn generated_code_event_fields(
        kind: GeneratedCodeEventKind,
    ) -> (&'static str, &'static str) {
        match kind {
            GeneratedCodeEventKind::Constructed => ("generated_code.constructed", "ok"),
            GeneratedCodeEventKind::Invoked => ("generated_code.invoked", "ok"),
            GeneratedCodeEventKind::Faulted => ("generated_code.faulted", "fail"),
        }
    }

    pub(super) fn decimal_digits(value: u64) -> u64 {
        if value == 0 {
            return 1;
        }
        value.ilog10() as u64 + 1
    }

    pub(super) fn generated_code_event_error_code_len(entry: &GeneratedCodeAuditEntry) -> u64 {
        u64::try_from(entry.source_id.len())
            .unwrap_or(u64::MAX)
            .saturating_add(" consumed=".len() as u64)
            .saturating_add(Self::decimal_digits(entry.instructions_consumed))
            .saturating_add(" outcome=".len() as u64)
            .saturating_add(u64::try_from(entry.outcome.len()).unwrap_or(u64::MAX))
    }

    pub(super) fn estimate_interpreter_event_bytes(event: &InterpreterEvent) -> u64 {
        (std::mem::size_of::<InterpreterEvent>() as u64)
            .saturating_add(Self::estimate_string_bytes(&event.trace_id))
            .saturating_add(Self::estimate_string_bytes(&event.component))
            .saturating_add(Self::estimate_string_bytes(&event.event))
            .saturating_add(Self::estimate_string_bytes(&event.outcome))
            .saturating_add(
                event
                    .error_code
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_generated_code_event_bytes(
        &self,
        entry: &GeneratedCodeAuditEntry,
    ) -> u64 {
        let (event_name, event_outcome) = Self::generated_code_event_fields(entry.kind);
        (std::mem::size_of::<InterpreterEvent>() as u64)
            .saturating_add(Self::estimate_string_bytes(&self.trace_id))
            .saturating_add(Self::estimate_string_bytes(COMPONENT))
            .saturating_add(Self::estimate_string_bytes(event_name))
            .saturating_add(Self::estimate_string_bytes(event_outcome))
            .saturating_add(
                MEMORY_ESTIMATE_STRING_BASE_BYTES
                    .saturating_add(Self::generated_code_event_error_code_len(entry)),
            )
    }

    pub(super) fn estimate_generated_code_audit_entry_bytes(
        entry: &GeneratedCodeAuditEntry,
    ) -> u64 {
        let capability_slots = u64::try_from(entry.granted_capabilities.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<String>() as u64);
        (std::mem::size_of::<GeneratedCodeAuditEntry>() as u64)
            .saturating_add(Self::estimate_string_bytes(&entry.source_id))
            .saturating_add(Self::estimate_string_bytes(&entry.source_hash))
            .saturating_add(Self::estimate_string_bytes(&entry.parameter_hash))
            .saturating_add(Self::estimate_string_bytes(&entry.construction_site))
            .saturating_add(capability_slots)
            .saturating_add(Self::saturating_sum(
                entry
                    .granted_capabilities
                    .iter()
                    .map(|capability| Self::estimate_string_bytes(capability)),
            ))
            .saturating_add(Self::estimate_string_bytes(&entry.outcome))
    }

    pub(super) fn estimate_generated_code_observability_pair_bytes(
        &self,
        entry: &GeneratedCodeAuditEntry,
    ) -> u64 {
        self.estimate_generated_code_event_bytes(entry)
            .saturating_add(Self::estimate_generated_code_audit_entry_bytes(entry))
    }

    pub(super) fn is_generated_code_interpreter_event(event: &InterpreterEvent) -> bool {
        event.component == COMPONENT
            && matches!(
                event.event.as_str(),
                "generated_code.constructed" | "generated_code.invoked" | "generated_code.faulted"
            )
    }

    pub(super) fn generated_code_observability_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.generated_code_audit
                .iter()
                .map(Self::estimate_generated_code_audit_entry_bytes),
        )
        .saturating_add(Self::saturating_sum(
            self.events
                .iter()
                .filter(|event| Self::is_generated_code_interpreter_event(event))
                .map(Self::estimate_interpreter_event_bytes),
        ))
    }

    /// Logical ownership of the general (non-generated-code) structured events
    /// in `events` (bd-zaeeh). The generated-code events are excluded here
    /// because they are charged by [`Self::generated_code_observability_memory_bytes`];
    /// the two partitions together cover `events` with no double-count.
    pub(super) fn general_interpreter_events_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.events
                .iter()
                .filter(|event| !Self::is_generated_code_interpreter_event(event))
                .map(Self::estimate_interpreter_event_bytes),
        )
    }

    pub(super) fn generated_code_interpreter_event(
        &self,
        entry: &GeneratedCodeAuditEntry,
    ) -> InterpreterEvent {
        let (event_name, event_outcome) = Self::generated_code_event_fields(entry.kind);
        InterpreterEvent {
            trace_id: self.trace_id.clone(),
            component: COMPONENT.to_string(),
            event: event_name.to_string(),
            outcome: event_outcome.to_string(),
            error_code: Some(format!(
                "{} consumed={} outcome={}",
                entry.source_id, entry.instructions_consumed, entry.outcome
            )),
        }
    }

    pub(super) fn estimate_generated_function_provenance_bytes(
        provenance: &GeneratedFunctionProvenance,
    ) -> u64 {
        Self::estimate_string_bytes(&provenance.source_id)
            .saturating_add(Self::estimate_string_bytes(&provenance.source_hash))
            .saturating_add(Self::estimate_string_bytes(&provenance.parameter_hash))
            .saturating_add(Self::estimate_string_bytes(&provenance.construction_site))
    }

    pub(super) fn estimate_generated_function_artifact_dynamic_bytes(
        artifact: &GeneratedFunctionArtifact,
    ) -> u64 {
        Self::estimate_string_bytes(&artifact.owner_specifier)
            .saturating_add(Self::estimate_generated_function_provenance_bytes(
                &artifact.provenance,
            ))
            .saturating_add(Self::estimate_label_bytes(&artifact.source_label))
            .saturating_add(
                Self::retained_module_program_bytes(artifact.compiled_module.as_ref(), "")
                    .saturating_sub(Self::estimate_string_bytes("")),
            )
    }

    pub(super) fn estimate_generated_function_artifact_entry_bytes(
        artifact: &GeneratedFunctionArtifact,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<ContentHash>() as u64)
            .saturating_add(std::mem::size_of::<GeneratedFunctionArtifact>() as u64)
            .saturating_add(Self::estimate_generated_function_artifact_dynamic_bytes(
                artifact,
            ))
    }

    pub(super) fn estimate_generated_function_store_base_bytes(
        store: &GeneratedFunctionStore,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<ContentHash>() as u64)
            .saturating_add(std::mem::size_of::<GeneratedFunctionStore>() as u64)
            .saturating_add(Self::estimate_string_bytes(&store.owner_specifier))
    }

    pub(super) fn generated_function_stores_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.module_state
                .generated_function_stores
                .values()
                .map(|store| {
                    Self::estimate_generated_function_store_base_bytes(store).saturating_add(
                        Self::saturating_sum(
                            store
                                .artifacts
                                .values()
                                .map(Self::estimate_generated_function_artifact_entry_bytes),
                        ),
                    )
                }),
        )
    }

    pub(super) fn generated_function_handle_peak_bytes() -> u64 {
        // `to_hex()` allocates two 64-byte strings, `format!` allocates the
        // 138-byte composite, and converting that String into `Arc<str>` may
        // briefly retain both composite buffers. Four final-sized strings are
        // a conservative upper bound for that short construction peak.
        MEMORY_ESTIMATE_STRING_BASE_BYTES
            .saturating_add(138)
            .saturating_mul(4)
    }

    pub(super) fn active_module_execution_memory_bytes(&self) -> u64 {
        self.registers_memory_bytes()
            .saturating_add(self.generator_delegation_memory_bytes())
            .saturating_add(self.register_context_labels_memory_bytes())
            .saturating_add(self.scope_chain_memory_bytes())
            .saturating_add(self.call_stack_memory_bytes())
    }

    pub(super) fn snapshot_module_execution(
        &mut self,
    ) -> Result<ModuleExecutionSnapshot, InterpreterError> {
        let accounted_bytes = self.charge_module_execution_snapshot()?;
        let registers = self.registers.to_vec();
        let register_bytes = self.registers_memory_bytes();
        let register_labels = self.register_labels.clone();
        let register_label_bytes = self.register_labels_memory_bytes();
        Ok(self.module_execution_snapshot(
            accounted_bytes,
            registers,
            register_bytes,
            register_labels,
            register_label_bytes,
        ))
    }

    /// [`Self::snapshot_module_execution`] for an isolated callback, which
    /// starts on a fresh register file with every label Public. The caller's
    /// registers and labels move into the snapshot rather than being cloned
    /// there and then overwritten in place. What is left is an `Undefined`
    /// file of `max_registers` slots and a Public label file of the same length
    /// as before, as the overwrite left them.
    pub(super) fn isolate_module_execution(
        &mut self,
    ) -> Result<ModuleExecutionSnapshot, InterpreterError> {
        let accounted_bytes = self.charge_module_execution_snapshot()?;
        // The spare files are cleared throughout (bd-9vouw.500).
        let (mut fresh_registers, mut fresh_labels) =
            self.take_spare_register_files(self.config.max_registers as usize);
        fresh_registers.resize(self.config.max_registers as usize, Value::Undefined);
        fresh_labels.resize(self.register_labels.len(), Label::Public);
        let register_bytes = self.registers_memory_bytes();
        let registers = std::mem::replace(&mut self.registers.value, fresh_registers);
        // `Undefined` carries no bytes beyond its slot.
        self.registers_value_bytes.set(Some(0));
        let register_label_bytes = self.register_labels_memory_bytes();
        let register_labels = std::mem::replace(&mut self.register_labels, fresh_labels);
        self.all_register_labels_public = true;
        // A Public label owns no bytes beyond its slot.
        self.register_labels_bytes.set(Some(0));
        let snapshot = self.module_execution_snapshot(
            accounted_bytes,
            registers,
            register_bytes,
            register_labels,
            register_label_bytes,
        );
        self.pc_label_stack.clear();
        // The fresh files are clear throughout (bd-9vouw.499).
        self.register_dirty_end = 0;
        Ok(snapshot)
    }

    /// Charge a module-execution snapshot of the current state to the budget
    /// and return its accounted bytes.
    pub(super) fn charge_module_execution_snapshot(&mut self) -> Result<u64, InterpreterError> {
        let accounted_bytes = self.module_execution_snapshot_memory_bytes();
        self.apply_memory_component_delta(0, accounted_bytes)?;
        self.module_snapshot_in_flight_bytes = self
            .module_snapshot_in_flight_bytes
            .saturating_add(accounted_bytes);
        Ok(accounted_bytes)
    }

    /// The snapshot of the current state with `registers` (whose
    /// [`Self::registers_memory_bytes`] is `register_bytes`) and
    /// `register_labels` as its register and label files.
    pub(super) fn module_execution_snapshot(
        &self,
        accounted_bytes: u64,
        registers: Vec<Value>,
        register_bytes: u64,
        register_labels: Vec<Label>,
        register_label_bytes: u64,
    ) -> ModuleExecutionSnapshot {
        ModuleExecutionSnapshot {
            accounted_bytes,
            registers,
            register_bytes,
            generator_delegation: self.generator_delegation.clone(),
            register_labels,
            register_label_bytes,
            register_dirty_end: self.register_dirty_end,
            active_inline_callback_context_label: self.active_inline_callback_context_label.clone(),
            pc_label_stack: self.pc_label_stack.clone(),
            call_stack: self.call_stack.to_vec(),
            ip: self.ip,
            register_base: self.register_base,
            register_width: self.register_width,
            catch_frames: self.catch_frames.clone(),
            pending_exception: self.pending_exception.clone(),
            pending_exception_label: self.pending_exception_label.clone(),
            pending_hostcall_result_label: self.pending_hostcall_result_label.clone(),
            pending_return: self.pending_return.clone(),
            suspended_abrupt_completions: self.suspended_abrupt_completions.clone(),
            finally_frames: self.finally_frames.clone(),
            pending_finally_entry: self.pending_finally_entry.clone(),
            scope_chain: self.scope_chain.clone(),
            pending_captures: self.pending_captures.clone(),
            current_module_specifier: self.current_module_specifier.clone(),
            active_generated_function_artifact: self.active_generated_function_artifact,
        }
    }

    pub(super) fn restore_module_execution(
        &mut self,
        snapshot: ModuleExecutionSnapshot,
        displaced_state_was_accounted: bool,
    ) {
        let accounted_bytes = snapshot.accounted_bytes;
        let displaced_state_bytes = if displaced_state_was_accounted {
            self.active_module_execution_memory_bytes()
        } else {
            0
        };
        self.install_register_file(snapshot.registers, Some(snapshot.register_bytes));
        self.generator_delegation = snapshot.generator_delegation;
        self.install_register_labels(
            snapshot.register_labels,
            Some(snapshot.register_label_bytes),
        );
        // No one writes the files while they are parked (bd-9vouw.499).
        self.register_dirty_end = snapshot.register_dirty_end;
        self.active_inline_callback_context_label = snapshot.active_inline_callback_context_label;
        self.pc_label_stack = snapshot.pc_label_stack;
        self.call_stack
            .replace(snapshot.call_stack, &mut self.closures.cold_cells);
        self.ip = snapshot.ip;
        self.register_base = snapshot.register_base;
        self.register_width = snapshot.register_width;
        self.catch_frames = snapshot.catch_frames;
        self.pending_exception = snapshot.pending_exception;
        self.pending_exception_label = snapshot.pending_exception_label;
        self.pending_hostcall_result_label = snapshot.pending_hostcall_result_label;
        self.pending_return = snapshot.pending_return;
        self.suspended_abrupt_completions = snapshot.suspended_abrupt_completions;
        self.finally_frames = snapshot.finally_frames;
        self.pending_finally_entry = snapshot.pending_finally_entry;
        self.scope_chain = snapshot.scope_chain;
        self.pending_captures = snapshot.pending_captures;
        self.current_module_specifier = snapshot.current_module_specifier;
        self.active_generated_function_artifact = snapshot.active_generated_function_artifact;
        let restored_state_bytes = if displaced_state_was_accounted {
            self.active_module_execution_memory_bytes()
        } else {
            0
        };
        self.module_snapshot_in_flight_bytes = self
            .module_snapshot_in_flight_bytes
            .saturating_sub(accounted_bytes);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(accounted_bytes)
            .saturating_sub(displaced_state_bytes)
            .saturating_add(restored_state_bytes);
    }

    /// Commit work protected by a module-execution rollback snapshot.
    /// Dropping the cloned structure releases its map/key/handle charge; shared
    /// lexical-cell payloads remain owned and charged by the live runtime views.
    pub(super) fn discard_module_execution_snapshot(&mut self, snapshot: ModuleExecutionSnapshot) {
        let accounted_bytes = snapshot.accounted_bytes;
        self.module_snapshot_in_flight_bytes = self
            .module_snapshot_in_flight_bytes
            .saturating_sub(accounted_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(accounted_bytes);
        drop(snapshot);
    }

    pub(super) fn prepare_module_execution(
        &mut self,
        module_specifier: &str,
    ) -> Result<(), InterpreterError> {
        let max_regs = self.config.max_registers as usize;
        let previous_register_bytes = self.registers_memory_bytes();
        let previous_register_context_label_bytes = self.register_context_labels_memory_bytes();
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        self.mutate_registers(|r| {
            r.clear();
            r.resize(max_regs, Value::Undefined);
        });
        self.install_register_labels(vec![Label::Public; max_regs], Some(0));
        self.call_stack.clear(&mut self.closures.cold_cells);
        self.ip = 0;
        self.register_base = 0;
        self.register_width = self.config.max_registers as usize;
        self.catch_frames.clear();
        self.pending_exception = None;
        self.pending_exception_label = Label::Public;
        self.pending_hostcall_result_label = None;
        self.pending_return = None;
        self.suspended_abrupt_completions.clear();
        self.finally_frames.clear();
        self.pending_finally_entry = None;
        self.scope_chain = ScopeChain::new();
        self.pending_captures.clear();
        self.current_module_specifier = Some(module_specifier.to_string());
        self.active_generated_function_artifact = None;
        self.apply_register_context_scope_call_stack_memory_delta(
            previous_register_bytes,
            previous_register_context_label_bytes,
            previous_scope_bytes,
            previous_call_stack_bytes,
        )?;
        self.inject_runtime_globals()?;
        Ok(())
    }

    pub(super) fn alloc_console_global(&mut self) -> Result<Value, InterpreterError> {
        let console = self.alloc_object_with_properties(&[
            (
                "log",
                Value::BuiltinFunction(BuiltinFunction::console_log()),
            ),
            (
                "error",
                Value::BuiltinFunction(BuiltinFunction::console_error()),
            ),
            (
                "warn",
                Value::BuiltinFunction(BuiltinFunction::console_warn()),
            ),
            (
                "info",
                Value::BuiltinFunction(BuiltinFunction::console_info()),
            ),
        ])?;
        for method in CONSOLE_EXTRA_METHODS {
            self.set_object_property(
                console,
                method.to_string(),
                Value::BuiltinFunction(BuiltinFunction::console_method(method)),
            )?;
        }
        Ok(Value::Object(console))
    }

    /// The global `Promise`: a constructible builtin (bd-auy04) whose statics
    /// live on its bound property object, like `Date`, in Node's order, with
    /// its own `get [Symbol.species]` (bd-9vouw.278).
    pub(super) fn alloc_promise_global(&mut self) -> Result<Value, InterpreterError> {
        let properties = self.alloc_object_with_properties(&[
            ("length", Value::Int(1)),
            ("name", Value::str("Promise")),
            (
                "all",
                Value::BuiltinFunction(BuiltinFunction::promise_all()),
            ),
            (
                "allSettled",
                Value::BuiltinFunction(BuiltinFunction::promise_all_settled()),
            ),
            (
                "any",
                Value::BuiltinFunction(BuiltinFunction::promise_any()),
            ),
            (
                "race",
                Value::BuiltinFunction(BuiltinFunction::promise_race()),
            ),
            (
                "resolve",
                Value::BuiltinFunction(BuiltinFunction::promise_resolve()),
            ),
            (
                "reject",
                Value::BuiltinFunction(BuiltinFunction::promise_reject()),
            ),
            (
                "withResolvers",
                Value::BuiltinFunction(BuiltinFunction::promise_with_resolvers()),
            ),
        ])?;
        self.mark_builtin_members_non_enumerable(properties)?;
        self.mark_materialized_constructor_name_and_length(properties)?;
        self.define_species_getter(properties, "Promise")?;
        Ok(Value::BuiltinFunction(
            BuiltinFunction::promise_constructor(properties),
        ))
    }

    pub(super) fn alloc_math_global(&mut self) -> Result<Value, InterpreterError> {
        // @@toStringTag goes on first, while the property map is empty:
        // set_symbol_property projects an insertion on a copy of the map and
        // charges that copy as a temporary peak, so tagging the finished
        // object peaked a whole property map above what Math retains (the
        // generated Function realm must fit its exact retained budget,
        // bd-fw7zd.8.3). Symbol keys list after string keys either way.
        let math = self.alloc_object_with_properties(&[])?;
        self.set_object_runtime_property(
            math,
            RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id()),
            Value::str("Math"),
        )?;
        self.set_own_property_attributes(
            math,
            &RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id()),
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )?;
        for (name, value) in [
            (
                "abs",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAbs)),
            ),
            (
                "ceil",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathCeil)),
            ),
            (
                "floor",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathFloor)),
            ),
            (
                "round",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathRound)),
            ),
            (
                "max",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathMax)),
            ),
            (
                "min",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathMin)),
            ),
            (
                "random",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathRandom)),
            ),
            (
                "pow",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathPow)),
            ),
            (
                "sqrt",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathSqrt)),
            ),
            (
                "sin",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathSin)),
            ),
            (
                "cos",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathCos)),
            ),
            (
                "log",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathLog)),
            ),
            (
                "exp",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathExp)),
            ),
            (
                "tan",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathTan)),
            ),
            (
                "trunc",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathTrunc)),
            ),
            (
                "sign",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathSign)),
            ),
            (
                "atan2",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAtan2)),
            ),
            (
                "asin",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAsin)),
            ),
            (
                "acos",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAcos)),
            ),
            (
                "hypot",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathHypot)),
            ),
            (
                "imul",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathImul)),
            ),
            (
                "atan",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAtan)),
            ),
            (
                "log10",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathLog10)),
            ),
            (
                "log2",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathLog2)),
            ),
            (
                "cbrt",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathCbrt)),
            ),
            (
                "clz32",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathClz32)),
            ),
            (
                "fround",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathFround)),
            ),
            (
                "acosh",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAcosh)),
            ),
            (
                "asinh",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAsinh)),
            ),
            (
                "atanh",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathAtanh)),
            ),
            (
                "sinh",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathSinh)),
            ),
            (
                "cosh",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathCosh)),
            ),
            (
                "tanh",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathTanh)),
            ),
            (
                "expm1",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathExpm1)),
            ),
            (
                "log1p",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::MathLog1p)),
            ),
        ] {
            self.set_object_property(math, name.to_string(), value)?;
        }
        self.mark_builtin_members_non_enumerable(math)?;
        // ES2020 20.2.1 value properties.
        for (name, value) in [
            ("E", std::f64::consts::E),
            ("LN10", std::f64::consts::LN_10),
            ("LN2", std::f64::consts::LN_2),
            ("LOG10E", std::f64::consts::LOG10_E),
            ("LOG2E", std::f64::consts::LOG2_E),
            ("PI", std::f64::consts::PI),
            ("SQRT1_2", std::f64::consts::FRAC_1_SQRT_2),
            ("SQRT2", std::f64::consts::SQRT_2),
        ] {
            self.set_object_property(math, name.to_string(), Value::Float(Float64::new(value)))?;
            self.set_own_property_attributes(
                math,
                &RuntimePropertyKey::String(JsString::from(name)),
                READ_ONLY_VALUE_ATTRIBUTES,
            )?;
        }
        Ok(Value::Object(math))
    }

    /// The function-valued members of a builtin namespace or constructor
    /// (`Math.max`, `JSON.parse`, `Promise.all`, `Date.now`) are
    /// { writable, !enumerable, configurable } (ES2020 17). Created by
    /// ordinary assignment they were enumerable, so `Object.keys(Math)` listed
    /// 31 names and `for (k in Math)` visited them (Node: none).
    pub(super) fn mark_builtin_members_non_enumerable(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        let keys: Vec<JsString> = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .properties
            .keys()
            .map(|key| JsString::from(key.as_str()))
            .collect();
        for key in keys {
            self.set_own_property_attributes(
                object_id,
                &RuntimePropertyKey::String(key),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        Ok(())
    }

    /// Gives a materialized constructor's property object the standard own
    /// `length` and `name` (ES2020 17: non-writable, non-enumerable,
    /// configurable). `Date.name` and `Promise.length` were undefined, so
    /// `Object.getPrototypeOf(d).constructor.name` was not "Date".
    pub(super) fn mark_materialized_constructor_name_and_length(
        &mut self,
        properties: ObjectId,
    ) -> Result<(), InterpreterError> {
        for key in ["length", "name"] {
            self.set_own_property_attributes(
                properties,
                &RuntimePropertyKey::String(JsString::from(key)),
                FUNCTION_NAME_LENGTH_ATTRIBUTES,
            )?;
        }
        Ok(())
    }

    pub(super) fn alloc_date_global(&mut self) -> Result<Value, InterpreterError> {
        let properties = self.alloc_object_with_properties(&[
            ("length", Value::Int(7)),
            ("name", Value::str("Date")),
            (
                "now",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::DateNow)),
            ),
            (
                "parse",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::DateParse)),
            ),
            (
                "UTC",
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::DateUtc)),
            ),
        ])?;
        self.mark_builtin_members_non_enumerable(properties)?;
        self.mark_materialized_constructor_name_and_length(properties)?;
        Ok(Value::BuiltinFunction(BuiltinFunction::date_constructor(
            properties,
        )))
    }

    pub(super) fn alloc_performance_global(&mut self) -> Result<Value, InterpreterError> {
        Ok(Value::Object(self.alloc_object_with_properties(&[(
            "now",
            Value::BuiltinFunction(BuiltinFunction::performance_now()),
        )])?))
    }

    pub(super) fn timer_global_kinds() -> [(&'static str, BuiltinFunctionKind); 7] {
        [
            ("setTimeout", BuiltinFunctionKind::SetTimeout),
            ("clearTimeout", BuiltinFunctionKind::ClearTimeout),
            ("setInterval", BuiltinFunctionKind::SetInterval),
            ("clearInterval", BuiltinFunctionKind::ClearInterval),
            ("setImmediate", BuiltinFunctionKind::SetImmediate),
            ("clearImmediate", BuiltinFunctionKind::ClearImmediate),
            ("queueMicrotask", BuiltinFunctionKind::QueueMicrotask),
        ]
    }

    /// The stateless global values the generated Function realm binds
    /// (bd-9vouw.133): all but `Function` itself, so generated code gets no
    /// recursive code generation through a bare name (bd-fw7zd.8.3).
    pub(super) fn generated_realm_stateless_values() -> Vec<(&'static str, Value)> {
        Self::stateless_global_values()
            .into_iter()
            .filter(|(name, _)| *name != "Function")
            .collect()
    }

    pub(super) fn projected_generated_function_realm_registry_bytes() -> u64 {
        // Every `ScopeBindingState` retains a public IFC label even when the
        // label has no dynamic payload.  Keep this projection in lockstep with
        // `estimate_scope_bindings_bytes`: omitting the fixed `Label` storage
        // undercharged the twelve canonical bindings by 384 bytes on this
        // target and made the debug recomputation assertion fail.
        let binding_label_bytes = std::mem::size_of::<Label>() as u64;
        let binding_bytes = |name: &str, value_bytes: u64| {
            MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                .saturating_add(Self::estimate_string_bytes(name))
                .saturating_add(value_bytes)
                .saturating_add(binding_label_bytes)
        };
        let object_bytes = Self::saturating_sum(
            GENERATED_REALM_OBJECT_GLOBALS
                .into_iter()
                .map(|name| binding_bytes(name, 0)),
        );
        // `Date` and `Promise` are constructible builtin function values
        // (`alloc_date_global` / `alloc_promise_global`), not plain objects:
        // each carries a builtin payload like the timer globals.
        let empty_builtin_bytes = Self::estimate_string_bytes("");
        let constructor_bytes = Self::saturating_sum(
            ["Date", "Promise"]
                .into_iter()
                .map(|name| binding_bytes(name, empty_builtin_bytes)),
        );
        let stateless_bytes = Self::saturating_sum(
            Self::generated_realm_stateless_values()
                .iter()
                .map(|(name, value)| binding_bytes(name, Self::estimate_value_bytes(value))),
        );
        object_bytes
            .saturating_add(constructor_bytes)
            .saturating_add(stateless_bytes)
    }

    /// Materialize the engine-owned safe outer environment used by generated
    /// functions. The transaction owns every heap append below: any object,
    /// heap-count, or map-budget refusal restores both the heap and memory
    /// accumulator to the exact pre-initialization state.
    pub(super) fn ensure_generated_function_realm_globals(
        &mut self,
    ) -> Result<(), InterpreterError> {
        if self.generated_function_realm_globals.is_some() {
            return Ok(());
        }

        let previous_heap_len = self.heap.len();
        let previous_estimated_memory_bytes = self.estimated_memory_bytes;
        #[cfg(debug_assertions)]
        let previous_recomputed_memory_bytes = self.recompute_base_estimated_memory_bytes();
        let result = (|| -> Result<(), InterpreterError> {
            let console = self.alloc_console_global()?;
            let performance = self.alloc_performance_global()?;
            let promise = self.alloc_promise_global()?;
            let math = self.alloc_math_global()?;
            let date = self.alloc_date_global()?;
            // bd-9vouw.133: the realm's own JSON and Reflect namespaces, the
            // standard constructors and global functions as values (`typeof
            // Object`, `[].map(String)`, `x instanceof Array` in a Function
            // body), and its own global object, bound as `globalThis` and
            // `global` and so the sloppy `this` of its functions: core-js 2's
            // `Function('return this')()` global detection (json5, UMD
            // builds). Its members are a snapshot of these bindings, so a
            // write through it stays in this realm.
            let json = self.alloc_json_global()?;
            let reflect = self.alloc_reflect_global()?;
            let atomics = self.alloc_atomics_global()?;
            let mut entries = vec![
                ("console", console),
                ("performance", performance),
                ("Promise", promise),
                ("Math", math),
                ("Date", date),
                ("JSON", Value::Object(json)),
                ("Reflect", Value::Object(reflect)),
                ("Atomics", Value::Object(atomics)),
            ];
            entries.extend(Self::generated_realm_stateless_values());
            let global = self.alloc_object_with_properties(&entries)?;
            for name in ["globalThis", "global"] {
                self.set_object_property(global, name.to_string(), Value::Object(global))?;
            }
            for name in entries
                .iter()
                .map(|(name, _)| *name)
                .chain(["globalThis", "global"])
            {
                self.set_own_property_attributes(
                    global,
                    &RuntimePropertyKey::String(JsString::from(name)),
                    NON_ENUMERABLE_DATA_ATTRIBUTES,
                )?;
            }
            self.seed_read_only_global_values(global)?;
            entries.push(("globalThis", Value::Object(global)));
            entries.push(("global", Value::Object(global)));
            let registry_bytes = Self::projected_generated_function_realm_registry_bytes();
            // No map/key allocation occurs until its complete retained charge
            // fits alongside every newly allocated canonical heap object.
            self.check_temporary_memory_budget(registry_bytes)?;

            let mut globals = BTreeMap::new();
            for (name, value) in entries {
                globals.insert(
                    name.to_string(),
                    ScopeBinding::with_state(BindingKind::Var, value, true),
                );
            }

            debug_assert_eq!(
                registry_bytes,
                Self::estimate_generated_function_realm_globals_bytes(&globals)
            );
            self.apply_memory_component_delta(0, registry_bytes)?;
            self.generated_function_realm_globals = Some(globals);
            Ok(())
        })();

        if let Err(error) = result {
            self.generated_function_realm_globals = None;
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_memory_bytes;
            return Err(error);
        }

        #[cfg(debug_assertions)]
        {
            let recomputed_memory_bytes = self.recompute_base_estimated_memory_bytes();
            debug_assert!(self.estimated_memory_bytes >= previous_estimated_memory_bytes);
            debug_assert!(recomputed_memory_bytes >= previous_recomputed_memory_bytes);
            debug_assert_eq!(
                self.estimated_memory_bytes - previous_estimated_memory_bytes,
                recomputed_memory_bytes - previous_recomputed_memory_bytes
            );
        }
        Ok(())
    }

    pub(super) fn generated_function_realm_scope_frame(
        &self,
    ) -> Result<ScopeFrame, InterpreterError> {
        let globals = self
            .generated_function_realm_globals
            .as_ref()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "generated Function realm globals are not initialized".to_string(),
            })?;
        Ok(ScopeFrame::from_bindings(globals.clone()))
    }

    /// Replace the top-level dynamic-code realm. Old stores are released and
    /// the monotonic generation changes before any new artifact can be
    /// retained, so a serialized/stashed v1 handle cannot alias identically
    /// sourced code recreated by the next execution.
    pub(super) fn rotate_generated_function_realm(&mut self) -> Result<(), InterpreterError> {
        let next_generation = self
            .generated_function_realm_generation
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "generated Function realm generation exhausted u64".to_string(),
            })?;
        let released_bytes = self
            .module_state
            .retained_generated_function_bytes
            .saturating_add(self.generated_function_realm_globals_memory_bytes())
            .saturating_add(self.realm_dynamic_globals_memory_bytes());

        self.module_state.generated_function_stores.clear();
        self.module_state.retained_generated_function_bytes = 0;
        self.generated_function_realm_globals = None;
        // Heap-backed realm values are recreated after the authoritative seed
        // reset. Keeping their binding cells here would retain stale ObjectIds.
        self.realm_dynamic_globals.clear();
        self.realm_global_object = None;
        self.process_global_object = None;
        self.generated_function_realm_generation = next_generation;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        Ok(())
    }

    /// Install the ambient runtime globals as a single failure-atomic
    /// transaction (bd-en0uq).
    ///
    /// The inner routine allocates several heap objects before installing
    /// their scope/realm bindings, and any allocation or memory-accounting
    /// step can refuse under a tight budget. Without a transaction a
    /// mid-sequence refusal would leave earlier heap objects charged but
    /// unreachable (their names never installed), and a retry would allocate
    /// duplicates. Snapshot the exact state the injection can mutate — the
    /// heap length, the live-memory estimate, the current scope frame's
    /// bindings, and the realm dynamic-global map — and restore all four on
    /// any failure so the observable state (and a subsequent retry) starts
    /// from the pre-injection point. No external reference to these scope or
    /// realm cells exists yet at execution setup, so restoring detached-clone
    /// snapshots preserves the correct value state.
    pub(super) fn inject_runtime_globals(&mut self) -> Result<(), InterpreterError> {
        let heap_checkpoint = self.heap.len();
        let memory_checkpoint = self.estimated_memory_bytes;
        let scope_checkpoint = self.snapshot_current_scope_frame_bindings()?;
        let realm_checkpoint = self.snapshot_realm_dynamic_globals()?;

        match self.inject_runtime_globals_inner() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.rollback_runtime_globals(
                    heap_checkpoint,
                    memory_checkpoint,
                    scope_checkpoint,
                    realm_checkpoint,
                );
                Err(err)
            }
        }
    }

    /// Detached-clone snapshot of the current (innermost) scope frame's
    /// bindings: fresh cells carrying the same value/initialized state, so a
    /// later restore is unaffected by in-place mutations to the live cells.
    pub(super) fn snapshot_current_scope_frame_bindings(
        &self,
    ) -> Result<BTreeMap<String, ScopeBinding>, InterpreterError> {
        let frame =
            self.scope_chain
                .frames
                .last()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "scope chain unexpectedly empty".to_string(),
                })?;
        let mut snapshot = BTreeMap::new();
        for (name, binding) in frame.bindings.iter() {
            snapshot.insert(name.clone(), binding.detached_clone()?);
        }
        Ok(snapshot)
    }

    /// Detached-clone snapshot of the realm dynamic-global map.
    pub(super) fn snapshot_realm_dynamic_globals(
        &self,
    ) -> Result<BTreeMap<String, ScopeBinding>, InterpreterError> {
        let mut snapshot = BTreeMap::new();
        for (name, binding) in &self.realm_dynamic_globals {
            snapshot.insert(name.clone(), binding.detached_clone()?);
        }
        Ok(snapshot)
    }

    /// Restore the four state components a runtime-global injection can touch
    /// to a pre-injection snapshot, then pin the live-memory estimate. The
    /// heap truncation drops every object allocated during the failed attempt;
    /// the scope-frame and realm-map restores drop any partially installed
    /// bindings; the estimate is reset last so it stays consistent with the
    /// restored components (equal to a full recompute at the checkpoint).
    pub(super) fn rollback_runtime_globals(
        &mut self,
        heap_checkpoint: usize,
        memory_checkpoint: u64,
        scope_checkpoint: BTreeMap<String, ScopeBinding>,
        realm_checkpoint: BTreeMap<String, ScopeBinding>,
    ) {
        self.rollback_heap_to_len(heap_checkpoint);
        if let Some(frame) = self.scope_chain.frames.last_mut() {
            frame.replace_bindings(scope_checkpoint);
        }
        self.realm_dynamic_globals = realm_checkpoint;
        if self
            .realm_global_object
            .is_some_and(|global| global.0 as usize >= heap_checkpoint)
        {
            self.realm_global_object = None;
        }
        if self
            .process_global_object
            .is_some_and(|process| process.0 as usize >= heap_checkpoint)
        {
            self.process_global_object = None;
        }
        self.estimated_memory_bytes = memory_checkpoint;
    }

    pub(super) fn inject_runtime_globals_inner(&mut self) -> Result<(), InterpreterError> {
        let process = if let Some(process) = self.process_global_object {
            Value::Object(process)
        } else {
            let process = self.alloc_process_global()?;
            self.process_global_object = Some(process);
            Value::Object(process)
        };
        self.inject_non_process_runtime_globals(process)
    }

    pub(super) fn alloc_process_global(&mut self) -> Result<ObjectId, InterpreterError> {
        // bd-my9hk: the argv the embedder launched the program with; empty
        // when it supplied none.
        let argv_values: Vec<Value> = self
            .config
            .process_argv
            .iter()
            .map(|arg| Value::str(arg.as_str()))
            .collect();
        let argv = Value::Object(self.alloc_array_from_values(&argv_values)?);
        let env = Value::Object(self.alloc_object_with_properties(&[])?);
        // bd-qmy52/bd-y30zw: platform, architecture and pid are process-SHAPE
        // descriptors readable only through a statically allowlisted member
        // under the trusted `ProcessShapeRead` grant. All are FIXED,
        // engine-contained values: platform/arch match the os builtins and pid is
        // a positive synthetic sentinel, never the nondeterministic host PID.
        // No env VALUES are exposed (env stays empty and env reads stay denied
        // at lowering).
        self.alloc_object_with_properties(&[
            ("argv", argv),
            ("env", env),
            ("platform", Value::str(NODE_OS_PLATFORM)),
            ("arch", Value::str(NODE_OS_ARCH)),
            ("pid", Value::Int(1)),
        ])
    }

    pub(super) fn inject_non_process_runtime_globals(
        &mut self,
        process: Value,
    ) -> Result<(), InterpreterError> {
        // The modules of a program share one `console`, `performance`,
        // `JSON`, `Reflect` and `Atomics` (bd-9vouw.297): a later module binds
        // the realm global object's own property, so a member one module adds
        // or replaces (reflect-metadata's `Reflect.defineMetadata`, a console
        // wrapper) is seen by the others and `globalThis.console === console`.
        // Each module made its own copies.
        let console = self.realm_namespace_global("console", Self::alloc_console_global)?;
        // bd-1piai: these ordinary JavaScript globals live in the realm-owned
        // name map, not in the replaceable module scope. Seed each one exactly
        // once so assignments, aliases, and nested module execution all observe
        // the same mutable binding and object identity.
        let promise = if self.realm_global_object.is_some()
            || self.realm_dynamic_globals.contains_key("Promise")
        {
            None
        } else {
            Some(self.alloc_promise_global()?)
        };
        let math = if self.realm_global_object.is_some()
            || self.realm_dynamic_globals.contains_key("Math")
        {
            None
        } else {
            Some(self.alloc_math_global()?)
        };
        let date = if self.realm_global_object.is_some()
            || self.realm_dynamic_globals.contains_key("Date")
        {
            None
        } else {
            Some(self.alloc_date_global()?)
        };
        let performance =
            self.realm_namespace_global("performance", Self::alloc_performance_global)?;

        self.inject_runtime_global_binding("process", process)?;
        self.inject_runtime_global_binding("console", console)?;
        self.inject_runtime_global_binding("performance", performance)?;
        if let Some(promise) = promise {
            self.put_realm_runtime_name("Promise", promise)?;
        }
        if let Some(math) = math {
            self.put_realm_runtime_name("Math", math)?;
        }
        if let Some(date) = date {
            self.put_realm_runtime_name("Date", date)?;
        }
        for (name, value) in Self::stateless_global_values() {
            self.inject_runtime_global_binding(name, value)?;
        }
        let json = self
            .realm_namespace_global("JSON", |this| this.alloc_json_global().map(Value::Object))?;
        self.inject_runtime_global_binding("JSON", json)?;
        let reflect = self.realm_namespace_global("Reflect", |this| {
            this.alloc_reflect_global().map(Value::Object)
        })?;
        self.inject_runtime_global_binding("Reflect", reflect)?;
        let atomics = self.realm_namespace_global("Atomics", |this| {
            this.alloc_atomics_global().map(Value::Object)
        })?;
        self.inject_runtime_global_binding("Atomics", atomics)?;
        self.seed_global_object()
    }

    /// The globals whose values hold no state of their own, so every realm
    /// binds the same values: `Function`; the timer globals (bd-suwvw: direct
    /// calls are still intercepted at lowering by
    /// `timer_builtin_call_capability`, these bindings make bare references
    /// work: `typeof setTimeout` is "function", a stored alias is callable,
    /// and `require('timers').setTimeout === setTimeout` holds via structural
    /// `BuiltinFunction` equality); and (bd-9vouw.17) the standard
    /// constructors and the bare global functions. Direct calls (`new
    /// TypeError(m)`, `parseInt(s)`) stay intercepted at lowering; these
    /// bindings make bare references work: `typeof TypeError`,
    /// `assert.throws(TypeError, f)`, `[1, 2].map(String)`, `new Array(n)`.
    pub(super) fn stateless_global_values() -> Vec<(&'static str, Value)> {
        let mut values = vec![(
            "Function",
            Value::BuiltinFunction(BuiltinFunction::function_constructor()),
        )];
        for (name, kind) in Self::timer_global_kinds() {
            values.push((
                name,
                Value::BuiltinFunction(BuiltinFunction::timer_global(kind)),
            ));
        }
        for name in STANDARD_CONSTRUCTOR_GLOBALS {
            values.push((
                name,
                Value::BuiltinFunction(BuiltinFunction::standard_constructor(name)),
            ));
        }
        for name in GLOBAL_FUNCTION_VALUES {
            let tag = crate::lowering_pipeline::global_function_capability(name)
                .expect("GLOBAL_FUNCTION_VALUES names are all in the shared lowering table");
            values.push((
                name,
                Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag)),
            ));
        }
        values
    }

    /// A `JSON` namespace object (bd-9vouw.17): direct `JSON.stringify(v)`
    /// calls stay intercepted at lowering; its members are the same
    /// hostcalls, so `typeof JSON` and `const { parse } = JSON` work.
    pub(super) fn alloc_json_global(&mut self) -> Result<ObjectId, InterpreterError> {
        let json = self.alloc_object_with_properties(&[
            (
                "parse",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:JsonParse")),
            ),
            (
                "stringify",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:JsonStringify")),
            ),
            (
                "rawJSON",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:JsonRawJson")),
            ),
            (
                "isRawJSON",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:JsonIsRawJson")),
            ),
        ])?;
        self.mark_builtin_members_non_enumerable(json)?;
        self.set_object_runtime_property(
            json,
            RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id()),
            Value::str("JSON"),
        )?;
        self.set_own_property_attributes(
            json,
            &RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id()),
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )?;
        Ok(json)
    }

    /// `Reflect` as a first-class namespace object, like `JSON`: direct
    /// `Reflect.get(o, k)` calls stay intercepted at lowering, and the
    /// object's members are the same hostcalls, so `typeof Reflect`,
    /// `const { ownKeys } = Reflect` and `Reflect.apply.call(...)` work.
    pub(super) fn alloc_reflect_global(&mut self) -> Result<ObjectId, InterpreterError> {
        let reflect_members: Vec<(&str, Value)> = REFLECT_MEMBERS
            .iter()
            .filter_map(|member| {
                crate::lowering_pipeline::reflect_member_capability(member).map(|tag| {
                    (
                        *member,
                        Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag)),
                    )
                })
            })
            .collect();
        let reflect = self.alloc_object_with_properties(&reflect_members)?;
        for member in REFLECT_MEMBERS {
            self.set_own_property_attributes(
                reflect,
                &RuntimePropertyKey::String(JsString::from(member)),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        Ok(reflect)
    }

    /// bd-9vouw.17: the global object, bound as `globalThis` and as Node's
    /// `global`, seeded once per realm so every module sees the same
    /// identity. It holds the standard intrinsics exactly as the bare
    /// names resolve (`globalThis.Object === Object`), non-enumerable as in
    /// Node, and never a host-authority binding: `process` stays reachable
    /// only through the gated identifier. Its intrinsic members are a
    /// snapshot of the bindings, which resolve first; a free name no binding
    /// resolves reads and writes its properties (`realm_global_object`).
    /// The namespace object a module binds as `name` (bd-9vouw.297): the
    /// realm global object's own data property when it holds an object with
    /// a Public stored label (the copy the first module seeded, or the one a
    /// program assigned to `globalThis[name]`), else a fresh one from
    /// `alloc`: before the global object exists, or when the program deleted
    /// the property or stored a non-object, an accessor or a labelled value
    /// there (binding that would drop its label).
    pub(super) fn realm_namespace_global(
        &mut self,
        name: &str,
        alloc: impl FnOnce(&mut Self) -> Result<Value, InterpreterError>,
    ) -> Result<Value, InterpreterError> {
        if let Some(global) = self.realm_global_object {
            let key = RuntimePropertyKey::String(JsString::from(name));
            if self.runtime_property_label(global, &key) == Label::Public
                && let Some(value @ Value::Object(_)) = self
                    .heap
                    .get(global.0 as usize)
                    .and_then(|object| object.own_runtime_property_value(&key))
            {
                return Ok(value);
            }
        }
        alloc(self)
    }

    pub(super) fn seed_global_object(&mut self) -> Result<(), InterpreterError> {
        // One global object per realm: a repeated injection keeps its identity.
        let bound = self
            .scope_chain
            .frames
            .last()
            .and_then(|frame| frame.get("globalThis"))
            .map(|binding| {
                binding.state().map(|state| match state.value {
                    Value::Object(global) => Some(global),
                    _ => None,
                })
            })
            .transpose()?
            .flatten();
        if let Some(global) = bound {
            self.realm_global_object.get_or_insert(global);
            return Ok(());
        }
        // A module's fresh scope chain binds the realm's existing object.
        if let Some(global) = self.realm_global_object {
            for name in ["globalThis", "global"] {
                self.inject_runtime_global_binding(name, Value::Object(global))?;
            }
            return Ok(());
        }
        let mut members = Vec::new();
        for name in GLOBAL_OBJECT_MEMBERS
            .iter()
            .chain(STANDARD_CONSTRUCTOR_GLOBALS.iter())
            .chain(GLOBAL_FUNCTION_VALUES.iter())
        {
            if let Some(binding) = self.resolve_runtime_name_binding(name) {
                let value = binding.state()?.value.clone();
                members.push((*name, value));
            }
        }
        // ECMA-402's namespace is a property of the global object only; free
        // `Intl` resolves through it.
        let intl = self.alloc_intl_object()?;
        members.push(("Intl", Value::Object(intl)));
        let global = self.alloc_object_with_properties(&members)?;
        for (name, _) in &members {
            self.set_own_property_attributes(
                global,
                &RuntimePropertyKey::String(JsString::from(*name)),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        for name in ["globalThis", "global"] {
            self.set_object_property(global, name.to_string(), Value::Object(global))?;
            self.set_own_property_attributes(
                global,
                &RuntimePropertyKey::String(JsString::from(name)),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
            // A global-frame binding like `console` and `performance`, so a
            // program's own top-level `global`/`globalThis` binding resolves
            // the way theirs do (PREDECLARED_RUNTIME_GLOBALS in lowering).
            self.inject_runtime_global_binding(name, Value::Object(global))?;
        }
        self.seed_read_only_global_values(global)?;
        self.realm_global_object = Some(global);
        Ok(())
    }

    pub(super) fn inject_runtime_global_binding(
        &mut self,
        name: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let (replaced, replaced_state) = {
            let frame = self.scope_chain.current_mut()?;
            let binding_name = name.to_string();
            // perf: hot path - do get_mut first to avoid clone for declare()
            let replaced = frame.declare(binding_name, BindingKind::Var);
            let replaced_state = replaced
                .as_ref()
                .map(ScopeBinding::snapshot_state)
                .transpose()?;
            if let Some(binding) = frame.get_mut(name) {
                {
                    let mut state = binding.state_mut()?;
                    state.value = value;
                    state.initialized = true;
                }
                self.closures.refresh_cell(&binding.state);
            }
            (replaced, replaced_state)
        };

        if let Err(err) = self.apply_scope_chain_memory_delta(previous_scope_bytes) {
            if let Ok(frame) = self.scope_chain.current_mut() {
                if let Some(old_binding) = replaced {
                    if let Some(old_state) = replaced_state {
                        old_binding.restore_state(old_state)?;
                        self.closures.refresh_cell(&old_binding.state);
                    }
                    frame.insert_binding(name.to_string(), old_binding);
                } else {
                    frame.remove_binding(name);
                }
            }
            return Err(err);
        }

        Ok(())
    }

    pub(super) fn insert_cjs_bindings(
        &mut self,
        module_object: ObjectId,
        exports_object: ObjectId,
        module_specifier: Option<&str>,
    ) -> Result<(), InterpreterError> {
        let _ = self.scope_chain.current()?;
        let filename_specifier = module_specifier.or(self.current_module_specifier.as_deref());
        self.check_temporary_memory_budget(self.cjs_binding_construction_peak_bytes(
            filename_specifier,
            module_specifier.unwrap_or_default(),
        ))?;
        let (filename_value, dirname_value) = self.cjs_filename_dirname(filename_specifier);
        let already_owned_temporary_bytes = Self::estimate_value_bytes(&filename_value)
            .saturating_add(Self::estimate_value_bytes(&dirname_value));
        let require_value = Value::BuiltinFunction(self.construct_require_builtin(
            module_specifier.unwrap_or_default(),
            already_owned_temporary_bytes,
        )?);

        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let mut replaced = Vec::with_capacity(5);
        {
            let frame = self.scope_chain.current_mut()?;
            for (name, value) in [
                ("require", require_value),
                ("exports", Value::Object(exports_object)),
                ("module", Value::Object(module_object)),
                ("__filename", filename_value),
                ("__dirname", dirname_value),
            ] {
                let name = name.to_string();
                let replaced_binding = frame.declare(name.clone(), BindingKind::Var);
                let replaced_state = replaced_binding
                    .as_ref()
                    .map(ScopeBinding::snapshot_state)
                    .transpose()?;
                if let Some(binding) = frame.get_mut(&name) {
                    {
                        let mut state = binding.state_mut()?;
                        state.value = value;
                        state.initialized = true;
                    }
                    self.closures.refresh_cell(&binding.state);
                }
                replaced.push((name, replaced_binding, replaced_state));
            }
        }
        if let Err(err) = self.apply_scope_chain_memory_delta(previous_scope_bytes) {
            if let Ok(current) = self.scope_chain.current_mut() {
                for (name, old, old_state) in replaced {
                    if let Some(old_binding) = old {
                        if let Some(old_state) = old_state {
                            old_binding.restore_state(old_state)?;
                            self.closures.refresh_cell(&old_binding.state);
                        }
                        current.insert_binding(name, old_binding);
                    } else {
                        current.remove_binding(&name);
                    }
                }
            }
            return Err(err);
        }
        Ok(())
    }

    pub(super) fn cjs_filename_dirname(&self, module_specifier: Option<&str>) -> (Value, Value) {
        let Some(specifier) = module_specifier else {
            return (Value::Undefined, Value::Undefined);
        };
        let dirname = self.cjs_dirname_view(specifier);
        (
            Value::str(self.module_filename_view(specifier)),
            Value::str(dirname),
        )
    }

    pub(super) fn module_filename_view<'a>(&'a self, specifier: &'a str) -> &'a str {
        self.module_resolver
            .as_ref()
            .and_then(|installed| installed.resolver.source_location(specifier))
            .and_then(|location| location.filename.to_str())
            .unwrap_or(specifier)
    }

    pub(super) fn cjs_dirname_view<'a>(&'a self, specifier: &'a str) -> &'a str {
        Path::new(self.module_filename_view(specifier))
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .and_then(Path::to_str)
            .or(self.config.module_root.as_deref())
            .unwrap_or_default()
    }

    pub(super) fn cjs_binding_construction_peak_bytes(
        &self,
        filename_specifier: Option<&str>,
        require_specifier: &str,
    ) -> u64 {
        let path_payload_bytes = filename_specifier.map_or(0, |specifier| {
            Self::estimate_string_bytes(self.module_filename_view(specifier)).saturating_add(
                Self::estimate_string_bytes(self.cjs_dirname_view(specifier)),
            )
        });
        let require_payload_bytes = if require_specifier.is_empty() {
            0
        } else {
            Self::estimate_string_bytes(require_specifier)
        };
        let names = ["require", "exports", "module", "__filename", "__dirname"];
        let rollback_slots = u64::try_from(names.len().saturating_mul(std::mem::size_of::<(
            String,
            Option<ScopeBinding>,
            Option<ScopeBindingState>,
        )>()))
        .unwrap_or(u64::MAX);
        let binding_and_name_bytes = Self::saturating_sum(names.into_iter().map(|name| {
            MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                .saturating_add(Self::estimate_string_bytes(name).saturating_mul(2))
        }));
        path_payload_bytes
            .saturating_add(require_payload_bytes)
            .saturating_add(rollback_slots)
            .saturating_add(binding_and_name_bytes)
    }

    /// `require.main` (bd-rff5g): the entry's `module` object when the entry
    /// runs as CommonJS (Node's `process.mainModule`), so `require.main ===
    /// module` holds in the entry and nowhere else; otherwise undefined.
    pub(super) fn cjs_main_module(&self) -> Value {
        if !self.config.commonjs_entry {
            return Value::Undefined;
        }
        self.entry_module_specifier
            .as_deref()
            .and_then(|entry| self.module_state.modules.get(entry))
            .and_then(|record| record.cjs_module_object)
            .map_or(Value::Undefined, Value::Object)
    }

    pub(super) fn construct_require_builtin(
        &self,
        module_specifier: &str,
        already_owned_temporary_bytes: u64,
    ) -> Result<BuiltinFunction, InterpreterError> {
        let construction_bytes = if module_specifier.is_empty() {
            0
        } else {
            already_owned_temporary_bytes
                .saturating_add(Self::estimate_string_bytes(module_specifier))
        };
        self.check_temporary_memory_budget(construction_bytes)?;
        Ok(BuiltinFunction::require(module_specifier))
    }

    pub(super) fn set_cjs_require_property(
        &mut self,
        module_object: ObjectId,
        module_specifier: &str,
    ) -> Result<(), InterpreterError> {
        let object =
            self.heap
                .get(module_object.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound {
                    id: module_object.0,
                })?;
        if object.is_frozen {
            return Err(InterpreterError::TypeError {
                expected: "mutable object".to_string(),
                got: "frozen object".to_string(),
            });
        }
        const REQUIRE_KEY: &str = "require";
        let key_bytes = Self::estimate_string_bytes(REQUIRE_KEY);
        let require_bytes = if module_specifier.is_empty() {
            0
        } else {
            Self::estimate_string_bytes(module_specifier)
        };
        self.check_temporary_memory_budget(key_bytes.saturating_add(require_bytes))?;
        let key = REQUIRE_KEY.to_string();
        let require = self.construct_require_builtin(module_specifier, key_bytes)?;
        self.set_object_property(module_object, key, Value::BuiltinFunction(require))
    }

    pub(super) fn inject_active_cjs_bindings(&mut self) -> Result<(), InterpreterError> {
        let (module_object, exports_object, module_specifier) = {
            let Some(context) = self.active_cjs_context.as_ref() else {
                return Ok(());
            };
            // Only the evaluating module's own code gets its bindings, and
            // only where its chain does not hold them already. A function of
            // another module called while this one evaluates keeps the
            // bindings of its own module from its captured chain: a babel
            // helper's `module.exports = _typeof = ...` replaced the caller's
            // exports (date-fns), and zod's `(0, exports.makeIssue)(...)`
            // read the caller's `exports` (bd-9vouw.180).
            if self.current_module_specifier.as_deref() != Some(context.module_specifier.as_str())
                || self.scope_chain.binds("module")
            {
                return Ok(());
            }
            (
                context.module_object,
                context.exports_object,
                context.module_specifier.clone(),
            )
        };
        self.insert_cjs_bindings(
            module_object,
            exports_object,
            Some(module_specifier.as_str()),
        )
    }

    pub(super) fn module_specifier_diagnostic(specifier: &JsString) -> String {
        specifier
            .encode_utf16()
            .map(|unit| format!("\\u{unit:04X}"))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Convert at the UTF-8-backed loader boundary without allowing lone
    /// UTF-16 units to alias through `JsString`'s lossy display projection.
    pub(super) fn utf8_module_specifier(specifier: &JsString) -> Result<&str, InterpreterError> {
        specifier
            .as_str()
            .ok_or_else(|| InterpreterError::ModuleResolutionFailed {
                specifier: Self::module_specifier_diagnostic(specifier),
                reason: ModuleResolutionFailureReason::MalformedSpecifier,
            })
    }

    pub(super) fn resolve_specifier_base(
        &self,
        specifier: &str,
    ) -> Result<PathBuf, InterpreterError> {
        if Path::new(specifier).is_absolute() {
            return Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(
                    "absolute paths not allowed in module specifiers".to_string(),
                ),
            });
        }

        if specifier.starts_with("./") || specifier.starts_with("../") {
            if self.config.module_root.is_none()
                && Path::new(specifier)
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: ModuleResolutionFailureReason::Other(
                        "parent-directory imports require a configured module root".to_string(),
                    ),
                });
            }

            let base = self
                .current_module_specifier
                .as_deref()
                .and_then(|label| Path::new(label).parent())
                .filter(|path| !path.as_os_str().is_empty())
                .map(PathBuf::from)
                .or_else(|| self.config.module_root.as_ref().map(PathBuf::from))
                .ok_or_else(|| InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: ModuleResolutionFailureReason::Other(
                        "no module root available for relative import".to_string(),
                    ),
                })?;
            Ok(base.join(specifier))
        } else {
            Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::BareSpecifiersNotSupported,
            })
        }
    }

    pub(super) fn canonicalize_module_candidate(
        &self,
        specifier: &str,
        candidate: &Path,
    ) -> Result<PathBuf, InterpreterError> {
        let canonical =
            candidate
                .canonicalize()
                .map_err(|error| InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: ModuleResolutionFailureReason::Other(format!(
                        "failed to canonicalize module path: {error}"
                    )),
                })?;

        let canonical_root_storage;
        let canonical_root = if let Some(canonical_root) =
            self.config.canonical_module_root.as_ref()
        {
            canonical_root
        } else if let Some(module_root) = self.config.module_root.as_ref() {
            canonical_root_storage = Path::new(module_root).canonicalize().map_err(|error| {
                InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: ModuleResolutionFailureReason::Other(format!(
                        "failed to canonicalize module root: {error}"
                    )),
                }
            })?;
            &canonical_root_storage
        } else {
            // bd-zpn3w: fail-closed when no module root is configured. The
            // previous code returned `Ok(canonical)` here, silently skipping
            // the escape check — a caller who forgot to set `module_root`
            // believed the boundary was enforced but it wasn't, exposing a
            // filesystem-read pivot to any extension that issues a relative
            // `require()`. Refusing without a configured root preserves
            // Axiom-1 fail-closed defaults from `bd-ooaka`.
            return Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(
                    "module root not configured — refusing to resolve without an escape boundary"
                        .to_string(),
                ),
            });
        };

        if !canonical.starts_with(canonical_root) {
            return Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(
                    "module specifier escapes module root".to_string(),
                ),
            });
        }

        // bd-zpn3w: post-canonical `metadata().is_file()` check closes the
        // TOCTOU window between the `resolve_module_candidate` `is_file()`
        // probe (which does not follow symlinks) and this `canonicalize()`
        // (which does). Between the two `stat` calls an attacker on a shared
        // filesystem can swap a regular file for a symlink to a directory,
        // device, or socket — the previous code would have returned that
        // canonical path as if it were the requested module.
        let canonical_metadata = std::fs::metadata(&canonical).map_err(|error| {
            InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(format!(
                    "failed to read canonical module metadata: {error}"
                )),
            }
        })?;
        if !canonical_metadata.is_file() {
            return Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(
                    "canonical module path is not a regular file".to_string(),
                ),
            });
        }

        Ok(canonical)
    }

    pub(super) fn resolve_module_specifier(
        &self,
        specifier: &str,
    ) -> Result<package_resolution::ModuleResolutionTarget, InterpreterError> {
        use package_resolution::ModuleResolutionTarget;

        if let Some(native) = NativeBuiltinModule::from_specifier(specifier) {
            return Ok(ModuleResolutionTarget::Native(native));
        }
        // bd-mgfhs: an ES module's bare specifier names a package, resolved
        // like `require` but with the `import` condition. A private mapping
        // may select a native provider instead of a file.
        if Self::is_bare_module_specifier(specifier) {
            let target = self.resolve_bare_import_specifier(specifier)?;
            let ModuleResolutionTarget::File(candidate) = target else {
                return Ok(target);
            };
            let canonical = self.canonicalize_module_candidate(specifier, &candidate)?;
            return Ok(ModuleResolutionTarget::File(canonical));
        }
        let resolved = self.resolve_specifier_base(specifier)?;
        let candidate = self.resolve_module_candidate(&resolved).ok_or_else(|| {
            InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::ModuleNotFound,
            }
        })?;
        let canonical = self.canonicalize_module_candidate(specifier, &candidate)?;
        Ok(ModuleResolutionTarget::File(canonical))
    }

    /// Authorize an exact captured route before consulting the evaluation
    /// cache. A policy refusal or unknown route never reaches path lookup.
    pub(super) fn resolve_installed_module(
        &self,
        specifier: &str,
        style: ImportStyle,
        import_attributes: &ImportAttributes,
    ) -> Result<SharedResolutionOutcome, InterpreterError> {
        let installed =
            self.module_resolver
                .as_ref()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "closed-world module resolution has no installed resolver".to_string(),
                })?;
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::ModuleLoad)
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: RuntimeCapability::ModuleLoad.to_string(),
            });
        }
        let request = ModuleRequest::new(specifier, style)
            .with_referrer(
                self.current_module_specifier
                    .as_deref()
                    .unwrap_or_else(|| installed.resolver.entry_referrer()),
            )
            .with_compatibility_mode(CompatibilityMode::NodeCompat)
            .with_import_attributes(import_attributes.clone());
        let resolved = installed
            .resolver
            .resolve_shared(&request, &installed.context)
            .map_err(|error| {
                // A resolver can bind an observed absence or package-map
                // refusal into its closed world. Optional dependencies may
                // catch those exact Node errors. Unknown routes and runtime
                // policy denials remain outside guest exception handling.
                if let Some(reason) = ModuleResolutionFailureReason::from_captured_code(error.code)
                {
                    InterpreterError::ModuleResolutionFailed {
                        specifier: specifier.to_string(),
                        reason,
                    }
                } else {
                    InterpreterError::ModuleLoweringFailed {
                        specifier: specifier.to_string(),
                        error: format!("closed-world module resolution refused: {error}"),
                    }
                }
            })?;
        let record = &resolved.module.record;
        Self::check_module_import_attributes(specifier, style, record.syntax, import_attributes)?;
        if u64::try_from(record.source.len()).unwrap_or(u64::MAX)
            > self.config.module_parser_options.budget.max_source_bytes
        {
            return Err(InterpreterError::ModuleParseFailed {
                specifier: specifier.to_string(),
                error: "resolved module exceeds the configured parser source-byte budget"
                    .to_string(),
            });
        }
        self.check_temporary_memory_budget(Self::estimate_string_bytes(&record.source))?;
        // Only the sealed engine-owned record memoizes this hash. The
        // provider's claim is checked after the same resource checks on every
        // request, even when the ordinary evaluation cache already has it.
        if record.id.is_empty()
            || resolved.module.request_specifier != specifier
            || resolved.module.canonical_specifier.is_empty()
            || resolved.module.content_hash != record.canonical_hash()
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: specifier.to_string(),
                error: "resolved module identity or canonical content hash is inconsistent"
                    .to_string(),
            });
        }
        if record.syntax == ModuleSyntax::Wasm {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: specifier.to_string(),
                error: "Wasm source requires a separately admitted runtime provider".to_string(),
            });
        }
        if let Some(missing) = record
            .required_capabilities
            .difference(&self.config.granted_capabilities)
            .next()
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: missing.to_string(),
            });
        }
        if record
            .provenance
            .origin
            .starts_with("franken-engine/native-builtin/")
        {
            if NativeBuiltinModule::from_record(record).is_none() {
                return Err(InterpreterError::ModuleLoweringFailed {
                    specifier: specifier.to_string(),
                    error: "resolved built-in is not an authenticated native provider descriptor"
                        .to_string(),
                });
            }
        }
        Ok(resolved)
    }

    /// Resolve an admitted metadata route without requesting an executable
    /// record or touching the module evaluation cache. Policy and resolution
    /// authority are rechecked even when the same filename was already given.
    pub(super) fn resolve_installed_module_metadata(
        &self,
        specifier: &str,
        style: ImportStyle,
    ) -> Result<MetadataResolutionOutcome, InterpreterError> {
        let installed =
            self.module_resolver
                .as_ref()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "closed-world module metadata resolution has no installed resolver"
                        .to_string(),
                })?;
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::ModuleLoad)
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: RuntimeCapability::ModuleLoad.to_string(),
            });
        }
        let request = ModuleRequest::new(specifier, style)
            .with_referrer(
                self.current_module_specifier
                    .as_deref()
                    .unwrap_or_else(|| installed.resolver.entry_referrer()),
            )
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        let resolved = installed
            .resolver
            .resolve_metadata(&request, &installed.context)
            .map_err(|error| {
                if let Some(reason) = ModuleResolutionFailureReason::from_captured_code(error.code)
                {
                    InterpreterError::ModuleResolutionFailed {
                        specifier: specifier.to_string(),
                        reason,
                    }
                } else {
                    InterpreterError::ModuleLoweringFailed {
                        specifier: specifier.to_string(),
                        error: format!("closed-world module resolution refused: {error}"),
                    }
                }
            })?;
        let metadata = &resolved.module.metadata;
        let metadata_bytes = [
            metadata.id.as_str(),
            metadata.provenance.origin.as_str(),
            resolved.module.request_specifier.as_str(),
            resolved.module.canonical_specifier.as_str(),
        ]
        .into_iter()
        .chain(resolved.module.probe_sequence.iter().map(String::as_str))
        .fold(0_u64, |bytes, value| {
            bytes.saturating_add(Self::estimate_string_bytes(value))
        });
        let target_url = match (&metadata.target, style) {
            (ModuleMetadataTarget::Filename, ImportStyle::Require) => None,
            (ModuleMetadataTarget::SourceUrl, ImportStyle::Import) => Some(
                installed
                    .resolver
                    .source_location(&metadata.id)
                    .ok_or_else(|| InterpreterError::ModuleLoweringFailed {
                        specifier: specifier.to_string(),
                        error: "resolved URL metadata has no installed source location".to_string(),
                    })?
                    .url
                    .as_str(),
            ),
            (ModuleMetadataTarget::AbsoluteUrl(url), ImportStyle::Import) => Some(url.as_str()),
            _ => {
                return Err(InterpreterError::ModuleLoweringFailed {
                    specifier: specifier.to_string(),
                    error: "resolved metadata target does not match lookup purpose".to_string(),
                });
            }
        };
        let target_bytes =
            target_url.map_or(0, |url| Self::estimate_string_bytes(url).saturating_mul(8));
        self.check_temporary_memory_budget(metadata_bytes.saturating_add(target_bytes))?;
        if let Some(url) = target_url
            && !Url::parse(url).is_ok_and(|parsed| parsed.as_str() == url)
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: specifier.to_string(),
                error: "resolved URL metadata must contain a normalized absolute URL".to_string(),
            });
        }
        if metadata.id.is_empty()
            || resolved.module.request_specifier != specifier
            || resolved.module.canonical_specifier.is_empty()
            || !metadata
                .required_capabilities
                .contains(&RuntimeCapability::ModuleLoad)
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: specifier.to_string(),
                error: "resolved module metadata has inconsistent identity or resolution authority"
                    .to_string(),
            });
        }
        if let Some(missing) = metadata
            .required_capabilities
            .difference(&self.config.granted_capabilities)
            .next()
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: missing.to_string(),
            });
        }
        if metadata.target == ModuleMetadataTarget::Filename
            && metadata.provenance.kind == ModuleSourceKind::BuiltIn
            && node_builtin_specifier(&metadata.provenance.origin)
                != Some(metadata.provenance.origin.as_str())
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: specifier.to_string(),
                error: "resolved builtin metadata must name an exact canonical Node builtin"
                    .to_string(),
            });
        }
        Ok(resolved)
    }

    /// The module-map key of a resolved module file: the entry module's own
    /// specifier when the file is the entry's (bd-9vouw.411). The entry is
    /// recorded under its source label, the path as the caller gave it
    /// (`app.mjs`, `./app.mjs`, `/dir/./app.mjs`), while imports and
    /// `require` calls resolve to canonical paths, so a cycle back to the
    /// entry missed its record and loaded and evaluated the entry a second
    /// time (its top-level code ran twice, and the first run saw the cycle's
    /// exports missing).
    pub(super) fn module_key_for_canonical_path(&self, canonical: &Path) -> String {
        if let Some(entry) = self.entry_module_specifier.as_deref()
            && Path::new(entry)
                .canonicalize()
                .is_ok_and(|entry_path| entry_path == canonical)
        {
            return entry.to_string();
        }
        canonical.display().to_string()
    }

    /// Not a relative (`./`, `../`) or absolute path: a package name, a
    /// package import (`#x`) or a core module.
    pub(super) fn is_bare_module_specifier(specifier: &str) -> bool {
        !(specifier.starts_with("./")
            || specifier.starts_with("../")
            || specifier.starts_with('/')
            || Path::new(specifier).is_absolute())
    }

    pub(super) fn resolve_require_specifier(
        &self,
        specifier: &str,
    ) -> Result<String, InterpreterError> {
        let is_path_specifier = specifier.starts_with("./")
            || specifier.starts_with("../")
            || specifier == "."
            || specifier == ".."
            || specifier.starts_with('/')
            || Path::new(specifier).is_absolute();
        let candidate = if is_path_specifier {
            // `require('.')` and `require('..')` name directories, as `./`
            // and `../` do.
            let relative = match specifier {
                "." => "./",
                ".." => "../",
                other => other,
            };
            let resolved = self.resolve_specifier_base(relative)?;
            self.resolve_require_candidate(&resolved, relative.ends_with('/'))?
                .ok_or_else(|| InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: ModuleResolutionFailureReason::ModuleNotFound,
                })?
        } else {
            self.resolve_bare_require_specifier(specifier)?
        };
        let canonical = self.canonicalize_module_candidate(specifier, &candidate)?;
        Ok(self.module_key_for_canonical_path(&canonical))
    }

    pub(super) fn resolve_module_candidate(&self, candidate: &Path) -> Option<PathBuf> {
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
        if candidate.extension().is_none() {
            let mjs_path = candidate.with_extension("mjs");
            if mjs_path.is_file() {
                return Some(mjs_path);
            }
            let js_path = candidate.with_extension("js");
            if js_path.is_file() {
                return Some(js_path);
            }
        }
        if candidate.is_dir() {
            let index_mjs = candidate.join("index.mjs");
            if index_mjs.is_file() {
                return Some(index_mjs);
            }
            let index_js = candidate.join("index.js");
            if index_js.is_file() {
                return Some(index_js);
            }
        }
        if candidate.extension().is_none() {
            let index_mjs = candidate.join("index.mjs");
            if index_mjs.is_file() {
                return Some(index_mjs);
            }
            let index_js = candidate.join("index.js");
            if index_js.is_file() {
                return Some(index_js);
            }
        }
        // TypeScript sources (bd-9vouw.431): a project names a module
        // without its extension (`./lib`, `./app.config`, `./dir` for
        // `dir/index.ts`) or by the JavaScript file it compiles to
        // (`./lib.js` for `lib.ts`, `./m.mjs` for `m.mts`: TypeScript's
        // NodeNext spelling), as Bun resolves. Only a specifier no
        // JavaScript file answers reaches these probes.
        let typescript_files = match candidate
            .extension()
            .and_then(|extension| extension.to_str())
        {
            Some("js") => vec![
                candidate.with_extension("ts"),
                candidate.with_extension("tsx"),
            ],
            Some("jsx") => vec![candidate.with_extension("tsx")],
            Some("mjs") => vec![candidate.with_extension("mts")],
            Some("cjs") => vec![candidate.with_extension("cts")],
            _ => ["ts", "tsx", "mts", "cts"]
                .into_iter()
                .map(|extension| package_resolution::with_appended_extension(candidate, extension))
                .collect(),
        };
        if let Some(path) = typescript_files.into_iter().find(|path| path.is_file()) {
            return Some(path);
        }
        if candidate.is_dir() {
            return ["index.ts", "index.tsx"]
                .into_iter()
                .map(|index| candidate.join(index))
                .find(|path| path.is_file());
        }
        None
    }

    /// Node's LOAD_AS_FILE then LOAD_AS_DIRECTORY for a `require` path: the
    /// file itself, then with an extension appended (`a.min` probes
    /// `a.min.js`), then a directory's package.json `main`, then its index.
    pub(super) fn resolve_require_candidate(
        &self,
        candidate: &Path,
        force_directory: bool,
    ) -> Result<Option<PathBuf>, InterpreterError> {
        if !force_directory {
            if candidate.is_file() {
                return Ok(Some(candidate.to_path_buf()));
            }
            let with_extension = ["js", "json", "node"]
                .into_iter()
                .map(|extension| package_resolution::with_appended_extension(candidate, extension))
                .find(|path| path.is_file());
            if with_extension.is_some() {
                return Ok(with_extension);
            }
        }
        if candidate.is_dir() {
            if let Some(main) = self.resolve_package_main(candidate)? {
                return Ok(Some(main));
            }
            return Ok(["index.js", "index.json", "index.node"]
                .into_iter()
                .map(|index| candidate.join(index))
                .find(|path| path.is_file()));
        }
        Ok(None)
    }

    pub(super) fn ensure_module_record(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<ObjectId, InterpreterError> {
        if let Some(record) = self.module_state.modules.get(specifier) {
            return Ok(record.namespace_object);
        }
        // Entry modules are already compiled. Imported records are installed
        // before parsing to support cycle detection, so their actual program
        // is attached by `retain_module_program` immediately after lowering.
        let retain_entry_program = specifier == module.header.source_label;
        let retained_program_bytes = if retain_entry_program {
            Self::retained_module_program_bytes(module, specifier)
        } else {
            0
        };
        // Enforce the logical budget before allocating either the namespace or
        // the duplicated executable IR. If namespace allocation is refused,
        // release this precharge so a failed module load cannot poison later
        // budget checks.
        self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
        self.apply_memory_component_delta(0, retained_program_bytes)?;
        let namespace_object = match self.alloc_object_with_prototype(None) {
            Ok(namespace_object) => namespace_object,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(retained_program_bytes);
                return Err(error);
            }
        };
        // A missing ordinary prototype link lazily inherits Object.prototype.
        // Module namespaces instead have an explicit null [[Prototype]].
        self.store_prototype_link(namespace_object, None);
        let compiled_module = retain_entry_program.then(|| Arc::new(module.clone()));
        self.module_state.modules.insert(
            specifier.to_string(),
            ModuleRuntimeRecord {
                status: ModuleRuntimeStatus::Evaluating,
                namespace_object,
                import_meta_object: None,
                exports: BTreeMap::new(),
                star_exports: BTreeMap::new(),
                local_export_bindings: BTreeMap::new(),
                local_binding_indices: BTreeMap::new(),
                import_origins: BTreeMap::new(),
                star_sources: BTreeSet::new(),
                flow_label_ceiling: None,
                resolved_source_hash: None,
                import_bindings: BTreeMap::new(),
                star_reexporters: BTreeSet::new(),
                cjs_module_object: None,
                compiled_module,
                evaluation_promise: None,
                evaluation_exception: None,
                async_execution: None,
            },
        );
        self.module_state.retained_program_bytes = self
            .module_state
            .retained_program_bytes
            .saturating_add(retained_program_bytes);
        if retain_entry_program {
            self.declare_module_export_bindings(specifier, module)?;
        }
        // ES2020 26.3.1: a namespace's @@toStringTag is "Module", neither
        // writable, enumerable nor configurable (bd-9vouw.399).
        let tag = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        self.set_object_runtime_property(namespace_object, tag.clone(), Value::str("Module"))?;
        self.set_own_property_attributes(
            namespace_object,
            &tag,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: false,
            },
        )?;
        // Namespace [[IsExtensible]] is false from creation, including when a
        // cycle exposes it before evaluation finishes. Export publication is
        // an internal binding update, not an ordinary property definition.
        self.mutate_heap(|heap| heap[namespace_object.0 as usize].is_non_extensible = true);
        Ok(namespace_object)
    }

    pub(super) fn retained_module_function_source_bytes(module: &Ir3Module) -> u64 {
        use crate::ast::FunctionSourceText;

        let entry_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<(u32, FunctionSourceText)>() as u64);
        let mut bytes = u64::try_from(module.function_sources.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(entry_bytes);
        let mut owners: [Option<&FunctionSourceText>; MEMORY_ESTIMATE_FUNCTION_SOURCE_OWNERS] =
            [None; MEMORY_ESTIMATE_FUNCTION_SOURCE_OWNERS];
        let mut owner_count = 0;
        for source in module.function_sources.values() {
            if owners[..owner_count]
                .iter()
                .flatten()
                .any(|owner| source.shares_backing(owner))
            {
                continue;
            }
            // A short view retains the entire original source allocation.
            // Count its Arc control words as well as the backing text.
            bytes = bytes
                .saturating_add(std::mem::size_of::<[usize; 2]>() as u64)
                .saturating_add(u64::try_from(source.retained_backing_len()).unwrap_or(u64::MAX));
            if owner_count < owners.len() {
                owners[owner_count] = Some(source);
                owner_count += 1;
            }
            // No allocating set or quadratic owner scan during preflight.
            // Repeated owners outside the fixed table are charged again,
            // giving a conservative logical bound rather than free storage.
        }
        bytes
    }

    pub(super) fn retained_module_program_bytes(module: &Ir3Module, specifier: &str) -> u64 {
        let instruction_slots = u64::try_from(module.instructions.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Ir3Instruction>() as u64);
        let instruction_strings = module.instructions.iter().fold(0u64, |total, instruction| {
            let dynamic = match instruction {
                Ir3Instruction::LoadBigInt { value, .. } => Self::estimate_string_bytes(value),
                Ir3Instruction::HostCall { capability, .. } => {
                    Self::estimate_string_bytes(&capability.0)
                }
                Ir3Instruction::ImportModule {
                    import_attributes, ..
                } => Self::import_attributes_memory_bytes(import_attributes),
                _ => 0,
            };
            total.saturating_add(dynamic)
        });
        let constant_pool = module.constant_pool.iter().fold(
            u64::try_from(module.constant_pool.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(std::mem::size_of::<JsString>() as u64),
            |total, value| total.saturating_add(Self::estimate_js_string_bytes(value)),
        );
        let function_table = module.function_table.iter().fold(
            u64::try_from(module.function_table.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(std::mem::size_of::<crate::ir_contract::Ir3FunctionDesc>() as u64),
            |total, function| {
                total.saturating_add(
                    function
                        .name
                        .as_deref()
                        .map(Self::estimate_string_bytes)
                        .unwrap_or(0),
                )
            },
        );
        let required_capabilities = module.required_capabilities.iter().fold(
            u64::try_from(module.required_capabilities.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(std::mem::size_of::<CapabilityTag>() as u64),
            |total, capability| total.saturating_add(Self::estimate_string_bytes(&capability.0)),
        );
        let specialization = module.specialization.as_ref().map_or(0, |linkage| {
            let proof_inputs = linkage.proof_input_ids.iter().fold(
                u64::try_from(linkage.proof_input_ids.capacity())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<String>() as u64),
                |total, proof_id| total.saturating_add(Self::estimate_string_bytes(proof_id)),
            );
            (std::mem::size_of::<crate::ir_contract::SpecializationLinkage>() as u64)
                .saturating_add(proof_inputs)
                .saturating_add(Self::estimate_string_bytes(&linkage.optimization_class))
        });
        (std::mem::size_of::<Ir3Module>() as u64)
            .saturating_add(Self::estimate_string_bytes(&module.header.source_label))
            .saturating_add(instruction_slots)
            .saturating_add(instruction_strings)
            .saturating_add(constant_pool)
            .saturating_add(function_table)
            .saturating_add(Self::retained_module_function_source_bytes(module))
            .saturating_add(required_capabilities)
            .saturating_add(specialization)
            .saturating_add(Self::estimate_string_bytes(specifier))
    }

    /// Transient bytes of an isolated call's two-instruction trampoline.
    /// Async continuations retain their original owner program and their own
    /// activation; they do not retain or copy this temporary call site.
    pub(super) fn isolated_call_site_bytes() -> u64 {
        2u64.saturating_mul(std::mem::size_of::<Ir3Instruction>() as u64)
    }

    pub(super) fn transient_module_wrapper_bytes(module: &Ir3Module) -> u64 {
        // Appending the synthetic call/return pair can make Vec grow to roughly
        // twice its previous capacity. Charge that conservative peak rather
        // than only the retained program's steady-state footprint.
        Self::retained_module_program_bytes(module, "<inline-wrapper>")
            .saturating_mul(2)
            .saturating_add(2u64.saturating_mul(std::mem::size_of::<Ir3Instruction>() as u64))
    }

    pub(super) fn retain_module_program(
        &mut self,
        specifier: &str,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        let record = self.module_state.modules.get(specifier).ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "module record missing before program retention".to_string(),
            }
        })?;
        if record.compiled_module.is_some() {
            return Ok(());
        }
        self.declare_module_export_bindings(specifier, module)?;
        let retained_program_bytes = Self::retained_module_program_bytes(module, specifier);
        self.apply_memory_component_delta(0, retained_program_bytes)?;
        let record = self
            .module_state
            .modules
            .get_mut(specifier)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "module record disappeared during program retention".to_string(),
            })?;
        record.compiled_module = Some(Arc::new(module.clone()));
        self.module_state.retained_program_bytes = self
            .module_state
            .retained_program_bytes
            .saturating_add(retained_program_bytes);
        Ok(())
    }

    /// Create the shared CommonJS cache carrier without changing lexical
    /// bindings. JSON modules use the same metadata but execute no wrapper.
    pub(super) fn alloc_cjs_module_object(
        &mut self,
        module: &Ir3Module,
        module_specifier: &str,
        parent_module_object: Option<ObjectId>,
        exports: Value,
    ) -> Result<ObjectId, InterpreterError> {
        self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
        let module_object = self.alloc_object_with_prototype(None)?;
        self.set_object_property(module_object, "exports".to_string(), exports)?;
        self.check_temporary_memory_budget(
            Self::estimate_string_bytes(self.module_filename_view(module_specifier))
                .saturating_add(Self::estimate_string_bytes(
                    self.cjs_dirname_view(module_specifier),
                )),
        )?;
        let (filename_value, dirname_value) = self.cjs_filename_dirname(Some(module_specifier));
        self.set_object_property(module_object, "id".to_string(), filename_value.clone())?;
        self.set_object_property(
            module_object,
            "filename".to_string(),
            filename_value.clone(),
        )?;
        self.set_object_property(module_object, "path".to_string(), dirname_value.clone())?;
        let parent_value = parent_module_object
            .map(Value::Object)
            .unwrap_or(Value::Null);
        self.set_object_property(module_object, "parent".to_string(), parent_value)?;
        self.set_object_property(module_object, "loaded".to_string(), Value::Bool(false))?;
        self.set_cjs_require_property(module_object, module_specifier)?;
        Ok(module_object)
    }

    pub(super) fn init_cjs_environment(
        &mut self,
        module: &Ir3Module,
        module_specifier: &str,
        parent_module_object: Option<ObjectId>,
    ) -> Result<CjsModuleContext, InterpreterError> {
        self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
        let exports_object = self.alloc_object_with_prototype(None)?;
        let module_object = self.alloc_cjs_module_object(
            module,
            module_specifier,
            parent_module_object,
            Value::Object(exports_object),
        )?;
        let context = CjsModuleContext {
            module_object,
            exports_object,
            module_specifier: module_specifier.to_string(),
        };
        self.insert_cjs_bindings(
            context.module_object,
            context.exports_object,
            Some(module_specifier),
        )?;
        Ok(context)
    }

    /// `module` runs a `module.exports` getter (ansi-styles 4 defines one:
    /// `Object.defineProperty(module, 'exports', { get: assembleStyles })`),
    /// which had no module to call it in (bd-9vouw.192).
    pub(super) fn finalize_cjs_exports(
        &mut self,
        module: Option<&Ir3Module>,
        context: &CjsModuleContext,
    ) -> Result<(), InterpreterError> {
        let export_value = self.prototype_chain_get_with_receiver(
            module,
            context.module_object,
            "exports",
            Value::Object(context.module_object),
        )?;
        self.register_module_export("default", export_value.clone())?;
        if let Value::Object(object_id) = export_value {
            let properties = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
                .properties
                .exact_entries()
                .into_iter()
                .map(|(key, value)| (key, value.clone()))
                .collect::<Vec<_>>();
            for (key, value) in properties {
                if key.as_str() == Some("default") {
                    continue;
                }
                self.register_module_export_exact(key, value)?;
            }
        }
        Ok(())
    }

    pub(super) fn import_attributes_memory_bytes(attributes: &ImportAttributes) -> u64 {
        if attributes.is_empty() {
            return 0;
        }
        Self::saturating_sum(attributes.iter().map(|(key, value)| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(key))
                .saturating_add(Self::estimate_string_bytes(value))
        }))
        .saturating_add(std::mem::size_of::<[usize; 2]>() as u64)
        .saturating_add(std::mem::size_of::<BTreeMap<String, String>>() as u64)
    }

    pub(super) fn check_module_import_attributes(
        specifier: &str,
        style: ImportStyle,
        syntax: ModuleSyntax,
        attributes: &ImportAttributes,
    ) -> Result<(), InterpreterError> {
        validate_import_attributes(style, syntax, attributes).map_err(|error| {
            InterpreterError::ModuleLoweringFailed {
                specifier: specifier.to_string(),
                error: error.to_string(),
            }
        })
    }

    pub(super) fn load_module_resolved(
        &mut self,
        module: &Ir3Module,
        resolved: &str,
        load_kind: ModuleLoadKind<'_>,
        import_bound: Option<&Label>,
        delivered: Option<SharedResolvedModule>,
    ) -> Result<Value, InterpreterError> {
        if self.module_resolver.is_some() && delivered.is_none() {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: resolved.to_string(),
                error: "installed resolver cannot fall back to filesystem source".to_string(),
            });
        }
        // LOAD_AS_FILE/LOAD_INDEX must select a .node candidate before any
        // directory fallback, just as Node does. Selection is not permission
        // to execute it: refuse before reading source or populating the module
        // cache, including repeated attempts caught by optional-dependency code.
        if delivered.is_none()
            && Path::new(resolved)
                .extension()
                .is_some_and(|extension| extension == "node")
        {
            return Err(InterpreterError::ModuleResolutionFailed {
                specifier: resolved.to_string(),
                reason: ModuleResolutionFailureReason::NativeAddonUnsupported,
            });
        }
        let is_json = match delivered.as_ref() {
            Some(source) => source.record.syntax == ModuleSyntax::Json,
            None => Path::new(resolved)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json")),
        };
        // Dynamic options have no runtime transport yet. A typed static import
        // or require cache entry cannot authorize an untyped ImportCall.
        if is_json && matches!(load_kind, ModuleLoadKind::DynamicImport) {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: resolved.to_string(),
                error: "dynamic JSON import requires import-options transport; use a static import with type: 'json' or require()".to_string(),
            });
        }
        let empty_attributes = ImportAttributes::default();
        let (style, attributes) = match load_kind {
            ModuleLoadKind::Require => (ImportStyle::Require, &empty_attributes),
            ModuleLoadKind::Import(attributes) => (ImportStyle::Import, attributes),
            ModuleLoadKind::DynamicImport => (ImportStyle::Import, &empty_attributes),
        };
        // Delivered records declare their format, including extensionless JSON
        // and JavaScript whose identity happens to end in .json. Only the
        // ordinary filesystem host uses its existing filename/package rules.
        let syntax = delivered.as_ref().map_or(
            if is_json {
                ModuleSyntax::Json
            } else {
                ModuleSyntax::EsModule
            },
            |source| source.record.syntax,
        );
        Self::check_module_import_attributes(resolved, style, syntax, attributes)?;
        let source_hash = delivered.as_ref().map(|source| source.content_hash);
        if let Some(record) = self.module_state.modules.get(resolved) {
            if source_hash.is_some() && record.resolved_source_hash != source_hash {
                return Err(InterpreterError::ModuleLoweringFailed {
                    specifier: resolved.to_string(),
                    error: "resolved module changed after its first authorized load".to_string(),
                });
            }
            match &record.flow_label_ceiling {
                Some(ceiling) => Self::check_import_flow_bound(resolved, ceiling, import_bound)?,
                // Still being lowered (a cycle reached it first): its bound is
                // unknown, so a bounded importer cannot rely on it. A module
                // that failed to load runs no code, and its error is thrown
                // again below as on the first import (bd-9vouw.389).
                None if import_bound.is_some()
                    && !matches!(record.status, ModuleRuntimeStatus::Failed(_)) =>
                {
                    return Err(InterpreterError::ModuleLoweringFailed {
                        specifier: resolved.to_string(),
                        error: "module flow label ceiling is not known yet (bd-j8f7q)".to_string(),
                    });
                }
                None => {}
            }
            let namespace = record.namespace_object;
            let async_promise = match &record.status {
                ModuleRuntimeStatus::AsyncEvaluating => {
                    Some(record.evaluation_promise.ok_or_else(|| {
                        InterpreterError::ModuleEvaluationFailed {
                            specifier: resolved.to_string(),
                            reason: "async-evaluating module has no evaluation Promise".to_string(),
                        }
                    })?)
                }
                ModuleRuntimeStatus::Evaluating | ModuleRuntimeStatus::Evaluated => None,
                ModuleRuntimeStatus::Failed(reason) => {
                    if record.evaluation_exception.is_some() {
                        return self.rethrow_cached_module_exception(resolved);
                    }
                    // A module whose source was invalid fails every import
                    // with its SyntaxError again (bd-9vouw.389).
                    let reason = reason.clone();
                    let syntax_message = reason
                        .strip_prefix(MODULE_SYNTAX_ERROR_REASON_PREFIX)
                        .map(str::to_string);
                    let json_label = is_json
                        .then_some(record.flow_label_ceiling.as_ref())
                        .flatten();
                    let label_bytes = json_label.map(Self::estimate_label_bytes).unwrap_or(0);
                    self.check_temporary_memory_budget(label_bytes)?;
                    let json_label = json_label.cloned();
                    self.json_reserve_temporary(label_bytes)?;
                    let mut failure = match syntax_message {
                        Some(message) => self.throw_js_error("SyntaxError", message),
                        None => InterpreterError::ModuleEvaluationFailed {
                            specifier: resolved.to_string(),
                            reason,
                        },
                    };
                    if matches!(failure, InterpreterError::UncaughtException { .. })
                        && let Some(label) = json_label.as_ref()
                        && let Err(error) = self.join_pending_exception_label(label)
                    {
                        failure = error;
                    }
                    drop(json_label);
                    self.json_release_temporary(label_bytes);
                    return Err(failure);
                }
            };
            if let Some(promise) = async_promise {
                self.pending_async_module_import = Some((resolved.to_string(), promise));
            }
            return Ok(Value::Object(namespace));
        }

        let namespace_object = self.ensure_module_record(module, resolved)?;
        if let Some(record) = self.module_state.modules.get_mut(resolved) {
            record.resolved_source_hash = source_hash;
        }

        if is_json {
            // Borrow captured bytes on first load as well as cache hits. JSON
            // needs neither a generated JavaScript string nor an owned parser
            // input, AST, lowering pass, execution snapshot or retained IR.
            let source = match delivered.as_ref() {
                Some(source) => Cow::Borrowed(source.record.source.as_str()),
                None => match self.read_module_source(resolved) {
                    Ok(source) => Cow::Owned(source),
                    Err(error) => {
                        self.fail_module_record(resolved, &error.to_string());
                        return Err(error);
                    }
                },
            };
            return self.load_json_module(module, resolved, source.as_ref(), import_bound);
        }

        let source_is_delivered = delivered.is_some();
        let native_provider = delivered
            .as_ref()
            .and_then(|source| NativeBuiltinModule::from_record(&source.record));
        let native_path = matches!(
            native_provider,
            Some(
                NativeBuiltinModule::Path
                    | NativeBuiltinModule::PathPosix
                    | NativeBuiltinModule::PathWin32
            )
        );
        let native_factory = native_provider.and_then(|native| {
            crate::lowering_pipeline::native_runtime_module_source_bytes(native)
                .map(|bytes| (native, bytes))
        });
        let declared_goal = match delivered.as_ref() {
            Some(delivered) => Some(if delivered.record.syntax == ModuleSyntax::CommonJs {
                ParseGoal::Script
            } else {
                ParseGoal::Module
            }),
            None => match self.file_module_parse_goal(resolved, load_kind) {
                Ok(goal) => goal,
                Err(error) => {
                    self.fail_module_record(resolved, &error.to_string());
                    return Err(error);
                }
            },
        };
        let source = match delivered {
            // Cached evaluations returned above without copying the source.
            // The parser requires ownership only for this first compilation.
            Some(delivered) => delivered.record.source.clone(),
            None => match self.read_module_source(resolved) {
                Ok(source) => source,
                Err(error) => {
                    self.fail_module_record(resolved, &error.to_string());
                    return Err(error);
                }
            },
        };
        // Delivered sources were already prepared by their capture host.
        // Normalize filesystem TypeScript before any syntax detection so the
        // detection and execution parser consume the same JavaScript bytes.
        let (source, typed_hostcall_capabilities) = if !source_is_delivered
            && crate::ts_normalization::source_label_has_typescript_extension(resolved)
        {
            match crate::ts_normalization::prepare_source_entry_for_public_entrypoints(
                &source,
                resolved,
                &self.trace_id,
                "module-import",
                "baseline_interpreter",
            ) {
                Ok(prepared) => {
                    let typed_caps = prepared
                        .normalization_output
                        .as_ref()
                        .map(|out| out.ordered_hostcall_capabilities.clone())
                        .unwrap_or_default();
                    (prepared.prepared_source, typed_caps)
                }
                Err(crate::ts_normalization::TsNormalizationError::EmptySource) => {
                    (String::new(), Vec::new())
                }
                Err(error) => {
                    self.fail_module_record(resolved, &error.to_string());
                    return Err(InterpreterError::ModuleParseFailed {
                        specifier: resolved.to_string(),
                        error: error.to_string(),
                    });
                }
            }
        } else {
            (source, Vec::new())
        };
        let source_has_use_strict =
            crate::parser::source_has_use_strict_directive(&source, ParseGoal::Script);
        let (parse_goal, parsed) = match declared_goal {
            Some(goal) => (
                goal,
                CanonicalEs2020Parser.parse_with_options(
                    ParserSource {
                        label: resolved.to_string(),
                        text: source,
                    },
                    goal,
                    &self.config.module_parser_options,
                ),
            ),
            None => {
                // Reuse a successful detection AST for CommonJS lowering.
                // A budget failure or empty source is not evidence of ESM.
                let script = CanonicalEs2020Parser.parse_with_options(
                    ParserSource {
                        label: resolved.to_string(),
                        text: source.clone(),
                    },
                    ParseGoal::Script,
                    &self.config.module_parser_options,
                );
                if script.as_ref().is_err_and(|error| {
                    !matches!(
                        error.code,
                        ParseErrorCode::BudgetExceeded
                            | ParseErrorCode::SourceTooLarge
                            | ParseErrorCode::EmptySource
                    )
                }) {
                    (
                        ParseGoal::Module,
                        CanonicalEs2020Parser.parse_with_options(
                            ParserSource {
                                label: resolved.to_string(),
                                text: source,
                            },
                            ParseGoal::Module,
                            &self.config.module_parser_options,
                        ),
                    )
                } else {
                    (ParseGoal::Script, script)
                }
            }
        };
        let is_cjs = parse_goal == ParseGoal::Script;
        // A module whose source is not valid (a parse error or an early
        // error) is a SyntaxError the importer can catch, as Node's loader
        // throws for `require` and rejects `import()` with (bd-9vouw.389);
        // its record fails, so importing it again fails again. Unsupported
        // syntax and every policy refusal stay uncatchable.
        let syntax_tree = match (native_factory, parsed) {
            _ if native_path => {
                self.check_temporary_memory_budget(
                    crate::lowering_pipeline::path_module::RUNTIME_SOURCE_BYTES as u64,
                )
                .inspect_err(|error| self.fail_module_record(resolved, &error.to_string()))?;
                crate::lowering_pipeline::path_module::runtime_module_tree().map_err(|error| {
                    self.fail_module_record(resolved, &error.to_string());
                    InterpreterError::ModuleLoweringFailed {
                        specifier: resolved.to_string(),
                        error: error.to_string(),
                    }
                })?
            }
            (Some((native, source_bytes)), _) => {
                self.check_temporary_memory_budget(source_bytes as u64)
                    .inspect_err(|error| self.fail_module_record(resolved, &error.to_string()))?;
                crate::lowering_pipeline::native_runtime_module_tree(native).map_err(|error| {
                    self.fail_module_record(resolved, &error.to_string());
                    InterpreterError::ModuleLoweringFailed {
                        specifier: resolved.to_string(),
                        error: error.to_string(),
                    }
                })?
            }
            (None, Ok(syntax_tree)) => syntax_tree,
            // An empty file, or one holding only comments, white space or
            // TypeScript declarations, is a module with no code and no
            // exports, which Node and Bun load (bd-9vouw.430); the parser
            // reports it as an empty source.
            (None, Err(error)) if error.code == ParseErrorCode::EmptySource => {
                crate::ast::SyntaxTree {
                    goal: parse_goal,
                    body: Vec::new(),
                    span: crate::ast::SourceSpan::new(0, 0, 1, 1, 1, 1),
                }
            }
            (None, Err(error)) => {
                return Err(
                    // InvalidGoal: an import or export declaration in a
                    // CommonJS (script) module, a SyntaxError in Node too.
                    if matches!(
                        error.code,
                        ParseErrorCode::StrictModeWithStatement
                            | ParseErrorCode::AwaitOutsideAsync
                            | ParseErrorCode::InvalidClassElementName
                            | ParseErrorCode::InvalidSyntax
                            | ParseErrorCode::InvalidGoal
                    ) {
                        self.fail_module_with_syntax_error(resolved, error.message.clone())
                    } else {
                        self.fail_module_record(resolved, &error.to_string());
                        InterpreterError::ModuleParseFailed {
                            specifier: resolved.to_string(),
                            error: error.to_string(),
                        }
                    },
                );
            }
        };
        // An empty file (or one holding only comments) is a module with no
        // code and no exports, which Node loads; lowering refuses an empty
        // body, so it lowers as one empty block.
        let mut syntax_tree = syntax_tree;
        if syntax_tree.body.is_empty() {
            syntax_tree
                .body
                .push(crate::ast::Statement::Block(crate::ast::BlockStatement {
                    body: Vec::new(),
                    span: syntax_tree.span,
                }));
        }
        let mut ir0 = Ir0Module::from_syntax_tree(syntax_tree, resolved);
        ir0.script_strict = Some(parse_goal == ParseGoal::Module || source_has_use_strict);
        // Dependencies execute in this same admitted cell. Preserve its
        // explicit process-shape grant and effective host/replay provenance
        // instead of lowering every dependency under fresh deny-all/unknown
        // defaults. No module record or source text can widen these settings.
        let ambient_grant = if self.config.process_shape_read_allowed {
            AmbientAuthorityGrant::TrustedProcessShape
        } else {
            AmbientAuthorityGrant::DenyAll
        };
        let lowering_ctx =
            LoweringContext::new(&self.trace_id, "module-import", "baseline_interpreter")
                .with_ambient_authority_grant(ambient_grant)
                .with_host_io_exception_provenance(self.filesystem_exception_provenance())
                .with_typed_hostcall_capabilities(typed_hostcall_capabilities);
        let lowering_ctx = if is_cjs {
            lowering_ctx.with_authenticated_commonjs_runtime_bindings()
        } else {
            lowering_ctx
        };
        let lowering_ctx = if self.module_resolver.is_some() {
            lowering_ctx.with_preserved_runtime_module_loads()
        } else {
            lowering_ctx
        };
        // bd-j8f7q: a module a bounded importer loads bounds its own imports
        // too, so the bound holds transitively and is checked at each edge.
        let lowered = if import_bound.is_some() {
            crate::lowering_pipeline::lower_bounded_import_ir0_to_ir3(&ir0, &lowering_ctx)
        } else {
            lower_ir0_to_ir3(&ir0, &lowering_ctx)
        };
        let lowering_output = match lowered {
            Ok(lowering_output) => lowering_output,
            Err(error) => {
                return Err(match error {
                    crate::lowering_pipeline::LoweringPipelineError::SemanticViolation(
                        violation,
                    ) => self.fail_module_with_syntax_error(resolved, violation.to_string()),
                    error => {
                        self.fail_module_record(resolved, &error.to_string());
                        InterpreterError::ModuleLoweringFailed {
                            specifier: resolved.to_string(),
                            error: error.to_string(),
                        }
                    }
                });
            }
        };
        let ceiling = crate::lowering_pipeline::lowered_unit_flow_label_ceiling(
            &lowering_output.ir2,
            lowering_ctx.host_io_exception_provenance,
        );
        if let Err(refusal) = Self::check_import_flow_bound(resolved, &ceiling, import_bound) {
            if let Some(record) = self.module_state.modules.get_mut(resolved) {
                record.status = ModuleRuntimeStatus::Failed(refusal.to_string());
            }
            return Err(refusal);
        }
        self.set_module_flow_label_ceiling(resolved, &ceiling)
            .inspect_err(|error| self.fail_module_record(resolved, &error.to_string()))?;
        self.retain_module_program(resolved, &lowering_output.ir3)?;
        let eval_result = if is_cjs {
            self.evaluate_cjs_ir3(&lowering_output.ir3, resolved)
                .map(|()| false)
        } else {
            self.evaluate_module_ir3(&lowering_output.ir3, resolved)
        };
        match eval_result {
            Ok(async_evaluating) => {
                if let Some(record) = self.module_state.modules.get_mut(resolved) {
                    record.status = if async_evaluating {
                        ModuleRuntimeStatus::AsyncEvaluating
                    } else {
                        ModuleRuntimeStatus::Evaluated
                    };
                }
                if !async_evaluating {
                    self.sort_module_namespace_keys(resolved)?;
                }
                if async_evaluating {
                    let promise = self
                        .module_state
                        .modules
                        .get(resolved)
                        .and_then(|record| record.evaluation_promise)
                        .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                            specifier: resolved.to_string(),
                            reason: "suspended module has no evaluation Promise".to_string(),
                        })?;
                    self.pending_async_module_import = Some((resolved.to_string(), promise));
                }
                Ok(Value::Object(namespace_object))
            }
            Err(err) => {
                if let Some(record) = self.module_state.modules.get_mut(resolved) {
                    record.status = ModuleRuntimeStatus::Failed(err.to_string());
                }
                if !is_cjs && matches!(&err, InterpreterError::UncaughtException { .. }) {
                    self.cache_pending_module_exception(resolved)?;
                }
                Err(err)
            }
        }
    }

    /// Retain an ESM evaluation's first guest throw without consuming the
    /// pending slot needed by its current importer. Admit the retained payload
    /// before cloning it; a resource refusal remains an engine failure.
    pub(super) fn cache_pending_module_exception(
        &mut self,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let record = self.module_state.modules.get(specifier).ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "module exception has no module record".to_string(),
            }
        })?;
        if record.evaluation_exception.is_some() {
            return Ok(());
        }
        let Some(value) = self.pending_exception.as_ref() else {
            return Ok(());
        };
        let retained_bytes = Self::estimate_value_bytes(value)
            .saturating_add(Self::estimate_label_bytes(&self.pending_exception_label));
        self.apply_memory_component_delta(0, retained_bytes)?;
        let exception = self
            .pending_exception
            .as_ref()
            .map(|value| (value.clone(), self.pending_exception_label.clone()));
        self.module_state
            .modules
            .get_mut(specifier)
            .expect("module record remains present during exception retention")
            .evaluation_exception = exception;
        Ok(())
    }

    /// Re-arm the recorded completion in the current importer. The module
    /// record remains its owner and GC root after the pending slot is consumed.
    pub(super) fn rethrow_cached_module_exception<T>(
        &mut self,
        specifier: &str,
    ) -> Result<T, InterpreterError> {
        let exception = self
            .module_state
            .modules
            .get(specifier)
            .and_then(|record| record.evaluation_exception.as_ref())
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "module has no retained guest exception".to_string(),
            })?;
        self.check_temporary_memory_budget(Self::module_evaluation_exception_bytes(exception))?;
        let exception = exception.clone();
        self.rearm_nested_module_throw(Some(exception))?;
        // Do not inspect a mutable thrown object again just to format a
        // diagnostic. Its exact value is already in the pending slot; its
        // message could now be arbitrarily large or carry newer provenance.
        Err(InterpreterError::UncaughtException {
            value: "module evaluation failed".to_string(),
        })
    }

    #[cfg(test)]
    pub(super) fn import_module(
        &mut self,
        module: &Ir3Module,
        specifier: &JsString,
    ) -> Result<Value, InterpreterError> {
        self.import_module_with_native_effect_provenance(
            module,
            specifier,
            &ImportAttributes::default(),
            &mut false,
        )
    }

    pub(super) fn import_module_with_native_effect_provenance(
        &mut self,
        module: &Ir3Module,
        specifier: &JsString,
        import_attributes: &ImportAttributes,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        *native_effect = false;
        let specifier = Self::utf8_module_specifier(specifier)?;
        self.run_pre_import_hook(module, specifier)?;
        let delivered = self
            .module_resolver
            .as_ref()
            .map(|_| {
                self.resolve_installed_module(specifier, ImportStyle::Import, import_attributes)
            })
            .transpose()?;
        // A unit lowered under the bounded-imports contract assumed this
        // module yields at most IFC_BOUNDED_IMPORT_LABEL.
        let import_bound = (crate::lowering_pipeline::is_bounded_import_specifier(specifier)
            && Self::unit_declares_bounded_imports(module))
        .then_some(crate::lowering_pipeline::IFC_BOUNDED_IMPORT_LABEL);
        if let Some(source) = delivered.as_ref()
            && let Some(native) = NativeBuiltinModule::from_record(&source.module.record)
        {
            let namespace =
                self.load_native_builtin_namespace(module, source, native, import_bound.as_ref())?;
            *native_effect = matches!(
                native,
                NativeBuiltinModule::Http
                    | NativeBuiltinModule::Https
                    | NativeBuiltinModule::ChildProcess
            );
            return Ok(namespace);
        }
        let resolved = match &delivered {
            Some(source) => source.module.record.id.clone(),
            None => match self.resolve_module_specifier(specifier)? {
                package_resolution::ModuleResolutionTarget::File(path) => {
                    self.module_key_for_canonical_path(&path)
                }
                package_resolution::ModuleResolutionTarget::Native(native) => {
                    Self::check_module_import_attributes(
                        specifier,
                        ImportStyle::Import,
                        ModuleSyntax::EsModule,
                        import_attributes,
                    )?;
                    let namespace = self.load_ordinary_native_builtin_namespace(
                        module,
                        specifier,
                        native,
                        import_bound.as_ref(),
                    )?;
                    *native_effect = matches!(
                        native,
                        NativeBuiltinModule::Http
                            | NativeBuiltinModule::Https
                            | NativeBuiltinModule::ChildProcess
                    );
                    return Ok(namespace);
                }
            },
        };
        self.load_module_resolved(
            module,
            &resolved,
            ModuleLoadKind::Import(import_attributes),
            import_bound.as_ref(),
            delivered.map(|source| source.module),
        )
    }

    /// Mark a module whose load failed before evaluation, so a later import
    /// of it fails with the same reason instead of seeing an empty record.
    pub(super) fn fail_module_record(&mut self, resolved: &str, reason: &str) {
        if let Some(record) = self.module_state.modules.get_mut(resolved) {
            record.status = ModuleRuntimeStatus::Failed(reason.to_string());
        }
    }

    /// Fail a module whose source is invalid: its record remembers the
    /// SyntaxError, which this import and every later one throws
    /// (bd-9vouw.389).
    pub(super) fn fail_module_with_syntax_error(
        &mut self,
        resolved: &str,
        message: String,
    ) -> InterpreterError {
        self.fail_module_record(
            resolved,
            &format!("{MODULE_SYNTAX_ERROR_REASON_PREFIX}{message}"),
        );
        self.throw_js_error("SyntaxError", message)
    }

    /// Whether `module` was lowered under the bounded-imports contract
    /// (bd-j8f7q): it carries the contract marker.
    pub(super) fn unit_declares_bounded_imports(module: &Ir3Module) -> bool {
        module.instructions.iter().any(|instruction| {
            matches!(instruction, Ir3Instruction::HostCall { capability, .. }
                if capability.0 == crate::lowering_pipeline::IFC_BOUNDED_IMPORTS_CONTRACT)
        })
    }

    /// Retain a module's flow ceiling only after its dynamic label payload
    /// has been admitted. Replacement must not leave a new cache label behind
    /// when the memory budget refuses the operation.
    pub(super) fn set_module_flow_label_ceiling(
        &mut self,
        specifier: &str,
        ceiling: &Label,
    ) -> Result<(), InterpreterError> {
        let previous_bytes = self
            .module_state
            .modules
            .get(specifier)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "module record missing before flow ceiling publication".to_string(),
            })?
            .flow_label_ceiling
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let next_bytes = Self::estimate_label_bytes(ceiling);
        self.check_temporary_memory_budget(next_bytes)?;
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.module_state
            .modules
            .get_mut(specifier)
            .expect("module record was checked before flow ceiling admission")
            .flow_label_ceiling = Some(ceiling.clone());
        Ok(())
    }

    /// Refuse an import whose module can produce a label above the
    /// importer's assumed bound (bd-j8f7q).
    pub(super) fn check_import_flow_bound(
        resolved: &str,
        ceiling: &Label,
        import_bound: Option<&Label>,
    ) -> Result<(), InterpreterError> {
        match import_bound {
            Some(bound) if !ceiling.can_flow_to(bound) => {
                Err(InterpreterError::ModuleLoweringFailed {
                    specifier: resolved.to_string(),
                    error: format!(
                        "module flow label ceiling {ceiling:?} exceeds the importer's bounded-import contract {bound:?} (bd-j8f7q)"
                    ),
                })
            }
            _ => Ok(()),
        }
    }

    /// The captured-graph `node:module` surface. `createRequire` itself is
    /// unbound: each call validates the executing module's trusted origin,
    /// then returns the ordinary require value bound to that opaque id.
    pub(super) fn module_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(MODULE_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let object = self.alloc_object_with_properties(&[(
            "createRequire",
            Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ModuleCreateRequire,
            )),
        )])?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(MODULE_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// First-class crypto exports use the same native hostcalls as direct
    /// lowering. In particular, fetching the module or extracting a method
    /// never reads entropy; RandomRead is checked when that method is called.
    pub(super) fn crypto_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(CRYPTO_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let constants = self.crypto_constants(RegRange { start: 0, count: 0 })?;
        let mut members: Vec<(&str, Value)> = crate::lowering_pipeline::CRYPTO_METHOD_NAMES
            .iter()
            .map(|&name| {
                let tag = crate::lowering_pipeline::crypto_method_capability(name)
                    .expect("native crypto exports share the lowering inventory");
                (
                    name,
                    Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag)),
                )
            })
            .collect();
        members.push(("constants", constants));
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(CRYPTO_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// Loading child_process only creates realm-owned callable values. The
    /// existing signed process provider, live capability hooks and IFC policy
    /// are checked when a function is invoked, even through an alias.
    pub(super) fn child_process_core_module(
        &mut self,
        module: &Ir3Module,
    ) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(CHILD_PROCESS_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let mut members = Vec::with_capacity(CHILD_PROCESS_FUNCTIONS.len());
        for (operation, name, _) in CHILD_PROCESS_FUNCTIONS {
            let function =
                Value::BuiltinFunction(BuiltinFunction::native_child_process_function(operation));
            let prototype = self.native_child_process_function_prototype(operation)?;
            let backing = self
                .ensure_function_own_property_object(module, &function)?
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "native child_process function has no property storage".to_string(),
                })?;
            self.set_object_property(backing, "prototype".to_string(), Value::Object(prototype))?;
            self.set_own_property_attributes(
                backing,
                &RuntimePropertyKey::String(JsString::from("prototype")),
                PropertyAttributes {
                    writable: true,
                    enumerable: false,
                    configurable: false,
                },
            )?;
            members.push((name, function));
        }
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(CHILD_PROCESS_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    pub(super) fn native_child_process_function_prototype(
        &mut self,
        operation: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let (operation, _, _) =
            native_child_process_function_metadata(operation).ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "known native child_process function".to_string(),
                    got: operation.to_string(),
                }
            })?;
        let key = format!("\0franken-engine/native-child_process/prototype/{operation}");
        if let Some(object) = self.builtin_prototypes.get(&key) {
            return Ok(*object);
        }
        let parent = self.ensure_builtin_prototype("Object")?;
        let prototype = self.alloc_object_with_prototype(Some(parent))?;
        self.install_prototype_constructor(
            prototype,
            Value::BuiltinFunction(BuiltinFunction::native_child_process_function(operation)),
        )?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(key, prototype);
        });
        Ok(prototype)
    }

    /// First-class HTTP modules share the already implemented request,
    /// listener and Agent kernels. Loading either module grants no network
    /// authority and performs no I/O. Every invocation checks its exact tag.
    pub(super) fn http_core_module(
        &mut self,
        module: &Ir3Module,
        use_tls: bool,
    ) -> Result<Value, InterpreterError> {
        let key = if use_tls {
            HTTPS_MODULE_KEY
        } else {
            HTTP_MODULE_KEY
        };
        if let Some(object) = self.builtin_prototypes.get(key) {
            return Ok(Value::Object(*object));
        }
        let tags: &[&'static str] = if use_tls {
            &[
                "builtin:HttpsGet",
                "builtin:HttpsRequest",
                "builtin:HttpsAgent",
            ]
        } else {
            &[
                "builtin:HttpCreateServer",
                "builtin:HttpGet",
                "builtin:HttpRequest",
                "builtin:HttpAgent",
            ]
        };
        let mut members = Vec::with_capacity(tags.len() + 2);
        for &tag in tags {
            let (_, name, _) = native_http_function_metadata(tag)
                .expect("the native HTTP export table contains known operations");
            let function = Value::BuiltinFunction(BuiltinFunction::native_http_function(tag));
            let prototype = self.native_http_function_prototype(tag)?;
            let backing = self
                .ensure_function_own_property_object(module, &function)?
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "native HTTP function has no property storage".to_string(),
                })?;
            self.set_object_property(backing, "prototype".to_string(), Value::Object(prototype))?;
            self.set_own_property_attributes(
                backing,
                &RuntimePropertyKey::String(JsString::from("prototype")),
                PropertyAttributes {
                    writable: true,
                    enumerable: false,
                    configurable: false,
                },
            )?;
            members.push((name, function));
        }
        if !use_tls {
            members.push(("STATUS_CODES", self.http_status_codes()?));
            members.push(("METHODS", self.http_methods()?));
        }
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(key.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    pub(super) fn native_http_function_prototype(
        &mut self,
        tag: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let (tag, _, _) =
            native_http_function_metadata(tag).ok_or_else(|| InterpreterError::TypeError {
                expected: "known native HTTP function".to_string(),
                got: tag.to_string(),
            })?;
        let key = format!("\0franken-engine/native-http/prototype/{tag}");
        if let Some(object) = self.builtin_prototypes.get(&key) {
            return Ok(*object);
        }
        let parent = match tag {
            "builtin:HttpAgent" => self.ensure_builtin_prototype("EventEmitter")?,
            "builtin:HttpsAgent" => self.native_http_function_prototype("builtin:HttpAgent")?,
            _ => self.ensure_builtin_prototype("Object")?,
        };
        let prototype = self.alloc_object_with_prototype(Some(parent))?;
        self.install_prototype_constructor(
            prototype,
            Value::BuiltinFunction(BuiltinFunction::native_http_function(tag)),
        )?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(key, prototype);
        });
        Ok(prototype)
    }

    /// The codec functions retain their existing work, output, memory and
    /// callback-label checks when passed across a module or invoked indirectly.
    pub(super) fn zlib_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(ZLIB_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let constants = self.zlib_constants()?;
        let mut members: Vec<(&str, Value)> = crate::lowering_pipeline::ZLIB_METHOD_NAMES
            .iter()
            .map(|&name| {
                let tag = crate::lowering_pipeline::zlib_method_capability(name)
                    .expect("native zlib exports share the lowering inventory");
                (
                    name,
                    Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag)),
                )
            })
            .collect();
        members.push(("constants", constants));
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(ZLIB_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// `require('timers')` (bd-9vouw.231): Node's timers module, whose six
    /// timer functions are the realm's own. xml2js reads
    /// `require('timers').setImmediate`; the timers facade lowers only the
    /// calls it recognizes on a confirmed alias, so the require reached the
    /// runtime and found no module. The promises property and direct
    /// timers/promises imports share one retained native factory. Loading
    /// either module initializes wrappers without scheduling any timer.
    pub(super) fn timers_core_module(
        &mut self,
        module: &Ir3Module,
    ) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(TIMERS_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        self.source_builtin_module(module, NativeBuiltinModule::TimersPromises, None)?;
        let carrier = self
            .builtin_prototypes
            .get("\0franken-engine/native-timers/promises")
            .copied()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "native timer promises factory has no export carrier".to_string(),
            })?;
        let mut members = Self::timer_global_kinds()
            .into_iter()
            .filter(|(name, _)| *name != "queueMicrotask")
            .map(|(name, kind)| {
                (
                    name,
                    Value::BuiltinFunction(BuiltinFunction::new_kind(kind)),
                )
            })
            .collect::<Vec<_>>();
        members.push((
            "promises",
            Value::Accessor {
                get: Some(Arc::new(Value::BuiltinFunction(BuiltinFunction::bound_to(
                    BuiltinFunctionKind::NativeTimerPromisesGetter,
                    carrier,
                )))),
                set: None,
            },
        ));
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(TIMERS_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// `require('perf_hooks')` (bd-9vouw.302): Node's perf_hooks module with
    /// the realm's `performance`, the same object as the global (no further
    /// authority). cannon-es reads `require('perf_hooks').performance`; the
    /// require reached the runtime and found no module. Not provided:
    /// `PerformanceObserver`, `monitorEventLoopDelay`, `createHistogram`,
    /// `constants`.
    pub(super) fn perf_hooks_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(PERF_HOOKS_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let (performance, label) = match self.resolve_runtime_name_binding("performance") {
            Some(binding) => {
                let state = binding.state()?;
                self.check_temporary_memory_budget(
                    Self::estimate_value_bytes(&state.value)
                        .saturating_add(Self::estimate_label_bytes(&state.label)),
                )?;
                (state.value.clone(), state.label.clone())
            }
            None => (Value::Undefined, Label::Public),
        };
        let object = self.alloc_object_with_properties(&[("performance", performance)])?;
        // The mutable binding may carry provenance even when its value is a
        // scalar or an otherwise Public object. Retain that reference label
        // before caching the provider so neither CJS nor ESM can erase it.
        self.set_own_runtime_property_label(
            object,
            &RuntimePropertyKey::String(JsString::from("performance")),
            &label,
        )?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(PERF_HOOKS_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// `require('url')` (bd-9vouw.224): Node's url module with the realm's
    /// `URL` and `URLSearchParams` and the legacy `fileURLToPath`, `format`
    /// and `parse` over the url facade's own HostCalls. The facade lowers only
    /// the call shapes it recognizes on a confirmed alias; joi's
    /// `@sideway/address` reads `require('url').URL`, so the require reached
    /// the runtime and found no module. Not provided: `pathToFileURL` (it
    /// resolves against the working directory), `resolve`, `resolveObject`,
    /// `domainToASCII`, `domainToUnicode`, `urlToHttpOptions`, `Url`.
    pub(super) fn url_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(URL_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let object = self.alloc_object_with_properties(&[
            (
                "URL",
                Value::BuiltinFunction(BuiltinFunction::standard_constructor("URL")),
            ),
            (
                "URLSearchParams",
                Value::BuiltinFunction(BuiltinFunction::standard_constructor("URLSearchParams")),
            ),
            (
                "fileURLToPath",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall(
                    "builtin:UrlFileUrlToPath",
                )),
            ),
            (
                "format",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:UrlFormat")),
            ),
            (
                "parse",
                Value::BuiltinFunction(BuiltinFunction::static_hostcall("builtin:UrlParse")),
            ),
        ])?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(URL_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// `require('os')` (bd-9vouw.204): Node's os module over the os facade's
    /// own HostCalls (fixed, engine-contained values; no host reads), with
    /// `constants`, `EOL` and `devNull` as the facade reads them. The facade
    /// claims a program-level alias only where it can lower every use: hjson's
    /// `var os = require('os')` read `os.EOL || '\n'` inside an object
    /// literal, so the require reached the runtime and found no module.
    pub(super) fn os_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(OS_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let constants = self.os_constants_object()?;
        let mut members = Vec::with_capacity(crate::lowering_pipeline::OS_METHOD_NAMES.len() + 3);
        for name in crate::lowering_pipeline::OS_METHOD_NAMES {
            let tag = crate::lowering_pipeline::os_method_capability(name)
                .expect("OS_METHOD_NAMES names are all in the facade table");
            members.push((
                name,
                Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag)),
            ));
        }
        members.push(("constants", constants));
        members.push(("EOL", Value::str("\n")));
        members.push(("devNull", Value::str("/dev/null")));
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(OS_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// querystring's supported native methods as ordinary mutable properties.
    /// Caching in the realm's traced prototype roots keeps module and function
    /// identity stable across literal, dynamic and cross-file require calls.
    /// Calling an extracted method still enters `call_static_hostcall`, which
    /// checks the caller's Builtin capability and joins its operand labels.
    pub(super) fn querystring_core_module(&mut self) -> Result<Value, InterpreterError> {
        if let Some(object) = self.builtin_prototypes.get(QUERYSTRING_MODULE_KEY) {
            return Ok(Value::Object(*object));
        }
        let members: Vec<(&str, Value)> = crate::lowering_pipeline::QUERYSTRING_METHOD_NAMES
            .iter()
            .map(|&name| {
                let tag = crate::lowering_pipeline::querystring_method_capability(name)
                    .expect("querystring module exports have native capability tags");
                (
                    name,
                    Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag)),
                )
            })
            .collect();
        let object = self.alloc_object_with_properties(&members)?;
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(QUERYSTRING_MODULE_KEY.to_string(), object);
        });
        Ok(Value::Object(object))
    }

    /// `os.constants`: `{ signals, errno, priority }` (real POSIX numbers; see
    /// the NODE_OS_* tables).
    pub(super) fn os_constants_object(&mut self) -> Result<Value, InterpreterError> {
        let signals = self.alloc_os_constant_group(NODE_OS_SIGNALS)?;
        let errno = self.alloc_os_constant_group(NODE_OS_ERRNO)?;
        let priority = self.alloc_os_constant_group(NODE_OS_PRIORITY)?;
        let object_id = self.alloc_object_with_properties(&[
            ("signals", signals),
            ("errno", errno),
            ("priority", priority),
        ])?;
        Ok(Value::Object(object_id))
    }

    #[cfg(test)]
    pub(super) fn require_module(
        &mut self,
        module: &Ir3Module,
        specifier: &JsString,
    ) -> Result<Value, InterpreterError> {
        self.require_module_with_native_effect_provenance(module, specifier, &mut false)
    }

    pub(super) fn require_module_with_native_effect_provenance(
        &mut self,
        module: &Ir3Module,
        specifier: &JsString,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        *native_effect = false;
        let specifier = Self::utf8_module_specifier(specifier)?;
        self.run_pre_import_hook(module, specifier)?;
        if self.module_resolver.is_none()
            && let Some(native) = NativeBuiltinModule::from_specifier(specifier)
        {
            let value = self.native_builtin_module(module, native, None)?;
            *native_effect = matches!(
                native,
                NativeBuiltinModule::Http
                    | NativeBuiltinModule::Https
                    | NativeBuiltinModule::ChildProcess
            );
            return Ok(value);
        }
        let delivered = self
            .module_resolver
            .as_ref()
            .map(|_| {
                self.resolve_installed_module(
                    specifier,
                    ImportStyle::Require,
                    &ImportAttributes::default(),
                )
            })
            .transpose()?;
        let resolved = match &delivered {
            Some(source) => source.module.record.id.clone(),
            None => self.resolve_require_specifier(specifier)?,
        };
        if let Some(source) = delivered.as_ref()
            && let Some(native) = NativeBuiltinModule::from_record(&source.module.record)
        {
            let value = self.load_native_builtin_resolved(module, source, native, None)?;
            *native_effect = matches!(
                native,
                NativeBuiltinModule::Http
                    | NativeBuiltinModule::Https
                    | NativeBuiltinModule::ChildProcess
            );
            return Ok(value);
        }
        let is_json = match delivered.as_ref() {
            Some(source) => source.module.record.syntax == ModuleSyntax::Json,
            None => Path::new(&resolved)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json")),
        };
        let namespace = self.load_module_resolved(
            module,
            &resolved,
            ModuleLoadKind::Require,
            None,
            delivered.map(|source| source.module),
        )?;
        if let Some(record) = self.module_state.modules.get(&resolved)
            && let Some(module_object) = record.cjs_module_object
        {
            // Native JSON keeps the parsed value's label on this cache
            // carrier, including primitives with no reachable object graph.
            if is_json {
                return self.iterator_protocol_property(
                    Some(module),
                    module_object,
                    &RuntimePropertyKey::String(JsString::from("exports")),
                    Value::Object(module_object),
                );
            }
            // A `module.exports` getter runs on every require, as in Node.
            let export_value = self.prototype_chain_get_with_receiver(
                Some(module),
                module_object,
                "exports",
                Value::Object(module_object),
            )?;
            return Ok(export_value);
        }
        // Requiring an ES module returns its namespace. A JSON namespace's
        // default also remains the fallback for a record without a CJS carrier.
        if !is_json {
            return Ok(namespace);
        }
        let Value::Object(namespace_object) = namespace else {
            return Ok(namespace);
        };
        self.iterator_protocol_property(
            Some(module),
            namespace_object,
            &RuntimePropertyKey::String(JsString::from("default")),
            Value::Object(namespace_object),
        )
    }

    /// Built-ins share the ordinary module identity map. Pin the descriptor
    /// before returning its realm-owned value so a resolver cannot change the
    /// provider behind a cached opaque id, or alias a source module's id.
    pub(super) fn load_native_builtin_resolved(
        &mut self,
        module: &Ir3Module,
        source: &SharedResolutionOutcome,
        native: NativeBuiltinModule,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        let resolved = &source.module.record.id;
        if let Some(record) = self.module_state.modules.get(resolved)
            && record.resolved_source_hash != Some(source.module.content_hash)
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: resolved.clone(),
                error: "resolved module changed after its first authorized load".to_string(),
            });
        }
        let value = self.native_builtin_module(module, native, import_bound)?;
        // A source provider can create its private retained module while it
        // initializes. A resolver-supplied id must not overwrite that new
        // module's authenticated identity with a different provider hash.
        if let Some(record) = self.module_state.modules.get(resolved)
            && record.resolved_source_hash != Some(source.module.content_hash)
        {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: resolved.clone(),
                error: "resolved module changed during native provider initialization".to_string(),
            });
        }
        let new_record = !self.module_state.modules.contains_key(resolved);
        self.ensure_module_record(module, resolved)?;
        if let Some(record) = self.module_state.modules.get_mut(resolved) {
            record.resolved_source_hash = Some(source.module.content_hash);
            // A CommonJS cache hit must not reset a separately evaluated
            // native ESM facade, including an in-flight or failed facade
            // whose private id was also supplied by the resolver.
            if new_record {
                record.status = ModuleRuntimeStatus::Evaluated;
            }
        }
        Ok(value)
    }

    /// Return the engine-owned object for a supported CommonJS core module.
    /// Installed resolvers must authorize and authenticate the descriptor
    /// before reaching this cache, including on repeated and alias lookups.
    pub(super) fn native_builtin_module(
        &mut self,
        module: &Ir3Module,
        native: NativeBuiltinModule,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        match native {
            NativeBuiltinModule::Crypto => self.crypto_core_module(),
            NativeBuiltinModule::Zlib => self.zlib_core_module(),
            NativeBuiltinModule::Http => self.http_core_module(module, false),
            NativeBuiltinModule::Https => self.http_core_module(module, true),
            NativeBuiltinModule::ChildProcess => self.child_process_core_module(module),
            NativeBuiltinModule::Module => self.module_core_module(),
            NativeBuiltinModule::Os => self.os_core_module(),
            NativeBuiltinModule::Querystring => self.querystring_core_module(),
            NativeBuiltinModule::Url => self.url_core_module(),
            NativeBuiltinModule::Timers => self.timers_core_module(module),
            NativeBuiltinModule::PerfHooks => self.perf_hooks_core_module(),
            NativeBuiltinModule::Path
            | NativeBuiltinModule::PathPosix
            | NativeBuiltinModule::PathWin32 => self.path_core_module(module, native),
            NativeBuiltinModule::Buffer
            | NativeBuiltinModule::Util
            | NativeBuiltinModule::UtilTypes
            | NativeBuiltinModule::Events
            | NativeBuiltinModule::Fs
            | NativeBuiltinModule::FsPromises
            | NativeBuiltinModule::Assert
            | NativeBuiltinModule::AssertStrict
            | NativeBuiltinModule::StringDecoder
            | NativeBuiltinModule::TimersPromises
            | NativeBuiltinModule::Stream
            | NativeBuiltinModule::StreamPromises
            | NativeBuiltinModule::StreamConsumers
            | NativeBuiltinModule::StreamWeb
            | NativeBuiltinModule::Readline
            | NativeBuiltinModule::ReadlinePromises
            | NativeBuiltinModule::DiagnosticsChannel => {
                self.source_builtin_module(module, native, import_bound)
            }
        }
    }

    /// Keep named exports tied to the engine's supported provider surface.
    /// CommonJS mutations change the values read on first ESM initialization,
    /// but adding an arbitrary property cannot add a module export. Reuse the
    /// facade inventories where the provider itself is table-driven.
    pub(super) fn native_builtin_export_names(native: NativeBuiltinModule) -> Vec<&'static str> {
        match native {
            NativeBuiltinModule::ChildProcess => CHILD_PROCESS_FUNCTIONS
                .iter()
                .map(|(_, name, _)| *name)
                .collect(),
            NativeBuiltinModule::Http => {
                vec![
                    "Agent",
                    "METHODS",
                    "STATUS_CODES",
                    "createServer",
                    "get",
                    "request",
                ]
            }
            NativeBuiltinModule::Https => vec!["Agent", "get", "request"],
            NativeBuiltinModule::Fs => vec![
                "readFileSync",
                "writeFileSync",
                "appendFileSync",
                "existsSync",
                "statSync",
                "lstatSync",
                "readdirSync",
                "mkdirSync",
                "unlinkSync",
                "rmdirSync",
                "rmSync",
                "renameSync",
                "copyFileSync",
                "accessSync",
                "chmodSync",
                "utimesSync",
                "realpathSync",
                "readlinkSync",
                "symlinkSync",
                "truncateSync",
                "mkdtempSync",
                "openSync",
                "closeSync",
                "fsyncSync",
                "readSync",
                "writeSync",
                "readvSync",
                "writevSync",
                "cpSync",
                "readFile",
                "writeFile",
                "appendFile",
                "exists",
                "stat",
                "lstat",
                "readdir",
                "mkdir",
                "unlink",
                "rmdir",
                "rm",
                "rename",
                "copyFile",
                "access",
                "chmod",
                "utimes",
                "realpath",
                "readlink",
                "symlink",
                "truncate",
                "mkdtemp",
                "open",
                "close",
                "fsync",
                "read",
                "write",
                "readv",
                "writev",
                "cp",
                "Dir",
                "opendirSync",
                "opendir",
                "globSync",
                "glob",
                "createReadStream",
                "createWriteStream",
                "ReadStream",
                "WriteStream",
                "constants",
                "promises",
            ],
            NativeBuiltinModule::FsPromises => vec![
                "constants",
                "open",
                "mkdir",
                "readdir",
                "stat",
                "lstat",
                "unlink",
                "rmdir",
                "rm",
                "rename",
                "copyFile",
                "access",
                "chmod",
                "utimes",
                "realpath",
                "readlink",
                "symlink",
                "truncate",
                "mkdtemp",
                "readFile",
                "writeFile",
                "appendFile",
                "opendir",
                "glob",
                "cp",
            ],
            NativeBuiltinModule::Module => vec!["createRequire"],
            NativeBuiltinModule::Crypto => crate::lowering_pipeline::CRYPTO_METHOD_NAMES
                .into_iter()
                .chain(["constants"])
                .collect(),
            NativeBuiltinModule::Zlib => crate::lowering_pipeline::ZLIB_METHOD_NAMES
                .into_iter()
                .chain(["constants"])
                .collect(),
            NativeBuiltinModule::Buffer => vec![
                "Buffer",
                "SlowBuffer",
                "transcode",
                "isUtf8",
                "isAscii",
                "kMaxLength",
                "kStringMaxLength",
                "btoa",
                "atob",
                "constants",
                "INSPECT_MAX_BYTES",
                "Blob",
                "resolveObjectURL",
                "File",
            ],
            NativeBuiltinModule::Events => vec![
                "EventEmitter",
                "once",
                "on",
                "defaultMaxListeners",
                "errorMonitor",
                "captureRejections",
                "listenerCount",
                "getEventListeners",
                "setMaxListeners",
                "getMaxListeners",
                "addAbortListener",
            ],
            NativeBuiltinModule::Os => crate::lowering_pipeline::OS_METHOD_NAMES
                .into_iter()
                .chain(["constants", "EOL", "devNull"])
                .collect(),
            NativeBuiltinModule::Querystring => {
                crate::lowering_pipeline::QUERYSTRING_METHOD_NAMES.to_vec()
            }
            NativeBuiltinModule::Url => {
                vec!["URL", "URLSearchParams", "fileURLToPath", "format", "parse"]
            }
            NativeBuiltinModule::Timers => Self::timer_global_kinds()
                .into_iter()
                .filter_map(|(name, _)| (name != "queueMicrotask").then_some(name))
                .chain(std::iter::once("promises"))
                .collect(),
            NativeBuiltinModule::PerfHooks => vec!["performance"],
            NativeBuiltinModule::Path
            | NativeBuiltinModule::PathPosix
            | NativeBuiltinModule::PathWin32 => PATH_ESM_EXPORT_NAMES.to_vec(),
            NativeBuiltinModule::Util => vec![
                "format",
                "formatWithOptions",
                "inspect",
                "inherits",
                "promisify",
                "callbackify",
                "deprecate",
                "debuglog",
                "debug",
                "isDeepStrictEqual",
                "parseArgs",
                "parseEnv",
                "styleText",
                "stripVTControlCharacters",
                "toUSVString",
                "types",
                "isArray",
                "TextEncoder",
                "TextDecoder",
                "MIMEType",
                "MIMEParams",
            ],
            NativeBuiltinModule::UtilTypes => vec![
                "isDate",
                "isRegExp",
                "isMap",
                "isSet",
                "isWeakMap",
                "isWeakSet",
                "isPromise",
                "isArrayBuffer",
                "isAnyArrayBuffer",
                "isDataView",
                "isNativeError",
                "isProxy",
                "isGeneratorFunction",
                "isAsyncFunction",
                "isGeneratorObject",
                "isNumberObject",
                "isStringObject",
                "isBooleanObject",
                "isBigIntObject",
                "isSymbolObject",
                "isBoxedPrimitive",
                "isTypedArray",
                "isArrayBufferView",
                "isInt8Array",
                "isUint8Array",
                "isUint8ClampedArray",
                "isInt16Array",
                "isUint16Array",
                "isInt32Array",
                "isUint32Array",
                "isFloat32Array",
                "isFloat64Array",
                "isBigInt64Array",
                "isBigUint64Array",
            ],
            NativeBuiltinModule::Assert | NativeBuiltinModule::AssertStrict => vec![
                "AssertionError",
                "fail",
                "ok",
                "equal",
                "notEqual",
                "deepEqual",
                "notDeepEqual",
                "strictEqual",
                "notStrictEqual",
                "deepStrictEqual",
                "notDeepStrictEqual",
                "match",
                "doesNotMatch",
                "ifError",
                "throws",
                "doesNotThrow",
                "rejects",
                "doesNotReject",
                "strict",
            ],
            NativeBuiltinModule::StringDecoder => vec!["StringDecoder"],
            NativeBuiltinModule::Readline => vec![
                "Interface",
                "createInterface",
                "promises",
                "cursorTo",
                "moveCursor",
                "clearLine",
                "clearScreenDown",
            ],
            NativeBuiltinModule::ReadlinePromises => {
                vec!["Interface", "createInterface", "Readline"]
            }
            NativeBuiltinModule::DiagnosticsChannel => vec![
                "channel",
                "hasSubscribers",
                "subscribe",
                "unsubscribe",
                "tracingChannel",
                "Channel",
            ],
            NativeBuiltinModule::TimersPromises => {
                vec!["setTimeout", "setImmediate", "setInterval", "scheduler"]
            }
            NativeBuiltinModule::Stream => vec![
                "Stream",
                "Readable",
                "Writable",
                "Duplex",
                "Transform",
                "PassThrough",
                "pipeline",
                "finished",
                "compose",
                "destroy",
                "isReadable",
                "isWritable",
                "isErrored",
                "isDisturbed",
                "isDestroyed",
                "addAbortSignal",
                "duplexPair",
                "promises",
                "_isUint8Array",
                "_uint8ArrayToBuffer",
            ],
            NativeBuiltinModule::StreamPromises => vec!["pipeline", "finished"],
            NativeBuiltinModule::StreamConsumers => {
                vec!["arrayBuffer", "blob", "buffer", "text", "json"]
            }
            NativeBuiltinModule::StreamWeb => vec![
                "ReadableStream",
                "ReadableStreamDefaultReader",
                "ReadableStreamDefaultController",
                "ReadableByteStreamController",
                "ReadableStreamBYOBReader",
                "ReadableStreamBYOBRequest",
                "WritableStream",
                "WritableStreamDefaultWriter",
                "WritableStreamDefaultController",
                "TransformStream",
                "TransformStreamDefaultController",
                "CountQueuingStrategy",
                "ByteLengthQueuingStrategy",
                "TextEncoderStream",
                "TextDecoderStream",
            ],
        }
    }

    /// Bound the mutable state reachable from a native export without calling
    /// guest code. A descriptor authenticates the provider, not later guest
    /// writes to its shared CommonJS object. Unknown accessors, proxies and
    /// opaque suspended values stay fail-high. Callable effects retain their ordinary
    /// invocation checks; their existing property storage is visited here too.
    /// The iterative walk charges every edge and reserves its guest-sized
    /// worklist before growing it, including on cached namespace imports.
    pub(super) fn native_builtin_state_label(
        &mut self,
        module: &Ir3Module,
        root: ObjectId,
    ) -> Result<Label, InterpreterError> {
        self.native_builtin_state_label_with_floor(module, root, Label::Internal)
    }

    pub(super) fn native_builtin_state_label_with_floor(
        &mut self,
        module: &Ir3Module,
        root: ObjectId,
        mut label: Label,
    ) -> Result<Label, InterpreterError> {
        // Only the root and its prototype chain can supply properties read
        // during the namespace snapshot. Nested accessors remain deferred
        // code, like methods, but only audited native factory code is admitted.
        // Private prototype-override cells expose their own value and label,
        // not their implementation carrier's implicit Object prototype.
        let mut pending = vec![(root, true, true)];
        let mut visited = BTreeSet::new();
        while let Some((object_id, snapshot_lookup, follow_prototype)) = pending.pop() {
            self.charge_property_copy_work()?;
            if visited.contains(&(object_id, snapshot_lookup, follow_prototype)) {
                continue;
            }
            let object = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let edges = object
                .properties
                .exact_len()
                .saturating_add(object.properties.baseline_symbol_key_order().len());
            let work = u64::try_from(edges).unwrap_or(u64::MAX).saturating_mul(3);
            if work
                > self
                    .config
                    .instruction_budget
                    .saturating_sub(self.instructions_executed)
            {
                return Err(InterpreterError::BudgetExhausted {
                    executed: self.instructions_executed,
                    budget: self.config.instruction_budget,
                });
            }
            // An accessor can contribute storage and receivers for two
            // intrinsic functions. Include Vec's retained spare capacity.
            let slots = pending
                .len()
                .saturating_add(edges.saturating_mul(4))
                .saturating_add(1);
            let capacity = pending.capacity().max(slots.saturating_mul(2));
            let temporary_bytes = (visited.len().saturating_add(1) as u64)
                .saturating_mul(64)
                .saturating_add((capacity as u64).saturating_mul(std::mem::size_of::<(
                    ObjectId,
                    bool,
                    bool,
                )>() as u64));
            self.check_temporary_memory_budget(
                temporary_bytes.saturating_add(Self::estimate_label_bytes(&label)),
            )?;
            visited.insert((object_id, snapshot_lookup, follow_prototype));
            if object.brand() == Some(PROXY_TYPE_TAG)
                || !object.private_elements.is_empty()
                || object.primitive_value.is_some()
                || object.blob.is_some()
                || object.regexp.is_some()
                || self.weakmap_storage.contains_key(&object_id)
            {
                // These payloads are not ordinary labeled property edges.
                // Keep them opaque until their complete retained-state label
                // contract is available to this bounded import path.
                return Ok(Label::TopSecret);
            }
            for candidate in self
                .object_mutation_labels
                .get(&object_id)
                .into_iter()
                .chain(self.binary_storage_label_ref(object_id))
                .chain(self.url_state_label_ref(object_id))
                .chain(self.cluster_state_label_ref(object_id))
                .chain(self.stream_state_label_ref(object_id))
                .chain(object.property_labels.values_unordered())
            {
                self.check_temporary_memory_budget(
                    temporary_bytes
                        .saturating_add(Self::estimate_label_bytes(&label))
                        .saturating_add(Self::estimate_label_bytes(candidate)),
                )?;
                label = self.join_owned_label_with_temporary_budget(label, candidate)?;
            }
            for (_, property) in object.property_labels.baseline_symbol_properties() {
                if let BaselineSymbolProperty::Data(candidate) = property {
                    self.check_temporary_memory_budget(
                        temporary_bytes
                            .saturating_add(Self::estimate_label_bytes(&label))
                            .saturating_add(Self::estimate_label_bytes(candidate)),
                    )?;
                    label = self.join_owned_label_with_temporary_budget(label, candidate)?;
                }
            }
            let mut opaque = false;
            for value in object.properties.values_unordered() {
                opaque |=
                    self.queue_native_builtin_value(module, value, !snapshot_lookup, &mut pending)?;
            }
            for (_, property) in object.properties.baseline_symbol_properties() {
                match property {
                    BaselineSymbolProperty::Data(value) => {
                        opaque |= self.queue_native_builtin_value(
                            module,
                            value,
                            !snapshot_lookup,
                            &mut pending,
                        )?;
                    }
                    BaselineSymbolProperty::Accessor { get, set } => {
                        opaque |= self.queue_native_builtin_accessor(
                            module,
                            get.as_ref(),
                            set.as_ref(),
                            !snapshot_lookup,
                            &mut pending,
                        )?;
                    }
                }
            }
            if follow_prototype
                && let Some(prototype) = self.observable_prototype_link(object, object_id)
            {
                pending.push((prototype, snapshot_lookup, true));
            }
            self.instructions_executed = self.instructions_executed.saturating_add(work);
            if opaque {
                return Ok(Label::TopSecret);
            }
        }
        Ok(label)
    }

    pub(super) fn queue_native_builtin_value(
        &self,
        module: &Ir3Module,
        value: &Value,
        allow_deferred_factory_accessor: bool,
        pending: &mut Vec<(ObjectId, bool, bool)>,
    ) -> Result<bool, InterpreterError> {
        match value {
            Value::Object(object) => pending.push((*object, false, true)),
            Value::Accessor { get, set } => {
                return self.queue_native_builtin_accessor(
                    module,
                    get.as_deref(),
                    set.as_deref(),
                    allow_deferred_factory_accessor,
                    pending,
                );
            }
            Value::Promise(_)
            | Value::Iterator(_)
            | Value::Generator(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorObject(_) => return Ok(true),
            function if function.is_callable() => {
                if let Value::BuiltinFunction(builtin) = function {
                    if builtin.kind == BuiltinFunctionKind::CallableProxy {
                        return Ok(true);
                    }
                    if let Some(receiver) = builtin.bound_object {
                        pending.push((ObjectId(receiver), false, true));
                    }
                }
                if let Some(object) = self.function_own_property_object(module, function)? {
                    pending.push((object, false, true));
                }
                if let Some((object, follow_prototype)) =
                    self.existing_function_prototype_state_object(module, function)?
                {
                    pending.push((object, false, follow_prototype));
                }
            }
            _ => {}
        }
        Ok(false)
    }

    /// Visit a lazily created intrinsic prototype only while it remains outside
    /// the function's ordinary property storage. Materialized properties are
    /// already visited with the backing object, including replacement labels.
    pub(super) fn existing_function_prototype_state_object(
        &self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<(ObjectId, bool)>, InterpreterError> {
        let (index, closure) = match function {
            Value::Function(index) => (*index, false),
            Value::Closure(index)
            | Value::GeneratorFunction(index)
            | Value::AsyncGeneratorFunction(index) => (*index, true),
            _ => return Ok(None),
        };
        if !self.function_has_intrinsic_prototype(function) {
            return Ok(None);
        }
        if let Some(backing) = self.function_own_property_object(module, function)?
            && self
                .heap
                .get(backing.0 as usize)
                .is_some_and(|object| object.properties.contains_key("prototype"))
        {
            return Ok(None);
        }
        let foreign = self.foreign_closure_module(function, module)?;
        let ids = self.prototype_owner_ids(foreign.as_deref().unwrap_or(module));
        let intrinsic_owner = if closure { ids.closure } else { ids.function };
        Ok(self
            .function_prototypes
            .get(&(intrinsic_owner, index))
            .map(|object| (*object, true)))
    }

    /// Identify the narrowly audited deferred accessors in immutable native
    /// factory programs. The guest-visible function name is not authority.
    /// In particular, util.promisify/deprecate create closures in the same
    /// program that capture guest callbacks; their code is not an accessor.
    pub(super) fn is_deferred_native_factory_accessor(
        &self,
        function: &Value,
        setter: bool,
    ) -> bool {
        let Value::Closure(closure_id) = function else {
            return false;
        };
        if self
            .closure_generated_function_artifacts
            .get(closure_id)
            .is_some()
        {
            return false;
        }
        let Some(origin) = self.closure_module_origins.get(closure_id) else {
            return false;
        };
        let provider = match origin.as_str() {
            "\0franken-engine/native-util" => 0,
            "\0franken-engine/native-string_decoder" => 1,
            "\0franken-engine/native-timers/promises" => 2,
            "\0franken-engine/native-stream" => 3,
            "\0franken-engine/native-buffer" => 4,
            "\0franken-engine/native-stream/web" => 5,
            "\0franken-engine/native-diagnostics_channel" => 6,
            _ => return false,
        };
        static FACTORY_HASHES: OnceLock<[ContentHash; 7]> = OnceLock::new();
        let hashes = FACTORY_HASHES.get_or_init(|| {
            [
                NativeBuiltinModule::Util
                    .record("\0franken-engine/native-util")
                    .canonical_hash(),
                NativeBuiltinModule::StringDecoder
                    .record("\0franken-engine/native-string_decoder")
                    .canonical_hash(),
                NativeBuiltinModule::TimersPromises
                    .record("\0franken-engine/native-timers/promises")
                    .canonical_hash(),
                NativeBuiltinModule::Stream
                    .record("\0franken-engine/native-stream")
                    .canonical_hash(),
                NativeBuiltinModule::Buffer
                    .record("\0franken-engine/native-buffer")
                    .canonical_hash(),
                NativeBuiltinModule::StreamWeb
                    .record("\0franken-engine/native-stream/web")
                    .canonical_hash(),
                NativeBuiltinModule::DiagnosticsChannel
                    .record("\0franken-engine/native-diagnostics_channel")
                    .canonical_hash(),
            ]
        });
        let Some(record) = self.module_state.modules.get(origin) else {
            return false;
        };
        if record.resolved_source_hash != Some(hashes[provider])
            || !matches!(record.status, ModuleRuntimeStatus::Evaluated)
        {
            return false;
        }
        let Some(program) = record.compiled_module.as_ref() else {
            return false;
        };
        if program.header.source_label != *origin {
            return false;
        }
        let Some(closure) = self.closures.get(*closure_id as usize) else {
            return false;
        };
        let Some(code) = program.function_table.get(closure.function_index as usize) else {
            return false;
        };
        if code.is_generator || code.rest_param_index.is_some() {
            return false;
        }
        if provider == 6 {
            // These two immutable prototype getters inspect private channel
            // state only when called on a receiver. Namespace publication
            // never invokes them. A guest getter, even with the same name,
            // must retain the ordinary fail-high path.
            let Some(source) = program.function_sources.get(&closure.function_index) else {
                return false;
            };
            return !setter
                && code.arity == 0
                && code.name.as_deref() == Some("hasSubscribers")
                && matches!(
                    source.as_str().trim(),
                    "get hasSubscribers() {\n      const s = state(this);\n      return s.subscribers.length !== 0 || s.storeCount !== 0;\n    }"
                        | "get hasSubscribers() {\n      for (let i = 0; i < eventNames.length; i++) if (this[eventNames[i]].hasSubscribers) return true;\n      return false;\n    }"
                );
        }
        if provider == 5 {
            // Web Stream accessors are deferred receiver operations over the
            // factory's private WeakMaps. Reading an export never invokes one.
            // Authenticate the entire retained getter against the immutable
            // embedded sources; a same-named guest function or a callback
            // created by a stream algorithm cannot acquire this admission.
            let Some(source) = program.function_sources.get(&closure.function_index) else {
                return false;
            };
            let source = source.as_str().trim();
            return !setter
                && code.arity == 0
                && source.starts_with("get ")
                && (include_str!("../lowering_pipeline/web_stream_module.js").contains(source)
                    || include_str!("../lowering_pipeline/web_text_stream_module.js")
                        .contains(source));
        }
        if provider == 4 {
            // File's two metadata getters are deferred until an actual File
            // receiver is read. Authenticate their complete immutable bodies;
            // the same program also contains lazy Web Stream accessors and
            // ordinary callbacks that must not inherit this admission.
            let source = program
                .function_sources
                .get(&closure.function_index)
                .map(|source| source.as_str().trim());
            return !setter
                && code.arity == 0
                && matches!(
                    (code.name.as_deref(), source),
                    (
                        Some("name"),
                        Some("get name() { return state(this).name; }")
                    ) | (
                        Some("lastModified"),
                        Some("get lastModified() { return state(this).lastModified; }")
                    )
                );
        }
        if provider == 3 {
            // Only stream's receiver-owned state accessors are deferred here.
            // The same retained program contains the lazy Web factory, whose
            // class getters can have identical names and arities (notably
            // "closed") while reading captured maps and promise state.
            // Immutable source distinguishes object methods from class
            // accessors and decoder function expressions; guest .name writes
            // cannot supply this identity.
            let Some(name) = code.name.as_deref() else {
                return false;
            };
            let Some(source) = program.function_sources.get(&closure.function_index) else {
                return false;
            };
            if !source
                .as_str()
                .trim_start()
                .strip_prefix(name)
                .is_some_and(|tail| tail.starts_with('('))
            {
                return false;
            }
            return matches!(
                (setter, name, code.arity),
                (
                    false,
                    "get"
                        | "readableDidRead"
                        | "readableAborted"
                        | "readableHighWaterMark"
                        | "readableBuffer"
                        | "readableLength"
                        | "readableObjectMode"
                        | "readableEncoding"
                        | "errored"
                        | "closed"
                        | "readableEnded"
                        | "writableFinished"
                        | "writableObjectMode"
                        | "writableBuffer"
                        | "writableEnded"
                        | "writableNeedDrain"
                        | "writableHighWaterMark"
                        | "writableCorked"
                        | "writableLength"
                        | "writableAborted",
                    0
                ) | (true, "set", 1)
            );
        }
        matches!(
            (provider, setter, code.name.as_deref(), code.arity),
            (
                0,
                false,
                Some("get" | "type" | "subtype" | "essence" | "params"),
                0
            ) | (0, true, Some("set" | "type" | "subtype"), 1)
                | (1 | 2, false, Some("get"), 0)
        )
    }

    pub(super) fn queue_native_builtin_accessor(
        &self,
        module: &Ir3Module,
        get: Option<&Value>,
        set: Option<&Value>,
        allow_deferred_factory_accessor: bool,
        pending: &mut Vec<(ObjectId, bool, bool)>,
    ) -> Result<bool, InterpreterError> {
        // These canonical accessors only expose the receiver or its already
        // visited prototype. Their identity cannot be forged by guest source.
        // Keep arbitrary getters opaque, including guest replacements of an
        // intrinsic accessor; descriptor/property labels are still joined.
        for (function, setter) in [(get, false), (set, true)] {
            let Some(function) = function else {
                continue;
            };
            if allow_deferred_factory_accessor
                && self.is_deferred_native_factory_accessor(function, setter)
            {
                if self.queue_native_builtin_value(module, function, true, pending)? {
                    return Ok(true);
                }
                continue;
            }
            let Value::BuiltinFunction(builtin) = function else {
                return Ok(true);
            };
            let inert = builtin.kind == BuiltinFunctionKind::ThrowTypeError
                || (!setter
                    && builtin.kind == BuiltinFunctionKind::NativeTimerPromisesGetter
                    && builtin.bound_object.is_some_and(|holder| {
                        self.builtin_prototypes
                            .get("\0franken-engine/native-timers/promises")
                            == Some(&ObjectId(holder))
                    }))
                || (setter && builtin.kind == BuiltinFunctionKind::ObjectProtoSetter)
                || (!setter
                    && builtin.kind == BuiltinFunctionKind::PrototypeGetter
                    && builtin
                        .module_specifier
                        .0
                        .as_deref()
                        .and_then(prototype_getters::prototype_getter_entry)
                        .is_some_and(|(owner, key, _)| {
                            (*owner == "Object" && *key == "__proto__")
                                || *key == prototype_getters::SPECIES_GETTER_KEY
                                || (*owner == "TypedArray"
                                    && *key == prototype_getters::TYPED_ARRAY_TO_STRING_TAG)
                        }));
            if !inert || self.queue_native_builtin_value(module, function, true, pending)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Ordinary imports use the same native providers and authority contract as
    /// an installed resolver. This path is entered only without a resolver;
    /// a captured graph's refusal can never fall back to an ambient provider.
    pub(super) fn load_ordinary_native_builtin_namespace(
        &mut self,
        module: &Ir3Module,
        request_specifier: &str,
        native: NativeBuiltinModule,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        let descriptor = native.record(native.canonical_specifier());
        if let Some(missing) = descriptor
            .required_capabilities
            .difference(&self.config.granted_capabilities)
            .next()
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: missing.to_string(),
            });
        }
        let value = self.native_builtin_module(module, native, import_bound)?;
        self.native_builtin_namespace(module, request_specifier, native, value, import_bound)
    }

    /// Authenticate an installed resolver's native identity before consulting
    /// the namespace cache, including repeated and aliased requests.
    pub(super) fn load_native_builtin_namespace(
        &mut self,
        module: &Ir3Module,
        source: &SharedResolutionOutcome,
        native: NativeBuiltinModule,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        let value = self.load_native_builtin_resolved(module, source, native, import_bound)?;
        self.native_builtin_namespace(
            module,
            &source.module.request_specifier,
            native,
            value,
            import_bound,
        )
    }

    /// Materialize one ESM namespace per native provider. Its default export
    /// is the realm's runtime CommonJS object; named exports snapshot the
    /// supported properties only on the first ESM load. Authorization has
    /// already run for this request, including cache hits. Path and PathPosix
    /// share their default object but keep distinct facades.
    pub(super) fn native_builtin_namespace(
        &mut self,
        module: &Ir3Module,
        request_specifier: &str,
        native: NativeBuiltinModule,
        value: Value,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        let specifier = match native {
            NativeBuiltinModule::Buffer => "\0franken-engine/native-buffer/esm",
            NativeBuiltinModule::Crypto => "\0franken-engine/native-crypto/esm",
            NativeBuiltinModule::Zlib => "\0franken-engine/native-zlib/esm",
            NativeBuiltinModule::Http => "\0franken-engine/native-http/esm",
            NativeBuiltinModule::Https => "\0franken-engine/native-https/esm",
            NativeBuiltinModule::ChildProcess => "\0franken-engine/native-child_process/esm",
            NativeBuiltinModule::Fs => "\0franken-engine/native-fs/esm",
            NativeBuiltinModule::FsPromises => "\0franken-engine/native-fs/promises/esm",
            NativeBuiltinModule::Module => "\0franken-engine/native-module/esm",
            NativeBuiltinModule::Events => "\0franken-engine/native-events/esm",
            NativeBuiltinModule::Os => "\0franken-engine/native-os/esm",
            NativeBuiltinModule::Querystring => "\0franken-engine/native-querystring/esm",
            NativeBuiltinModule::Url => "\0franken-engine/native-url/esm",
            NativeBuiltinModule::Timers => "\0franken-engine/native-timers/esm",
            NativeBuiltinModule::PerfHooks => "\0franken-engine/native-perf_hooks/esm",
            NativeBuiltinModule::Path => PATH_ESM_MODULE_ID,
            NativeBuiltinModule::PathPosix => PATH_POSIX_ESM_MODULE_ID,
            NativeBuiltinModule::PathWin32 => PATH_WIN32_ESM_MODULE_ID,
            NativeBuiltinModule::Util => "\0franken-engine/native-util/esm",
            NativeBuiltinModule::UtilTypes => "\0franken-engine/native-util/types/esm",
            NativeBuiltinModule::Assert => "\0franken-engine/native-assert/esm",
            NativeBuiltinModule::AssertStrict => "\0franken-engine/native-assert/strict/esm",
            NativeBuiltinModule::StringDecoder => "\0franken-engine/native-string_decoder/esm",
            NativeBuiltinModule::TimersPromises => "\0franken-engine/native-timers/promises/esm",
            NativeBuiltinModule::Stream => "\0franken-engine/native-stream/esm",
            NativeBuiltinModule::StreamPromises => "\0franken-engine/native-stream/promises/esm",
            NativeBuiltinModule::StreamConsumers => "\0franken-engine/native-stream/consumers/esm",
            NativeBuiltinModule::StreamWeb => "\0franken-engine/native-stream/web/esm",
            NativeBuiltinModule::Readline => "\0franken-engine/native-readline/esm",
            NativeBuiltinModule::ReadlinePromises => {
                "\0franken-engine/native-readline/promises/esm"
            }
            NativeBuiltinModule::DiagnosticsChannel => {
                "\0franken-engine/native-diagnostics_channel/esm"
            }
        };
        let object = match &value {
            Value::Object(object) => *object,
            function => self
                .function_own_property_object(module, function)?
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "native provider has no export property storage".to_string(),
                })?,
        };
        if import_bound.is_some() {
            // A submodule can cache a classified reference to an otherwise
            // public function. Its selection label is independent of the
            // mutable state reachable from that function's property storage.
            let selected_label = self.json_parse_context_label()?;
            Self::check_import_flow_bound(request_specifier, &selected_label, import_bound)?;
            let ceiling = self.native_builtin_state_label(module, object)?;
            Self::check_import_flow_bound(request_specifier, &ceiling, import_bound)?;
        }
        let content_hash = native.record(specifier).canonical_hash();
        if let Some(record) = self.module_state.modules.get(specifier) {
            if record.resolved_source_hash != Some(content_hash) {
                return Err(InterpreterError::ModuleLoweringFailed {
                    specifier: request_specifier.to_string(),
                    error: "native namespace identity is already bound to another source"
                        .to_string(),
                });
            }
            match &record.status {
                ModuleRuntimeStatus::Failed(_) => {
                    let key = RuntimePropertyKey::String(JsString::from("error"));
                    let cached =
                        self.builtin_prototypes
                            .get(specifier)
                            .copied()
                            .and_then(|carrier| {
                                self.heap
                                    .get(carrier.0 as usize)
                                    .and_then(|object| object.own_runtime_property_value(&key))
                                    .map(|value| (carrier, value))
                            });
                    if let Some((carrier, thrown)) = cached {
                        let label = self.runtime_property_label(carrier, &key);
                        self.replace_pending_abrupt_slots(Some((thrown, label)), None)?;
                        return Err(InterpreterError::UncaughtException {
                            value: "native namespace evaluation failed".to_string(),
                        });
                    }
                    // A containment failure has no guest exception to replay.
                    // Never turn it into a catchable module Error on a retry.
                    return Err(InterpreterError::InternalError {
                        details: "native namespace initialization was refused".to_string(),
                    });
                }
                ModuleRuntimeStatus::Evaluating => {
                    let namespace = record.namespace_object;
                    // A getter may recursively import this facade. Its import
                    // must wait for the outer initialization, including a
                    // later throw, instead of exposing a partial namespace.
                    let promise = self.ensure_module_evaluation_promise(specifier)?;
                    self.pending_async_module_import = Some((specifier.to_string(), promise));
                    return Ok(Value::Object(namespace));
                }
                ModuleRuntimeStatus::Evaluated
                    if record.exports.contains_key(&JsString::from("default")) =>
                {
                    let namespace = record.namespace_object;
                    if import_bound.is_some() {
                        let ceiling = self.native_builtin_state_label(module, namespace)?;
                        Self::check_import_flow_bound(request_specifier, &ceiling, import_bound)?;
                    }
                    return Ok(Value::Object(namespace));
                }
                ModuleRuntimeStatus::AsyncEvaluating => {
                    return Err(InterpreterError::InternalError {
                        details: "a native namespace cannot evaluate asynchronously".to_string(),
                    });
                }
                ModuleRuntimeStatus::Evaluated => {}
            }
        }
        let namespace = self.ensure_module_record(module, specifier)?;
        if let Some(record) = self.module_state.modules.get_mut(specifier) {
            record.resolved_source_hash = Some(content_hash);
            record.status = ModuleRuntimeStatus::Evaluating;
        }
        let initialized = (|| -> Result<(), InterpreterError> {
            // Native imports can run outside a hostcall observation scope.
            // Track descriptor shape, getter effects and exceptional labels
            // while preserving the caller's pending-result ownership.
            let selected_label = self.json_parse_context_label()?;
            let selected_bytes = Self::estimate_label_bytes(&selected_label);
            self.json_reserve_temporary(selected_bytes)?;
            let observation = self.begin_property_observation([]);
            self.json_release_temporary(selected_bytes);
            let observation = observation?;
            let outcome = (|| -> Result<(), InterpreterError> {
                // Opening the scope saved and cleared the pending result.
                // The provider reference still labels every published export.
                self.json_observe_label(selected_label)?;
                for name in Self::native_builtin_export_names(native) {
                    let key = RuntimePropertyKey::String(JsString::from(name));
                    let member =
                        self.iterator_protocol_property(Some(module), object, &key, value.clone())?;
                    let label = self.json_parse_context_label()?;
                    self.publish_module_export(
                        specifier,
                        JsString::from(name),
                        member,
                        label.clone(),
                        ExportPublication::Own,
                    )?;
                    self.set_own_runtime_property_label(namespace, &key, &label)?;
                }
                // Publish the completion marker last so a partial initialization
                // can never be mistaken for a successfully cached namespace.
                let key = RuntimePropertyKey::String(JsString::from("default"));
                let default_label = self.json_parse_context_label()?;
                self.publish_module_export(
                    specifier,
                    JsString::from("default"),
                    value.clone(),
                    default_label.clone(),
                    ExportPublication::Own,
                )?;
                self.set_own_runtime_property_label(namespace, &key, &default_label)?;
                self.sort_module_namespace_keys(specifier)?;
                if import_bound.is_some() {
                    let ceiling = self.native_builtin_state_label(module, namespace)?;
                    Self::check_import_flow_bound(request_specifier, &ceiling, import_bound)?;
                }
                self.seal_object(namespace)?;
                Ok(())
            })();
            self.finish_property_write_observation(observation, outcome)
        })();
        match initialized {
            Ok(()) => {
                if let Some(promise) = self
                    .module_state
                    .modules
                    .get(specifier)
                    .and_then(|record| record.evaluation_promise)
                {
                    if let Err(error) = self.fulfill_promise(
                        promise,
                        Self::value_to_js_value(&Value::Object(namespace)),
                        Label::Public,
                    ) {
                        self.fail_module_record(
                            specifier,
                            "native namespace initialization was refused",
                        );
                        return Err(error);
                    }
                }
                if let Some(record) = self.module_state.modules.get_mut(specifier) {
                    record.status = ModuleRuntimeStatus::Evaluated;
                }
                Ok(Value::Object(namespace))
            }
            Err(error) => {
                // Keep diagnostics independent of the thrown payload. The
                // private rooted carrier retains its identity and IFC label;
                // it is never added to the observable namespace or exports.
                self.fail_module_record(specifier, "native namespace evaluation failed");
                let guest_exception = if matches!(error, InterpreterError::UncaughtException { .. })
                {
                    self.pending_exception
                        .clone()
                        .map(|value| (value, self.pending_exception_label.clone()))
                } else if Self::js_catchable_error_name(&error).is_some() {
                    Some((
                        self.native_error_to_thrown_value(&error)?,
                        self.pending_hostcall_result_label
                            .clone()
                            .unwrap_or(Label::Public),
                    ))
                } else {
                    None
                };
                let Some((thrown, label)) = guest_exception else {
                    return Err(error);
                };
                self.replace_pending_abrupt_slots(Some((thrown.clone(), label.clone())), None)?;
                self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
                let carrier = self.alloc_object_with_prototype(None)?;
                let key = RuntimePropertyKey::String(JsString::from("error"));
                self.set_object_runtime_property(carrier, key.clone(), thrown.clone())?;
                self.set_own_runtime_property_label(carrier, &key, &label)?;
                self.mutate_builtin_prototypes(|prototypes| {
                    prototypes.insert(specifier.to_string(), carrier);
                });
                if let Some(promise) = self
                    .module_state
                    .modules
                    .get(specifier)
                    .and_then(|record| record.evaluation_promise)
                {
                    // Only guest-facing import Promises report unhandled
                    // rejection; this internal dependency is always observed.
                    self.promise_store
                        .mark_rejection_handled(promise)
                        .map_err(|error| InterpreterError::InternalError {
                            details: error.to_string(),
                        })?;
                    let reason = self.promise_value(&thrown)?;
                    self.reject_promise(promise, reason, label)?;
                }
                Err(InterpreterError::UncaughtException {
                    value: "native namespace evaluation failed".to_string(),
                })
            }
        }
    }

    /// Instantiate the existing path factory once per realm through the same
    /// retained-module and CommonJS execution path as other source modules.
    /// Its methods therefore keep their defining module and lexical context
    /// when a captured npm package exports or calls them. The private source
    /// descriptor carries no policy decision; the caller has already checked
    /// its import hook and, when installed, its resolver on every request.
    pub(super) fn path_core_module(
        &mut self,
        module: &Ir3Module,
        native: NativeBuiltinModule,
    ) -> Result<Value, InterpreterError> {
        let key = if native == NativeBuiltinModule::PathWin32 {
            PATH_WIN32_MODULE_KEY
        } else {
            PATH_MODULE_KEY
        };
        if let Some(object) = self.builtin_prototypes.get(key) {
            return Ok(Value::Object(*object));
        }
        let record = NativeBuiltinModule::Path.record(PATH_RUNTIME_MODULE_ID);
        let source = ResolvedModule {
            request_specifier: "node:path".to_string(),
            canonical_specifier: PATH_RUNTIME_MODULE_ID.to_string(),
            content_hash: record.canonical_hash(),
            record,
            probe_sequence: Vec::new(),
        };
        self.load_module_resolved(
            module,
            PATH_RUNTIME_MODULE_ID,
            ModuleLoadKind::Require,
            None,
            Some(source.into()),
        )?;
        let module_object = self
            .module_state
            .modules
            .get(PATH_RUNTIME_MODULE_ID)
            .and_then(|record| record.cjs_module_object)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: "node:path".to_string(),
                reason: "native path factory did not initialize its CommonJS exports".to_string(),
            })?;
        let posix = self.prototype_chain_get(module_object, "exports")?;
        let Value::Object(posix) = posix else {
            return Err(InterpreterError::InternalError {
                details: "native path factory exported a non-object".to_string(),
            });
        };
        let Value::Object(win32) = self.prototype_chain_get(posix, "win32")? else {
            return Err(InterpreterError::InternalError {
                details: "native path factory omitted its Windows namespace".to_string(),
            });
        };
        self.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert(PATH_MODULE_KEY.to_string(), posix);
            prototypes.insert(PATH_WIN32_MODULE_KEY.to_string(), win32);
        });
        Ok(Value::Object(if native == NativeBuiltinModule::PathWin32 {
            win32
        } else {
            posix
        }))
    }

    /// Execute the existing engine-owned factories as retained CommonJS
    /// modules. Their closures keep their defining module across captured
    /// package boundaries; aliases and submodules share the parent instance.
    /// The authenticated descriptor is checked before this private cache.
    pub(super) fn source_builtin_module(
        &mut self,
        module: &Ir3Module,
        native: NativeBuiltinModule,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        // A first submodule selection may observe a guest getter or a
        // classified prototype/shape. Keep those observations on its private
        // cached reference, including calls without an outer hostcall scope.
        let selected_label = self.json_parse_context_label()?;
        let selected_bytes = Self::estimate_label_bytes(&selected_label);
        self.json_reserve_temporary(selected_bytes)?;
        let observation = self.begin_property_observation([]);
        self.json_release_temporary(selected_bytes);
        let observation = observation?;
        let outcome = (|| {
            self.json_observe_label(selected_label)?;
            self.source_builtin_module_inner(module, native, import_bound)
        })();
        self.finish_property_read_observation(observation, outcome)
    }

    pub(super) fn source_builtin_module_inner(
        &mut self,
        module: &Ir3Module,
        native: NativeBuiltinModule,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        let (factory, id, member) = match native {
            NativeBuiltinModule::Events => (
                NativeBuiltinModule::Events,
                "\0franken-engine/native-events",
                None,
            ),
            NativeBuiltinModule::Fs => {
                (NativeBuiltinModule::Fs, "\0franken-engine/native-fs", None)
            }
            NativeBuiltinModule::FsPromises => (
                NativeBuiltinModule::Fs,
                "\0franken-engine/native-fs",
                Some("promises"),
            ),
            NativeBuiltinModule::Buffer => (
                NativeBuiltinModule::Buffer,
                "\0franken-engine/native-buffer",
                None,
            ),
            NativeBuiltinModule::Util => (
                NativeBuiltinModule::Util,
                "\0franken-engine/native-util",
                None,
            ),
            NativeBuiltinModule::UtilTypes => (
                NativeBuiltinModule::Util,
                "\0franken-engine/native-util",
                Some("types"),
            ),
            NativeBuiltinModule::Assert => (
                NativeBuiltinModule::Assert,
                "\0franken-engine/native-assert",
                None,
            ),
            NativeBuiltinModule::AssertStrict => (
                NativeBuiltinModule::Assert,
                "\0franken-engine/native-assert",
                Some("strict"),
            ),
            NativeBuiltinModule::StringDecoder => (
                NativeBuiltinModule::StringDecoder,
                "\0franken-engine/native-string_decoder",
                None,
            ),
            NativeBuiltinModule::TimersPromises => (
                NativeBuiltinModule::TimersPromises,
                "\0franken-engine/native-timers/promises",
                None,
            ),
            NativeBuiltinModule::Stream => (
                NativeBuiltinModule::Stream,
                "\0franken-engine/native-stream",
                None,
            ),
            NativeBuiltinModule::StreamPromises => (
                NativeBuiltinModule::Stream,
                "\0franken-engine/native-stream",
                Some("promises"),
            ),
            NativeBuiltinModule::StreamConsumers => (
                NativeBuiltinModule::StreamConsumers,
                "\0franken-engine/native-stream/consumers",
                None,
            ),
            NativeBuiltinModule::StreamWeb => (
                NativeBuiltinModule::StreamWeb,
                "\0franken-engine/native-stream/web",
                None,
            ),
            NativeBuiltinModule::Readline => (
                NativeBuiltinModule::Readline,
                "\0franken-engine/native-readline",
                None,
            ),
            NativeBuiltinModule::ReadlinePromises => (
                NativeBuiltinModule::Readline,
                "\0franken-engine/native-readline",
                Some("promises"),
            ),
            NativeBuiltinModule::DiagnosticsChannel => (
                NativeBuiltinModule::DiagnosticsChannel,
                "\0franken-engine/native-diagnostics_channel",
                None,
            ),
            _ => {
                return Err(InterpreterError::InternalError {
                    details: "native provider has no engine-owned source factory".to_string(),
                });
            }
        };
        let carrier = match self.builtin_prototypes.get(id).copied() {
            Some(carrier) => carrier,
            None => {
                let record = factory.record(id);
                let source = ResolvedModule {
                    request_specifier: factory.canonical_specifier().to_string(),
                    canonical_specifier: id.to_string(),
                    content_hash: record.canonical_hash(),
                    record,
                    probe_sequence: Vec::new(),
                };
                self.load_module_resolved(
                    module,
                    id,
                    ModuleLoadKind::Require,
                    None,
                    Some(source.into()),
                )?;
                let module_object = self
                    .module_state
                    .modules
                    .get(id)
                    .and_then(|record| record.cjs_module_object)
                    .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                        specifier: factory.canonical_specifier().to_string(),
                        reason: "native factory did not initialize its CommonJS exports"
                            .to_string(),
                    })?;
                let value = self.iterator_protocol_property(
                    Some(module),
                    module_object,
                    &RuntimePropertyKey::String(JsString::from("exports")),
                    Value::Object(module_object),
                )?;
                self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
                let carrier = self.alloc_object_with_prototype(None)?;
                self.json_store_parsed_property(carrier, JsString::from("exports"), value.clone())?;
                // These submodules retain their original objects even when
                // a package replaces the parent's property before the first
                // submodule load. Capture only during factory initialization;
                // a later require must neither select nor invoke guest code.
                let stable_member = match factory {
                    NativeBuiltinModule::Util => Some("types"),
                    NativeBuiltinModule::Stream
                    | NativeBuiltinModule::Fs
                    | NativeBuiltinModule::Readline => Some("promises"),
                    _ => None,
                };
                if let Some(name) = stable_member {
                    let selected = self.get_v(
                        module,
                        &value,
                        &RuntimePropertyKey::String(JsString::from(name)),
                    )?;
                    self.json_store_parsed_property(carrier, JsString::from(name), selected)?;
                }
                self.mutate_builtin_prototypes(|prototypes| {
                    prototypes.insert(id.to_string(), carrier);
                });
                carrier
            }
        };
        let name = member.unwrap_or("exports");
        let key = RuntimePropertyKey::String(JsString::from(name));
        if member == Some("strict")
            && self
                .heap
                .get(carrier.0 as usize)
                .and_then(|object| object.own_runtime_property_value(&key))
                .is_none()
        {
            // assert/strict snapshots assert.strict on its first load. Keep
            // that value and its observed label in a private rooted carrier,
            // including when a package supplied an accessor or undefined.
            let value = self.iterator_protocol_property(
                Some(module),
                carrier,
                &RuntimePropertyKey::String(JsString::from("exports")),
                Value::Object(carrier),
            )?;
            let backing = match &value {
                Value::Object(object) => *object,
                function => self
                    .function_own_property_object(module, function)?
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "native assert factory has no export property storage".to_string(),
                    })?,
            };
            if import_bound.is_some() {
                // Selection itself can run a guest getter. Admit the parent
                // state before Get, only while this alias is still uncached.
                let ceiling = self.native_builtin_state_label(module, backing)?;
                Self::check_import_flow_bound(
                    native.canonical_specifier(),
                    &ceiling,
                    import_bound,
                )?;
            }
            let strict = self.iterator_protocol_property(Some(module), backing, &key, value)?;
            self.json_store_parsed_property(carrier, JsString::from(name), strict)?;
        }
        self.iterator_protocol_property(Some(module), carrier, &key, Value::Object(carrier))
    }

    /// Read a dependency once and charge its raw bytes before decoding or
    /// syntax detection. Reading at most limit + 1 also bounds files that grow
    /// after they were selected by the resolver.
    pub(super) fn read_module_source(&self, resolved: &str) -> Result<String, InterpreterError> {
        let failed = |error: std::io::Error| InterpreterError::ModuleReadFailed {
            specifier: resolved.to_string(),
            error: error.to_string(),
        };
        let file = fs::File::open(resolved).map_err(failed)?;
        let limit = self.config.module_parser_options.budget.max_source_bytes;
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(failed)?;
        let source_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if source_bytes > limit {
            return Err(InterpreterError::ModuleParseFailed {
                specifier: resolved.to_string(),
                error: "module exceeds the configured parser source-byte budget".to_string(),
            });
        }
        self.check_temporary_memory_budget(source_bytes)?;
        self.observe_module_input(Path::new(resolved), &bytes)
            .map_err(|error| InterpreterError::ModuleReadFailed {
                specifier: resolved.to_string(),
                error,
            })?;
        String::from_utf8(bytes).map_err(|error| InterpreterError::ModuleReadFailed {
            specifier: resolved.to_string(),
            error: error.to_string(),
        })
    }

    pub(super) fn observe_module_input(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let Some(integrity) = &self.config.module_source_integrity else {
            return Ok(());
        };
        let root = self
            .canonical_module_root_path()
            .ok_or_else(|| "module integrity requires a configured root".to_string())?;
        integrity.observe(&root, path, bytes)
    }

    /// A declared format wins over source detection. An ambiguous .js or
    /// TypeScript file follows its nearest package scope for every load form,
    /// including relative static imports.
    pub(super) fn file_module_parse_goal(
        &self,
        resolved: &str,
        load_kind: ModuleLoadKind<'_>,
    ) -> Result<Option<ParseGoal>, InterpreterError> {
        let extension = Path::new(resolved)
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        Ok(match extension.as_deref() {
            Some("mjs" | "mts") => Some(ParseGoal::Module),
            Some("cjs" | "cts") => Some(ParseGoal::Script),
            Some("json") => Some(match load_kind {
                ModuleLoadKind::Import(_) => ParseGoal::Module,
                ModuleLoadKind::Require | ModuleLoadKind::DynamicImport => ParseGoal::Script,
            }),
            Some("js" | "ts" | "tsx") => self.package_parse_goal_for_module(resolved)?,
            _ => match load_kind {
                ModuleLoadKind::DynamicImport => self.package_parse_goal_for_module(resolved)?,
                ModuleLoadKind::Require => Some(ParseGoal::Script),
                ModuleLoadKind::Import(_) => Some(ParseGoal::Module),
            },
        })
    }

    pub(super) fn generated_function_owner(
        &self,
        executing_module: &Ir3Module,
    ) -> Result<(ContentHash, String, Arc<Ir3Module>), InterpreterError> {
        let owner_specifier = self
            .current_module_specifier
            .as_deref()
            .unwrap_or(&executing_module.header.source_label);
        let record = self
            .module_state
            .modules
            .get(owner_specifier)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: owner_specifier.to_string(),
                reason: "dynamic Function owner module record is not retained".to_string(),
            })?;
        let owner_program = record.compiled_module.as_ref().ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: owner_specifier.to_string(),
                reason: "dynamic Function owner module has no retained program".to_string(),
            }
        })?;
        if owner_program.header.source_label != owner_specifier {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: owner_specifier.to_string(),
                reason: format!(
                    "dynamic Function owner mismatch: registry key `{owner_specifier}` retained program `{}`",
                    owner_program.header.source_label
                ),
            });
        }
        self.check_temporary_memory_budget(Self::retained_module_program_bytes(owner_program, ""))?;
        Ok((
            owner_program.content_hash(),
            owner_specifier.to_string(),
            Arc::clone(owner_program),
        ))
    }

    pub(super) fn derive_generated_function_artifact_id(
        realm_generation: u64,
        owner_program_id: ContentHash,
        construction_ordinal: u64,
        provenance: &GeneratedFunctionProvenance,
        compiled_program_id: ContentHash,
        function_index: u32,
    ) -> ContentHash {
        fn mix(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
            buf.extend_from_slice(field);
        }

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"franken-engine.generated-function-artifact.v2\n");
        preimage.extend_from_slice(&realm_generation.to_le_bytes());
        preimage.extend_from_slice(owner_program_id.as_bytes());
        preimage.extend_from_slice(&construction_ordinal.to_le_bytes());
        preimage.extend_from_slice(compiled_program_id.as_bytes());
        preimage.extend_from_slice(&function_index.to_le_bytes());
        mix(&mut preimage, provenance.source_id.as_bytes());
        mix(&mut preimage, provenance.source_hash.as_bytes());
        mix(&mut preimage, provenance.parameter_hash.as_bytes());
        mix(&mut preimage, provenance.construction_site.as_bytes());
        ContentHash::compute(&preimage)
    }

    #[cfg(test)]
    pub(super) fn retain_generated_function_artifact(
        &mut self,
        owner_program_id: ContentHash,
        owner_specifier: String,
        owner_program: Arc<Ir3Module>,
        provenance: GeneratedFunctionProvenance,
        compiled_module: Ir3Module,
        function_index: u32,
    ) -> Result<BuiltinFunction, InterpreterError> {
        self.ensure_generated_function_realm_globals()?;
        self.retain_generated_function_artifact_transaction(
            owner_program_id,
            owner_specifier,
            owner_program,
            provenance,
            Label::Public,
            compiled_module,
            function_index,
            0,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn retain_generated_function_artifact_transaction(
        &mut self,
        owner_program_id: ContentHash,
        owner_specifier: String,
        owner_program: Arc<Ir3Module>,
        provenance: GeneratedFunctionProvenance,
        source_label: Label,
        compiled_module: Ir3Module,
        function_index: u32,
        compilation_scratch_bytes: u64,
        audit_entry: Option<GeneratedCodeAuditEntry>,
    ) -> Result<BuiltinFunction, InterpreterError> {
        if owner_program.header.source_label != owner_specifier {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: owner_specifier,
                reason: format!(
                    "generated Function retention owner mismatch: retained program `{}`",
                    owner_program.header.source_label
                ),
            });
        }
        let (construction_ordinal, create_store) = match self
            .module_state
            .generated_function_stores
            .get(&owner_program_id)
        {
            Some(store) => {
                if store.realm_generation != self.generated_function_realm_generation
                    || store.owner_program_id != owner_program_id
                    || store.owner_specifier != owner_specifier
                    || !Arc::ptr_eq(&store.owner_program, &owner_program)
                {
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "generated Function owner store mismatch for {}",
                            owner_program_id.to_hex()
                        ),
                    });
                }
                (store.next_construction_ordinal, false)
            }
            None => (0, true),
        };
        let next_construction_ordinal =
            construction_ordinal
                .checked_add(1)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "generated Function construction ordinal capacity".to_string(),
                    got: format!(
                        "owner {} exhausted u64 construction ordinals",
                        owner_program_id.to_hex()
                    ),
                })?;
        if compilation_scratch_bytes == 0 {
            self.check_temporary_memory_budget(Self::retained_module_program_bytes(
                &compiled_module,
                "",
            ))?;
        }
        let compiled_program_id = compiled_module.content_hash();
        let artifact_id = Self::derive_generated_function_artifact_id(
            self.generated_function_realm_generation,
            owner_program_id,
            construction_ordinal,
            &provenance,
            compiled_program_id,
            function_index,
        );
        if self
            .module_state
            .generated_function_stores
            .get(&owner_program_id)
            .is_some_and(|store| store.artifacts.contains_key(&artifact_id))
        {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generated Function artifact identity collision for {}",
                    artifact_id.to_hex()
                ),
            });
        }

        let artifact = GeneratedFunctionArtifact {
            owner_program_id,
            owner_specifier: owner_specifier.clone(),
            artifact_id,
            provenance,
            source_label,
            compiled_module: Arc::new(compiled_module),
            function_index,
        };
        let additional_bytes = Self::estimate_generated_function_artifact_entry_bytes(&artifact)
            .saturating_add(if create_store {
                let empty_store = GeneratedFunctionStore {
                    realm_generation: self.generated_function_realm_generation,
                    owner_program_id,
                    owner_specifier: owner_specifier.clone(),
                    owner_program: Arc::clone(&owner_program),
                    next_construction_ordinal: 0,
                    artifacts: BTreeMap::new(),
                };
                Self::estimate_generated_function_store_base_bytes(&empty_store)
            } else {
                0
            });
        let record_audit = audit_entry.is_some()
            && self.generated_code_audit.len() < MAX_GENERATED_CODE_AUDIT_ENTRIES;
        let observability_bytes = audit_entry
            .as_ref()
            .filter(|_| record_audit)
            .map(|entry| self.estimate_generated_code_observability_pair_bytes(entry))
            .unwrap_or(0);
        let previous_retained_bytes = self.module_state.retained_generated_function_bytes;
        let next_retained_bytes = previous_retained_bytes.saturating_add(additional_bytes);
        let previous_transition_bytes =
            previous_retained_bytes.saturating_add(compilation_scratch_bytes);
        let next_transition_bytes = next_retained_bytes.saturating_add(observability_bytes);
        let requested_peak_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_transition_bytes)
            .saturating_add(next_transition_bytes)
            .saturating_add(Self::generated_function_handle_peak_bytes());
        if self
            .memory_request_exceeds_budget(requested_peak_bytes, self.config.max_total_memory_bytes)
        {
            return Err(
                self.memory_budget_error(requested_peak_bytes, self.heap_object_count_u32())
            );
        }
        self.apply_memory_component_delta(previous_transition_bytes, next_transition_bytes)?;

        if create_store {
            self.module_state.generated_function_stores.insert(
                owner_program_id,
                GeneratedFunctionStore {
                    realm_generation: self.generated_function_realm_generation,
                    owner_program_id,
                    owner_specifier,
                    owner_program,
                    next_construction_ordinal: 0,
                    artifacts: BTreeMap::new(),
                },
            );
        }
        let store = self
            .module_state
            .generated_function_stores
            .get_mut(&owner_program_id)
            .expect("generated Function owner store was validated or inserted");
        store.next_construction_ordinal = next_construction_ordinal;
        let replaced = store.artifacts.insert(artifact_id, artifact);
        debug_assert!(replaced.is_none());
        self.module_state.retained_generated_function_bytes = next_retained_bytes;
        debug_assert_eq!(
            self.module_state.retained_generated_function_bytes,
            self.generated_function_stores_memory_bytes()
        );
        if let Some(audit_entry) = audit_entry.filter(|_| record_audit) {
            self.append_generated_code_event_precharged(audit_entry, observability_bytes);
        }

        Ok(BuiltinFunction::generated_function(
            owner_program_id,
            artifact_id,
        ))
    }

    pub(super) fn primitive_string_upper_bound_bytes(value: &Value) -> u64 {
        match value {
            Value::Str(text) => u64::try_from(text.as_utf8_projection().len()).unwrap_or(u64::MAX),
            Value::BigInt(digits) => u64::try_from(digits.len()).unwrap_or(u64::MAX),
            _ => 64,
        }
    }

    pub(super) fn generated_function_argument_string_upper_bound_bytes(
        &self,
        value: &Value,
    ) -> u64 {
        match value {
            Value::Str(text) => u64::try_from(text.as_utf8_projection().len()).unwrap_or(u64::MAX),
            Value::BigInt(digits) => u64::try_from(digits.len()).unwrap_or(u64::MAX),
            Value::Object(id) => self
                .heap
                .get(id.0 as usize)
                .map(|object| {
                    let buffer_bytes = object
                        .typed_array
                        .as_ref()
                        .filter(|view| view.is_buffer)
                        .map(|view| {
                            u64::try_from(view.byte_length)
                                .unwrap_or(u64::MAX)
                                .saturating_mul(3)
                        })
                        .unwrap_or(0);
                    let name_bytes = object
                        .properties
                        .get("name")
                        .map(Self::primitive_string_upper_bound_bytes)
                        .unwrap_or("Error".len() as u64);
                    let message_bytes = object
                        .properties
                        .get("message")
                        .map(Self::primitive_string_upper_bound_bytes)
                        .unwrap_or(0);
                    buffer_bytes.max(name_bytes.saturating_add(message_bytes).saturating_add(2))
                })
                .unwrap_or(64)
                .max(64),
            Value::BuiltinFunction(builtin) => {
                u64::try_from("[Function: builtin ]".len() + builtin.display_name().len())
                    .unwrap_or(u64::MAX)
            }
            Value::Symbol(symbol) => {
                let description_bytes = well_known_symbol_description(*symbol)
                    .map(|description| description.len() as u64)
                    .or_else(|| {
                        self.symbol_state.description(*symbol).map(|description| {
                            u64::try_from(description.as_utf8_projection().len())
                                .unwrap_or(u64::MAX)
                        })
                    })
                    .unwrap_or(0);
                ("Symbol(".len() as u64)
                    .saturating_add(description_bytes)
                    .saturating_add(1)
            }
            _ => 64,
        }
    }

    pub(super) fn generated_function_source_upper_bound_bytes(
        &self,
        args: RegRange,
    ) -> Result<u64, InterpreterError> {
        let mut rendered_argument_bytes = 0u64;
        for index in 0..args.count {
            let reg =
                args.start
                    .checked_add(index)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            if reg >= self.config.max_registers {
                return Err(InterpreterError::RegisterOutOfBounds {
                    register: reg,
                    max: self.config.max_registers,
                });
            }
            let actual_reg = self.register_base.checked_add(reg as usize).ok_or(
                InterpreterError::RegisterOutOfBounds {
                    register: reg,
                    max: self.config.max_registers,
                },
            )?;
            rendered_argument_bytes = rendered_argument_bytes.saturating_add(
                self.registers
                    .get(actual_reg)
                    .map(|value| self.generated_function_argument_string_upper_bound_bytes(value))
                    .unwrap_or("undefined".len() as u64),
            );
        }
        Ok(rendered_argument_bytes
            .saturating_add(u64::from(args.count))
            .saturating_add("function anonymous(\n) {\n\n}".len() as u64))
    }

    pub(super) fn generated_function_compilation_scratch_bytes(
        &self,
        args: RegRange,
    ) -> Result<u64, InterpreterError> {
        let source_bytes = self.generated_function_source_upper_bound_bytes(args)?;
        Ok(Self::generated_function_scratch_bytes_from_source(
            source_bytes,
            args.count,
        ))
    }

    pub(super) fn generated_function_scratch_bytes_from_source(
        source_bytes: u64,
        argument_count: u32,
    ) -> u64 {
        let argument_slots = u64::from(argument_count).saturating_mul(
            (std::mem::size_of::<String>() as u64)
                .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES),
        );
        GENERATED_FUNCTION_COMPILATION_FIXED_SCRATCH_BYTES
            .saturating_add(argument_slots)
            .saturating_add(
                source_bytes
                    .saturating_mul(GENERATED_FUNCTION_COMPILATION_SCRATCH_BYTES_PER_SOURCE_BYTE),
            )
    }

    /// The Function constructor's arguments as strings when any is an object
    /// or a Symbol (ES2020 19.2.1.1.1 steps 7-12): every argument ToString'd
    /// in order, an object through ToPrimitive with the string hint (its
    /// toString runs), a Symbol a TypeError. `None` when all are other
    /// primitives, whose conversion is not observable. The strings are charged against the
    /// temporary budget until the compilation scratch covers them.
    pub(super) fn generated_function_object_argument_texts(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Option<Vec<String>>, InterpreterError> {
        let mut observable = false;
        for index in 0..args.count {
            observable |= self
                .builtin_arg(args, index)?
                .is_some_and(|value| value.is_object_like() || matches!(value, Value::Symbol(_)));
        }
        if !observable {
            return Ok(None);
        }
        self.scoped_conversion(|this| {
            let mut texts = Vec::with_capacity(args.count as usize);
            let mut text_bytes = 0u64;
            for index in 0..args.count {
                let value = this.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
                let value = if value.is_object_like() {
                    this.gc_nested_request = None;
                    let coerced = this.coerce_runtime_primitive(Some(module), value, true)?;
                    this.conversion_observe_hooks()?;
                    coerced
                } else {
                    value
                };
                if matches!(value, Value::Symbol(_)) {
                    return Err(InterpreterError::TypeError {
                        expected: "string-convertible Function constructor argument".to_string(),
                        got: "symbol".to_string(),
                    });
                }
                let text = this.value_to_string(&value);
                text_bytes =
                    text_bytes.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
                this.check_temporary_memory_budget(text_bytes)?;
                texts.push(text);
            }
            Ok(Some(texts))
        })
    }

    pub(super) fn construct_generated_function(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.construct_dynamic_function(module, args, DynamicFunctionKind::Normal)
    }

    /// CreateDynamicFunction (ES2020 19.2.1.1.1) for the Function
    /// constructor and, through a generated wrapper, for %GeneratorFunction%,
    /// %AsyncFunction% and %AsyncGeneratorFunction% (bd-9vouw.321). A
    /// generated function runs its body as a plain call, so a generator or
    /// async kind is compiled as `function WRAPPER() { return <kind>
    /// anonymous(params) { body }; }`. The wrapper runs once, in the same
    /// contained-codegen envelope, and its result is a real function of that
    /// kind whose closure carries the generated artifact's provenance, as a
    /// function returned from `new Function(...)` code does. The wrapper
    /// must parse to exactly that return, so text in the parameters or body
    /// cannot close the inner function and run in the wrapper.
    pub(super) fn construct_dynamic_function(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        kind: DynamicFunctionKind,
    ) -> Result<Value, InterpreterError> {
        if self.config.disallow_dynamic_codegen {
            return Err(InterpreterError::CapabilityDenied {
                capability: "eval".to_string(),
            });
        }
        // bd-9vouw.60: code generation is the call the behavior firewall
        // exists to see, but a builtin callee never reaches the per-call hook
        // (only IR3 functions and closures do). Every Function-constructor
        // path (`Function(src)`, `new Function(src)`, `.call`, Reflect) ends
        // here, so it reports as a call named "Function"; `u32::MAX` marks
        // "no IR3 function".
        if let Some(hook) = self
            .hook
            .as_ref()
            .filter(|hook| hook.instruction_hooks_enabled())
        {
            let mut arguments = Vec::with_capacity(args.count as usize);
            for index in 0..args.count {
                arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
            }
            let callee = FunctionRef::Function {
                function_index: u32::MAX,
                name: Some("Function".to_string()),
            };
            let ctx = self.hook_context(module);
            self.enforce_hook_action(hook.pre_call(&ctx, &callee, &arguments))?;
        }
        self.ensure_generated_function_realm_globals()?;
        let (owner_program_id, owner_specifier, owner_program) =
            self.generated_function_owner(module)?;
        // ES2020 19.2.1.1.1 CreateDynamicFunction steps 7-12: each parameter
        // and the body are ToString'd, in order, before anything is parsed,
        // so an object argument's toString runs (handlebars passes
        // source-map SourceNodes); they read "[object Object]". Primitive
        // arguments keep the non-observable conversion below.
        let converted = self.generated_function_object_argument_texts(module, args)?;
        let mut source_label = self.join_arg_range_label(args)?;
        if let Some(conversion_label) = self.take_pending_hostcall_result_label() {
            source_label =
                self.join_owned_label_with_temporary_budget(source_label, &conversion_label)?;
        }
        // Reserve the complete source/parse/lowering workspace before cloning
        // even the first argument string. The closure keeps every transient
        // owner scoped together so only the returned IR3/provenance survive to
        // the atomic scratch -> retained-artifact transition below.
        let compilation_scratch_bytes = match &converted {
            Some(texts) => Self::generated_function_scratch_bytes_from_source(
                texts
                    .iter()
                    .fold(0u64, |total, text| {
                        total.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX))
                    })
                    .saturating_add(u64::from(args.count))
                    .saturating_add("function anonymous(\n) {\n\n}".len() as u64)
                    .saturating_add(kind.wrapper_overhead_bytes()),
                args.count,
            ),
            None => self
                .generated_function_compilation_scratch_bytes(args)?
                .saturating_add(kind.wrapper_overhead_bytes()),
        };
        let record_construction_audit =
            self.generated_code_audit.len() < MAX_GENERATED_CODE_AUDIT_ENTRIES;
        self.apply_memory_component_delta(0, compilation_scratch_bytes)?;
        let compilation = (|| {
            let mut parts = Vec::new();
            parts
                .try_reserve_exact(args.count as usize)
                .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
            match &converted {
                Some(texts) => parts.extend(texts.iter().cloned()),
                None => {
                    for index in 0..args.count {
                        let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
                        parts.push(self.value_to_string(&value));
                    }
                }
            }

            let body_source = parts.pop().unwrap_or_default();
            let parameter_source = parts.join(",");
            let provenance = Self::derive_generated_function_provenance(
                &owner_specifier,
                &parameter_source,
                &body_source,
            );
            let audit_entry = record_construction_audit.then(|| GeneratedCodeAuditEntry {
                source_id: provenance.source_id.clone(),
                source_hash: provenance.source_hash.clone(),
                parameter_hash: provenance.parameter_hash.clone(),
                construction_site: provenance.construction_site.clone(),
                kind: GeneratedCodeEventKind::Constructed,
                instructions_consumed: 0,
                caller_call_depth: 0,
                granted_capabilities: Vec::new(),
                outcome: "constructed".to_string(),
            });
            let generated_source = match kind {
                DynamicFunctionKind::Normal => {
                    Self::function_constructor_source(&parameter_source, &body_source)
                }
                kind => kind.wrapper_source(&parameter_source, &body_source),
            };
            self.run_pre_allocation_hook(module, AllocKind::Function, generated_source.len())?;

            // ES2020 19.2.1.1.1 CreateDynamicFunction steps 18-20: a body or
            // parameter list that is not valid source is a SyntaxError the
            // caller can catch, as is an early error in it (`break` outside a
            // loop, a duplicate `let`, a strict `with`, `get constructor()` in
            // a class). They aborted the whole program. Syntax the parser or
            // lowering does not support (`UnsupportedSyntax`) stays a refusal:
            // it says nothing about the source being invalid.
            let parse = |text: String| {
                CanonicalEs2020Parser.parse_with_options(
                    ParserSource {
                        label: "<function-constructor>".to_string(),
                        text,
                    },
                    ParseGoal::Script,
                    &ParserOptions::default(),
                )
            };
            // An import or export declaration in the function body
            // (InvalidGoal: script code) is a SyntaxError too (bd-9vouw.396).
            let parse_failure = |this: &mut Self, error: ParseError| {
                if matches!(
                    error.code,
                    ParseErrorCode::StrictModeWithStatement
                        | ParseErrorCode::AwaitOutsideAsync
                        | ParseErrorCode::InvalidClassElementName
                        | ParseErrorCode::InvalidSyntax
                        | ParseErrorCode::InvalidGoal
                ) {
                    this.throw_js_error("SyntaxError", error.message.clone())
                } else {
                    InterpreterError::ModuleParseFailed {
                        specifier: "<function-constructor>".to_string(),
                        error: error.to_string(),
                    }
                }
            };
            // The parameters first, on their own; their tree is dropped
            // before the full source is parsed.
            let parameters_valid = match parse(kind.parameters_source(&parameter_source)) {
                Ok(tree) => kind.is_single_declaration(&tree),
                // The wrapper around the parameters is balanced, so a
                // structural failure (an unbalanced list or a missing body
                // brace) comes from the parameter text itself: `a){ /*`
                // opens a comment that swallows the `) {}`.
                Err(error)
                    if error.code == ParseErrorCode::UnsupportedSyntax
                        && (error.message.contains("unbalanced parentheses")
                            || error.message.contains("requires a braced body")) =>
                {
                    return Err(self.throw_js_error("SyntaxError", error.message.clone()));
                }
                Err(error) => return Err(parse_failure(self, error)),
            };
            let syntax_tree = match parse(generated_source) {
                Ok(syntax_tree) => syntax_tree,
                Err(error) => return Err(parse_failure(self, error)),
            };
            let exact = match kind {
                // A body that closes the function early (`}; x(); function
                // y() {`) leaves more statements after it (bd-9vouw.322).
                DynamicFunctionKind::Normal => kind.is_single_declaration(&syntax_tree),
                kind => kind.is_exact_wrapper(&syntax_tree),
            };
            if !exact || !parameters_valid {
                return Err(self.throw_js_error(
                    "SyntaxError",
                    format!("invalid parameters or body for {}", kind.constructor_name()),
                ));
            }
            let ir0 = Ir0Module::from_syntax_tree(syntax_tree, "<function-constructor>");
            let lowering_ctx = LoweringContext::new(
                &self.trace_id,
                "function-constructor",
                "baseline_interpreter",
            );
            let lowering_ctx = if self.module_resolver.is_some() {
                lowering_ctx.with_preserved_runtime_module_loads()
            } else {
                lowering_ctx
            };
            let lowering_output = match lower_ir0_to_ir3(&ir0, &lowering_ctx) {
                Ok(lowering_output) => lowering_output,
                Err(crate::lowering_pipeline::LoweringPipelineError::SemanticViolation(error)) => {
                    return Err(self.throw_js_error("SyntaxError", error.to_string()));
                }
                Err(error) => {
                    return Err(InterpreterError::ModuleLoweringFailed {
                        specifier: "<function-constructor>".to_string(),
                        error: error.to_string(),
                    });
                }
            };
            let entry_name = match kind {
                DynamicFunctionKind::Normal => "anonymous",
                _ => DYNAMIC_FUNCTION_WRAPPER,
            };
            let function_index = lowering_output
                .ir3
                .function_table
                .iter()
                .position(|desc| desc.name.as_deref() == Some(entry_name))
                .ok_or_else(|| InterpreterError::ModuleLoweringFailed {
                    specifier: "<function-constructor>".to_string(),
                    error: "generated function descriptor missing".to_string(),
                })?;
            let function_index =
                u32::try_from(function_index).map_err(|_| InterpreterError::TypeError {
                    expected: "u32-bounded generated function descriptor".to_string(),
                    got: format!("function index {function_index}"),
                })?;
            Ok((lowering_output.ir3, function_index, provenance, audit_entry))
        })();
        let (compiled_module, function_index, provenance, audit_entry) = match compilation {
            Ok(compilation) => compilation,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(compilation_scratch_bytes);
                return Err(error);
            }
        };
        let retained = self.retain_generated_function_artifact_transaction(
            owner_program_id,
            owner_specifier,
            owner_program,
            provenance,
            source_label.clone(),
            compiled_module,
            function_index,
            compilation_scratch_bytes,
            audit_entry,
        );
        let wrapper = match retained {
            Ok(builtin) => builtin,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(compilation_scratch_bytes);
                return Err(error);
            }
        };
        if kind == DynamicFunctionKind::Normal {
            if source_label != Label::Public {
                self.replace_pending_hostcall_result_label(Some(source_label))?;
            }
            return Ok(Value::BuiltinFunction(wrapper));
        }
        // The wrapper returns the generator, async or async generator
        // function its body defines.
        let (function, label) = self.call_generated_function_artifact(
            &wrapper,
            RegRange { start: 0, count: 0 },
            None,
            None,
        )?;
        let final_label = if source_label != Label::Public {
            self.join_owned_label_with_temporary_budget(label, &source_label)?
        } else {
            label
        };
        self.replace_pending_hostcall_result_label(Some(final_label))?;
        Ok(function)
    }

    pub(super) fn function_constructor_source(parameter_source: &str, body_source: &str) -> String {
        format!("function anonymous({parameter_source}\n) {{\n{body_source}\n}}")
    }

    /// Derive deterministic, content-addressed provenance for a generated
    /// function (bd-8enww.3.4 / YTBG-C4). The synthetic `source_id` is a pure
    /// function of the construction-site label and the *length-prefixed*
    /// parameter/body source, so two distinct decompositions of the same byte
    /// stream cannot collide (the project's canonical-hashing discipline). The
    /// source/parameter hashes are the auditable distillation that lets the
    /// trail attribute spend without retaining hostile raw source text.
    pub(super) fn derive_generated_function_provenance(
        construction_site: &str,
        parameter_source: &str,
        body_source: &str,
    ) -> GeneratedFunctionProvenance {
        fn mix(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
            buf.extend_from_slice(field);
        }
        let full_source = Self::function_constructor_source(parameter_source, body_source);
        let mut preimage: Vec<u8> = Vec::new();
        preimage.extend_from_slice(b"franken-engine.generated-function-provenance.v1\n");
        mix(&mut preimage, construction_site.as_bytes());
        mix(&mut preimage, parameter_source.as_bytes());
        mix(&mut preimage, body_source.as_bytes());
        let id_hex = ContentHash::compute(&preimage).to_hex();
        GeneratedFunctionProvenance {
            source_id: format!("genfn:{}", &id_hex[..16]),
            source_hash: ContentHash::compute(full_source.as_bytes()).to_hex(),
            parameter_hash: ContentHash::compute(parameter_source.as_bytes()).to_hex(),
            construction_site: construction_site.to_string(),
        }
    }

    /// Contained-codegen capability envelope (bd-8enww.3.3 / 3.4 security
    /// accounting): a `Function`-constructor body is granted *only* the safe
    /// subset (`Builtin` / `Console` / `Timer`) of whatever its own compiled
    /// module statically declares. Dangerous capabilities (fs / net / process /
    /// …) that adversarial generated code might declare are filtered out here,
    /// so constructing code at runtime can never be an authority-escalation
    /// vector — the safe set is the hard ceiling for dynamic construction,
    /// independent of what the generated body asks for.
    pub(super) fn contained_codegen_capability_grant(
        required_capabilities: &[CapabilityTag],
    ) -> Vec<RuntimeCapability> {
        required_capabilities
            .iter()
            .filter_map(|tag| RuntimeCapability::from_tag_str(&tag.0))
            .filter(|capability| {
                matches!(
                    capability,
                    RuntimeCapability::Builtin
                        | RuntimeCapability::Console
                        | RuntimeCapability::Timer
                )
            })
            .collect()
    }

    /// Classify the first-class callables that the generated-function realm
    /// installs behind its writable canonical globals. This deliberately does
    /// not classify arbitrary builtins: runtime inference may restore only the
    /// three capabilities admitted by the contained-codegen ceiling.
    pub(super) fn contained_codegen_realm_builtin_capability(
        kind: BuiltinFunctionKind,
    ) -> Option<RuntimeCapability> {
        match kind {
            BuiltinFunctionKind::ConsoleLog
            | BuiltinFunctionKind::ConsoleError
            | BuiltinFunctionKind::ConsoleWarn
            | BuiltinFunctionKind::ConsoleInfo
            | BuiltinFunctionKind::ConsoleMethod => Some(RuntimeCapability::Console),
            BuiltinFunctionKind::SetTimeout
            | BuiltinFunctionKind::ClearTimeout
            | BuiltinFunctionKind::SetInterval
            | BuiltinFunctionKind::ClearInterval
            | BuiltinFunctionKind::SetImmediate
            | BuiltinFunctionKind::ClearImmediate
            | BuiltinFunctionKind::QueueMicrotask => Some(RuntimeCapability::Timer),
            BuiltinFunctionKind::PerformanceNow
            | BuiltinFunctionKind::PromiseResolve
            | BuiltinFunctionKind::PromiseReject
            | BuiltinFunctionKind::PromiseAll
            | BuiltinFunctionKind::PromiseRace
            | BuiltinFunctionKind::PromiseAllSettled
            | BuiltinFunctionKind::PromiseAny
            | BuiltinFunctionKind::PromiseWithResolvers
            | BuiltinFunctionKind::PromiseConstructor
            | BuiltinFunctionKind::DateConstructor
            | BuiltinFunctionKind::DateNow
            | BuiltinFunctionKind::MathAbs
            | BuiltinFunctionKind::MathCeil
            | BuiltinFunctionKind::MathFloor
            | BuiltinFunctionKind::MathRound
            | BuiltinFunctionKind::MathMax
            | BuiltinFunctionKind::MathMin
            | BuiltinFunctionKind::MathRandom
            | BuiltinFunctionKind::MathPow
            | BuiltinFunctionKind::MathSqrt
            | BuiltinFunctionKind::MathSin
            | BuiltinFunctionKind::MathCos
            | BuiltinFunctionKind::MathLog
            | BuiltinFunctionKind::MathExp
            | BuiltinFunctionKind::MathTan
            | BuiltinFunctionKind::MathTrunc
            | BuiltinFunctionKind::MathSign
            | BuiltinFunctionKind::MathAtan2
            | BuiltinFunctionKind::MathAsin
            | BuiltinFunctionKind::MathAcos
            | BuiltinFunctionKind::MathHypot
            | BuiltinFunctionKind::MathImul
            | BuiltinFunctionKind::MathAtan
            | BuiltinFunctionKind::MathLog10
            | BuiltinFunctionKind::MathLog2
            | BuiltinFunctionKind::MathCbrt
            | BuiltinFunctionKind::MathClz32
            | BuiltinFunctionKind::MathFround
            | BuiltinFunctionKind::MathAcosh
            | BuiltinFunctionKind::MathAsinh
            | BuiltinFunctionKind::MathAtanh
            | BuiltinFunctionKind::MathSinh
            | BuiltinFunctionKind::MathCosh
            | BuiltinFunctionKind::MathTanh
            | BuiltinFunctionKind::MathExpm1
            | BuiltinFunctionKind::MathLog1p => Some(RuntimeCapability::Builtin),
            _ => None,
        }
    }

    pub(super) fn contained_codegen_runtime_name_capability(
        &self,
        name: &str,
        generated_scope_frame: &ScopeFrame,
    ) -> Result<Option<RuntimeCapability>, InterpreterError> {
        let expected = match name {
            "console" => RuntimeCapability::Console,
            "setTimeout" | "clearTimeout" | "setInterval" | "clearInterval" | "setImmediate"
            | "clearImmediate" | "queueMicrotask" => RuntimeCapability::Timer,
            "performance" | "Promise" | "Math" | "Date" => RuntimeCapability::Builtin,
            // Generated sloppy globals are intentionally excluded even when
            // their current value aliases a canonical realm object. Authority
            // is inferred only for the engine-seeded canonical names.
            _ => return Ok(None),
        };
        let Some(binding) = generated_scope_frame.bindings.get(name) else {
            return Ok(None);
        };
        let state = binding.state()?;
        if !state.initialized {
            return Ok(None);
        }
        let exposes_expected_capability = match &state.value {
            Value::BuiltinFunction(builtin) => {
                Self::contained_codegen_realm_builtin_capability(builtin.kind) == Some(expected)
            }
            Value::Object(object_id) => self.heap.get(object_id.0 as usize).is_some_and(|object| {
                object.properties.values().any(|value| {
                    matches!(
                        value,
                        Value::BuiltinFunction(builtin)
                            if Self::contained_codegen_realm_builtin_capability(builtin.kind)
                                == Some(expected)
                    )
                })
            }),
            _ => false,
        };
        Ok(exposes_expected_capability.then_some(expected))
    }

    /// Build the invocation-local effective grant set. Static HostCalls remain
    /// authoritative, while `LoadName` references can recover a safe grant only
    /// when they resolve to an engine-seeded canonical realm builtin at call
    /// entry. This covers writable `Math`/`Promise`/timer globals without
    /// treating arbitrary generated sloppy globals as authority declarations.
    pub(super) fn contained_codegen_effective_capability_grant(
        &self,
        module: &Ir3Module,
        generated_scope_frame: &ScopeFrame,
    ) -> Result<Vec<RuntimeCapability>, InterpreterError> {
        let mut granted = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        granted.extend(Self::contained_codegen_capability_grant(
            &module.required_capabilities,
        ));
        for instruction in &module.instructions {
            let Ir3Instruction::LoadName {
                name_pool_index, ..
            } = instruction
            else {
                continue;
            };
            let name = Self::scoped_constant_name(module, *name_pool_index);
            if let Some(capability) = self
                .contained_codegen_runtime_name_capability(name.as_ref(), generated_scope_frame)?
            {
                granted.insert(capability);
            }
        }
        Ok(granted.into_iter().collect())
    }

    pub(super) fn validate_contained_codegen_grant(
        capabilities: &[RuntimeCapability],
    ) -> Result<ContainedCodegenGrant, InterpreterError> {
        let unique = capabilities.iter().copied().collect::<BTreeSet<_>>();
        let safe = unique.iter().all(|capability| {
            matches!(
                capability,
                RuntimeCapability::VmDispatch
                    | RuntimeCapability::HeapAllocate
                    | RuntimeCapability::Builtin
                    | RuntimeCapability::Console
                    | RuntimeCapability::Timer
            )
        });
        if unique.len() != capabilities.len()
            || !safe
            || !unique.contains(&RuntimeCapability::VmDispatch)
            || !unique.contains(&RuntimeCapability::HeapAllocate)
        {
            return Err(InterpreterError::InternalError {
                details: "generated-code authority escaped its validated contained envelope"
                    .to_string(),
            });
        }

        let mut stored = [RuntimeCapability::VmDispatch; 5];
        let mut len = 0usize;
        for capability in [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Console,
            RuntimeCapability::Timer,
            RuntimeCapability::Builtin,
        ] {
            if unique.contains(&capability) {
                stored[len] = capability;
                len += 1;
            }
        }
        Ok(ContainedCodegenGrant {
            capabilities: stored,
            len: u8::try_from(len).expect("contained-codegen grant has at most five entries"),
        })
    }

    pub(super) fn contained_codegen_grant_for_artifact(
        &self,
        handle: GeneratedFunctionArtifactHandle,
    ) -> Result<ContainedCodegenGrant, InterpreterError> {
        let artifact =
            self.resolve_generated_function_artifact(handle.owner_program_id, handle.artifact_id)?;
        let generated_scope_frame = self.generated_function_realm_scope_frame()?;
        let capabilities = self.contained_codegen_effective_capability_grant(
            artifact.compiled_module.as_ref(),
            &generated_scope_frame,
        )?;
        Self::validate_contained_codegen_grant(&capabilities)
    }

    /// The grant a call runs with. Authority follows code: generated code
    /// (and every closure it creates) runs within its contained grant, and a
    /// closure of the program itself runs with the program's grant even when
    /// generated code calls it (bd-9vouw.189). An ejs template compiled with
    /// `new Function` calls the template engine's own `escapeFn`, whose
    /// `String(...)` was denied under the template's grant.
    pub(super) fn replace_with_contained_codegen_grant(
        &mut self,
        grant: Option<ContainedCodegenGrant>,
    ) -> Option<ReplacedCodegenGrant> {
        let next = match grant {
            Some(grant) => {
                self.codegen_caller_grants
                    .push(self.config.granted_capabilities.clone());
                let previous = std::mem::replace(
                    &mut self.config.granted_capabilities,
                    grant.as_slice().iter().copied().collect(),
                );
                return Some(ReplacedCodegenGrant {
                    previous,
                    entered_generated_code: true,
                });
            }
            None => self.codegen_caller_grants.first()?.clone(),
        };
        if next == self.config.granted_capabilities {
            return None;
        }
        Some(ReplacedCodegenGrant {
            previous: std::mem::replace(&mut self.config.granted_capabilities, next),
            entered_generated_code: false,
        })
    }

    pub(super) fn restore_replaced_codegen_grants(
        &mut self,
        replaced: Option<ReplacedCodegenGrant>,
    ) {
        if let Some(replaced) = replaced {
            self.config.granted_capabilities = replaced.previous;
            if replaced.entered_generated_code {
                self.codegen_caller_grants.pop();
            }
        }
    }

    pub(super) fn contained_codegen_capability_name(capability: RuntimeCapability) -> &'static str {
        match capability {
            RuntimeCapability::VmDispatch => "vm_dispatch",
            RuntimeCapability::HeapAllocate => "heap_allocate",
            RuntimeCapability::Builtin => "builtin",
            RuntimeCapability::Console => "console",
            RuntimeCapability::Timer => "timer",
            _ => "uncontained",
        }
    }

    pub(super) fn generated_code_invocation_outcome(
        result: &Result<Value, InterpreterError>,
        result_label: &Result<Label, InterpreterError>,
    ) -> (GeneratedCodeEventKind, String) {
        match result
            .as_ref()
            .err()
            .or_else(|| result_label.as_ref().err())
        {
            Some(error) => (
                GeneratedCodeEventKind::Faulted,
                format!("faulted:{}", generated_code_fault_code(error)),
            ),
            None => (GeneratedCodeEventKind::Invoked, "completed".to_string()),
        }
    }

    pub(super) fn estimate_generated_code_invocation_reservation_bytes(
        &self,
        provenance: &GeneratedFunctionProvenance,
        granted_capabilities: &[RuntimeCapability],
    ) -> u64 {
        const MAX_INVOCATION_OUTCOME: &str = "faulted:memory_budget_exceeded";
        const MAX_INVOCATION_EVENT_NAME: &str = "generated_code.faulted";

        let capability_slots = u64::try_from(granted_capabilities.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<String>() as u64);
        let capability_bytes =
            Self::saturating_sum(granted_capabilities.iter().map(|capability| {
                Self::estimate_string_bytes(Self::contained_codegen_capability_name(*capability))
            }));
        let audit_bytes = (std::mem::size_of::<GeneratedCodeAuditEntry>() as u64)
            .saturating_add(Self::estimate_string_bytes(&provenance.source_id))
            .saturating_add(Self::estimate_string_bytes(&provenance.source_hash))
            .saturating_add(Self::estimate_string_bytes(&provenance.parameter_hash))
            .saturating_add(Self::estimate_string_bytes(&provenance.construction_site))
            .saturating_add(capability_slots)
            .saturating_add(capability_bytes)
            .saturating_add(Self::estimate_string_bytes(MAX_INVOCATION_OUTCOME));
        let error_code_len = u64::try_from(provenance.source_id.len())
            .unwrap_or(u64::MAX)
            .saturating_add(" consumed=".len() as u64)
            .saturating_add(Self::decimal_digits(u64::MAX))
            .saturating_add(" outcome=".len() as u64)
            .saturating_add(MAX_INVOCATION_OUTCOME.len() as u64);
        let event_bytes = (std::mem::size_of::<InterpreterEvent>() as u64)
            .saturating_add(Self::estimate_string_bytes(&self.trace_id))
            .saturating_add(Self::estimate_string_bytes(COMPONENT))
            .saturating_add(Self::estimate_string_bytes(MAX_INVOCATION_EVENT_NAME))
            .saturating_add(Self::estimate_string_bytes("fail"))
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(error_code_len));
        audit_bytes.saturating_add(event_bytes)
    }

    pub(super) fn reserve_generated_code_invocation_event(
        &mut self,
        provenance: &GeneratedFunctionProvenance,
        granted_capabilities: &[RuntimeCapability],
    ) -> Result<u64, InterpreterError> {
        if self.generated_code_audit.len() >= MAX_GENERATED_CODE_AUDIT_ENTRIES {
            return Ok(0);
        }
        let reservation_bytes = self
            .estimate_generated_code_invocation_reservation_bytes(provenance, granted_capabilities);
        self.apply_memory_component_delta(0, reservation_bytes)?;
        self.generated_code_observability_reservation_bytes = self
            .generated_code_observability_reservation_bytes
            .saturating_add(reservation_bytes);
        Ok(reservation_bytes)
    }

    pub(super) fn release_generated_code_observability_reservation(
        &mut self,
        reservation_bytes: u64,
    ) {
        self.generated_code_observability_reservation_bytes = self
            .generated_code_observability_reservation_bytes
            .saturating_sub(reservation_bytes);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(reservation_bytes);
    }

    pub(super) fn append_generated_code_event_precharged(
        &mut self,
        entry: GeneratedCodeAuditEntry,
        charged_bytes: u64,
    ) {
        debug_assert!(self.generated_code_audit.len() < MAX_GENERATED_CODE_AUDIT_ENTRIES);
        debug_assert_eq!(
            charged_bytes,
            self.estimate_generated_code_observability_pair_bytes(&entry)
        );
        let event = self.generated_code_interpreter_event(&entry);
        debug_assert_eq!(
            self.estimate_generated_code_event_bytes(&entry),
            Self::estimate_interpreter_event_bytes(&event)
        );
        self.events.push(event);
        self.generated_code_audit.push(entry);
        self.generated_code_observability_bytes = self
            .generated_code_observability_bytes
            .saturating_add(charged_bytes);
    }

    pub(super) fn commit_reserved_generated_code_event(
        &mut self,
        entry: GeneratedCodeAuditEntry,
        reservation_bytes: u64,
    ) -> Result<(), InterpreterError> {
        if reservation_bytes == 0 {
            debug_assert!(self.generated_code_audit.len() >= MAX_GENERATED_CODE_AUDIT_ENTRIES);
            return Ok(());
        }
        if self.generated_code_audit.len() >= MAX_GENERATED_CODE_AUDIT_ENTRIES {
            drop(entry);
            self.release_generated_code_observability_reservation(reservation_bytes);
            return Ok(());
        }
        let actual_bytes = self.estimate_generated_code_observability_pair_bytes(&entry);
        if actual_bytes > reservation_bytes {
            drop(entry);
            self.release_generated_code_observability_reservation(reservation_bytes);
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generated-code observability reservation underflow: reserved {reservation_bytes} bytes, requires {actual_bytes}"
                ),
            });
        }
        self.apply_memory_component_delta(reservation_bytes, actual_bytes)?;
        self.generated_code_observability_reservation_bytes = self
            .generated_code_observability_reservation_bytes
            .saturating_sub(reservation_bytes);
        self.append_generated_code_event_precharged(entry, actual_bytes);
        Ok(())
    }

    /// Append a generated-code audit entry (bd-8enww.3.4 / bd-fw7zd.8.2) and
    /// its paired standard structured event as one budget transaction. Once
    /// the cap is reached, both surfaces drop the pair deterministically; the
    /// standard event can therefore no longer outgrow the bounded audit trail.
    #[cfg(test)]
    pub(super) fn record_generated_code_event(
        &mut self,
        entry: GeneratedCodeAuditEntry,
    ) -> Result<(), InterpreterError> {
        if self.generated_code_audit.len() >= MAX_GENERATED_CODE_AUDIT_ENTRIES {
            return Ok(());
        }
        let charged_bytes = self.estimate_generated_code_observability_pair_bytes(&entry);
        self.apply_memory_component_delta(0, charged_bytes)?;
        self.append_generated_code_event_precharged(entry, charged_bytes);
        Ok(())
    }

    pub(super) fn parse_generated_function_handle(
        builtin: &BuiltinFunction,
    ) -> Result<(ContentHash, ContentHash), InterpreterError> {
        fn decode_hash(field: &str) -> Option<ContentHash> {
            if field.len() != 64
                || !field
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return None;
            }
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(field, &mut bytes).ok()?;
            Some(ContentHash::from_bytes(bytes))
        }

        let mut fields = builtin.module_specifier.split(':');
        let (Some(domain), Some(version), Some(owner), Some(artifact), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(InterpreterError::TypeError {
                expected: "owner-scoped generated Function handle".to_string(),
                got: builtin.module_specifier.to_string(),
            });
        };
        if domain != "genfn" || version != "v1" {
            return Err(InterpreterError::TypeError {
                expected: "generated Function handle version genfn:v1".to_string(),
                got: builtin.module_specifier.to_string(),
            });
        }
        let owner_program_id = decode_hash(owner).ok_or_else(|| InterpreterError::TypeError {
            expected: "64-hex generated Function owner identity".to_string(),
            got: owner.to_string(),
        })?;
        let artifact_id = decode_hash(artifact).ok_or_else(|| InterpreterError::TypeError {
            expected: "64-hex generated Function artifact identity".to_string(),
            got: artifact.to_string(),
        })?;
        Ok((owner_program_id, artifact_id))
    }

    pub(super) fn resolve_generated_function_artifact(
        &self,
        owner_program_id: ContentHash,
        artifact_id: ContentHash,
    ) -> Result<&GeneratedFunctionArtifact, InterpreterError> {
        let store = self
            .module_state
            .generated_function_stores
            .get(&owner_program_id)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: owner_program_id.to_hex(),
                reason: "generated Function owner store is not retained".to_string(),
            })?;
        if store.realm_generation != self.generated_function_realm_generation {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: store.owner_specifier.clone(),
                reason: format!(
                    "generated Function owner store belongs to stale realm generation {}; current generation is {}",
                    store.realm_generation, self.generated_function_realm_generation
                ),
            });
        }
        if store.owner_program_id != owner_program_id {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generated Function store key/owner mismatch for {}",
                    owner_program_id.to_hex()
                ),
            });
        }
        let artifact = store.artifacts.get(&artifact_id).ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: store.owner_specifier.clone(),
                reason: format!(
                    "generated Function artifact {} is not retained by its owner",
                    artifact_id.to_hex()
                ),
            }
        })?;
        if artifact.owner_program_id != owner_program_id
            || artifact.artifact_id != artifact_id
            || artifact.owner_specifier != store.owner_specifier
        {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generated Function artifact provenance mismatch for {}",
                    artifact_id.to_hex()
                ),
            });
        }

        let record = self
            .module_state
            .modules
            .get(&artifact.owner_specifier)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: artifact.owner_specifier.clone(),
                reason: "generated Function owner module record was evicted".to_string(),
            })?;
        if let ModuleRuntimeStatus::Failed(reason) = &record.status {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: artifact.owner_specifier.clone(),
                reason: format!("generated Function owner module failed: {reason}"),
            });
        }
        let retained_program = record.compiled_module.as_ref().ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: artifact.owner_specifier.clone(),
                reason: "generated Function owner program was evicted".to_string(),
            }
        })?;
        if retained_program.header.source_label != artifact.owner_specifier {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: artifact.owner_specifier.clone(),
                reason: format!(
                    "generated Function owner mismatch: registry retained program `{}`",
                    retained_program.header.source_label
                ),
            });
        }
        if !Arc::ptr_eq(retained_program, &store.owner_program) {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: artifact.owner_specifier.clone(),
                reason: format!(
                    "generated Function owner program identity changed from {}",
                    owner_program_id.to_hex()
                ),
            });
        }
        Ok(artifact)
    }

    pub(super) fn active_generated_artifact_source_label(&self) -> Option<Label> {
        let handle = self.active_generated_function_artifact?;
        let store = self
            .module_state
            .generated_function_stores
            .get(&handle.owner_program_id)?;
        let artifact = store.artifacts.get(&handle.artifact_id)?;
        (artifact.source_label != Label::Public).then(|| artifact.source_label.clone())
    }

    /// Invoke a function produced by the `Function` constructor (bd-8enww.3.3).
    ///
    /// The generated function's executable program lives in its own
    /// `Ir3Module` (the artifact's `compiled_module`), distinct from the module
    /// the interpreter is currently running. We execute it re-entrantly using
    /// the same wrapper-module + `run_loop` pattern as
    /// `invoke_inline_method_call`: clone the artifact module, append a `Call`
    /// of the generated function descriptor followed by a `Return`, isolate the
    /// execution state, run, then restore the caller's state.
    ///
    /// Scope discipline (ES2020 §19.2.1.1.1 CreateDynamicFunction): a function
    /// built by the `Function` constructor closes over the sanitized realm
    /// environment only — never construction-site/call-site frames or the
    /// writable ambient realm map. Each invocation receives fresh frame
    /// structure sharing only the engine-owned canonical realm cells.
    pub(super) fn call_generated_function_artifact(
        &mut self,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<(Value, Label), InterpreterError> {
        self.invoke_generated_function_artifact(builtin, args, receiver, receiver_register, None)
    }

    pub(super) fn construct_generated_function_artifact(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        new_target: Value,
        mut new_target_label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        let (owner_program_id, artifact_id) = Self::parse_generated_function_handle(builtin)?;
        // Refuse a stale/forged artifact before invoking an observable getter.
        self.resolve_generated_function_artifact(owner_program_id, artifact_id)?;
        if let Some((_, label)) = self.constructor_prototype_override(module, &new_target)? {
            new_target_label =
                self.join_owned_label_with_temporary_budget(new_target_label, &label)?;
        }
        let observation = self.begin_property_observation([])?;
        let mut prototype_value = None;
        let outcome = (|| -> Result<(), InterpreterError> {
            self.check_temporary_memory_budget(Self::estimate_label_bytes(&new_target_label))?;
            self.json_observe_label(new_target_label.clone())?;
            let value = self.get_v(
                module,
                &new_target,
                &RuntimePropertyKey::String(JsString::from("prototype")),
            )?;
            // Retain success observations before closing the scope. The same
            // guard seals getter failures into their exception/result labels.
            let observed = self.json_parse_context_label()?;
            new_target_label =
                self.join_owned_label_with_temporary_budget(observed, &new_target_label)?;
            prototype_value = Some(value);
            Ok(())
        })();
        self.finish_property_write_observation(observation, outcome)?;
        let prototype = self.constructed_prototype_link(
            module,
            prototype_value.expect("a successful prototype read supplied its value"),
        )?;
        self.invoke_generated_function_artifact(
            builtin,
            args,
            None,
            None,
            Some(GeneratedFunctionConstruction {
                new_target,
                new_target_label,
                prototype,
            }),
        )
    }

    pub(super) fn invoke_generated_function_artifact(
        &mut self,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
        construction: Option<GeneratedFunctionConstruction>,
    ) -> Result<(Value, Label), InterpreterError> {
        let (owner_program_id, artifact_id) = Self::parse_generated_function_handle(builtin)?;
        let artifact_handle = GeneratedFunctionArtifactHandle {
            owner_program_id,
            artifact_id,
        };
        let artifact = self.resolve_generated_function_artifact(owner_program_id, artifact_id)?;
        let function_index = artifact.function_index;
        let transient_artifact_bytes =
            Self::transient_module_wrapper_bytes(artifact.compiled_module.as_ref())
                .saturating_add(Self::estimate_generated_function_provenance_bytes(
                    &artifact.provenance,
                ))
                .saturating_add(Self::estimate_label_bytes(&artifact.source_label));
        let owner_specifier_bytes = Self::estimate_string_bytes(&artifact.owner_specifier);
        let construction_bytes = construction.as_ref().map_or(0, |construction| {
            Self::estimate_value_bytes(&construction.new_target)
                .saturating_add(Self::estimate_label_bytes(&construction.new_target_label))
        });
        let arg_count = args.count;
        // A method-form call reserves r0 for the receiver and r1 for the
        // generated callee; a plain call needs only the callee in r0.
        let metadata_registers: u32 = if receiver.is_some() { 2 } else { 1 };
        let required_registers = metadata_registers.checked_add(arg_count).ok_or_else(|| {
            InterpreterError::TypeError {
                expected: "u32-bounded generated-function register budget".to_string(),
                got: format!(
                    "{metadata_registers} receiver/callee registers + {arg_count} arguments"
                ),
            }
        })?;
        if required_registers > self.config.max_registers {
            return Err(InterpreterError::TypeError {
                expected: "generated-function arguments within register budget".to_string(),
                got: format!(
                    "{required_registers} registers required but max is {}",
                    self.config.max_registers
                ),
            });
        }
        let caller_call_depth = self.effective_call_depth();
        self.check_module_reentrant_call_depth()?;
        let generated_hidden_call_depth = caller_call_depth;
        let instructions_before = self.instructions_executed;

        let generated_realm_globals =
            self.generated_function_realm_globals
                .as_ref()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "generated Function realm globals are not initialized".to_string(),
                })?;
        let projected_generated_scope_bytes =
            Self::estimate_generated_function_realm_scope_bytes(generated_realm_globals);
        let projected_argument_transport_bytes =
            u64::from(arg_count).saturating_mul(std::mem::size_of::<Value>() as u64);
        let projected_label_transport_bytes =
            self.isolated_call_label_transport_bytes_from_registers(receiver_register, args)?;
        self.check_temporary_memory_budget(
            transient_artifact_bytes
                .saturating_add(owner_specifier_bytes)
                .saturating_add(construction_bytes)
                .saturating_add(projected_argument_transport_bytes)
                .saturating_add(projected_label_transport_bytes)
                .saturating_add(projected_generated_scope_bytes)
                .saturating_add(self.module_execution_snapshot_memory_bytes()),
        )?;
        let generated_scope_frame = self.generated_function_realm_scope_frame()?;
        let effective_generated_capabilities = self.contained_codegen_effective_capability_grant(
            artifact.compiled_module.as_ref(),
            &generated_scope_frame,
        )?;
        let effective_generated_grant =
            Self::validate_contained_codegen_grant(&effective_generated_capabilities)?;

        // Read call values and labels only after the complete wrapper +
        // transport + snapshot peak is known to fit. `RegRange` is relative to
        // the caller's current register base.
        let owner_specifier = artifact.owner_specifier.clone();
        let mut arguments = Vec::with_capacity(args.count as usize);
        for index in 0..args.count {
            let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
            arguments.push(value);
        }
        let argument_transport_bytes = u64::try_from(arguments.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Value>() as u64);
        let call_labels =
            self.clone_isolated_call_labels_from_registers(receiver_register, args)?;
        let mut remaining_label_transport_bytes =
            Self::isolated_call_label_transport_bytes(&call_labels, arguments.len());
        let transient_execution_bytes = transient_artifact_bytes
            .saturating_add(owner_specifier_bytes)
            .saturating_add(construction_bytes)
            .saturating_add(argument_transport_bytes)
            .saturating_add(remaining_label_transport_bytes);
        self.apply_memory_component_delta(0, transient_execution_bytes)?;
        // Re-resolve after the mutable precharge so the artifact borrow cannot
        // overlap interpreter mutation. No guest code runs between these two
        // reads; any mismatch is still treated as a contained stale handle.
        let (mut wrapper, provenance) =
            match self.resolve_generated_function_artifact(owner_program_id, artifact_id) {
                Ok(artifact) => (
                    artifact.compiled_module.as_ref().clone(),
                    artifact.provenance.clone(),
                ),
                Err(error) => {
                    self.estimated_memory_bytes = self
                        .estimated_memory_bytes
                        .saturating_sub(transient_execution_bytes);
                    return Err(error);
                }
            };
        let wrapper_start = wrapper.instructions.len();
        if construction.is_some() {
            // The real constructor frame below returns to this wrapper.
        } else if receiver.is_some() {
            wrapper.instructions.push(Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange {
                    start: 2,
                    count: arg_count,
                },
                dst: 0,
            });
        } else {
            wrapper.instructions.push(Ir3Instruction::Call {
                callee: 0,
                args: RegRange {
                    start: 1,
                    count: arg_count,
                },
                dst: 0,
            });
        }
        wrapper
            .instructions
            .push(Ir3Instruction::Return { value: 0 });

        // Contained-codegen capability envelope: replace (never extend) the
        // caller's live grants with the generated function's validated safe
        // set. The engine-local VmDispatch / HeapAllocate baseline keeps normal
        // bytecode and object allocation live; static declarations and
        // runtime-resolved canonical realm builtins can contribute only Builtin
        // / Console / Timer. Caller fs/net/process authority therefore cannot
        // remain live across this boundary. The exact prior set is restored
        // after every regular return, fault, budget refusal, or cancellation
        // path below.
        let observability_reservation_bytes = match self.reserve_generated_code_invocation_event(
            &provenance,
            effective_generated_grant.as_slice(),
        ) {
            Ok(reservation_bytes) => reservation_bytes,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(transient_execution_bytes);
                return Err(error);
            }
        };

        // bd-8enww.3.4: capture the caller's JS call-stack depth and the shared
        // instruction-budget reading BEFORE the re-entrant run, so the audit
        // entry can attribute exact budget spend and call context to this
        // generated function. The instruction counter is deliberately NOT part
        // of `snapshot_module_execution`, so the post-call delta reflects the
        // generated body's real spend against the one shared budget.
        let setup_previous_register_bytes = self.registers_memory_bytes();
        let setup_previous_register_context_label_bytes =
            self.register_context_labels_memory_bytes();
        // The snapshot takes the caller's registers and labels, leaving the
        // fresh files the generated body starts on.
        let snapshot = match self.isolate_module_execution() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(transient_execution_bytes);
                self.release_generated_code_observability_reservation(
                    observability_reservation_bytes,
                );
                return Err(error);
            }
        };
        let IsolatedCallLabels {
            receiver: receiver_label,
            arguments: argument_labels,
        } = call_labels;
        // The context is excluded from generated-code name resolution. Move it
        // out and restore ownership after the isolated call instead of cloning
        // its attacker-sized module specifier as an uncharged temporary.
        let saved_active_cjs_context = self.active_cjs_context.take();
        let setup_previous_scope_bytes = self.scope_chain_memory_bytes();
        let setup_previous_call_stack_bytes = self.call_stack_memory_bytes();
        let mut wrapper_memory_committed = false;
        let previous_granted_capabilities =
            self.replace_with_contained_codegen_grant(Some(effective_generated_grant));
        let previous_reentrant_depth = self.module_reentrant_call_depth;
        let result = (|| -> Result<Value, InterpreterError> {
            self.call_stack.clear(&mut self.closures.cold_cells);
            self.ip = wrapper_start;
            self.register_base = 0;
            self.register_width = self.config.max_registers as usize;
            self.catch_frames.clear();
            self.pending_exception = None;
            self.pending_exception_label = Label::Public;
            self.pending_hostcall_result_label = None;
            self.pending_return = None;
            self.suspended_abrupt_completions.clear();
            self.finally_frames.clear();
            self.pending_finally_entry = None;
            self.current_module_specifier = Some(owner_specifier);
            self.active_generated_function_artifact = Some(artifact_handle);
            if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                self.active_inline_callback_context_label =
                    match self.active_inline_callback_context_label.take() {
                        Some(existing) => Some(
                            self.join_owned_label_with_temporary_budget(existing, &artifact_label)?,
                        ),
                        None => Some(artifact_label),
                    };
            }
            // The generated body sees one fresh sanitized realm frame. It has
            // no structural or binding-cell edge to either caller or owner
            // module frames.
            self.scope_chain.frames = vec![generated_scope_frame];
            self.apply_register_context_scope_call_stack_memory_delta(
                setup_previous_register_bytes,
                setup_previous_register_context_label_bytes,
                setup_previous_scope_bytes,
                setup_previous_call_stack_bytes,
            )?;
            wrapper_memory_committed = true;
            let argument_start = if let Some(receiver) = receiver {
                self.seed_isolated_receiver(
                    0,
                    receiver,
                    Some(receiver_label),
                    &mut remaining_label_transport_bytes,
                )?;
                self.write_reg(1, Value::Function(function_index))?;
                2
            } else {
                // A plain generated-function call has no receiver register, so
                // release the precharged Public placeholder without seeding it.
                self.release_isolated_label_transport_charge(
                    &mut remaining_label_transport_bytes,
                    Self::estimate_label_bytes(&receiver_label),
                );
                self.write_reg(0, Value::Function(function_index))?;
                1
            };
            self.seed_isolated_arguments(
                argument_start,
                arguments,
                argument_labels,
                &mut remaining_label_transport_bytes,
                "generated-function argument register",
            )?;
            self.module_reentrant_call_depth = generated_hidden_call_depth;
            if let Some(construction) = &construction {
                self.enter_constructor_call_with_prototype(
                    &wrapper,
                    Value::Function(function_index),
                    Label::Public,
                    RegRange {
                        start: argument_start,
                        count: arg_count,
                    },
                    wrapper_start,
                    0,
                    construction.new_target.clone(),
                    construction.new_target_label.clone(),
                    false,
                    None,
                    Some(construction.prototype),
                )?;
            }
            self.run_loop(&wrapper)
        })();
        self.module_reentrant_call_depth = previous_reentrant_depth;
        let result_label = if result.is_ok() {
            self.clone_register_label_with_temporary_budget(0)
                .and_then(|label| match &construction {
                    Some(construction) => self.join_owned_label_with_temporary_budget(
                        label,
                        &construction.new_target_label,
                    ),
                    None => Ok(label),
                })
        } else {
            Ok(Label::Public)
        };
        // Preserve a thrown value across the snapshot restore so an enclosing
        // try/catch in the caller can still observe it (same contract as
        // `invoke_inline_method_call`).
        let thrown_value = match &result {
            Err(InterpreterError::UncaughtException { .. }) => self
                .pending_exception
                .clone()
                .map(|v| (v, self.pending_exception_label.clone())),
            _ => None,
        };
        drop(wrapper);
        drop(construction);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
            transient_artifact_bytes
                .saturating_add(owner_specifier_bytes)
                .saturating_add(construction_bytes)
                .saturating_add(argument_transport_bytes)
                .saturating_add(remaining_label_transport_bytes),
        );
        self.restore_module_execution(snapshot, wrapper_memory_committed);
        self.active_cjs_context = saved_active_cjs_context;
        self.restore_replaced_codegen_grants(previous_granted_capabilities);

        // A native JS fault raised inside the isolated generated run (for
        // example, an unresolved name in the canonical realm) has no inner
        // catch frame left to materialize it as a thrown JS Error. Preserve
        // the native variant when the restored caller can still catch/reject
        // it through `run_loop`; otherwise surface the same uncaught-exception
        // boundary diagnostic as an explicit throw. This keeps containment
        // failures distinguishable from parse-time failures without turning
        // engine/resource faults into catchable guest exceptions.
        let result = match result {
            Err(error)
                if !self.has_active_catch_frame() && self.nearest_async_call_depth().is_none() =>
            {
                if let Some(error_name) = Self::js_catchable_error_name(&error) {
                    Err(InterpreterError::UncaughtException {
                        value: format!("{error_name}: {error}"),
                    })
                } else {
                    Err(error)
                }
            }
            other => other,
        };

        // bd-8enww.3.4: record the invocation in the audit trail with the exact
        // instruction budget the generated body consumed. The shared counter is
        // NOT rolled back by `restore_module_execution`, so this delta is the
        // real spend — adversarial generated code cannot hide its cost.
        if observability_reservation_bytes != 0 {
            let instructions_consumed = self
                .instructions_executed
                .saturating_sub(instructions_before);
            let (kind, outcome) = Self::generated_code_invocation_outcome(&result, &result_label);
            let granted_capabilities = effective_generated_grant
                .as_slice()
                .iter()
                .map(|capability| Self::contained_codegen_capability_name(*capability).to_string())
                .collect();
            self.commit_reserved_generated_code_event(
                GeneratedCodeAuditEntry {
                    source_id: provenance.source_id,
                    source_hash: provenance.source_hash,
                    parameter_hash: provenance.parameter_hash,
                    construction_site: provenance.construction_site,
                    kind,
                    instructions_consumed,
                    caller_call_depth,
                    granted_capabilities,
                    outcome,
                },
                observability_reservation_bytes,
            )?;
        }
        if let Some((value, label)) = thrown_value {
            self.replace_pending_abrupt_slots(Some((value, label)), None)?;
        }

        let result_label = result_label?;
        result.map(|value| (value, result_label))
    }

    /// Single semantic implementation shared by the direct
    /// `builtin:ArrayIsArray` hostcall and its first-class callable twin.
    /// Array.isArray (ES2020 7.2.2 IsArray): a proxy answers for its target,
    /// and Array.prototype is itself an array.
    pub(super) fn array_is_array_value(
        &self,
        arg: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let is_array = match arg {
            Some(Value::Object(object_id)) => self.generic_is_array(object_id)?,
            _ => false,
        };
        Ok(Value::Bool(is_array))
    }

    /// Authority-bearing native function values that do not use
    /// `call_static_hostcall`. Resolve the operation at invocation time so
    /// aliases, bound functions, call/apply and callbacks retain the same
    /// capability and live-hook boundary as direct HostCall instructions.
    pub(super) fn native_value_host_effect_tag(
        builtin: &BuiltinFunction,
    ) -> Option<Cow<'static, str>> {
        let tag = match builtin.kind {
            BuiltinFunctionKind::NativeHttpFunction => {
                native_http_function_metadata(&builtin.module_specifier)?.0
            }
            BuiltinFunctionKind::NativeChildProcessFunction => "process_spawn",
            BuiltinFunctionKind::ConsoleLog => "console:log",
            BuiltinFunctionKind::ConsoleError => "console:error",
            BuiltinFunctionKind::ConsoleWarn => "console:warn",
            BuiltinFunctionKind::ConsoleInfo => "console:info",
            BuiltinFunctionKind::ConsoleMethod => {
                return Some(Cow::Owned(format!("console:{}", builtin.display_name())));
            }
            BuiltinFunctionKind::SetTimeout => "builtin:SetTimeout",
            BuiltinFunctionKind::ClearTimeout => "builtin:ClearTimeout",
            BuiltinFunctionKind::SetInterval => "builtin:SetInterval",
            BuiltinFunctionKind::ClearInterval => "builtin:ClearInterval",
            BuiltinFunctionKind::SetImmediate => "builtin:SetImmediate",
            BuiltinFunctionKind::ClearImmediate => "builtin:ClearImmediate",
            BuiltinFunctionKind::QueueMicrotask => "builtin:QueueMicrotask",
            // StaticHostcall already gates its exact tag. Direct HostCall
            // dispatch does not enter this function and keeps its own gate.
            _ => return None,
        };
        Some(Cow::Borrowed(tag))
    }

    /// A native effect function or WeakSet method selected from a classified
    /// module or property carries that selection into its request state or
    /// private membership before mutation. Other builtins retain their existing
    /// invocation contract. The observation scope accounts its label and
    /// restores the caller on successful, thrown and resource-limit exits.
    pub(super) fn dispatch_builtin_function_with_callee_register(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
        callee: u32,
    ) -> Result<Value, InterpreterError> {
        if !builtin.kind.observes_host_effect_selection()
            && builtin.kind != BuiltinFunctionKind::WeakSetMethod
        {
            return self.dispatch_builtin_function(
                module,
                builtin,
                args,
                receiver,
                receiver_register,
            );
        }
        let observation = self.begin_property_observation([callee])?;
        let outcome =
            self.dispatch_builtin_function(module, builtin, args, receiver, receiver_register);
        self.finish_property_read_observation(observation, outcome)
    }

    /// Keep the Writable lifecycle lane out of the monolithic builtin
    /// dispatcher.  Writable methods can synchronously drive user callbacks;
    /// retaining the large catch-all dispatch frame while those callbacks run
    /// makes ordinary callback composition consume the native test-thread
    /// stack.  This small front dispatcher gives that finite lane a bounded
    /// frame without changing its ordering or return-value semantics.
    #[inline(never)]
    pub(super) fn dispatch_builtin_function(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        if let Some(capability) = Self::native_value_host_effect_tag(builtin) {
            let instruction_index = u32::try_from(self.ip).unwrap_or(u32::MAX);
            check_hostcall_capability_gate(self, capability.as_ref(), instruction_index)?;
        }
        let legacy_regexp_generation = self.legacy_regexp_generation;
        let receiver_given = receiver.is_some();
        let receiver_had_register = receiver_register.is_some();
        // bd-9vouw.77: count this dispatch so a builtin reached from inside
        // another builtin's Rust frame never arms a nested loop.
        self.gc_enter_builtin();
        let result = match builtin.kind {
            // Reflect invocation reenters the VM. Keep its saved function
            // values out of the broad builtin dispatcher's large Rust frame;
            // call_static_hostcall retains tag validation and authority gates.
            BuiltinFunctionKind::StaticHostcall
                if matches!(
                    &*builtin.module_specifier,
                    "builtin:ReflectApply" | "builtin:ReflectConstruct"
                ) =>
            {
                self.call_static_hostcall(module, builtin, args)
            }
            BuiltinFunctionKind::AsyncGeneratorNext
            | BuiltinFunctionKind::AsyncGeneratorReturn
            | BuiltinFunctionKind::AsyncGeneratorThrow => self.dispatch_async_generator_resume(
                module,
                builtin.kind,
                args,
                receiver,
                receiver_register,
            ),
            BuiltinFunctionKind::GeneratorNext
            | BuiltinFunctionKind::GeneratorReturn
            | BuiltinFunctionKind::GeneratorThrow => self.dispatch_generator_resume(
                module,
                builtin.kind,
                args,
                receiver,
                receiver_register,
            ),
            BuiltinFunctionKind::FunctionPrototypeCall
            | BuiltinFunctionKind::FunctionPrototypeApply => self.forward_function_invocation(
                Some(module),
                receiver.unwrap_or(Value::Undefined),
                receiver_register,
                args,
                builtin.kind == BuiltinFunctionKind::FunctionPrototypeApply,
            ),
            BuiltinFunctionKind::DateGetTime
            | BuiltinFunctionKind::DatePrototypeMethod
            | BuiltinFunctionKind::DatePrototypeToPrimitive => self.dispatch_date_builtin_function(
                module,
                builtin,
                args,
                receiver,
                receiver_register,
            ),
            BuiltinFunctionKind::StreamWritableWrite
            | BuiltinFunctionKind::StreamWritableEnd
            | BuiltinFunctionKind::StreamWritableCork
            | BuiltinFunctionKind::StreamWritableUncork
            | BuiltinFunctionKind::StreamWritableDestroy => {
                self.dispatch_writable_builtin_function(module, builtin.kind, args, receiver)
            }
            _ => self.dispatch_builtin_function_inner(
                module,
                builtin,
                args,
                receiver,
                receiver_register,
            ),
        };
        self.gc_exit_builtin();
        // bd-9vouw.113: a match this call recorded carries its operands'
        // label. A receiver passed without its register leaves the match
        // unlabelled, which reads as TopSecret.
        if result.is_ok()
            && self.legacy_regexp_generation != legacy_regexp_generation
            && (receiver_had_register || !receiver_given)
        {
            let mut label = self.join_arg_range_label(args)?;
            if let Some(register) = receiver_register {
                label = label.join(self.get_register_label(register)?);
            }
            self.label_legacy_regexp_match(legacy_regexp_generation, &label);
        }
        result
    }

    /// Date's time belongs to the object, so a Public alias must still
    /// observe the provenance of an earlier setter. This boundary is shared
    /// by direct calls and call/apply/Reflect's isolated invocation paths.
    pub(super) fn dispatch_date_builtin_function(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let end =
            args.start
                .checked_add(args.count)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
        let observation =
            self.begin_property_observation(receiver_register.into_iter().chain(args.start..end))?;
        let outcome = (|| {
            if let Some(receiver) = receiver.as_ref() {
                self.observe_date_value_label(receiver)?;
            }
            self.dispatch_builtin_function_inner(module, builtin, args, receiver, receiver_register)
        })();
        self.finish_property_read_observation(observation, outcome)
    }

    #[inline(never)]
    pub(super) fn dispatch_generator_resume(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Generator(gen_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: "generator receiver".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        let argument = if args.count == 0 {
            Value::Undefined
        } else {
            self.read_reg(args.start)?
        };
        let mut label = self.join_arg_range_label(args)?;
        if let Some(reg) = receiver_register {
            label = label.join(self.get_register_label(reg)?);
        }
        let (result, result_label) = match kind {
            BuiltinFunctionKind::GeneratorNext => {
                self.generator_next(module, gen_id, argument, label)
            }
            BuiltinFunctionKind::GeneratorReturn => {
                self.generator_resume(module, gen_id, GeneratorResumeKind::Return, argument, label)
            }
            BuiltinFunctionKind::GeneratorThrow => {
                self.generator_resume(module, gen_id, GeneratorResumeKind::Throw, argument, label)
            }
            _ => unreachable!("finite generator method dispatcher"),
        }?;
        self.replace_pending_hostcall_result_label(Some(result_label))?;
        Ok(result)
    }

    #[inline(never)]
    pub(super) fn dispatch_writable_builtin_function(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        args: RegRange,
        receiver: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        match kind {
            BuiltinFunctionKind::StreamWritableWrite => self.writable_write(module, receiver, args),
            BuiltinFunctionKind::StreamWritableEnd => self.writable_end(module, receiver, args),
            BuiltinFunctionKind::StreamWritableCork => self.writable_cork(receiver, args),
            BuiltinFunctionKind::StreamWritableUncork => {
                self.writable_uncork(module, receiver, args)
            }
            BuiltinFunctionKind::StreamWritableDestroy => self.writable_destroy(receiver, args),
            _ => unreachable!("finite Writable lifecycle builtin selected a non-Writable method"),
        }
    }
}
