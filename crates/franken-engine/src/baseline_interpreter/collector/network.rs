//! Precise roots and weak owner tables for HTTP, loopback and child-process I/O.

use super::*;

impl PendingLoopbackTask {
    fn visit_gc_values(&self, mut visit: impl FnMut(Value)) {
        match self {
            Self::Listening {
                server,
                generation: _,
            }
            | Self::ServerClose {
                server,
                generation: _,
                label: _,
            } => {
                visit(Value::Object(*server));
            }
            Self::Connect {
                client,
                server,
                generation: _,
            } => {
                visit(Value::Object(*client));
                visit(Value::Object(*server));
            }
            Self::Data {
                target,
                bytes: _,
                label: _,
            }
            | Self::End { target, label: _ }
            | Self::Close {
                target,
                had_error: _,
                label: _,
            }
            | Self::Error {
                target,
                code: _,
                label: _,
                close_after: _,
            } => {
                visit(Value::Object(*target));
            }
        }
    }
}

impl PendingHttpTask {
    fn visit_gc_values(&self, mut visit: impl FnMut(Value)) {
        match self {
            Self::DispatchRequest {
                request,
                server,
                generation: _,
            } => {
                visit(Value::Object(*request));
                visit(Value::Object(*server));
            }
            Self::DeliverResponse { request, message } => {
                visit(Value::Object(*request));
                visit(Value::Object(*message));
            }
            Self::DeliverExternalResponse { request, response } => {
                visit(Value::Object(*request));
                if let Some(response) = response {
                    visit(Value::Object(*response));
                }
            }
            Self::MessageData { message }
            | Self::MessageEnd { message }
            | Self::MessageClose { message } => visit(Value::Object(*message)),
            Self::ClientError {
                request,
                code: _,
                label: _,
            } => {
                visit(Value::Object(*request));
            }
            Self::EmitLegacyEvent {
                target,
                event: _,
                arguments,
                leading_callback,
                label: _,
            } => {
                visit(Value::Object(*target));
                arguments.iter().cloned().for_each(&mut visit);
                if let Some(callback) = leading_callback {
                    visit(Value::Closure(*callback));
                }
            }
        }
    }
}

impl InterpreterCore {
    pub(super) fn is_child_process_gc_owner(&self, id: ObjectId) -> bool {
        self.completed_child_processes.contains_key(&id)
            || self.child_process_streams.contains_key(&id)
            || self.child_process_handles.contains_key(&id)
    }

    pub(in crate::baseline_interpreter) fn gc_pin_child_process_task(
        &mut self,
        task: &PendingChildProcessTask,
    ) -> usize {
        let checkpoint = self.gc.network_task_pins.len();
        self.gc.network_task_pins.push(Value::Object(task.child));
        if let Some(callback) = task.callback {
            self.gc.network_task_pins.push(Value::Closure(callback));
        }
        checkpoint
    }

    pub(in crate::baseline_interpreter) fn gc_pin_loopback_task(
        &mut self,
        task: &PendingLoopbackTask,
    ) -> usize {
        let checkpoint = self.gc.network_task_pins.len();
        task.visit_gc_values(|value| self.gc.network_task_pins.push(value));
        checkpoint
    }

    pub(in crate::baseline_interpreter) fn gc_pin_http_task(
        &mut self,
        task: &PendingHttpTask,
    ) -> usize {
        let checkpoint = self.gc.network_task_pins.len();
        task.visit_gc_values(|value| self.gc.network_task_pins.push(value));
        checkpoint
    }

    pub(in crate::baseline_interpreter) fn gc_network_task_active(&self) -> bool {
        !self.gc.network_task_pins.is_empty()
    }

    pub(in crate::baseline_interpreter) fn gc_pin_network_values(
        &mut self,
        values: impl IntoIterator<Item = Value>,
    ) -> usize {
        let checkpoint = self.gc.network_task_pins.len();
        self.gc.network_task_pins.extend(values);
        checkpoint
    }

    pub(in crate::baseline_interpreter) fn gc_unpin_network_values(&mut self, checkpoint: usize) {
        self.gc.network_task_pins.truncate(checkpoint);
    }

    pub(super) fn gc_mark_network_roots(&self, marker: &mut GcMarker) {
        self.gc
            .network_task_pins
            .iter()
            .for_each(|value| marker.value(value));
        // Listening ports and unfinished connections represent external
        // liveness. Closed port tombstones contain no heap references and
        // must remain until reset to preserve internal-port confinement.
        for port in self.loopback_ports.values() {
            match port {
                LoopbackPortState::Live {
                    server,
                    generation: _,
                } => marker.object(*server),
                LoopbackPortState::Closed { generation: _ } => {}
            }
        }
        for (server, state) in &self.loopback_servers {
            if state.listening || !state.active_connections.is_empty() {
                marker.object(*server);
            }
        }
        for (socket, state) in &self.loopback_sockets {
            if !state.destroyed && state.peer.is_some() {
                marker.object(*socket);
            }
        }
        for task in self.pending_loopback_tasks.values() {
            task.visit_gc_values(|value| marker.value(&value));
        }
        for task in self.pending_http_tasks.values() {
            task.visit_gc_values(|value| marker.value(&value));
        }
    }

    /// A reachable facade keeps its hidden state edges alive. The tables
    /// themselves are weak: an unused Agent or completed request must not
    /// keep every object it ever captured alive for the rest of execution.
    pub(super) fn gc_trace_network_object(&self, marker: &mut GcMarker, id: ObjectId) {
        if self.is_child_process_gc_owner(id) {
            if let Some(events) = self.event_listeners.get(&id) {
                for record in events.values().flatten() {
                    marker.value(&record.listener);
                }
            }
            if let Some(waiters) = self.event_promise_waiters.get(&id) {
                for record in waiters.values().flatten() {
                    marker.promise(record.promise.0);
                }
            }
        }
        // A raw once wrapper may escape the emitter's listener list. Its
        // original target and listener stay alive even if guest code deletes
        // or replaces the public .listener property.
        if let Some(state) = self.event_once_wrappers.get(&id) {
            marker.object(state.target);
            marker.value(&state.original_listener);
        }
        if let Some((child, _)) = self.child_process_streams.get(&id) {
            marker.object(*child);
        }
        if let Some(state) = self.completed_child_processes.get(&id) {
            let CompletedChildProcessState {
                settled: _,
                stdout,
                stdout_has_data: _,
                stderr,
                stderr_has_data: _,
                exit_code,
                signal,
                error,
                scheduled_events: _,
            } = state;
            for value in [stdout, stderr, exit_code, signal].into_iter().chain(error) {
                marker.value(value);
            }
        }
        if let Some(state) = self.loopback_servers.get(&id) {
            let LoopbackServerState {
                address: _,
                port: _,
                generation: _,
                listening: _,
                active_connections,
                close_requested: _,
                close_scheduled: _,
                tls: _,
                lifecycle_label: _,
            } = state;
            active_connections
                .iter()
                .for_each(|connection| marker.object(*connection));
        }
        if let Some(state) = self.loopback_sockets.get(&id) {
            let LoopbackSocketState {
                peer,
                owner_server,
                owner_server_generation: _,
                paused: _,
                encoding_utf8: _,
                local_ended: _,
                remote_ended: _,
                destroyed: _,
                close_scheduled: _,
                bytes_read: _,
                bytes_written: _,
                pending_data: _,
                pending_end: _,
                pending_outbound: _,
                pending_outbound_end: _,
                tls: _,
                lifecycle_label: _,
                end_completion_callback,
            } = state;
            if let Some(peer) = peer {
                marker.object(*peer);
            }
            if let Some(server) = owner_server {
                marker.object(*server);
            }
            if let Some(callback) = end_completion_callback {
                marker.value(callback);
            }
        }
        if let Some(state) = self.http_servers.get(&id) {
            let HttpServerState { lifecycle_label: _ } = state;
        }
        if let Some(state) = self.http_client_requests.get(&id) {
            let HttpClientRequestState {
                host: _,
                port: _,
                use_tls: _,
                internal_loopback_candidate: _,
                path: _,
                method: _,
                headers: _,
                body: _,
                ended: _,
                response_callback,
                lifecycle_label: _,
                egress_label: _,
            } = state;
            if let Some(callback) = response_callback {
                marker.closure(*callback);
            }
        }
        if let Some(state) = self.http_incoming_messages.get(&id) {
            let HttpIncomingMessageState {
                body: _,
                encoding_utf8: _,
                delivered: _,
                close_after_end: _,
                server_completion,
                lifecycle_label: _,
            } = state;
            if let Some(completion) = server_completion {
                let HttpServerCompletion {
                    server,
                    generation: _,
                    response,
                } = completion;
                marker.object(*server);
                marker.object(*response);
            }
        }
        if let Some(state) = self.http_server_responses.get(&id) {
            let HttpServerResponseState {
                client_request,
                server,
                server_generation: _,
                request_method: _,
                status_code: _,
                status_message: _,
                headers: _,
                body: _,
                ended: _,
                lifecycle_label: _,
            } = state;
            marker.object(*client_request);
            marker.object(*server);
        }
    }

    /// Return exactly the charge released by dead network owner entries.
    /// Task entries and live ports are roots, so neither is swept here.
    pub(super) fn gc_sweep_network_state(&mut self) -> u64 {
        let heap = &self.heap;
        let mut released = 0u64;
        // A process's listeners and once wrappers are weak owner tables too.
        // Every non-process emitter is still an explicit root, so none of
        // its records can be removed here. Inspect heap liveness before
        // dropping the child/pipe tables that classify process ownership.
        self.event_listeners.retain(|id, events| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                for (event, records) in events {
                    for record in records {
                        released = released.saturating_add(
                            Self::estimate_event_listener_record_bytes(event, record),
                        );
                    }
                }
            }
            live
        });
        self.event_promise_waiters.retain(|id, events| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                for (event, records) in events {
                    for record in records {
                        released = released.saturating_add(
                            Self::estimate_event_promise_waiter_record_bytes(
                                event,
                                &record.registration_label,
                            ),
                        );
                    }
                }
            }
            live
        });
        self.event_once_wrappers.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released =
                    released.saturating_add(Self::estimate_event_once_wrapper_state_bytes(state));
            }
            live
        });
        self.completed_child_processes.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released = released
                    .saturating_add(Self::estimate_completed_child_process_state_bytes(state));
            }
            live
        });
        self.child_process_streams.retain(|id, _| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released = released.saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(
                    std::mem::size_of::<(ObjectId, (ObjectId, ChildProcessStreamKind))>() as u64,
                ));
            }
            live
        });
        self.loopback_servers.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released =
                    released.saturating_add(Self::estimate_loopback_server_state_bytes(state));
            }
            live
        });
        self.loopback_sockets.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released =
                    released.saturating_add(Self::estimate_loopback_socket_state_bytes(state));
            }
            live
        });
        self.http_servers.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released = released.saturating_add(
                    MEMORY_ESTIMATE_HTTP_SERVER_BASE_BYTES
                        .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label)),
                );
            }
            live
        });
        self.http_client_requests.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released =
                    released.saturating_add(Self::estimate_http_client_request_state_bytes(state));
            }
            live
        });
        self.http_incoming_messages.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released = released
                    .saturating_add(Self::estimate_http_incoming_message_state_bytes(state));
            }
            live
        });
        self.http_server_responses.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released =
                    released.saturating_add(Self::estimate_http_server_response_state_bytes(state));
            }
            live
        });
        self.http_agents.retain(|id| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released = released.saturating_add(MEMORY_ESTIMATE_HTTP_AGENT_BASE_BYTES);
            }
            live
        });
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_heap_objects = 1024;
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        InterpreterCore::new(config, "child-process-gc")
    }

    fn child_and_streams(core: &mut InterpreterCore) -> (ObjectId, Vec<ObjectId>) {
        let child = core
            .allocate_child_process_facade(&ProcessCallOptions::default())
            .expect("allocate child facade");
        let streams = core
            .child_process_streams
            .iter()
            .filter_map(|(stream, (owner, _))| (*owner == child).then_some(*stream))
            .collect::<Vec<_>>();
        assert_eq!(streams.len(), 3);
        // No public property keeps the pipe facades alive. The native
        // lifecycle still owns and can address its original streams.
        for name in ["stdout", "stderr", "stdin"] {
            core.set_object_property(child, name.to_string(), Value::Null)
                .expect("replace guest-visible pipe property");
        }
        (child, streams)
    }

    fn assert_accounted(core: &InterpreterCore) {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "child-process collection must preserve exact memory accounting"
        );
    }

    #[test]
    fn a_pipe_keeps_its_child_hidden_results_and_other_pipes_until_unreachable() {
        let mut core = process_core();
        let (child, streams) = child_and_streams(&mut core);
        let stdout = core.alloc_object_with_prototype(None).expect("stdout");
        let stderr = core.alloc_object_with_prototype(None).expect("stderr");
        let error = core.alloc_object_with_prototype(None).expect("error");
        let garbage = core.alloc_object_with_prototype(None).expect("garbage");
        core.replace_child_process_state(
            child,
            CompletedChildProcessState {
                settled: true,
                stdout: Value::Object(stdout),
                stdout_has_data: true,
                stderr: Value::Object(stderr),
                stderr_has_data: true,
                exit_code: Value::Int(1),
                signal: Value::Null,
                error: Some(Value::Object(error)),
                scheduled_events: BTreeSet::new(),
            },
        )
        .expect("completed process state");
        core.write_reg(0, Value::Object(streams[0]))
            .expect("only one pipe remains reachable");
        core.collect_garbage();
        for id in [child, stdout, stderr, error].iter().chain(&streams) {
            assert!(core.heap.get(id.0 as usize).is_some(), "lost object {id:?}");
        }
        assert!(core.heap.is_reclaimed(garbage.0 as usize));
        assert_accounted(&core);

        core.write_reg(0, Value::Undefined).expect("release pipe");
        core.collect_garbage();
        for id in [child, stdout, stderr, error].iter().chain(&streams) {
            assert!(
                core.heap.is_reclaimed(id.0 as usize),
                "retained object {id:?}"
            );
        }
        assert!(core.completed_child_processes.is_empty());
        assert!(core.child_process_streams.is_empty());
        assert_accounted(&core);
    }

    #[test]
    fn queued_and_in_flight_waits_keep_callback_captures_and_handle_owners_alive() {
        let mut core = process_core();
        let (child, streams) = child_and_streams(&mut core);
        let payload = core.alloc_object_with_prototype(None).expect("capture");
        let callback = core.closures.len() as u32;
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![ScopeFrame::from_bindings(BTreeMap::from([(
                "payload".to_string(),
                ScopeBinding::with_state(BindingKind::Const, Value::Object(payload), true),
            )]))],
        });
        core.pending_child_process_tasks.insert(
            7,
            PendingChildProcessTask {
                child,
                handle: "native-handle".to_string(),
                callback: Some(callback),
                callback_label: Label::Internal,
                callback_encoding: Some("utf8".to_string()),
                options: ProcessCallOptions::default(),
            },
        );
        core.sync_estimated_memory_bytes().expect("account fixture");
        core.collect_garbage();
        assert!(core.heap.get(payload.0 as usize).is_some());
        assert!(core.closures.get(callback as usize).is_some());
        assert_accounted(&core);

        let task = core
            .pending_child_process_tasks
            .remove(&7)
            .expect("queued wait");
        core.child_process_task_in_flight_bytes =
            InterpreterCore::pending_child_process_task_bytes(&task);
        let checkpoint = core.gc_pin_child_process_task(&task);
        core.collect_garbage();
        assert!(core.heap.get(payload.0 as usize).is_some());
        assert!(core.closures.get(callback as usize).is_some());
        assert_accounted(&core);

        core.gc_unpin_network_values(checkpoint);
        core.child_process_task_in_flight_bytes = 0;
        core.child_process_handles
            .insert(child, "native-handle".to_string());
        core.sync_estimated_memory_bytes().expect("account handle");
        core.collect_garbage();
        assert!(core.heap.get(child.0 as usize).is_some());
        assert!(
            streams
                .iter()
                .all(|id| core.heap.get(id.0 as usize).is_some())
        );
        assert!(core.heap.is_reclaimed(payload.0 as usize));
        assert_accounted(&core);

        core.child_process_handles.clear();
        core.sync_estimated_memory_bytes().expect("release handle");
        core.collect_garbage();
        assert!(core.heap.is_reclaimed(child.0 as usize));
        assert!(core.child_process_streams.is_empty());
        assert_accounted(&core);
    }

    #[test]
    fn unreachable_completed_process_state_stays_bounded_across_repeated_batches() {
        let mut core = process_core();
        for _ in 0..16 {
            for _ in 0..32 {
                let (child, _) = child_and_streams(&mut core);
                let stdout = core.alloc_object_with_prototype(None).expect("output");
                let mut state = InterpreterCore::pending_child_process_state();
                state.settled = true;
                state.stdout = Value::Object(stdout);
                state.stdout_has_data = true;
                state.scheduled_events.insert("close".to_string());
                core.replace_child_process_state(child, state)
                    .expect("state");
            }
            core.collect_garbage();
            assert!(core.completed_child_processes.is_empty());
            assert!(core.child_process_streams.is_empty());
            assert_accounted(&core);
        }
        assert!(core.gc_stats().reclaimed_objects >= 16 * 32 * 5);
        assert_eq!(core.gc_stats().skipped_collections, 0);
    }

    #[test]
    fn completed_child_listener_cycles_are_weak_but_escaped_once_wrappers_keep_their_target() {
        let mut core = process_core();
        let (child, streams) = child_and_streams(&mut core);
        let mut state = InterpreterCore::pending_child_process_state();
        state.settled = true;
        core.replace_child_process_state(child, state)
            .expect("state");
        let callback = core.closures.len() as u32;
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![ScopeFrame::from_bindings(BTreeMap::from([(
                "child".to_string(),
                ScopeBinding::with_state(BindingKind::Const, Value::Object(child), true),
            )]))],
        });
        core.register_event_listener(child, "close", callback);
        let (wrapper_value, wrapper, _) = core
            .create_event_once_wrapper(streams[0], "data", Value::Closure(callback), None)
            .expect("once wrapper");
        core.insert_event_listener(
            streams[0],
            "data",
            EventListenerRecord {
                listener: wrapper_value.clone(),
                once: true,
            },
            false,
        )
        .expect("once listener");
        // Only the wrapper's private state retains its original listener.
        core.set_object_property(wrapper, "listener".to_string(), Value::Undefined)
            .expect("replace public listener");
        core.write_reg(0, Value::Object(child)).expect("child root");
        core.write_reg(1, Value::str("never")).expect("event name");
        core.register_event_promise_once(RegRange { start: 0, count: 2 })
            .expect("promise-backed waiter");
        core.write_reg(1, Value::Undefined)
            .expect("clear event name");
        core.sync_estimated_memory_bytes().expect("account fixture");
        core.collect_garbage();
        assert!(core.closures.get(callback as usize).is_some());
        assert!(!core.event_listeners.is_empty());
        assert!(!core.event_promise_waiters.is_empty());
        assert_accounted(&core);

        core.write_reg(0, wrapper_value)
            .expect("only escaped wrapper remains");
        core.collect_garbage();
        assert!(core.heap.get(child.0 as usize).is_some());
        assert!(core.closures.get(callback as usize).is_some());
        assert_accounted(&core);

        core.write_reg(0, Value::Undefined)
            .expect("release escaped wrapper");
        core.collect_garbage();
        assert!(core.heap.is_reclaimed(child.0 as usize));
        assert!(core.heap.is_reclaimed(wrapper.0 as usize));
        assert!(core.closures.get(callback as usize).is_none());
        assert!(core.completed_child_processes.is_empty());
        assert!(core.child_process_streams.is_empty());
        assert!(core.event_listeners.is_empty());
        assert!(core.event_once_wrappers.is_empty());
        assert!(core.event_promise_waiters.is_empty());
        assert_accounted(&core);
    }
}
