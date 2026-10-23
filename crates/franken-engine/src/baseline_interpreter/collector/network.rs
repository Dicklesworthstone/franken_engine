//! Precise roots and weak owner tables for HTTP and loopback I/O (bd-9vouw.164).

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
