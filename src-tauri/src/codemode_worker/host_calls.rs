use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::downstream::{CancelContext, CancelRegistry};

/// Cancellation owned by a script run, separate from its upstream request.
/// Stopping host work must not suppress the script's error response to a client.
#[derive(Clone, Default)]
pub struct HostCalls(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    registry: CancelRegistry,
    next: u64,
    active: HashSet<String>,
    stopped: bool,
}

pub struct HostCall {
    owner: HostCalls,
    id: String,
    pub context: CancelContext,
}

impl HostCalls {
    pub fn start(&self) -> HostCall {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = state.next.to_string();
        state.next += 1;
        state.registry.begin_client_request(id.clone());
        state.active.insert(id.clone());
        if state.stopped {
            state.registry.cancel(&id, Some("code mode worker stopped"));
        }
        HostCall {
            owner: self.clone(),
            context: state.registry.context(id.clone()),
            id,
        }
    }

    pub fn stop(&self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.stopped = true;
        for id in &state.active {
            state.registry.cancel(id, Some("code mode worker stopped"));
        }
    }
}

impl Drop for HostCall {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.remove(&self.id);
        state.registry.finish_client_request(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_a_run_cancels_every_host_and_prevents_late_dispatch() {
        let calls = HostCalls::default();
        let first = calls.start();
        let second = calls.start();
        assert!(!first.context.is_cancelled());
        calls.stop();
        assert!(first.context.is_cancelled());
        assert!(second.context.is_cancelled());
        assert!(calls.start().context.is_cancelled());
    }
}
