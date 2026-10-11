// SPDX-License-Identifier: Apache-2.0

use super::PresenceStatus;

/// Request-scoped confirmation; the caller supplies a trusted UI and monotonic ticks.
/// Request identifiers are not authentication secrets.
pub struct ManualPresenceState {
    generation: u64,
    started: u64,
    timeout: u64,
    status: PresenceStatus,
}

impl ManualPresenceState {
    pub const fn new(timeout: u64) -> Self {
        Self {
            generation: 0,
            started: 0,
            timeout,
            status: PresenceStatus::TimedOut,
        }
    }

    pub fn begin_wait(&mut self, now: u64) -> Option<u64> {
        self.status = PresenceStatus::TimedOut;
        self.generation = self.generation.checked_add(1)?;
        self.started = now;
        self.status = PresenceStatus::Pending;
        Some(self.generation)
    }

    pub fn pending_request(&mut self, now: u64) -> Option<u64> {
        (self.poll(now) == PresenceStatus::Pending).then_some(self.generation)
    }

    pub fn confirm(&mut self, request: u64, now: u64) -> bool {
        if self.poll(now) != PresenceStatus::Pending || request != self.generation {
            return false;
        }
        self.status = PresenceStatus::Confirmed;
        true
    }

    pub fn poll(&mut self, now: u64) -> PresenceStatus {
        if self.status == PresenceStatus::Pending
            && (now < self.started || now - self.started >= self.timeout)
        {
            self.status = PresenceStatus::TimedOut;
        }
        self.status
    }

    pub fn cancel(&mut self) {
        self.status = PresenceStatus::TimedOut;
    }
}
