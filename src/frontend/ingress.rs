use core::cell::Cell;

use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IngressKind {
    UsbHid = 1,
    Ble = 2,
    Nfc = 3,
    Internal = 4,
    UsbCcid = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Logical routing identity, not peer authentication or a security principal.
pub struct IngressId {
    kind: IngressKind,
    instance: u8,
}

impl IngressId {
    pub const fn new(kind: IngressKind, instance: u8) -> Self {
        Self { kind, instance }
    }

    pub const fn kind(self) -> IngressKind {
        self.kind
    }

    pub const fn instance(self) -> u8 {
        self.instance
    }
}

/// Serialized ownership of one trusted operation across frontends; callers provide exclusion.
pub struct IngressArbiter<T: TrustedBackend> {
    trusted: T,
    owner: Cell<Option<IngressId>>,
}

impl<T: TrustedBackend> IngressArbiter<T> {
    pub const fn new(trusted: T) -> Self {
        Self {
            trusted,
            owner: Cell::new(None),
        }
    }

    pub const fn owner(&self) -> Option<IngressId> {
        self.owner.get()
    }

    pub fn is_busy(&self) -> bool {
        let trusted_busy = self.trusted.is_busy();
        if !trusted_busy {
            self.owner.set(None);
        }
        self.owner.get().is_some() || trusted_busy
    }

    pub fn is_owned_by(&self, ingress: IngressId) -> bool {
        self.owner.get() == Some(ingress)
    }

    pub fn submit_cbor<'a>(&'a mut self, ingress: IngressId, request: &[u8]) -> TrustedResult<'a> {
        if self.owner.get().is_some() || self.trusted.is_busy() {
            return TrustedResult::Busy;
        }
        match self.trusted.submit_cbor(request) {
            TrustedResult::UserPresencePending => {
                self.owner.set(Some(ingress));
                TrustedResult::UserPresencePending
            }
            result => result,
        }
    }

    pub fn submit_u2f<'a>(&'a mut self, ingress: IngressId, request: &[u8]) -> TrustedResult<'a> {
        if self.owner.get().is_some() || self.trusted.is_busy() {
            return TrustedResult::Busy;
        }
        match self.trusted.submit_u2f(request) {
            TrustedResult::UserPresencePending => {
                self.owner.set(Some(ingress));
                TrustedResult::UserPresencePending
            }
            result => result,
        }
    }

    pub fn poll<'a>(&'a mut self, ingress: IngressId) -> Option<TrustedResult<'a>> {
        if self.owner.get() != Some(ingress) {
            return None;
        }
        match self.trusted.poll() {
            None => None,
            Some(TrustedResult::Response(data)) => {
                self.owner.set(None);
                Some(TrustedResult::Response(data))
            }
            Some(TrustedResult::InvalidRequest) => {
                self.owner.set(None);
                Some(TrustedResult::InvalidRequest)
            }
            Some(result) => Some(result),
        }
    }

    /// Requests cancellation; acceptance does not imply asynchronous completion.
    pub fn cancel(&mut self, ingress: IngressId) -> bool {
        if self.owner.get() != Some(ingress) {
            return false;
        }
        let accepted = self.trusted.cancel();
        if accepted && !self.trusted.is_busy() {
            self.owner.set(None);
        }
        accepted
    }

    pub fn finish_cancel(&mut self, ingress: IngressId) -> bool {
        if self.owner.get() != Some(ingress) || self.trusted.is_busy() {
            return false;
        }
        self.owner.set(None);
        true
    }

    pub fn into_inner(self) -> T {
        self.trusted
    }

    pub fn bind(&mut self, ingress: IngressId) -> IngressBackend<'_, T> {
        IngressBackend {
            arbiter: self,
            ingress,
        }
    }
}

pub struct IngressBackend<'a, T: TrustedBackend> {
    arbiter: &'a mut IngressArbiter<T>,
    ingress: IngressId,
}

impl<T: TrustedBackend> TrustedBackend for IngressBackend<'_, T> {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        self.arbiter.submit_cbor(self.ingress, request)
    }

    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        self.arbiter.submit_u2f(self.ingress, request)
    }

    fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>> {
        self.arbiter.poll(self.ingress)
    }

    fn cancel(&mut self) -> bool {
        self.arbiter.cancel(self.ingress)
    }

    fn is_busy(&self) -> bool {
        self.arbiter.is_busy()
    }
}
