use core::cell::RefCell;
use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};
use manekey::frontend::ingress::IngressArbiter;

/// Cooperative executor only; NoopRawMutex does not exclude IRQ or other-core access.
pub type SharedArbiter<T> = Mutex<NoopRawMutex, RefCell<IngressArbiter<T>>>;
