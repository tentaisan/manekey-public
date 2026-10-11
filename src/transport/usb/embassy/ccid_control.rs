use core::cell::{Cell, RefCell};
use core::mem::MaybeUninit;

use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_usb::control::{OutResponse, Recipient, Request, RequestType};
use embassy_usb::driver::Driver;
use embassy_usb::types::InterfaceNumber;
use embassy_usb::{Builder, Handler};

use crate::transport::usb::ccid_control::CcidAbortControl;

pub struct CcidUsbState<'d> {
    control: MaybeUninit<CcidControl<'d>>,
    shared: CcidControlShared,
}

impl<'d> Default for CcidUsbState<'d> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d> CcidUsbState<'d> {
    pub const fn new() -> Self {
        Self {
            control: MaybeUninit::uninit(),
            shared: CcidControlShared::new(),
        }
    }

    pub(super) fn register<D: Driver<'d>>(
        &'d mut self,
        builder: &mut Builder<'d, D>,
        interface: InterfaceNumber,
    ) -> &'d CcidControlShared {
        let control = self.control.write(CcidControl {
            interface,
            shared: &self.shared,
        });
        builder.handler(control);
        &self.shared
    }
}

struct CcidControl<'d> {
    interface: InterfaceNumber,
    shared: &'d CcidControlShared,
}

pub(super) struct CcidControlShared {
    abort: Mutex<CriticalSectionRawMutex, RefCell<CcidAbortControl>>,
    reset_generation: Mutex<CriticalSectionRawMutex, Cell<u32>>,
}

impl CcidControlShared {
    const fn new() -> Self {
        Self {
            abort: Mutex::new(RefCell::new(CcidAbortControl::new())),
            reset_generation: Mutex::new(Cell::new(0)),
        }
    }

    pub(super) fn take_abort(&self) -> Option<(u8, u8)> {
        self.abort.lock(|abort| abort.borrow_mut().take())
    }

    pub(super) fn reset_generation(&self) -> u32 {
        self.reset_generation.lock(Cell::get)
    }

    fn reset(&self) {
        self.abort.lock(|abort| abort.borrow_mut().reset());
        self.reset_generation
            .lock(|generation| generation.set(generation.get().wrapping_add(1)));
    }
}

impl Handler for CcidControl<'_> {
    fn reset(&mut self) {
        self.shared.reset();
    }

    fn control_out(&mut self, req: Request, data: &[u8]) -> Option<OutResponse> {
        if (req.request_type, req.recipient, req.index)
            != (
                RequestType::Class,
                Recipient::Interface,
                self.interface.0 as u16,
            )
        {
            return None;
        }
        Some(
            if self.shared.abort.lock(|abort| {
                abort
                    .borrow_mut()
                    .request(req.request, req.value, req.length, data)
            }) {
                OutResponse::Accepted
            } else {
                OutResponse::Rejected
            },
        )
    }
}
