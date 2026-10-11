/* USB endpoint/DPRAM portions derived from rp-rs/rp-hal, rp235x-hal/src/usb.rs.
 * Comparison snapshot: fa430d279b8f185769fe2e5e9aca0e57290acd1f (rp235x-hal 0.4.0).
 * Copyright (c) 2021-2024 The rp-rs Developers; MIT OR Apache-2.0.
 * Original terms are retained in RP NOTICE and LICENSE-LEGACY-*.
 * Modified for single-owner polling, PMP handoff and DPRAM allocation bounds.
 */

use core::cell::UnsafeCell;

#[cfg(not(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental"))]
use rp235x_hal::pac;
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use rp235x_pac as pac;
use usb_device::{
    Result as UsbResult, UsbDirection, UsbError,
    bus::{PollResult, UsbBus as UsbBusTrait},
    endpoint::{EndpointAddress, EndpointType},
};

fn ep_addr_to_ep_buf_ctrl_idx(ep_addr: EndpointAddress) -> usize {
    ep_addr.index() * 2 + usize::from(!ep_addr.is_in())
}

fn usb_delay() {
    for _ in 0..32 {
        core::hint::spin_loop();
    }
}

#[derive(Clone, Copy, Debug)]
struct Endpoint {
    ep_type: EndpointType,
    max_packet_size: u16,
    buffer_offset: u16,
}

impl Endpoint {
    unsafe fn get_buf_parts(&self) -> (*mut u8, usize) {
        const DPRAM_BASE: *mut u8 = pac::USB_DPRAM::ptr() as *mut u8;
        if self.ep_type == EndpointType::Control {
            (
                unsafe { DPRAM_BASE.add(0x100) },
                self.max_packet_size as usize,
            )
        } else {
            (
                unsafe { DPRAM_BASE.add(0x180 + (self.buffer_offset * 64) as usize) },
                self.max_packet_size as usize,
            )
        }
    }

    fn get_buf(&self) -> &[u8] {
        unsafe {
            let (base, len) = self.get_buf_parts();
            core::slice::from_raw_parts(base as *const _, len)
        }
    }

    fn get_buf_mut(&mut self) -> &mut [u8] {
        unsafe {
            let (base, len) = self.get_buf_parts();
            core::slice::from_raw_parts_mut(base, len)
        }
    }
}

struct Inner {
    in_endpoints: [Option<Endpoint>; 16],
    out_endpoints: [Option<Endpoint>; 16],
    next_offset: u16,
    read_setup: bool,
}

impl Inner {
    const fn new() -> Self {
        Self {
            in_endpoints: [None; 16],
            out_endpoints: [None; 16],
            next_offset: 0,
            read_setup: false,
        }
    }

    fn usb() -> &'static pac::usb::RegisterBlock {
        unsafe { &*pac::USB::ptr() }
    }

    fn dpram() -> &'static pac::usb_dpram::RegisterBlock {
        unsafe { &*pac::USB_DPRAM::ptr() }
    }

    fn ep_allocate(
        &mut self,
        ep_addr: Option<EndpointAddress>,
        ep_dir: UsbDirection,
        ep_type: EndpointType,
        max_packet_size: u16,
    ) -> UsbResult<EndpointAddress> {
        let ep_addr = ep_addr
            .or_else(|| {
                let eps = if ep_dir == UsbDirection::In {
                    self.in_endpoints.iter()
                } else {
                    self.out_endpoints.iter()
                };
                let mut iter = eps.enumerate();
                if ep_type != EndpointType::Control {
                    iter.next();
                }
                iter.find(|(_, ep)| ep.is_none())
                    .map(|(index, _)| EndpointAddress::from_parts(index, ep_dir))
            })
            .ok_or(UsbError::EndpointOverflow)?;

        let is_ep0 = ep_addr.index() == 0;
        let is_ctrl_ep = ep_type == EndpointType::Control;
        if !(is_ep0 ^ !is_ctrl_ep) {
            return Err(UsbError::Unsupported);
        }

        let eps = if ep_addr.is_in() {
            &mut self.in_endpoints
        } else {
            &mut self.out_endpoints
        };
        let maybe_ep = eps
            .get_mut(ep_addr.index())
            .ok_or(UsbError::EndpointOverflow)?;
        if maybe_ep.is_some() {
            return Err(UsbError::InvalidEndpoint);
        }

        if (!matches!(ep_type, EndpointType::Isochronous { .. }) && max_packet_size > 64)
            || max_packet_size > 1023
        {
            return Err(UsbError::Unsupported);
        }

        if ep_addr.index() == 0 {
            *maybe_ep = Some(Endpoint {
                ep_type,
                max_packet_size,
                buffer_offset: 0,
            });
        } else {
            let aligned_size = max_packet_size.div_ceil(64);
            if (self.next_offset + aligned_size) > ((4096 - 0x180) / 64) {
                return Err(UsbError::EndpointMemoryOverflow);
            }

            let buffer_offset = self.next_offset;
            self.next_offset += aligned_size;
            *maybe_ep = Some(Endpoint {
                ep_type,
                max_packet_size,
                buffer_offset,
            });
        }

        Ok(ep_addr)
    }

    fn ep_reset_all(&mut self) {
        let usb = Self::usb();
        let dpram = Self::dpram();

        usb.sie_ctrl().modify(|_, w| w.ep0_int_1buf().set_bit());
        dpram.ep_buffer_control(0).write(|w| w.pid_0().set_bit());
        dpram.ep_buffer_control(1).write(|w| w.pid_0().set_bit());
        usb_delay();
        dpram
            .ep_buffer_control(1)
            .write(|w| w.available_0().set_bit());

        for ep_index in 1..16 {
            if let Some(ep) = self.in_endpoints[ep_index] {
                self.configure_endpoint(ep_index, UsbDirection::In, ep);
            }
            if let Some(ep) = self.out_endpoints[ep_index] {
                self.configure_endpoint(ep_index, UsbDirection::Out, ep);
            }
        }
    }

    fn configure_endpoint(&self, ep_index: usize, direction: UsbDirection, ep: Endpoint) {
        use pac::usb_dpram::ep_control::ENDPOINT_TYPE_A;

        let dpram = Self::dpram();
        let ep_type = match ep.ep_type {
            EndpointType::Bulk => ENDPOINT_TYPE_A::BULK,
            EndpointType::Isochronous { .. } => ENDPOINT_TYPE_A::ISOCHRONOUS,
            EndpointType::Control => ENDPOINT_TYPE_A::CONTROL,
            EndpointType::Interrupt => ENDPOINT_TYPE_A::INTERRUPT,
        };
        let control_index = (ep_index - 1) * 2 + usize::from(direction == UsbDirection::Out);

        dpram.ep_control(control_index).modify(|_, w| unsafe {
            w.endpoint_type().variant(ep_type);
            w.interrupt_per_buff().set_bit();
            w.enable().set_bit();
            w.buffer_address().bits(0x180 + (ep.buffer_offset << 6))
        });

        let buf_index = ep_index * 2 + usize::from(direction == UsbDirection::Out);
        let buf_control = dpram.ep_buffer_control(buf_index);
        if direction == UsbDirection::In {
            buf_control.write(|w| w.pid_0().set_bit());
        } else {
            buf_control.write(|w| unsafe {
                w.pid_0().clear_bit();
                w.length_0().bits(ep.max_packet_size)
            });
            usb_delay();
            buf_control.modify(|_, w| w.available_0().set_bit());
        }
    }

    fn ep_write(&mut self, ep_addr: EndpointAddress, buf: &[u8]) -> UsbResult<usize> {
        let index = ep_addr.index();
        let ep = self
            .in_endpoints
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(UsbError::InvalidEndpoint)?;

        let buf_control = Self::dpram().ep_buffer_control(index * 2);
        if buf_control.read().available_0().bit_is_set() {
            return Err(UsbError::WouldBlock);
        }

        let ep_buf = ep.get_buf_mut();
        if ep_buf.len() < buf.len() {
            return Err(UsbError::BufferOverflow);
        }
        ep_buf[..buf.len()].copy_from_slice(buf);

        buf_control.modify(|r, w| unsafe {
            w.length_0().bits(buf.len() as u16);
            w.full_0().set_bit();
            w.pid_0().bit(!r.pid_0().bit())
        });
        usb_delay();
        buf_control.modify(|_, w| w.available_0().set_bit());

        Ok(buf.len())
    }

    fn ep_read(&mut self, ep_addr: EndpointAddress, buf: &mut [u8]) -> UsbResult<usize> {
        let index = ep_addr.index();
        let ep = self
            .out_endpoints
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(UsbError::InvalidEndpoint)?;

        let usb = Self::usb();
        let dpram = Self::dpram();
        let buf_control = dpram.ep_buffer_control(index * 2 + 1);
        let buf_control_val = buf_control.read();

        if index == 0 && self.read_setup {
            let len = 8;
            let ep_buf =
                unsafe { core::slice::from_raw_parts(pac::USB_DPRAM::ptr() as *const u8, len) };
            if len > buf.len() {
                return Err(UsbError::BufferOverflow);
            }
            buf[..len].copy_from_slice(ep_buf);

            dpram
                .ep_buffer_control(0)
                .modify(|_, w| w.pid_0().clear_bit());
            usb.sie_status().write(|w| w.setup_rec().clear_bit_by_one());
            usb.buff_status().write(|w| unsafe { w.bits(2) });

            let is_in_request = (buf[0] & 0x80) == 0x80;
            let data_length = u16::from(buf[6]) | (u16::from(buf[7]) << 8);
            let expect_data_or_zlp = is_in_request || data_length != 0;

            buf_control.modify(|_, w| unsafe {
                w.length_0().bits(ep.max_packet_size);
                w.full_0().clear_bit();
                w.pid_0().set_bit()
            });
            usb_delay();
            buf_control.modify(|_, w| w.available_0().bit(expect_data_or_zlp));

            self.read_setup = false;
            Ok(len)
        } else {
            if buf_control_val.full_0().bit_is_clear() {
                return Err(UsbError::WouldBlock);
            }
            let len = buf_control_val.length_0().bits().into();
            if len > buf.len() {
                return Err(UsbError::BufferOverflow);
            }

            buf[..len].copy_from_slice(&ep.get_buf()[..len]);
            usb.buff_status()
                .write(|w| unsafe { w.bits(1 << (index * 2 + 1)) });

            buf_control.modify(|r, w| unsafe {
                w.length_0().bits(ep.max_packet_size);
                w.full_0().clear_bit();
                w.pid_0().bit(!r.pid_0().bit())
            });
            if index != 0 || len == ep.max_packet_size.into() {
                usb_delay();
                buf_control.modify(|_, w| w.available_0().set_bit());
            }
            Ok(len)
        }
    }
}

/// Single-owner polling USB bus; serialize every bus/class call and exclude other cores, USB IRQ handlers and DMA.
/// Sync is required by usb-device and does not provide a concurrent-access lock.
pub struct PmpUsbBus {
    inner: UnsafeCell<Inner>,
}

unsafe impl Sync for PmpUsbBus {}

impl PmpUsbBus {
    /// Initialize exclusively in M-mode before delegation; reset waits have no wall-clock timeout.
    pub fn prepare_hardware(
        ctrl_reg: pac::USB,
        ctrl_dpram: pac::USB_DPRAM,
        force_vbus_detect_bit: bool,
        resets: &mut pac::RESETS,
    ) {
        Self::initialize_hardware(ctrl_reg, ctrl_dpram, force_vbus_detect_bit, resets);
    }

    pub fn new(
        ctrl_reg: pac::USB,
        ctrl_dpram: pac::USB_DPRAM,
        force_vbus_detect_bit: bool,
        resets: &mut pac::RESETS,
    ) -> Self {
        Self::initialize_hardware(ctrl_reg, ctrl_dpram, force_vbus_detect_bit, resets);

        unsafe { Self::from_preinitialized() }
    }

    fn initialize_hardware(
        ctrl_reg: pac::USB,
        ctrl_dpram: pac::USB_DPRAM,
        force_vbus_detect_bit: bool,
        resets: &mut pac::RESETS,
    ) {
        resets.reset().modify(|_, w| w.usbctrl().set_bit());
        resets.reset().modify(|_, w| w.usbctrl().clear_bit());
        while resets.reset_done().read().usbctrl().bit_is_clear() {}

        unsafe {
            let raw_ctrl_reg =
                core::slice::from_raw_parts_mut(pac::USB::ptr() as *mut u32, 1 + 0x98 / 4);
            raw_ctrl_reg.fill(0);

            let raw_ctrl_dpram =
                core::slice::from_raw_parts_mut(pac::USB_DPRAM::ptr() as *mut u32, 1 + 0xfc / 4);
            raw_ctrl_dpram.fill(0);
        }

        ctrl_reg.usb_muxing().modify(|_, w| {
            w.to_phy().set_bit();
            w.softcon().set_bit()
        });

        if force_vbus_detect_bit {
            ctrl_reg.usb_pwr().modify(|_, w| {
                w.vbus_detect().set_bit();
                w.vbus_detect_override_en().set_bit()
            });
        }

        ctrl_reg.main_ctrl().modify(|_, w| {
            w.sim_timing().clear_bit();
            w.host_ndevice().clear_bit();
            w.controller_en().set_bit()
        });

        let _ = ctrl_dpram;
    }

    /// # Safety
    /// Hardware initialization and MMIO/DPRAM delegation must be complete; remain the sole non-reentrant polling owner.
    pub unsafe fn from_preinitialized() -> Self {
        Self {
            inner: UnsafeCell::new(Inner::new()),
        }
    }

    fn inner(&self) -> &mut Inner {
        unsafe { &mut *self.inner.get() }
    }

    /// Rearm an empty OUT buffer without toggling DATA PID; preserve exclusive bus access.
    pub fn ensure_out_endpoint_available(&self, ep_index: usize) {
        let Some(ep) = self.inner().out_endpoints.get(ep_index).copied().flatten() else {
            return;
        };
        let dpram = Inner::dpram();
        let buf_index = ep_index * 2 + 1;
        let buf_control = dpram.ep_buffer_control(buf_index);
        if buf_control.read().full_0().bit_is_set() {
            return;
        }
        buf_control.modify(|_, w| unsafe {
            w.length_0().bits(ep.max_packet_size);
            w.full_0().clear_bit()
        });
        usb_delay();
        buf_control.modify(|_, w| w.available_0().set_bit());
    }

    /// Clear pending IN completion only after the final report is accepted by the controller.
    pub fn clear_in_endpoint_complete(&self, ep_index: usize) {
        if self
            .inner()
            .in_endpoints
            .get(ep_index)
            .and_then(|ep| *ep)
            .is_none()
        {
            return;
        }
        let usb = Inner::usb();
        usb.buff_status()
            .write(|w| unsafe { w.bits(1 << (ep_index * 2)) });
    }
}

impl UsbBusTrait for PmpUsbBus {
    fn alloc_ep(
        &mut self,
        ep_dir: UsbDirection,
        ep_addr: Option<EndpointAddress>,
        ep_type: EndpointType,
        max_packet_size: u16,
        _interval: u8,
    ) -> UsbResult<EndpointAddress> {
        self.inner()
            .ep_allocate(ep_addr, ep_dir, ep_type, max_packet_size)
    }

    fn enable(&mut self) {
        let usb = Inner::usb();
        usb.inte().modify(|_, w| {
            w.buff_status()
                .set_bit()
                .bus_reset()
                .set_bit()
                .dev_resume_from_host()
                .set_bit()
                .dev_suspend()
                .set_bit()
                .setup_req()
                .set_bit()
        });
        usb.sie_ctrl().modify(|_, w| w.pullup_en().set_bit());
    }

    fn reset(&self) {
        let inner = self.inner();
        let usb = Inner::usb();

        usb.sie_status().write(|w| w.bus_reset().clear_bit_by_one());
        usb.buff_status().write(|w| unsafe { w.bits(0xffff_ffff) });

        inner.ep_reset_all();
        usb.addr_endp().reset();
    }

    fn set_device_address(&self, addr: u8) {
        let usb = Inner::usb();
        let dpram = Inner::dpram();
        usb.addr_endp()
            .modify(|_, w| unsafe { w.address().bits(addr & 0x7f) });
        dpram
            .ep_buffer_control(0)
            .modify(|_, w| w.pid_0().set_bit());
        dpram
            .ep_buffer_control(1)
            .modify(|_, w| w.pid_0().set_bit());
    }

    fn write(&self, ep_addr: EndpointAddress, buf: &[u8]) -> UsbResult<usize> {
        self.inner().ep_write(ep_addr, buf)
    }

    fn read(&self, ep_addr: EndpointAddress, buf: &mut [u8]) -> UsbResult<usize> {
        self.inner().ep_read(ep_addr, buf)
    }

    fn set_stalled(&self, ep_addr: EndpointAddress, stalled: bool) {
        let usb = Inner::usb();
        let dpram = Inner::dpram();

        if ep_addr.index() == 0 {
            usb.ep_stall_arm().modify(|_, w| {
                if ep_addr.is_in() {
                    w.ep0_in().bit(stalled)
                } else {
                    w.ep0_out().bit(stalled)
                }
            });
        }

        let index = ep_addr_to_ep_buf_ctrl_idx(ep_addr);
        dpram
            .ep_buffer_control(index)
            .modify(|_, w| w.stall().bit(stalled));
    }

    fn is_stalled(&self, ep_addr: EndpointAddress) -> bool {
        let index = ep_addr_to_ep_buf_ctrl_idx(ep_addr);
        Inner::dpram()
            .ep_buffer_control(index)
            .read()
            .stall()
            .bit_is_set()
    }

    fn suspend(&self) {}

    fn resume(&self) {}

    fn poll(&self) -> PollResult {
        let inner = self.inner();
        let usb = Inner::usb();

        let ints = usb.ints().read();
        let mut buff_status = usb.buff_status().read().bits();

        if ints.bus_reset().bit_is_set() {
            return PollResult::Reset;
        } else if buff_status == 0 && ints.setup_req().bit_is_clear() {
            if ints.dev_suspend().bit_is_set() {
                usb.sie_status().write(|w| w.suspended().clear_bit_by_one());
                return PollResult::Suspend;
            } else if ints.dev_resume_from_host().bit_is_set() {
                usb.sie_status().write(|w| w.resume().clear_bit_by_one());
                return PollResult::Resume;
            }
            return PollResult::None;
        }

        let (mut ep_out, mut ep_in_complete, mut ep_setup): (u16, u16, u16) = (0, 0, 0);
        usb.buff_status().write(|w| unsafe { w.bits(0x5555_5555) });

        for i in 0..32u32 {
            if buff_status == 0 {
                break;
            } else if (buff_status & 1) == 1 {
                let is_in = (i & 1) == 0;
                let ep_idx = i / 2;
                if is_in {
                    ep_in_complete |= 1 << ep_idx;
                } else {
                    ep_out |= 1 << ep_idx;
                }
            }
            buff_status >>= 1;
        }

        if ints.setup_req().bit_is_set() {
            Inner::dpram()
                .ep_buffer_control(0)
                .modify(|_, w| w.available_0().clear_bit());

            ep_setup |= 1;
            inner.read_setup = true;
        }

        PollResult::Data {
            ep_out,
            ep_in_complete,
            ep_setup,
        }
    }

    const QUIRK_SET_ADDRESS_BEFORE_STATUS: bool = false;
}
