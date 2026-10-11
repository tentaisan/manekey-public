use crate::{
    boundary::local_trusted_call::{SharedTrustedCallBackend, SharedTrustedCallState},
    ctaphid::trusted::TRUSTED_RESPONSE_MAX,
    frontend::{
        ccid::{CCID_RESPONSE_MAX, CcidFrontend},
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    security::trusted_status,
    transport::{boundary_link::CopyPacket, usb::ccid_bulk::CcidBulkAssembler},
};
type BulkPacket = CopyPacket<64>;
#[repr(C)]
/// Port-owned unprivileged frontend workspace; not a hardware permission configuration.
pub struct Workspace {
    pub call: SharedTrustedCallState,
    response: [u8; TRUSTED_RESPONSE_MAX + 32],
    hid: CtaphidReportFrontend,
    report: [u8; 64],
    ccid: CcidFrontend,
    ccid_request: CcidBulkAssembler<CCID_RESPONSE_MAX>,
    ccid_response: [u8; CCID_RESPONSE_MAX],
    ccid_packet: BulkPacket,
    #[cfg(feature = "privileged-ble-frontend")]
    ble: BleWorkspace,
}
#[cfg(feature = "privileged-ble-frontend")]
const BLE_RESPONSE_FRAGMENTS: usize = 1 + TRUSTED_RESPONSE_MAX.saturating_sub(61).div_ceil(63);
#[cfg(feature = "privileged-ble-frontend")]
struct BleWorkspace {
    frontend: crate::frontend::ble::BleFidoIngressFrontend,
    packet: crate::transport::ble::boundary_slots::BlePacket,
    sink: crate::transport::ble::BleFidoFragmentQueue<BLE_RESPONSE_FRAGMENTS, 64>,
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            call: SharedTrustedCallState::new(),
            response: [0; TRUSTED_RESPONSE_MAX + 32],
            hid: CtaphidReportFrontend::new(),
            report: [0; 64],
            ccid: CcidFrontend::new(0),
            ccid_request: CcidBulkAssembler::new(),
            ccid_response: [0; CCID_RESPONSE_MAX],
            ccid_packet: BulkPacket {
                len: 0,
                data: [0; 64],
            },
            #[cfg(feature = "privileged-ble-frontend")]
            ble: BleWorkspace {
                frontend: crate::frontend::ble::BleFidoIngressFrontend::new(
                    64,
                    IngressId::new(IngressKind::Ble, 0),
                ),
                packet: crate::transport::ble::boundary_slots::BlePacket::empty(),
                sink: crate::transport::ble::BleFidoFragmentQueue::new(),
            },
        }
    }
}
fn syscall<const N: u8>(arg0: u32, arg1: u32) -> u32 {
    let result;
    unsafe {
        core::arch::asm!("svc {n}", n = const N, inout("r0") arg0 => result, in("r1") arg1);
    }
    result
}

/// # Safety
/// Own the initialized U-readable/writable workspace and run on unprivileged PSP.
/// The port must implement the expected SVC ABI, validate/copy all arguments and exclude concurrent access.
pub unsafe fn run(workspace: &mut Workspace) -> ! {
    let backend = unsafe {
        SharedTrustedCallBackend::with_gate(
            &mut workspace.call,
            crate::boundary::arm_m_mpu::SvcTrustedCallGate,
        )
    };
    let mut arbiter = IngressArbiter::new(backend);
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let ingress = IngressId::new(IngressKind::UsbHid, 0);
    let mut generation = syscall::<10>(0, 0);
    let mut last_poll = syscall::<5>(0, 0);
    let mut ccid_pending = 0;
    let mut ccid_offset = 0;
    let mut ccid_poll = syscall::<5>(0, 0);
    #[cfg(feature = "privileged-ble-frontend")]
    let (mut ble_generation, mut ble_offset, mut ble_poll) = (syscall::<16>(0, 0), 0, last_poll);
    loop {
        let _ = frontend.poll_cancel(&mut arbiter);
        #[cfg(feature = "privileged-ble-frontend")]
        {
            use crate::transport::ble::{BleFidoProfileHandler, boundary_slots::BlePacket};
            let ble = &mut workspace.ble;
            let current = syscall::<16>(0, 0);
            if current != ble_generation {
                ble.frontend.bind(&mut arbiter).on_disconnect();
                ble.sink.clear();
                ble_offset = 0;
                ble_generation = current;
            }
            if ble.sink.fragments().count() == 0 {
                let _ = ble
                    .frontend
                    .bind(&mut arbiter)
                    .settle_disconnected_backend();
                if syscall::<17>(core::ptr::addr_of_mut!(ble.packet) as u32, ble_generation) != 0 {
                    if let Some(bytes) = ble.packet.bytes() {
                        let _ = ble
                            .frontend
                            .bind(&mut arbiter)
                            .handle_control_point_write::<64>(bytes, &mut ble.sink);
                    }
                } else {
                    let now = syscall::<5>(0, 0);
                    if now.wrapping_sub(ble_poll) >= 100 {
                        let _ = ble
                            .frontend
                            .bind(&mut arbiter)
                            .poll_status::<64>(&mut ble.sink);
                        ble_poll = now;
                    }
                }
            }
            if let Some(bytes) = ble.sink.fragments().nth(ble_offset) {
                ble.packet = BlePacket::from_slice(bytes).unwrap();
                if syscall::<18>(core::ptr::addr_of!(ble.packet) as u32, ble_generation)
                    == trusted_status::OK
                {
                    ble_offset += 1;
                }
            }
            if ble_offset != 0 && ble_offset == ble.sink.fragments().count() {
                ble_offset = 0;
                ble.sink.clear();
            }
        }
        {
            let current = syscall::<10>(0, 0);
            if current != generation {
                workspace.hid.on_link_lost(&mut arbiter, ingress);
                {
                    workspace.ccid.disconnect(&mut arbiter);
                    workspace.ccid_request.reset();
                    ccid_pending = 0;
                    ccid_offset = 0;
                }
                generation = current;
            }
            if workspace.hid.current_report().is_none()
                && syscall::<8>(workspace.report.as_mut_ptr() as u32, generation) == 64
            {
                workspace
                    .hid
                    .handle_report(&mut arbiter, ingress, workspace.report);
            }
            let now = syscall::<5>(0, 0);
            if workspace.hid.current_report().is_none() && now.wrapping_sub(last_poll) >= 100 {
                workspace.hid.poll(&mut arbiter, ingress);
                last_poll = now;
            }
            if let Some(report) = workspace.hid.current_report() {
                if syscall::<9>(report.as_ptr() as u32, generation) == trusted_status::OK {
                    workspace.hid.advance_report();
                }
            }
        }
        {
            let abort = syscall::<13>(0, 0);
            if abort != u32::MAX {
                workspace
                    .ccid
                    .begin_abort(&mut arbiter, abort as u8, (abort >> 8) as u8);
                ccid_pending = 0;
                ccid_offset = 0;
                workspace.ccid_request.reset();
            }
            if ccid_pending == 0 {
                let len = syscall::<11>(
                    core::ptr::addr_of_mut!(workspace.ccid_packet) as u32,
                    generation,
                );
                if len > 0 && len <= 65 {
                    if let Ok(Some(message)) = workspace
                        .ccid_request
                        .push(&workspace.ccid_packet.data[..(len - 1) as usize])
                    {
                        ccid_pending = workspace
                            .ccid
                            .handle_message(&mut arbiter, message, &mut workspace.ccid_response)
                            .unwrap_or(0);
                        workspace.ccid_request.reset();
                        ccid_offset = 0;
                    }
                } else {
                    let now = syscall::<5>(0, 0);
                    if now.wrapping_sub(ccid_poll) >= 100 {
                        ccid_pending = workspace
                            .ccid
                            .poll(&mut arbiter, &mut workspace.ccid_response)
                            .ok()
                            .flatten()
                            .unwrap_or(0);
                        ccid_poll = now;
                    }
                }
            }
            if ccid_pending != 0 {
                let end = (ccid_offset + 64).min(ccid_pending);
                let len = end - ccid_offset;
                workspace.ccid_packet.len = len as u32;
                workspace.ccid_packet.data[..len]
                    .copy_from_slice(&workspace.ccid_response[ccid_offset..end]);
                if syscall::<12>(
                    core::ptr::addr_of!(workspace.ccid_packet) as u32,
                    generation,
                ) == trusted_status::OK
                {
                    ccid_offset = end;
                    if len < 64 {
                        ccid_pending = 0;
                        ccid_offset = 0;
                    }
                }
            }
        }
        let byte = syscall::<1>(0, 0);
        if byte == u32::MAX {
            continue;
        }

        if byte == u32::MAX - 1 {
            frontend.disconnect(&mut arbiter);
            continue;
        }
        #[cfg(feature = "arm-m-maintenance")]
        if !frontend.is_receiving() && matches!(byte as u8, b'B' | b'R') {
            let _ = syscall::<3>(byte, 0);
            continue;
        }
        #[cfg(feature = "arm-m-maintenance")]
        if !frontend.is_receiving() && byte as u8 == b'?' {
            let _ = syscall::<4>(0, 0);
            continue;
        }
        match frontend.push_byte(&mut arbiter, byte as u8, &mut workspace.response) {
            Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                let _ = syscall::<2>(workspace.response.as_ptr() as u32, len as u32);
            }
            Err(_) => frontend.disconnect(&mut arbiter),
            _ => {}
        }
    }
}
