#![no_std]
#![no_main]

use core::cell::RefCell;

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::{
    join::join,
    select::{Either, select},
};
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, PIO0};
use embassy_rp::pio::InterruptHandler;
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_rp::{bind_interrupts, dma, peripherals};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
use embassy_usb::{Builder, Config};
use manekey::boundary::arm_gateway::ArmGatewayBackend;
use manekey::boundary::ble_bond_gateway::ArmBleBondGatewayStore;
use manekey::ctaphid::descriptor::{
    CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE, REPORT_SIZE_U8, REPORT_SIZE_U16,
};
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
use manekey::security::layout;
use manekey::transport::ble::{
    BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler, BleFidoProtocol, FidoBleProfile,
    StoredBleBond, StoredBleSecurityLevel,
};
use manekey::transport::usb::embassy::HidTransport;
use static_cell::StaticCell;
use trouble_host::prelude::*;

include!("tz_nonsecure_pre_init.rs");

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => UsbInterruptHandler<peripherals::USB>;
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
    #[cfg(not(feature = "rp2350-cyw43-polling"))]
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>, dma::InterruptHandler<DMA_CH1>;
});

include!("../ble/pico_cyw43_ble_common.rs");

const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);
const SECURITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
type GatewayArbiter = IngressArbiter<ArmGatewayBackend>;
type SharedArbiter = Mutex<ThreadModeRawMutex, RefCell<GatewayArbiter>>;
#[cfg(feature = "trustzone-multi-ingress-nonsecure")]
type InternalUart = manekey_rp::platform::rp2350::nonsecure_uart::NonsecureUart;
const FIDO_PENDING_POLL_MS: u64 = 100;
fn update_stack_watermark() {}
#[cfg(feature = "trustzone-multi-ingress-nonsecure")]
#[path = "../rp_internal_uart.rs"]
mod uart;
#[path = "../ble/pico_cyw43_multi_transport_usb.rs"]
mod usb;

struct SharedBleFrontend {
    protocol: BleFidoProtocol,
    arbiter: &'static SharedArbiter,
}

impl SharedBleFrontend {
    const fn new(arbiter: &'static SharedArbiter) -> Self {
        Self {
            protocol: BleFidoProtocol::new(BLE_PACKET_LEN),
            arbiter,
        }
    }
}

impl BleFidoProfileHandler for SharedBleFrontend {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            self.protocol.handle_write_with_backend::<MAX_FRAGMENT>(
                fragment,
                sink,
                &mut arbiter.bind(BLE_INGRESS),
            )
        })
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            self.protocol
                .poll_with_backend::<MAX_FRAGMENT>(sink, &mut arbiter.bind(BLE_INGRESS))
        })
    }

    fn on_disconnect(&mut self) {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            self.protocol
                .disconnect_with_backend(&mut arbiter.bind(BLE_INGRESS));
        });
    }
}

fn stored_from_trouble(bond: &trouble_host::BondInformation) -> StoredBleBond {
    let security_level = match bond.security_level {
        SecurityLevel::NoEncryption => StoredBleSecurityLevel::NoEncryption,
        SecurityLevel::Encrypted => StoredBleSecurityLevel::Encrypted,
        SecurityLevel::EncryptedAuthenticated => StoredBleSecurityLevel::EncryptedAuthenticated,
    };
    StoredBleBond {
        ltk: bond.ltk.to_le_bytes(),
        bd_addr: bond.identity.addr.addr.into_inner(),
        bd_addr_kind: bond.identity.addr.kind.as_raw(),
        irk: bond.identity.irk.map(|irk| irk.to_le_bytes()),
        is_bonded: bond.is_bonded,
        security_level,
    }
}

fn stored_to_trouble(bond: StoredBleBond) -> trouble_host::BondInformation {
    let security_level = match bond.security_level {
        StoredBleSecurityLevel::NoEncryption => SecurityLevel::NoEncryption,
        StoredBleSecurityLevel::Encrypted => SecurityLevel::Encrypted,
        StoredBleSecurityLevel::EncryptedAuthenticated => SecurityLevel::EncryptedAuthenticated,
    };
    trouble_host::BondInformation::new(
        trouble_host::Identity {
            addr: Address::new(AddrKind::new(bond.bd_addr_kind), BdAddr::new(bond.bd_addr)),
            irk: bond
                .irk
                .and_then(trouble_host::IdentityResolvingKey::from_le_bytes),
        },
        trouble_host::LongTermKey::from_le_bytes(bond.ltk),
        security_level,
        bond.is_bonded,
    )
}

#[embassy_executor::main]
/// Enter only after matching Secure gateway, clock/reset, memory, peripheral and IRQ attribution is complete.
/// Single-core thread-mode arbiter only; reserve radio/USB/UART ownership and delegated DMA buffers.
async fn main(spawner: Spawner) {
    unsafe { embassy_rp::time_driver::init() };

    let gateway = unsafe { ArmGatewayBackend::new(layout::SECURE_GATEWAY_ADDRESS) };
    static ARBITER: StaticCell<SharedArbiter> = StaticCell::new();
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(gateway))));

    #[cfg(not(feature = "trustzone-multi-ingress-nonsecure"))]
    {
        let usb = unsafe { peripherals::USB::steal() };
        let driver = Driver::new(usb, Irqs);
        let identity = CtaphidUsbDeviceInfo::new("Pico 2 W TrustZone USB + BLE", "tz-usb-ble");
        let mut config = Config::new(identity.vendor_id, identity.product_id);
        config.manufacturer = Some(identity.manufacturer);
        config.product = Some(identity.product);
        config.serial_number = identity.serial_number;
        config.max_power = 100;
        config.max_packet_size_0 = REPORT_SIZE_U8;
        static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; REPORT_SIZE]> = StaticCell::new();
        static HID_STATE: StaticCell<State> = StaticCell::new();
        let mut builder = Builder::new(
            driver,
            config,
            CONFIG_DESCRIPTOR.init([0; 256]),
            BOS_DESCRIPTOR.init([0; 256]),
            MSOS_DESCRIPTOR.init([0; 256]),
            CONTROL_BUF.init([0; REPORT_SIZE]),
        );
        let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
            &mut builder,
            HID_STATE.init(State::new()),
            embassy_usb::class::hid::Config {
                hid_subclass: HidSubclass::No,
                hid_boot_protocol: HidBootProtocol::None,
                poll_ms: identity.poll_ms,
                max_packet_size: REPORT_SIZE_U16,
                request_handler: None,
                report_descriptor: REPORT_DESCRIPTOR,
            },
        );
        spawner.spawn(usb_task(builder.build()).unwrap());
        spawner.spawn(usb::multi_usb_frontend_task(HidTransport::new(hid), arbiter).unwrap());
    }
    #[cfg(feature = "trustzone-multi-ingress-nonsecure")]
    {
        let device = usb::build_usb(Driver::new(unsafe { peripherals::USB::steal() }, Irqs));
        spawner.spawn(usb::multi_usb_device_task(device.device).unwrap());
        spawner.spawn(usb::multi_usb_frontend_task(device.hid, arbiter).unwrap());
        #[cfg(feature = "usb-ccid-experimental")]
        spawner.spawn(usb::multi_ccid_frontend_task(device.ccid, arbiter).unwrap());
        let link = unsafe { InternalUart::from_secure_handoff() };
        spawner.spawn(uart::multi_internal_task(link, arbiter).unwrap());
    }

    let (bt_device, control) = init_cyw43_bluetooth(
        &spawner,
        unsafe { peripherals::PIN_23::steal() },
        unsafe { peripherals::PIN_25::steal() },
        unsafe { peripherals::PIO0::steal() },
        unsafe { peripherals::PIN_24::steal() },
        unsafe { peripherals::PIN_29::steal() },
        unsafe { peripherals::DMA_CH0::steal() },
        unsafe { peripherals::DMA_CH1::steal() },
    )
    .await;

    #[cfg(feature = "trustzone-cyw43-ui")]
    let control = {
        spawner.spawn(cyw43_board_ui_task(control).unwrap());
    };
    run_ble(
        ExternalController::<_, 10>::new(bt_device),
        control,
        SharedBleFrontend::new(arbiter),
    )
    .await;
}

#[embassy_executor::task]
async fn usb_task(mut usb: embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>) {
    usb.run().await;
}

/// Sole BLE host/controller owner; transport bond keys are materialized in NS memory despite Secure Flash storage.
async fn run_ble<C: Controller>(
    controller: C,
    mut control: StatusLedControl,
    mut fido: SharedBleFrontend,
) -> ! {
    let profile = FidoBleProfile::manekey();
    let mut resources: HostResources<C, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(profile.address))
        .set_io_capabilities(IoCapabilities::NoInputNoOutput);
    let host = stack.build();

    let mut bond_store = unsafe { ArmBleBondGatewayStore::new(layout::BLE_BOND_GATEWAY_ADDRESS) };
    bond_store.load_bonds(|bond| {
        let _ = host.add_bond_information(stored_to_trouble(bond));
    });
    let runner = host.runner();
    let mut peripheral = host.peripheral();
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: fido_ble_device_name(&profile),
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();
    let admission = BleBondAdmission::from_bonded_only(cfg!(feature = "tz-ble-bonded-only"));

    let _ = join(ble_runner(runner), async {
        loop {
            match advertise(&mut peripheral, &server, &profile).await {
                Ok(conn) => {
                    let raw = conn.raw();
                    let _ = raw.set_bondable(admission.permits_new_bond());
                    if !admission.permits_peer(raw.is_bonded_peer()) {
                        raw.disconnect();
                        drop(conn);
                        Timer::after_millis(30).await;
                        continue;
                    }
                    let _ = secure_gatt_events(
                        &host,
                        &server,
                        &conn,
                        &mut fido,
                        &mut control,
                        &mut bond_store,
                        admission,
                    )
                    .await;
                    drop(conn);
                    Timer::after_millis(30).await;
                }
                Err(_) => {
                    Timer::after_secs(1).await;
                }
            }
        }
    })
    .await;
    unreachable!()
}

/// NS connection loop using Secure bond services; persistence failures are ignored, not pairing failures.
async fn secure_gatt_events<C: Controller, P: PacketPool, B: BleBondStore>(
    host: &trouble_host::Stack<'_, C, P>,
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, P>,
    fido: &mut SharedBleFrontend,
    control: &mut StatusLedControl,
    bonds: &mut B,
    admission: BleBondAdmission,
) -> Result<(), Error> {
    let deadline = Instant::now() + SECURITY_HANDSHAKE_TIMEOUT;
    let mut disconnect_requested = false;
    loop {
        match select(conn.next(), Timer::after_millis(100)).await {
            Either::First(GattConnectionEvent::Disconnected { .. }) => break,
            Either::First(GattConnectionEvent::PairingComplete { bond, .. }) => {
                if !admission.permits_new_bond() {
                    conn.raw().disconnect();
                    disconnect_requested = true;
                    continue;
                }
                if let Some(bond) = bond.as_ref() {
                    let _ = bonds.store_bond(stored_from_trouble(bond));
                }
            }
            Either::First(GattConnectionEvent::PairingFailed(_)) => {
                conn.raw().disconnect();
                disconnect_requested = true;
            }
            Either::First(GattConnectionEvent::BondLost) => {
                if admission.permits_new_bond() {
                    let _ = host.remove_bond_information(conn.raw().peer_identity());
                    let _ = bonds.clear_bonds();
                }
                conn.raw().disconnect();
                disconnect_requested = true;
            }
            Either::First(GattConnectionEvent::Gatt { event }) => {
                let mut sink = NotifySink::new();
                if let GattEvent::Write(write) = &event
                    && write.handle() == server.fido_service.control_point.handle
                {
                    write.with_data(|offset, data| {
                        let _ = manekey::transport::ble::handle_control_point_write_at_offset_and_drain::<BLE_PACKET_LEN>(
                            fido, offset, data, &mut sink, 0, || {},
                        );
                    });
                }
                if let Ok(reply) = event.accept() {
                    reply.send().await;
                }
                flush_notifications(conn, &server.fido_service.status, &mut sink, control).await;
            }
            Either::First(_) => {}
            Either::Second(()) => {
                if !conn.raw().is_connected() {
                    break;
                }
                if Instant::now() >= deadline
                    && !conn
                        .raw()
                        .security_level()
                        .is_ok_and(|level| level.encrypted())
                {
                    if !disconnect_requested {
                        conn.raw().disconnect();
                        disconnect_requested = true;
                    }
                    continue;
                }
                let mut sink = NotifySink::new();
                let _ = fido.poll_status::<BLE_PACKET_LEN>(&mut sink);
                flush_notifications(conn, &server.fido_service.status, &mut sink, control).await;
            }
        }
    }
    fido.on_disconnect();
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}
