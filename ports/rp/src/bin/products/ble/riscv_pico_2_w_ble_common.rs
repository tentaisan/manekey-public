// PIO program derived from Embassy cyw43-pio; Copyright (c) Embassy project contributors.
// Underlying Pico SDK portions: Copyright (c) 2020 Raspberry Pi (Trading) Ltd.; BSD-3-Clause, see RP NOTICE.
// Upstream: https://github.com/embassy-rs/embassy/blob/0af1937a5ac77f52fea943b677088c38ef9e91c6/cyw43-pio/src/lib.rs
// Original program: MIT OR Apache-2.0; see vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
// Modified for HAL setup and numeric PIO branch targets.
// CYW43 initialization and advertising follow TrouBLE examples; Copyright (c) Embassy project contributors.
// Comparison snapshot: trouble-host b6043f576b482d8a4ecd7d2634df48cba20bd7ba; see RP NOTICE for source paths.
// Original portions: MIT OR Apache-2.0; modified for RISC-V polling and shared USB/Internal ingress.

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use core::cell::RefCell;

use cyw43::aligned_bytes;
extern crate cyw43_riscv as cyw43;

use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_time::Timer;
#[cfg(feature = "riscv-pico-2-w-ble-security")]
use embassy_time::{Duration, Instant};
use embedded_hal::digital::OutputPin;
use hal::Clock;
use hal::fugit::RateExtU32;
use hal::gpio::{FunctionPio0, OutputDriveStrength, OutputSlewRate, PinState};
use hal::pio::{PIOBuilder, PIOExt, PinDir, ShiftDirection};
#[cfg(feature = "riscv-pico-2-w-ble-security")]
use manekey::transport::ble::BleBondAdmission;
use manekey::transport::ble::{
    BleBondStore, BleFidoFragmentQueue, BleFidoProfileHandler, FidoBleProfile,
};
#[cfg(all(
    feature = "riscv-pico-2-w-ble-bonded-only",
    not(any(
        feature = "riscv-pico-2-w-ble-bond-flash",
        feature = "riscv-pico-2-w-ble-dual-core-bond-flash"
    ))
))]
compile_error!("RISC-V bonded-only requires a persistent BLE bond store");
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use manekey::ctaphid::{
    CtaphidProtocol, Response,
    channel::MAX_MESSAGE_SIZE,
    descriptor::{
        CtaphidUsbDeviceInfo, POLL_MS as CTAPHID_POLL_MS, REPORT_SIZE as CTAPHID_REPORT_SIZE,
    },
};
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
#[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
use manekey::transport::ble::BleFidoFrontend;
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use manekey::transport::ble::{BleFidoError, BleFidoFragmentSink, BleFidoProtocol};
#[cfg(feature = "riscv-pico-2-w-ble-security")]
use manekey::transport::ble::{StoredBleBond, StoredBleSecurityLevel};
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use manekey_rp::platform::rp2350::riscv_usb::CTAPHID_REPORT_DESCRIPTOR;
use manekey_rp::platform::rp2350::{riscv_cyw43_pio::RiscvCyw43PioSpi, riscv_embassy_time};
use panic_halt as _;
use rp235x_hal as hal;
use static_cell::StaticCell;
use trouble_host::prelude::*;
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use usb_device::{
    bus::UsbBusAllocator,
    class_prelude::UsbClass,
    device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid},
};
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
use usbd_hid::hid_class::HIDClass;

#[cfg(all(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-gpio15"))]
compile_error!("RISC-V Pico 2 W BLE must select either GPIO15 or BOOTSEL user presence");

#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

static WIFI_FW_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> =
    &cyw43::Aligned(*cyw43_firmware_riscv::CYW43_43439A0);
static WIFI_CLM_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> =
    &cyw43::Aligned(*cyw43_firmware_riscv::CYW43_43439A0_CLM);
static BT_FW_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> =
    &cyw43::Aligned(*cyw43_firmware_riscv::CYW43_43439A0_BTFW);
static NVRAM_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> = aligned_bytes!(env!(
    "MANEKEY_CYW43_NVRAM_VERIFIED",
    "Set MANEKEY_CYW43_NVRAM_FILE to the fixed upstream NVRAM file"
));

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;
const BLE_PACKET_LEN: usize = 64;
#[cfg(not(feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"))]
const MAX_NOTIFY_FRAGMENTS: usize = 20;
#[cfg(feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental")]
const MAX_NOTIFY_FRAGMENTS: usize = 66;
#[cfg(feature = "riscv-pico-2-w-ble-security")]
const BLE_SECURITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

type NotifySink = BleFidoFragmentQueue<MAX_NOTIFY_FRAGMENTS, BLE_PACKET_LEN>;

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);
#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
static MULTI_ARBITER: critical_section::Mutex<RefCell<Option<IngressArbiter<SelectedBleBackend>>>> =
    critical_section::Mutex::new(RefCell::new(None));

fn selected_transport_ids() -> &'static [&'static [u8]] {
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    return manekey::transport::USB_BLE_TRANSPORTS;
    #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
    manekey::transport::BLE_TRANSPORTS
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
struct SharedBleFrontend {
    protocol: BleFidoProtocol,
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
impl SharedBleFrontend {
    const fn new() -> Self {
        Self {
            protocol: BleFidoProtocol::new(BLE_PACKET_LEN),
        }
    }
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
impl BleFidoProfileHandler for SharedBleFrontend {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        critical_section::with(|cs| {
            let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
            let mut backend = slot.as_mut().unwrap().bind(BLE_INGRESS);
            self.protocol
                .handle_write_with_backend::<MAX_FRAGMENT>(fragment, sink, &mut backend)
        })
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        critical_section::with(|cs| {
            let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
            let mut backend = slot.as_mut().unwrap().bind(BLE_INGRESS);
            self.protocol
                .poll_with_backend::<MAX_FRAGMENT>(sink, &mut backend)
        })
    }

    fn on_disconnect(&mut self) {
        critical_section::with(|cs| {
            let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
            let mut backend = slot.as_mut().unwrap().bind(BLE_INGRESS);
            self.protocol.disconnect_with_backend(&mut backend);
        });
    }
}

#[cfg(feature = "riscv-pico-2-w-ble-security")]
fn stored_ble_bond_from_trouble(bond: &trouble_host::BondInformation) -> StoredBleBond {
    let mut bd_addr = [0; 6];
    bd_addr.copy_from_slice(&bond.identity.addr.addr.into_inner());
    let security_level = match bond.security_level {
        SecurityLevel::NoEncryption => StoredBleSecurityLevel::NoEncryption,
        SecurityLevel::Encrypted => StoredBleSecurityLevel::Encrypted,
        SecurityLevel::EncryptedAuthenticated => StoredBleSecurityLevel::EncryptedAuthenticated,
    };
    StoredBleBond {
        ltk: bond.ltk.to_le_bytes(),
        bd_addr,
        bd_addr_kind: bond.identity.addr.kind.as_raw(),
        irk: bond.identity.irk.map(|irk| irk.to_le_bytes()),
        is_bonded: bond.is_bonded,
        security_level,
    }
}

#[cfg(any(
    feature = "riscv-pico-2-w-ble-bond-flash",
    feature = "riscv-pico-2-w-ble-dual-core-bond-flash"
))]
fn stored_ble_bond_to_trouble(bond: StoredBleBond) -> trouble_host::BondInformation {
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

type ButtonPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio15,
    hal::gpio::FunctionSio<hal::gpio::SioInput>,
    hal::gpio::PullUp,
>;

#[cfg(not(feature = "riscv-pico-2-w-ble-security"))]
#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[cfg(not(feature = "riscv-pico-2-w-ble-security"))]
#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb", write)]
    control_point: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", notify)]
    status: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read, value = BLE_PACKET_LEN as u16)]
    control_point_length: u16,
    #[characteristic(uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb", read, write, value = manekey::transport::ble::FIDO2_SERVICE_REVISION_BIT)]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read, value = manekey::transport::ble::FIDO_SERVICE_REVISION)]
    service_revision: &'static str,
}

#[cfg(feature = "riscv-pico-2-w-ble-security")]
#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[cfg(feature = "riscv-pico-2-w-ble-security")]
#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(
        uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
        write,
        permissions(write = encrypted)
    )]
    control_point: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(
        uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb",
        notify,
        permissions(cccd = encrypted)
    )]
    status: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read, value = BLE_PACKET_LEN as u16)]
    control_point_length: u16,
    #[characteristic(uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb", read, write, value = manekey::transport::ble::FIDO2_SERVICE_REVISION_BIT)]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read, value = manekey::transport::ble::FIDO_SERVICE_REVISION)]
    service_revision: &'static str,
}

#[embassy_executor::task]
/// Initialize once with exclusive radio/PIO/UART ownership and the selected backend; no CPU isolation is implied.
async fn ble_runtime(
    spawner: Spawner,
    pio0: hal::pac::PIO0,
    mut psm: hal::pac::PSM,
    sio: hal::pac::SIO,
    io_bank0: hal::pac::IO_BANK0,
    pads_bank0: hal::pac::PADS_BANK0,
    uart0: hal::pac::UART0,
    trng: hal::pac::TRNG,
    timer: hal::timer::Timer<hal::timer::CopyableTimer0>,
    mut resets: hal::pac::RESETS,
    peripheral_clock_hz: u32,
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")] usb_hid: &'static mut HIDClass<
        'static,
        hal::usb::UsbBus,
    >,
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    usb_dev: &'static mut usb_device::device::UsbDevice<'static, hal::usb::UsbBus>,
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    usb_ccid: &'static mut manekey::transport::usb::polling_ccid::PollingCcid<
        'static,
        hal::usb::UsbBus,
    >,
) {
    let sio = hal::Sio::new(sio);
    #[cfg(feature = "riscv-client-pin-sha256")]
    {
        resets.reset().modify(|_, w| w.sha256().set_bit());
        resets.reset().modify(|_, w| w.sha256().clear_bit());
        while resets.reset_done().read().sha256().bit_is_clear() {}
    }
    let pins = hal::gpio::Pins::new(io_bank0, pads_bank0, sio.gpio_bank0, &mut resets);
    let mut fifo = sio.fifo;
    let uart_pins = (pins.gpio0.into_function(), pins.gpio1.into_function());
    let uart = hal::uart::UartPeripheral::new(uart0, uart_pins, &mut resets)
        .enable(
            hal::uart::UartConfig::new(
                115_200.Hz(),
                hal::uart::DataBits::Eight,
                None,
                hal::uart::StopBits::One,
            ),
            peripheral_clock_hz.Hz(),
        )
        .unwrap();
    uart.write_full_blocking(b"\r\nMANEKEY RP2350 RISC-V CYW43 BLE\r\n");
    #[cfg(feature = "riscv-client-pin-sha256")]
    {
        assert!(unsafe { manekey_rp::platform::rp2350::riscv_crypto::sha256_known_answers() });
        uart.write_full_blocking(b"SHA256 KAT passed; ClientPIN hardware backend\r\n");
    }

    let button = pins.gpio15.into_pull_up_input();
    uart.write_full_blocking(b"FIDO backend init\r\n");
    let (backend, mut product_runtime) =
        match selected_ble_backend(spawner, timer, button, trng, &mut psm, &mut fifo) {
            Ok(selected) => selected,
            Err(mut code) => {
                let mut hex = [b'0'; 8];
                for byte in hex.iter_mut().rev() {
                    let nibble = (code & 0x0f) as u8;
                    *byte = if nibble < 10 {
                        b'0' + nibble
                    } else {
                        b'a' + nibble - 10
                    };
                    code >>= 4;
                }
                uart.write_full_blocking(b"FIDO backend failed=0x");
                uart.write_full_blocking(&hex);
                uart.write_full_blocking(b"\r\n");
                loop {
                    Timer::after_secs(1).await;
                }
            }
        };
    uart.write_full_blocking(b"FIDO backend ready\r\n");
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    critical_section::with(|cs| {
        *MULTI_ARBITER.borrow_ref_mut(cs) = Some(IngressArbiter::new(backend));
    });
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let usb_task = multi_usb_task(
        usb_hid,
        usb_dev,
        #[cfg(feature = "riscv-pico-2-w-ccid")]
        usb_ccid,
    )
    .expect("USB task already spawned");
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    spawner.spawn(usb_task);

    let mut pwr = pins.gpio23.into_push_pull_output_in_state(PinState::Low);
    let cs = pins.gpio25.into_push_pull_output_in_state(PinState::High);
    let mut dio = pins.gpio24.into_function::<FunctionPio0>();
    let mut clk = pins.gpio29.into_function::<FunctionPio0>();
    dio.set_drive_strength(OutputDriveStrength::TwelveMilliAmps);
    dio.set_slew_rate(OutputSlewRate::Fast);
    clk.set_drive_strength(OutputDriveStrength::TwelveMilliAmps);
    clk.set_slew_rate(OutputSlewRate::Fast);

    let (mut pio, sm0, _, _, _) = pio0.split(&mut resets);
    let program = pio::pio_asm!(
        ".side_set 1",
        ".wrap_target",
        "out pins, 1 side 0",
        "jmp x-- 0 side 1",
        "set pindirs, 0 side 0",
        "nop side 0",
        "in pins, 1 side 1",
        "jmp y-- 4 side 0",
        "wait 1 pin 0 side 0",
        "irq 0 side 0",
        ".wrap",
    )
    .program;
    let installed = pio.install(&program).unwrap();
    let wrap_target = installed.wrap_target();
    let (mut sm, rx, tx) = PIOBuilder::from_installed_program(installed)
        .set_pins(24, 1)
        .out_pins(24, 1)
        .in_pin_base(24)
        .side_set_pin_base(29)
        .clock_divisor_fixed_point(30, 0)
        .autopull(true)
        .autopush(true)
        .out_shift_direction(ShiftDirection::Left)
        .in_shift_direction(ShiftDirection::Left)
        .build(sm0);
    sm.set_pindirs([(24, PinDir::Output), (29, PinDir::Output)]);
    sm.set_pins([(24, hal::pio::PinState::Low), (29, hal::pio::PinState::Low)]);
    let spi = RiscvCyw43PioSpi::new(sm.start(), rx, tx, cs, wrap_target);

    uart.write_full_blocking(b"PIO ready; initializing CYW43\r\n");
    let _ = pwr.set_low();
    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net, bt, mut control, runner) =
        cyw43::new_with_bluetooth(state, pwr, spi, WIFI_FW_BYTES, BT_FW_BYTES, NVRAM_BYTES).await;

    let controller: ExternalController<_, 10> = ExternalController::new(bt);
    let profile = FidoBleProfile::manekey();
    let address = Address::random(profile.address);
    let mut resources: HostResources<_, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    #[cfg(feature = "riscv-pico-2-w-ble-security")]
    let stack = stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
    let host = stack.build();
    #[cfg(feature = "riscv-pico-2-w-ble-bond-flash")]
    let mut bond_store = manekey_rp::platform::rp::storage::RiscvBleBondFlashStorage::new();
    #[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
    let mut bond_store = selected_dual_core_ble_bond_store();
    #[cfg(not(any(
        feature = "riscv-pico-2-w-ble-bond-flash",
        feature = "riscv-pico-2-w-ble-dual-core-bond-flash"
    )))]
    let mut bond_store = ();
    #[cfg(any(
        feature = "riscv-pico-2-w-ble-bond-flash",
        feature = "riscv-pico-2-w-ble-dual-core-bond-flash"
    ))]
    bond_store.load_bonds(|record| {
        let _ = host.add_bond_information(stored_ble_bond_to_trouble(record));
    });
    let mut ble_runner = host.runner();
    let mut peripheral = host.peripheral();
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: core::str::from_utf8(profile.device_name).unwrap_or("ManeKey FIDO BLE"),
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();
    #[cfg(feature = "riscv-pico-2-w-ble-security")]
    let admission =
        BleBondAdmission::from_bonded_only(cfg!(feature = "riscv-pico-2-w-ble-bonded-only"));
    #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
    let mut fido = BleFidoFrontend::new(BLE_PACKET_LEN, backend);
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let mut fido = SharedBleFrontend::new();

    #[cfg(feature = "riscv-pico-2-w-internal-uart")]
    let internal = internal_uart_loop(
        |buffer| uart.read_raw(buffer).ok().unwrap_or(0),
        |bytes| uart.write_full_blocking(bytes),
    );
    #[cfg(not(feature = "riscv-pico-2-w-internal-uart"))]
    let internal = core::future::pending::<()>();
    let _ = embassy_futures::join::join(
        internal,
        join3(
            runner.run(),
            async {
                loop {
                    if ble_runner.run().await.is_err() {
                        panic!("TrouBLE runner stopped");
                    }
                }
            },
            async {
                control.init(WIFI_CLM_BYTES).await;

                #[cfg(any(not(feature = "riscv-pico-2-w-internal-uart"), any()))]
                uart.write_full_blocking(b"CYW43 Bluetooth HCI initialized\r\n");

                #[cfg(any(not(feature = "riscv-pico-2-w-internal-uart"), any()))]
                uart.write_full_blocking(b"CYW43 control ready; starting BLE advertising loop\r\n");

                let _ = embassy_futures::join::join(
                    async {
                        let mut previous = None;
                        loop {
                            let lit = manekey_rp::platform::rp2350::riscv_ui::PRESENCE_UI.get()
                                == manekey::presence::PresenceUiHint::TouchRequired;
                            if previous != Some(lit) {
                                control.gpio_set(0, lit).await;
                                previous = Some(lit);
                            }
                            Timer::after_millis(10).await;
                        }
                    },
                    async {
                        loop {
                            match advertise_fido(&mut peripheral, &server, &profile).await {
                                Ok(conn) => {
                                    #[cfg(not(feature = "riscv-pico-2-w-internal-uart"))]
                                    uart.write_full_blocking(b"FIDO BLE connected\r\n");
                                    #[cfg(feature = "riscv-pico-2-w-ble-security")]
                                    {
                                        let raw = conn.raw();
                                        let _bondable =
                                            raw.set_bondable(admission.permits_new_bond());
                                    }
                                    #[cfg(feature = "riscv-pico-2-w-ble-security")]
                                    if !admission.permits_peer(conn.raw().is_bonded_peer()) {
                                        conn.raw().disconnect();
                                        drop(conn);
                                        Timer::after_millis(30).await;
                                        continue;
                                    }
                                    let _ = gatt_events(
                                        &host,
                                        &server,
                                        &conn,
                                        &mut fido,
                                        &mut product_runtime,
                                        &mut bond_store,
                                        #[cfg(feature = "riscv-pico-2-w-ble-security")]
                                        admission,
                                    )
                                    .await;
                                    #[cfg(not(feature = "riscv-pico-2-w-internal-uart"))]
                                    uart.write_full_blocking(b"FIDO BLE connection closed\r\n");
                                    drop(conn);
                                    Timer::after_millis(30).await;
                                }
                                Err(_) => {
                                    #[cfg(not(feature = "riscv-pico-2-w-internal-uart"))]
                                    uart.write_full_blocking(b"FIDO BLE advertise error\r\n");
                                    Timer::after_secs(1).await;
                                }
                            }
                        }
                    },
                )
                .await;
            },
        ),
    )
    .await;
}

#[cfg(feature = "riscv-pico-2-w-internal-uart")]
/// Sole framed UART owner after startup; serialize backend access through the initialized arbiter.
async fn internal_uart_loop(
    mut read: impl FnMut(&mut [u8]) -> usize,
    mut write: impl FnMut(&[u8]),
) {
    use manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX;
    use manekey::frontend::internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome};
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut response = [0; TRUSTED_RESPONSE_MAX + 32];
    let mut input = [0; 64];
    loop {
        critical_section::with(|cs| {
            frontend.poll_cancel(MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap());
        });
        let length = read(&mut input);
        for byte in &input[..length] {
            let outcome = critical_section::with(|cs| {
                frontend.push_byte(
                    MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                    *byte,
                    &mut response,
                )
            });
            if let Ok(Some(InterconnectCtap2Outcome::Response { len })) = outcome {
                for chunk in response[..len].chunks(32) {
                    write(chunk);
                    Timer::after_millis(1).await;
                }
            }
        }
        Timer::after_millis(1).await;
    }
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
struct UsbEgress {
    cid: u32,
    cmd: u8,
    data: [u8; MAX_MESSAGE_SIZE],
    len: usize,
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
impl UsbEgress {
    const fn new() -> Self {
        Self {
            cid: 0,
            cmd: 0,
            data: [0; MAX_MESSAGE_SIZE],
            len: 0,
        }
    }

    fn capture(&mut self, response: Response<'_>) {
        let Response::Msg { cid, cmd, data } = response;
        self.cid = cid;
        self.cmd = cmd;
        self.data[..data.len()].copy_from_slice(data);
        self.len = data.len();
    }

    fn response(&self) -> Response<'_> {
        Response::Msg {
            cid: self.cid,
            cmd: self.cmd,
            data: &self.data[..self.len],
        }
    }
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
#[embassy_executor::task]
/// Sole USB polling owner sharing only the serialized arbiter; failed or timed-out writes may drop responses.
async fn multi_usb_task(
    hid: &'static mut HIDClass<'static, hal::usb::UsbBus>,
    usb_dev: &'static mut usb_device::device::UsbDevice<'static, hal::usb::UsbBus>,
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    ccid: &'static mut manekey::transport::usb::polling_ccid::PollingCcid<
        'static,
        hal::usb::UsbBus,
    >,
) {
    let mut protocol = CtaphidProtocol::new();
    let mut report = [0u8; CTAPHID_REPORT_SIZE];
    let mut egress = UsbEgress::new();
    let mut trusted_poll_ticks = 0u8;
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    let mut ccid_frontend = manekey::frontend::ccid::CcidFrontend::new(0);
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    let mut ccid_assembler = manekey::transport::usb::ccid_bulk::CcidBulkAssembler::<
        { manekey::frontend::ccid::CCID_RESPONSE_MAX },
    >::new();
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    let mut ccid_response = [0; manekey::frontend::ccid::CCID_RESPONSE_MAX];
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    let (mut ccid_len, mut ccid_sent, mut ccid_zlp, mut ccid_ticks) = (0usize, 0usize, false, 0u8);

    loop {
        let mut has_response = false;
        #[cfg(feature = "riscv-pico-2-w-ccid")]
        let usb_event = usb_dev.poll(&mut [hid as &mut dyn UsbClass<hal::usb::UsbBus>, ccid]);
        #[cfg(not(feature = "riscv-pico-2-w-ccid"))]
        let usb_event = usb_dev.poll(&mut [hid as &mut dyn UsbClass<hal::usb::UsbBus>]);
        if usb_event && let Ok(CTAPHID_REPORT_SIZE) = hid.pull_raw_output(&mut report) {
            has_response = critical_section::with(|cs| {
                let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
                let mut backend = slot.as_mut().unwrap().bind(USB_INGRESS);
                if let Some(response) = protocol.handle_raw_with_backend(report, &mut backend) {
                    egress.capture(response);
                    true
                } else {
                    false
                }
            });
        }

        #[cfg(feature = "riscv-pico-2-w-ccid")]
        {
            if ccid.take_reset() {
                critical_section::with(|cs| {
                    ccid_frontend.disconnect(MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap())
                });
                ccid_assembler.reset();
                ccid_len = 0;
                ccid_sent = 0;
                ccid_zlp = false;
            }
            if let Some((slot, sequence)) = ccid.take_abort() {
                critical_section::with(|cs| {
                    ccid_frontend.begin_abort(
                        MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                        slot,
                        sequence,
                    )
                });
            }
            ccid_ticks = ccid_ticks.saturating_add(1);
            if ccid_len == 0 && !ccid_zlp {
                let mut packet = [0; 64];
                if let Ok(length) = ccid.read(&mut packet) {
                    if let Ok(Some(message)) = ccid_assembler.push(&packet[..length]) {
                        ccid_len = critical_section::with(|cs| {
                            ccid_frontend.handle_message(
                                MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                                message,
                                &mut ccid_response,
                            )
                        })
                        .unwrap_or(0);
                        ccid_sent = 0;
                        ccid_assembler.reset();
                    }
                } else if ccid_ticks >= 100 {
                    ccid_ticks = 0;
                    ccid_len = critical_section::with(|cs| {
                        ccid_frontend.poll(
                            MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                            &mut ccid_response,
                        )
                    })
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                    ccid_sent = 0;
                }
            }
            if ccid_len != 0 {
                let end = (ccid_sent + 64).min(ccid_len);
                if let Ok(length) = ccid.write(&ccid_response[ccid_sent..end]) {
                    ccid_sent += length;
                    if ccid_sent == ccid_len {
                        ccid_zlp = ccid_len % 64 == 0;
                        ccid_len = 0;
                    }
                }
            } else if ccid_zlp && ccid.write(&[]).is_ok() {
                ccid_zlp = false;
            }
        }

        trusted_poll_ticks = trusted_poll_ticks.saturating_add(1);
        if !has_response && trusted_poll_ticks >= 100 {
            trusted_poll_ticks = 0;
            has_response = critical_section::with(|cs| {
                let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
                let mut backend = slot.as_mut().unwrap().bind(USB_INGRESS);
                if let Some(response) = protocol.poll_with_backend(&mut backend) {
                    egress.capture(response);
                    true
                } else {
                    false
                }
            });
        }

        if has_response {
            let deadline = embassy_time::Instant::now() + embassy_time::Duration::from_secs(5);
            'response: for packet in manekey::ctaphid::framing::response_reports(egress.response())
            {
                loop {
                    match hid.push_raw_input(&packet) {
                        Ok(_) => break,
                        Err(usb_device::UsbError::WouldBlock) => {
                            #[cfg(feature = "riscv-pico-2-w-ccid")]
                            usb_dev.poll(&mut [hid as &mut dyn UsbClass<hal::usb::UsbBus>, ccid]);
                            #[cfg(not(feature = "riscv-pico-2-w-ccid"))]
                            usb_dev.poll(&mut [hid as &mut dyn UsbClass<hal::usb::UsbBus>]);
                            if embassy_time::Instant::now() >= deadline {
                                break 'response;
                            }
                            Timer::after_millis(1).await;
                        }
                        Err(_) => break 'response,
                    }
                }
                Timer::after_millis(1).await;
            }
        }
        Timer::after_millis(1).await;
    }
}

async fn advertise_fido<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server Server<'values>,
    profile: &FidoBleProfile,
) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv_data = [0; 31];
    let adv_len = profile
        .encode_legacy_advertising_data(&mut adv_data)
        .unwrap();
    let mut scan_data = [0; 31];
    let scan_len = profile.encode_legacy_scan_response(&mut scan_data).unwrap();

    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..adv_len],
                scan_data: &scan_data[..scan_len],
            },
        )
        .await?;

    Ok(advertiser.accept().await?.with_attribute_server(server)?)
}

/// Best-effort notification enqueue; failures are discarded and the queue is cleared without delivery acknowledgement.
async fn flush_notifications<P: PacketPool>(
    conn: &GattConnection<'_, '_, P>,
    status: &Characteristic<heapless::Vec<u8, BLE_PACKET_LEN>>,
    sink: &mut NotifySink,
) {
    for fragment in sink.fragments() {
        if let Ok(value) =
            manekey::transport::ble::notification_fragment_vec::<BLE_PACKET_LEN>(fragment)
        {
            let _ = status.notify(conn, &value, false).await;
        }
    }
    sink.clear();
}

/// Connection-local protocol owner; bond persistence failures are not propagated by this event loop.
async fn gatt_events<C: Controller, P: PacketPool, B: BleBondStore>(
    stack: &Stack<'_, C, P>,
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, P>,
    fido: &mut impl BleFidoProfileHandler,
    product_runtime: &mut SelectedBleRuntime,
    _bond_store: &mut B,
    #[cfg(feature = "riscv-pico-2-w-ble-security")] admission: BleBondAdmission,
) -> Result<(), Error> {
    let control_point = &server.fido_service.control_point;
    let status = &server.fido_service.status;
    let control_point_length = &server.fido_service.control_point_length;
    let service_revision_bitfield = &server.fido_service.service_revision_bitfield;
    #[cfg(feature = "riscv-pico-2-w-ble-security")]
    let security_deadline = Instant::now() + BLE_SECURITY_HANDSHAKE_TIMEOUT;
    #[cfg(feature = "riscv-pico-2-w-ble-security")]
    let mut security_disconnect_requested = false;

    loop {
        selected_ble_runtime_tick(product_runtime);
        match embassy_futures::select::select(
            conn.next(),
            Timer::after_millis(SELECTED_BLE_RUNTIME_TICK_MS),
        )
        .await
        {
            embassy_futures::select::Either::First(GattConnectionEvent::Disconnected {
                ..
            }) => break,
            #[cfg(feature = "riscv-pico-2-w-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::PairingComplete {
                bond,
                ..
            }) => {
                if !admission.permits_new_bond() {
                    conn.raw().disconnect();
                    security_disconnect_requested = true;
                    continue;
                }
                if let Some(bond) = bond.as_ref() {
                    let _ = _bond_store.store_bond(stored_ble_bond_from_trouble(bond));
                }
            }
            #[cfg(feature = "riscv-pico-2-w-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::PairingFailed(_)) => {
                conn.raw().disconnect();
                security_disconnect_requested = true;
            }
            #[cfg(feature = "riscv-pico-2-w-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::Encrypted {
                bond: _bond,
                ..
            }) => {}
            #[cfg(feature = "riscv-pico-2-w-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::BondLost) => {
                if admission.permits_new_bond() {
                    let identity = conn.raw().peer_identity();
                    let _ = stack.remove_bond_information(identity);
                    let _ = _bond_store.clear_bonds();
                }
                conn.raw().disconnect();
                security_disconnect_requested = true;
            }
            embassy_futures::select::Either::First(GattConnectionEvent::Gatt { event }) => {
                let mut sink = NotifySink::new();
                match &event {
                    GattEvent::Read(event) if event.handle() == control_point_length.handle => {}
                    GattEvent::Read(event)
                        if event.handle() == service_revision_bitfield.handle => {}
                    GattEvent::Write(event) if event.handle() == control_point.handle => {
                        event.with_data(|offset, data| {
                            let _ = manekey::transport::ble::handle_control_point_write_at_offset_and_drain::<
                                BLE_PACKET_LEN,
                            >(fido, offset, data, &mut sink, 0, || {});
                        });
                    }
                    _ => {}
                }
                if let Ok(reply) = event.accept() {
                    reply.send().await;
                }
                flush_notifications(conn, status, &mut sink).await;
            }
            embassy_futures::select::Either::First(_) => {}
            embassy_futures::select::Either::Second(()) => {
                if !conn.raw().is_connected() {
                    break;
                }
                #[cfg(feature = "riscv-pico-2-w-ble-security")]
                if Instant::now() >= security_deadline
                    && !conn
                        .raw()
                        .security_level()
                        .is_ok_and(|level| level.encrypted())
                {
                    if !security_disconnect_requested {
                        conn.raw().disconnect();
                        security_disconnect_requested = true;
                    }
                    continue;
                }
                if selected_ble_runtime_should_poll_status(product_runtime) {
                    let mut sink = NotifySink::new();
                    let _ = fido.poll_status::<BLE_PACKET_LEN>(&mut sink);
                    flush_notifications(conn, status, &mut sink).await;
                }
            }
        }
    }
    fido.on_disconnect();
    Ok(())
}

#[hal::entry]
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        12_000_000,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();
    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    unsafe { riscv_embassy_time::init() };

    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    static USB_BUS: StaticCell<UsbBusAllocator<hal::usb::UsbBus>> = StaticCell::new();
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    static USB_HID: StaticCell<HIDClass<'static, hal::usb::UsbBus>> = StaticCell::new();
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    static USB_DEVICE: StaticCell<usb_device::device::UsbDevice<'static, hal::usb::UsbBus>> =
        StaticCell::new();
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let usb_bus = USB_BUS.init(UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    )));
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let usb_hid = USB_HID.init(HIDClass::new(
        usb_bus,
        CTAPHID_REPORT_DESCRIPTOR,
        CTAPHID_POLL_MS,
    ));
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    static USB_CCID: StaticCell<
        manekey::transport::usb::polling_ccid::PollingCcid<'static, hal::usb::UsbBus>,
    > = StaticCell::new();
    #[cfg(feature = "riscv-pico-2-w-ccid")]
    let usb_ccid = USB_CCID.init(manekey::transport::usb::polling_ccid::PollingCcid::new(
        usb_bus,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    ));
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let identity = CtaphidUsbDeviceInfo::new("RP2350 RISC-V USB + BLE FIDO", "riscv-usb-ble-fido");
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let usb_dev = USB_DEVICE.init(
        UsbDeviceBuilder::new(usb_bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build(),
    );

    static EXECUTOR: StaticCell<embassy_executor::Executor> = StaticCell::new();
    EXECUTOR
        .init(embassy_executor::Executor::new())
        .run(|spawner: Spawner| {
            spawner.spawn(
                ble_runtime(
                    spawner,
                    pac.PIO0,
                    pac.PSM,
                    pac.SIO,
                    pac.IO_BANK0,
                    pac.PADS_BANK0,
                    pac.UART0,
                    pac.TRNG,
                    timer,
                    pac.RESETS,
                    clocks.peripheral_clock.freq().to_Hz(),
                    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
                    usb_hid,
                    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
                    usb_dev,
                    #[cfg(feature = "riscv-pico-2-w-ccid")]
                    usb_ccid,
                )
                .unwrap(),
            );
        })
}
