/* CYW43 initialization and advertising follow TrouBLE examples; Copyright (c) Embassy project contributors.
 * Comparison snapshot: trouble-host b6043f576b482d8a4ecd7d2634df48cba20bd7ba, examples/rp-pico-w/src/bin/ble_bas_peripheral.rs and examples/apps/src/ble_bas_peripheral.rs.
 * Original portions: MIT OR Apache-2.0; see vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
 * Modified for FIDO services, shared ingress, stored bonds, notification handling and selectable PIO transport.
 */

use cyw43::aligned_bytes;

#[cfg(feature = "pico-ble-security")]
use manekey::transport::ble::BleBondAdmission;
use manekey::transport::ble::BleBondStore;
#[cfg(feature = "pico-ble-bond-flash")]
use manekey::transport::ble::{StoredBleBond, StoredBleSecurityLevel};

#[cfg(feature = "pico-ble-bond-flash")]
type SelectedBleBondStore = manekey_rp::platform::rp::storage::SharedBleBondFlashStorage<'static>;
#[cfg(not(feature = "pico-ble-bond-flash"))]
type SelectedBleBondStore = ();

#[cfg(feature = "pico-ble-bond-flash")]
fn selected_ble_bond_store(flash: &'static SharedRpFlash<'static>) -> SelectedBleBondStore {
    manekey_rp::platform::rp::storage::SharedBleBondFlashStorage::new(flash)
}

#[cfg(all(
    not(feature = "pico-ble-bond-flash"),
    not(feature = "trustzone-nonsecure-image")
))]
fn selected_ble_bond_store(_flash: &'static SharedRpFlash<'static>) -> SelectedBleBondStore {
    ()
}

#[cfg(feature = "pico-ble-bond-flash")]
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

#[cfg(feature = "pico-ble-bond-flash")]
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

#[cfg(not(any(
    feature = "up-always-present",
    feature = "up-gpio15",
    feature = "up-bootsel-experimental",
    feature = "trustzone-usb-ble-nonsecure-experimental"
)))]
compile_error!("select one Pico W user-presence provider");

#[cfg(any(
    all(feature = "up-always-present", feature = "up-gpio15"),
    all(feature = "up-always-present", feature = "up-bootsel-experimental"),
    all(feature = "up-gpio15", feature = "up-bootsel-experimental")
))]
compile_error!("Pico W user-presence providers are mutually exclusive");

#[cfg(feature = "chip-rp235xa")]
#[unsafe(link_section = ".start_block")]
#[used]
static IMAGE_DEF: embassy_rp::block::Block<3> = {
    use embassy_rp::block::{
        Architecture, Block, Security, item_image_type_exe, item_vector_table,
    };

    let vector_table = item_vector_table(0x1000_0100);
    Block::new([
        item_image_type_exe(Security::Secure, Architecture::Arm),
        vector_table[0],
        vector_table[1],
    ])
};

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;
const BLE_PACKET_LEN: usize = 64;
#[cfg(not(feature = "experimental-large-message-buffers"))]
const MAX_NOTIFY_FRAGMENTS: usize = 20;

#[cfg(feature = "experimental-large-message-buffers")]
const MAX_NOTIFY_FRAGMENTS: usize = 66;

type NotifySink =
    manekey::transport::ble::BleFidoFragmentQueue<MAX_NOTIFY_FRAGMENTS, BLE_PACKET_LEN>;

#[derive(Clone, Copy)]
struct RpEmbassyTokenClock;

impl manekey::ctaphid::pin_uv_auth::PinUvAuthTokenClock for RpEmbassyTokenClock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}

#[cfg(feature = "up-always-present")]
type SelectedUserPresence = manekey::presence::AlwaysPresent;

#[cfg(all(not(feature = "up-always-present"), feature = "up-gpio15"))]
type SelectedUserPresence = manekey_rp::platform::rp::user_interface::GpioUserPresence<'static>;

#[cfg(all(
    feature = "up-bootsel-experimental",
    not(feature = "dual-core-transport")
))]
type SelectedUserPresence = manekey_rp::platform::rp::user_interface::RpBootselPresence;

#[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
type SelectedUserPresence = manekey_rp::platform::rp::user_interface::Core0BootselPresence;

#[cfg(any(feature = "board-ui-experimental", feature = "trustzone-cyw43-ui"))]
type StatusLedControl = ();
#[cfg(not(any(feature = "board-ui-experimental", feature = "trustzone-cyw43-ui")))]
type StatusLedControl = cyw43::Control<'static>;

#[cfg(feature = "board-ui-experimental")]
static BOARD_UI_STATUS: manekey::user_interface::AtomicUiStatus =
    manekey::user_interface::AtomicUiStatus::new();

#[cfg(feature = "board-ui-experimental")]
type SelectedPresenceObserver = manekey::user_interface::UiPresenceObserver<
    manekey::presence::DefmtPresenceObserver,
    &'static manekey::user_interface::AtomicUiStatus,
>;
#[cfg(not(feature = "board-ui-experimental"))]
type SelectedPresenceObserver = manekey::presence::DefmtPresenceObserver;

#[cfg(feature = "board-ui-experimental")]
fn selected_presence_observer() -> SelectedPresenceObserver {
    manekey::user_interface::UiPresenceObserver::new(
        manekey::presence::DefmtPresenceObserver,
        &BOARD_UI_STATUS,
    )
}

#[cfg(not(feature = "board-ui-experimental"))]
fn selected_presence_observer() -> SelectedPresenceObserver {
    manekey::presence::DefmtPresenceObserver
}

#[cfg(feature = "chip-rp2040")]
type SelectedEntropySource =
    manekey::ctaphid::entropy::HmacDrbgEntropy<manekey_rp::platform::rp::entropy::RoscEntropy>;

#[cfg(feature = "chip-rp235xa")]
type SelectedEntropySource = manekey::ctaphid::entropy::HmacDrbgEntropy<
    manekey_rp::platform::rp2350::entropy::Rp2350Trng<'static, embassy_rp::peripherals::TRNG>,
>;

fn fido_ble_device_name(profile: &manekey::transport::ble::FidoBleProfile) -> &str {
    core::str::from_utf8(profile.device_name).unwrap_or("ManeKey FIDO BLE")
}

#[cfg(feature = "up-always-present")]
fn selected_user_presence(
    _pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_15>,
) -> SelectedUserPresence {
    manekey::presence::AlwaysPresent
}

#[cfg(all(not(feature = "up-always-present"), feature = "up-gpio15"))]
fn selected_user_presence(
    pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_15>,
) -> SelectedUserPresence {
    manekey_rp::platform::rp::user_interface::GpioUserPresence::new(embassy_rp::gpio::Input::new(
        pin,
        embassy_rp::gpio::Pull::Up,
    ))
}

#[cfg(all(
    feature = "up-bootsel-experimental",
    not(feature = "dual-core-transport")
))]
fn selected_user_presence(
    bootsel: embassy_rp::Peri<'static, embassy_rp::peripherals::BOOTSEL>,
) -> SelectedUserPresence {
    manekey_rp::platform::rp::user_interface::rp_bootsel_presence(bootsel)
}

#[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
fn selected_user_presence() -> SelectedUserPresence {
    manekey_rp::platform::rp::user_interface::core0_bootsel_presence()
}

#[cfg(feature = "chip-rp2040")]
fn selected_entropy() -> SelectedEntropySource {
    manekey::ctaphid::entropy::HmacDrbgEntropy::new(manekey_rp::platform::rp::entropy::RoscEntropy)
        .expect("seed HMAC-DRBG from RP2040 ROSC")
}

#[cfg(feature = "chip-rp235xa")]
fn selected_entropy(
    trng: embassy_rp::Peri<'static, embassy_rp::peripherals::TRNG>,
) -> SelectedEntropySource {
    manekey::ctaphid::entropy::HmacDrbgEntropy::new(
        manekey_rp::platform::rp2350::entropy::Rp2350Trng::new(embassy_rp::trng::Trng::new(
            trng,
            Irqs,
            Default::default(),
        )),
    )
    .expect("seed HMAC-DRBG from RP2350 TRNG")
}

static WIFI_FW_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> =
    &cyw43::Aligned(*cyw43_firmware::CYW43_43439A0);
static WIFI_CLM_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> =
    &cyw43::Aligned(*cyw43_firmware::CYW43_43439A0_CLM);
static BT_FW_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> =
    &cyw43::Aligned(*cyw43_firmware::CYW43_43439A0_BTFW);
static NVRAM_BYTES: &cyw43::Aligned<cyw43::A4, [u8]> = aligned_bytes!(env!(
    "MANEKEY_CYW43_NVRAM_VERIFIED",
    "Set MANEKEY_CYW43_NVRAM_FILE to the fixed upstream NVRAM file"
));

#[cfg(not(feature = "pico-ble-security"))]
#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[cfg(not(feature = "pico-ble-security"))]
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

#[cfg(feature = "pico-ble-security")]
#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[cfg(feature = "pico-ble-security")]
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
async fn cyw43_task(
    runner: cyw43::Runner<
        'static,
        cyw43::SpiBus<embassy_rp::gpio::Output<'static>, SelectedCyw43Spi>,
        cyw43::Cyw43439,
    >,
) -> ! {
    runner.run().await
}

#[cfg(feature = "rp2350-cyw43-polling")]
type SelectedCyw43Spi = manekey_rp::platform::rp2350::arm_cyw43_polling::ArmPollingPioSpi;
#[cfg(not(feature = "rp2350-cyw43-polling"))]
type SelectedCyw43Spi = cyw43_pio::PioSpi<'static, PIO0, 0>;

async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
    loop {
        if runner.run().await.is_err() {
            panic!("BLE runner error");
        }
    }
}

/// Initialize once with exclusive radio/PIO ownership and selected DMA or polling resources.
/// Non-Secure use requires prior Secure peripheral, IRQ and buffer attribution.
async fn init_cyw43_bluetooth(
    spawner: &embassy_executor::Spawner,
    pwr_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_23>,
    cs_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>,
    pio0: embassy_rp::Peri<'static, embassy_rp::peripherals::PIO0>,
    dio_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_24>,
    clk_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_29>,
    _dma_ch0: embassy_rp::Peri<'static, embassy_rp::peripherals::DMA_CH0>,
    _dma_ch1: embassy_rp::Peri<'static, embassy_rp::peripherals::DMA_CH1>,
) -> (cyw43::bluetooth::BtDriver<'static>, cyw43::Control<'static>) {
    let pwr = embassy_rp::gpio::Output::new(pwr_pin, embassy_rp::gpio::Level::Low);
    let cs = embassy_rp::gpio::Output::new(cs_pin, embassy_rp::gpio::Level::High);
    let mut pio = embassy_rp::pio::Pio::new(pio0, Irqs);

    #[cfg(not(feature = "rp2350-cyw43-polling"))]
    let spi = cyw43_pio::PioSpi::new(
        &mut pio.common,
        pio.sm0,
        cyw43_pio::RM2_CLOCK_DIVIDER.saturating_mul_int(10),
        pio.irq0,
        cs,
        dio_pin,
        clk_pin,
        embassy_rp::dma::Channel::new(_dma_ch0, Irqs),
        embassy_rp::dma::Channel::new(_dma_ch1, Irqs),
    );
    #[cfg(feature = "rp2350-cyw43-polling")]
    let spi = SelectedCyw43Spi::new(&mut pio.common, pio.sm0, cs, dio_pin, clk_pin);

    static STATE: static_cell::StaticCell<cyw43::State> = static_cell::StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, bt_device, mut control, runner) =
        cyw43::new_with_bluetooth(state, pwr, spi, WIFI_FW_BYTES, BT_FW_BYTES, NVRAM_BYTES).await;

    spawner.spawn(cyw43_task(runner).unwrap());

    control.init(WIFI_CLM_BYTES).await;

    control.gpio_set(0, true).await;

    defmt::info!("CYW43 Bluetooth HCI initialized");

    (bt_device, control)
}

#[cfg(any(feature = "board-ui-experimental", feature = "trustzone-cyw43-ui"))]
#[embassy_executor::task]
/// Sole CYW43 GPIO owner; Secure-shared hint memory must remain readable for the selected image.
async fn cyw43_board_ui_task(mut control: cyw43::Control<'static>) -> ! {
    use manekey::presence::PresenceUiHint;

    let mut last_level = true;
    loop {
        #[cfg(feature = "board-ui-experimental")]
        let level = matches!(BOARD_UI_STATUS.get(), PresenceUiHint::TouchRequired);
        #[cfg(feature = "trustzone-cyw43-ui")]
        let level = unsafe {
            core::ptr::read_volatile(
                manekey::security::layout::PRESENCE_UI_HINT_ADDRESS as *const u32,
            )
        } == PresenceUiHint::TouchRequired as u32;
        if level != last_level {
            control.gpio_set(0, level).await;
            last_level = level;
        }
        embassy_time::Timer::after_millis(25).await;
    }
}

async fn advertise<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server Server<'values>,
    profile: &manekey::transport::ble::FidoBleProfile,
) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv_data = [0; 31];
    let adv_len = profile
        .encode_legacy_advertising_data(&mut adv_data)
        .expect("FIDO BLE advertising data must fit in 31 bytes");
    let mut scan_data = [0; 31];
    let scan_len = profile
        .encode_legacy_scan_response(&mut scan_data)
        .expect("FIDO BLE scan response must fit in 31 bytes");

    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..adv_len],
                scan_data: &scan_data[..scan_len],
            },
        )
        .await?;
    defmt::info!("FIDO BLE advertising active");
    Ok(advertiser.accept().await?.with_attribute_server(server)?)
}

/// Paced enqueue only, not radio-delivery acknowledgement; failure abandons and clears the response.
async fn flush_notifications<P: PacketPool>(
    conn: &GattConnection<'_, '_, P>,
    status: &Characteristic<heapless::Vec<u8, BLE_PACKET_LEN>>,
    sink: &mut NotifySink,
    control: &mut StatusLedControl,
) {
    #[cfg(any(feature = "board-ui-experimental", feature = "trustzone-cyw43-ui"))]
    let _ = control;
    for fragment in sink.fragments() {
        let Ok(value) =
            manekey::transport::ble::notification_fragment_vec::<BLE_PACKET_LEN>(fragment)
        else {
            defmt::warn!("FIDO BLE notification fragment too long");
            continue;
        };

        let _notify = status.notify(conn, &value, false).await;

        if let Err(error) = _notify {
            defmt::warn!(
                "FIDO BLE notification failed: {:?}; abandoning response",
                error
            );
            break;
        }
        #[cfg(not(any(feature = "board-ui-experimental", feature = "trustzone-cyw43-ui")))]
        control.gpio_set(0, false).await;

        embassy_time::Timer::after_millis(30).await;
        #[cfg(not(any(feature = "board-ui-experimental", feature = "trustzone-cyw43-ui")))]
        control.gpio_set(0, true).await;
    }
    sink.clear();
}

/// Connection runtime hooks; TICK_MS uses milliseconds and callbacks must preserve frontend ownership.
trait PicoBleFidoRuntime {
    const TICK_MS: u64;

    fn before_wait(&mut self) {}
    fn after_gatt_event(&mut self) {}
    fn after_poll_status(&mut self) {}
    fn should_poll_status(&mut self) -> bool {
        true
    }
}

/// Connection-local protocol owner; bond persistence failure is logged but does not fail pairing.
async fn gatt_events<C, P, F, R, B>(
    _stack: &trouble_host::Stack<'_, C, P>,
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, P>,
    fido: &mut F,
    control: &mut StatusLedControl,
    runtime: &mut R,
    _bond_store: &mut B,
    #[cfg(feature = "pico-ble-security")] admission: BleBondAdmission,
) -> Result<(), Error>
where
    C: Controller,
    P: PacketPool,
    F: manekey::transport::ble::BleFidoProfileHandler,
    R: PicoBleFidoRuntime,
    B: BleBondStore,
{
    let control_point = &server.fido_service.control_point;
    let status = &server.fido_service.status;
    let control_point_length = &server.fido_service.control_point_length;
    let service_revision_bitfield = &server.fido_service.service_revision_bitfield;
    let reason = loop {
        runtime.before_wait();
        match embassy_futures::select::select(
            conn.next(),
            embassy_time::Timer::after_millis(R::TICK_MS),
        )
        .await
        {
            embassy_futures::select::Either::First(GattConnectionEvent::Disconnected {
                reason,
            }) => break reason,
            #[cfg(feature = "pico-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::PairingComplete {
                security_level,
                bond,
            }) => {
                if !admission.permits_new_bond() {
                    conn.raw().disconnect();
                    continue;
                }
                #[cfg(feature = "pico-ble-bond-flash")]
                if let Some(record) = bond.as_ref() {
                    if !_bond_store.store_bond(stored_ble_bond_from_trouble(record)) {
                        defmt::warn!("BLE bond flash write failed");
                    }
                }
                defmt::info!(
                    "BLE pairing complete: level={:?} bonded={}",
                    security_level,
                    bond.is_some()
                );
            }
            #[cfg(feature = "pico-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::PairingFailed(_)) => {
                defmt::warn!("BLE pairing failed");
            }
            #[cfg(feature = "pico-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::Encrypted {
                security_level,
                bond,
            }) => {
                defmt::info!(
                    "BLE encrypted: level={:?} bond_present={}",
                    security_level,
                    bond.is_some()
                );
            }
            #[cfg(feature = "pico-ble-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::BondLost) => {
                defmt::warn!("BLE bond lost");
                if admission.permits_new_bond() {
                    let identity = conn.raw().peer_identity();
                    let _ = _stack.remove_bond_information(identity);
                    let _ = _bond_store.clear_bonds();
                }
                conn.raw().disconnect();
            }
            embassy_futures::select::Either::First(GattConnectionEvent::Gatt { event }) => {
                let mut notify_sink = NotifySink::new();
                let mut subscription = None;
                match &event {
                    GattEvent::Read(event) if event.handle() == control_point_length.handle => {
                        defmt::info!("GATT read control point length");
                    }
                    GattEvent::Read(event)
                        if event.handle() == service_revision_bitfield.handle =>
                    {
                        defmt::info!("GATT read service revision bitfield");
                    }
                    GattEvent::Write(event) if event.handle() == control_point.handle => {
                        event.with_data(|offset, data| {
                            if manekey::transport::ble::handle_control_point_write_at_offset_and_drain::<
                                BLE_PACKET_LEN,
                            >(fido, offset, data, &mut notify_sink, 0, || {})
                            .is_err()
                            {
                                defmt::warn!("FIDO BLE write error");
                            }
                        });
                    }
                    GattEvent::Write(event) if Some(event.handle()) == status.cccd_handle => {
                        event.with_data(|offset, data| {
                            if offset == 0 && data.len() == 2 && data[1] == 0 && data[0] <= 1 {
                                subscription = Some(data[0] == 1);
                            }
                        });
                    }
                    _ => {}
                }

                match event.accept() {
                    Ok(reply) => {
                        if let Some(enabled) = subscription {
                            fido.on_status_subscription(enabled);
                        }
                        reply.send().await;
                    }
                    Err(_) => defmt::warn!("GATT reply error"),
                };
                runtime.after_gatt_event();
                flush_notifications(conn, status, &mut notify_sink, control).await;
            }
            embassy_futures::select::Either::First(_) => {}
            embassy_futures::select::Either::Second(()) => {
                if runtime.should_poll_status() {
                    let mut notify_sink = NotifySink::new();
                    let poll = fido.poll_status::<BLE_PACKET_LEN>(&mut notify_sink);

                    if poll.is_err() {
                        defmt::warn!("FIDO BLE poll error");
                    }
                    runtime.after_poll_status();
                    flush_notifications(conn, status, &mut notify_sink, control).await;
                }
            }
        }
    };
    fido.on_disconnect();
    defmt::info!("GATT disconnected: {:?}", reason);
    Ok(())
}
