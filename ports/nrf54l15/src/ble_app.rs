use core::cell::RefCell;
use defmt::unwrap;
#[cfg(feature = "ble-security")]
use embassy_crypto_rustcrypto as _;
use embassy_executor::Spawner;
use embassy_futures::{
    join::join,
    select::{Either, select},
};
use embassy_nrf::{bind_interrupts, config, crypto::rng, uarte};
use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};
use embassy_time::{Duration, Timer};
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
use manekey::transport::ble::CONTROL_POINT_LENGTH_MIN;
#[cfg(feature = "ble-security")]
use manekey::transport::ble::{
    BleBondAdmission, BleBondStore, StoredBleBond, StoredBleSecurityLevel,
};
use manekey::transport::ble::{BleFidoFragmentQueue, BleFidoProfileHandler, FidoBleProfile};
use nrf_mpsl as _;
use nrf_sdc::{self as sdc, mpsl, mpsl::MultiprotocolServiceLayer};
use static_cell::StaticCell;
use trouble_host::prelude::*;
use {defmt_rtt as _, panic_probe as _};

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
const MAX_FRAGMENT: usize = CONTROL_POINT_LENGTH_MIN;

#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
const MAX_FRAGMENT: usize = 64;
#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
const MAX_FRAGMENTS: usize = 68;
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
const MAX_FRAGMENTS: usize = 16;

#[cfg(feature = "ble-notify-pacing")]
const NOTIFY_FRAGMENT_GAP_MS: u64 = 10;
#[cfg(not(feature = "ble-notify-pacing"))]
const NOTIFY_FRAGMENT_GAP_MS: u64 = 0;

#[cfg(feature = "nrf54l15-dual-task")]
type SelectedDirectDispatcher = nrf54l15::ble_ingress::BleProductDispatcher;
type SelectedArbiter = nrf54l15::ble_ingress::BleProductArbiter;

static ARBITER: StaticCell<SelectedArbiter> = StaticCell::new();
#[cfg(feature = "nrf54l15-dual-task")]
static TRUSTED_WORKER: StaticCell<
    nrf54l15::mailbox::Nrf54LocalTrustedWorker<SelectedDirectDispatcher>,
> = StaticCell::new();

#[cfg(not(feature = "ble-security"))]
#[gatt_server(
    connections_max = CONNECTIONS_MAX,
    mutex_type = NoopRawMutex,
    attribute_table_size = 32
)]
struct Server {
    fido: FidoService,
}

#[cfg(feature = "ble-security")]
#[gatt_server(
    connections_max = CONNECTIONS_MAX,
    mutex_type = NoopRawMutex,
    attribute_table_size = 32
)]
struct Server {
    fido: FidoService,
}

#[cfg(feature = "ble-security")]
#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(
        uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
        write,
        permissions(write = encrypted)
    )]
    control_point: heapless::Vec<u8, MAX_FRAGMENT>,
    #[characteristic(
        uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb",
        notify,
        permissions(cccd = encrypted)
    )]
    status: heapless::Vec<u8, MAX_FRAGMENT>,
    #[characteristic(
        uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        value = [MAX_FRAGMENT as u8, 0]
    )]
    control_point_length: [u8; 2],
    #[characteristic(
        uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        write,
        value = [0x20]
    )]
    service_revision_bitfield: [u8; 1],
    #[characteristic(uuid = "2a28", read, value = *b"FIDO_2_0")]
    service_revision: [u8; 8],
}

#[cfg(feature = "ble-security")]
fn stored_security_level_from_trouble(
    level: trouble_host::connection::SecurityLevel,
) -> StoredBleSecurityLevel {
    match level {
        trouble_host::connection::SecurityLevel::NoEncryption => {
            StoredBleSecurityLevel::NoEncryption
        }
        trouble_host::connection::SecurityLevel::Encrypted => StoredBleSecurityLevel::Encrypted,
        trouble_host::connection::SecurityLevel::EncryptedAuthenticated => {
            StoredBleSecurityLevel::EncryptedAuthenticated
        }
    }
}

#[cfg(feature = "ble-security")]
fn stored_security_level_to_trouble(
    level: StoredBleSecurityLevel,
) -> trouble_host::connection::SecurityLevel {
    match level {
        StoredBleSecurityLevel::NoEncryption => {
            trouble_host::connection::SecurityLevel::NoEncryption
        }
        StoredBleSecurityLevel::Encrypted => trouble_host::connection::SecurityLevel::Encrypted,
        StoredBleSecurityLevel::EncryptedAuthenticated => {
            trouble_host::connection::SecurityLevel::EncryptedAuthenticated
        }
    }
}

#[cfg(feature = "ble-security")]
fn stored_ble_bond_from_trouble(bond: &trouble_host::BondInformation) -> StoredBleBond {
    let mut bd_addr = [0; 6];
    bd_addr.copy_from_slice(&bond.identity.addr.addr.into_inner());
    StoredBleBond {
        ltk: bond.ltk.to_le_bytes(),
        bd_addr,
        bd_addr_kind: bond.identity.addr.kind.as_raw(),
        irk: bond.identity.irk.map(|irk| irk.to_le_bytes()),
        is_bonded: bond.is_bonded,
        security_level: stored_security_level_from_trouble(bond.security_level),
    }
}

#[cfg(feature = "ble-security")]
fn stored_ble_bond_to_trouble(bond: StoredBleBond) -> trouble_host::BondInformation {
    trouble_host::BondInformation::new(
        trouble_host::Identity {
            addr: Address::new(AddrKind::new(bond.bd_addr_kind), BdAddr::new(bond.bd_addr)),
            irk: bond
                .irk
                .and_then(trouble_host::IdentityResolvingKey::from_le_bytes),
        },
        trouble_host::LongTermKey::from_le_bytes(bond.ltk),
        stored_security_level_to_trouble(bond.security_level),
        bond.is_bonded,
    )
}

#[cfg(feature = "ble-security")]
fn restore_bond(
    stack: &trouble_host::Stack<'_, impl Controller, DefaultPacketPool>,
    store: &mut impl BleBondStore,
) {
    store.load_bonds(|record| {
        let _ = stack.add_bond_information(stored_ble_bond_to_trouble(record));
    });
}

#[cfg(not(feature = "ble-security"))]
#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb", write)]
    control_point: heapless::Vec<u8, MAX_FRAGMENT>,
    #[characteristic(uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", notify)]
    status: heapless::Vec<u8, MAX_FRAGMENT>,
    #[characteristic(
        uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        value = [MAX_FRAGMENT as u8, 0]
    )]
    control_point_length: [u8; 2],
    #[characteristic(
        uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        value = [0x20]
    )]
    service_revision_bitfield: [u8; 1],
    #[characteristic(uuid = "2a28", read, value = *b"FIDO_2_0")]
    service_revision: [u8; 8],
}

bind_interrupts!(struct Irqs {
    SWI00 => nrf_sdc::mpsl::LowPrioInterruptHandler;
    CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler;
    RADIO_0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    TIMER10 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    GRTC_3 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    SERIAL20 => uarte::InterruptHandler<embassy_nrf::peripherals::SERIAL20>;
    #[cfg(feature = "ble-virtual-hid-experimental")]
    SERIAL21 => embassy_nrf::buffered_uarte::InterruptHandler<embassy_nrf::peripherals::SERIAL21>;
});

#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    mpsl.run().await
}

#[cfg(feature = "nrf54l15-dual-task")]
#[embassy_executor::task]
async fn trusted_task(
    worker: &'static mut nrf54l15::mailbox::Nrf54LocalTrustedWorker<SelectedDirectDispatcher>,
) -> ! {
    nrf54l15::mailbox::run_local_trusted_worker(worker).await
}

fn build_sdc<'d, const N: usize>(
    p: sdc::Peripherals<'d>,
    rng: &'d mut nrf54l15::entropy::SharedNrf54Rng,
    mpsl: &'d MultiprotocolServiceLayer,
    mem: &'d mut sdc::Mem<N>,
) -> Result<sdc::SoftdeviceController<'d>, sdc::Error> {
    sdc::Builder::new()?
        .support_adv()
        .support_peripheral()
        .build(p, rng, mpsl, mem)
}

/// Controller acceptance is not peer-delivery acknowledgment; preserve the selected pacing policy.
async fn notify_fragments(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    fragments: &BleFidoFragmentQueue<MAX_FRAGMENTS, MAX_FRAGMENT>,
) -> Result<(), trouble_host::Error> {
    for (_index, fragment) in fragments.fragments().enumerate() {
        server.fido.status.notify_raw(conn, fragment, false).await?;
        if NOTIFY_FRAGMENT_GAP_MS != 0 {
            Timer::after_millis(NOTIFY_FRAGMENT_GAP_MS).await;
        }
    }

    Ok(())
}

#[embassy_executor::main]
/// Initialize static owners once in Secure thread mode with matching MPSL/SDC runtime and reserved media.
/// Dual-task separation is cooperative, not TrustZone isolation.
async fn main(spawner: Spawner) {
    nrf54l15::board::prepare_cmsis_dap_reset();
    let mut config: config::Config = Default::default();
    config.clock_speed = config::ClockSpeed::CK128;
    config.hfclk_source = config::HfclkSource::ExternalXtal;
    config.lfclk_source = config::LfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    #[cfg(feature = "ble-virtual-hid-experimental")]
    let virtual_uart = {
        let mut uart_config = uarte::Config::default();
        uart_config.baudrate = uarte::Baudrate::Baud115200;
        uart_config.parity = uarte::Parity::Excluded;
        static UART_TX: StaticCell<[u8; 256]> = StaticCell::new();
        static UART_RX: StaticCell<[u8; 1024]> = StaticCell::new();
        let uart = embassy_nrf::buffered_uarte::BufferedUarte::new(
            p.SERIAL21,
            p.P2_08,
            p.P2_07,
            Irqs,
            UART_TX.init([0; 256]),
            UART_RX.init([0; 1024]),
            uart_config,
        );

        embassy_nrf::pac::UARTE21_S
            .frametimeout()
            .write(|w| w.set_countertop(512));
        assert_eq!(
            embassy_nrf::pac::UARTE21_S
                .frametimeout()
                .read()
                .countertop(),
            512
        );
        uart
    };

    spawner.spawn(unwrap!(nrf54l15::ui::user_led_task(p.P2_00)));
    #[cfg(feature = "up-always-present")]
    let presence = manekey::presence::AlwaysPresent;
    #[cfg(not(feature = "up-always-present"))]
    let presence = nrf54l15::presence::UserKeyPresence::new(p.P0_00);

    let mpsl_p = mpsl::Peripherals::new(
        p.GRTC_CH7,
        p.GRTC_CH8,
        p.GRTC_CH9,
        p.GRTC_CH10,
        p.GRTC_CH11,
        p.TIMER10,
        p.TIMER20,
        p.TEMP,
        p.PPI10_CH0,
        p.PPI20_CH1,
        p.PPIB11_CH0,
        p.PPIB21_CH0,
    );
    let lfclk_cfg = mpsl::raw::mpsl_clock_lfclk_cfg_t {
        source: mpsl::raw::MPSL_CLOCK_LF_SRC_XTAL as u8,
        rc_ctiv: 0,
        rc_temp_ctiv: 0,
        accuracy_ppm: 50,
        skip_wait_lfclk_started: false,
    };
    static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
    let mpsl = MPSL.init(unwrap!(MultiprotocolServiceLayer::new(
        mpsl_p, Irqs, lfclk_cfg
    )));
    spawner.spawn(unwrap!(mpsl_task(&*mpsl)));

    let sdc_p = sdc::Peripherals::new(
        p.PPI00_CH1,
        p.PPI00_CH3,
        p.PPI10_CH1,
        p.PPI10_CH2,
        p.PPI10_CH3,
        p.PPI10_CH4,
        p.PPI10_CH5,
        p.PPI10_CH6,
        p.PPI10_CH7,
        p.PPI10_CH8,
        p.PPI10_CH9,
        p.PPI10_CH10,
        p.PPI10_CH11,
        p.PPIB00_CH1,
        p.PPIB00_CH2,
        p.PPIB00_CH3,
        p.PPIB10_CH1,
        p.PPIB10_CH2,
        p.PPIB10_CH3,
    );
    let rng = rng::Rng::new_blocking(p.CRYPTO_RNG);
    let shared_rng = nrf54l15::entropy::init_shared_rng(rng);
    #[cfg(feature = "cracen-sha256")]
    nrf54l15::crypto::init_symmetric(p.CRYPTO_SYMMETRIC);
    #[cfg(feature = "cracen-p256-experimental")]
    nrf54l15::crypto::init_pka(p.CRYPTO_PKA, shared_rng);

    let mut sdc_rng = shared_rng;
    let mut sdc_mem = sdc::Mem::<4720>::new();
    let controller = unwrap!(build_sdc(sdc_p, &mut sdc_rng, mpsl, &mut sdc_mem));

    let entropy = match nrf54l15::entropy::build_entropy(shared_rng) {
        Ok(entropy) => entropy,
        Err(_) => panic!(),
    };
    let rram = nrf54l15::storage::init_shared_rram(embassy_nrf::rramc::Nvmc::new(p.RRAMC));
    #[cfg(feature = "ble-security")]
    let mut bond_store = nrf54l15::storage::Nrf54RramBondStore::new(rram);

    #[cfg(feature = "nrf54l15-dual-task")]
    let arbiter = {
        let dispatcher = nrf54l15::fido::build_rram_dispatcher_with_transports(
            presence,
            entropy,
            rram,
            &nrf54l15::ui::USER_LED_STATUS,
            #[cfg(feature = "ble-virtual-hid-experimental")]
            manekey::transport::USB_BLE_TRANSPORTS,
            #[cfg(not(feature = "ble-virtual-hid-experimental"))]
            manekey::transport::BLE_TRANSPORTS,
        );
        let worker =
            TRUSTED_WORKER.init(nrf54l15::mailbox::Nrf54LocalTrustedWorker::new(dispatcher));
        spawner.spawn(unwrap!(trusted_task(worker)));
        ARBITER.init(Mutex::new(RefCell::new(
            manekey::frontend::ingress::IngressArbiter::new(
                nrf54l15::mailbox::local_mailbox_backend(),
            ),
        )))
    };
    #[cfg(all(
        not(feature = "nrf54l15-dual-task"),
        feature = "ble-virtual-hid-experimental"
    ))]
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(
        nrf54l15::fido::build_rram_ble_virtual_hid_arbiter(
            presence,
            entropy,
            rram,
            &nrf54l15::ui::USER_LED_STATUS,
        ),
    )));
    #[cfg(all(
        not(feature = "nrf54l15-dual-task"),
        not(feature = "ble-virtual-hid-experimental")
    ))]
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(
        nrf54l15::fido::build_rram_ble_arbiter(
            presence,
            entropy,
            rram,
            &nrf54l15::ui::USER_LED_STATUS,
        ),
    )));
    let mut fido = nrf54l15::ble_ingress::SharedBleIngressFrontend::new(MAX_FRAGMENT, arbiter);

    #[cfg(feature = "ble-virtual-hid-experimental")]
    {
        spawner.spawn(unwrap!(nrf54l15::samd11_virtual_hid::task(
            virtual_uart,
            arbiter
        )));
    }

    let profile = FidoBleProfile::manekey();
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack_builder = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(profile.address));
    #[cfg(feature = "ble-security")]
    let stack = stack_builder
        .set_io_capabilities(IoCapabilities::NoInputNoOutput)
        .build();
    #[cfg(not(feature = "ble-security"))]
    let stack = stack_builder.build();
    #[cfg(feature = "ble-security")]
    restore_bond(&stack, &mut bond_store);
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();
    #[cfg(feature = "ble-security")]
    let server = unwrap!(Server::new_with_config(GapConfig::Peripheral(
        PeripheralConfig {
            name: "ManeKey nRF54 P0",
            appearance: &appearance::UNKNOWN,
        }
    )));
    #[cfg(not(feature = "ble-security"))]
    let server = unwrap!(Server::new_default("ManeKey nRF54 P0"));

    join(runner.run(), async {







        let mut adv_data = [0; 31];
        let adv_len = match profile.encode_legacy_advertising_data(&mut adv_data) {
            Ok(len) => len,
            Err(_) => panic!(),
        };
        let mut scan_data = [0; 31];
        let scan_len = match profile.encode_legacy_scan_response(&mut scan_data) {
            Ok(len) => len,
            Err(_) => panic!(),
        };
        loop {
            let mut params = AdvertisementParameters::default();
            params.interval_min = Duration::from_millis(100);
            params.interval_max = Duration::from_millis(100);
            let acceptor = unwrap!(peripheral
                .advertise(
                    &params,
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_len],
                        scan_data: &scan_data[..scan_len],
                    },
                )
                .await);


            let connection = match acceptor.accept().await {
                Ok(connection) => connection,
                Err(error) => {

                    defmt::warn!("BLE connection rejected: {:?}", error);
                    Timer::after_millis(100).await;
                    continue;
                }
            };
            let conn = connection.with_attribute_server(&server).unwrap();
            #[cfg(feature = "ble-security")]
            {
                let admission = BleBondAdmission::from_bonded_only(cfg!(feature = "ble-bonded-only"));
                let raw = conn.raw();
                unwrap!(raw.set_bondable(admission.permits_new_bond()));
                if !admission.permits_peer(raw.is_bonded_peer()) {
                    raw.disconnect();
                    continue;
                }
            }
            loop {
                match select(conn.next(), Timer::after_millis(10)).await {
                    Either::First(GattConnectionEvent::Disconnected { .. }) => {
                        fido.on_disconnect();
                        break;
                    }
                    Either::First(GattConnectionEvent::Gatt { event: GattEvent::Write(event) })
                        if event.handle() == server.fido.control_point.handle() =>
                    {


                        let mut fragments = BleFidoFragmentQueue::<MAX_FRAGMENTS, MAX_FRAGMENT>::new();
                        let result = event.with_data(|offset, data| {
                            manekey::transport::ble::handle_control_point_write_at_offset_and_drain::<MAX_FRAGMENT>(
                                &mut fido,
                                offset,
                                data,
                                &mut fragments,
                                1,
                                || {},
                            )
                        });




                        unwrap!(event.accept()).send().await;


                        if result.is_ok() {


                            if notify_fragments(&server, &conn, &fragments).await.is_err() {
                                fido.on_disconnect();
                                conn.raw().disconnect();
                                break;
                            }


                        } else {


                        }
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::PairingComplete { bond, .. }) => {
                        defmt::info!("BLE pairing complete; bond={}", bond.is_some());
                        if let Some(bond) = bond.as_ref() {
                            let _ = bond_store.store_bond(stored_ble_bond_from_trouble(bond));
                        }
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::PairingFailed(error)) => {
                        defmt::warn!("BLE pairing failed: {:?}", error);
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::PassKeyDisplay(_)) => {
                        defmt::warn!("BLE requires passkey display");
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::PassKeyConfirm(_)) => {


                        defmt::warn!("BLE requires numeric confirmation");
                        let _ = conn.pass_key_cancel();
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::PassKeyInput) => {
                        defmt::warn!("BLE requires passkey input");
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::Encrypted { bond, .. }) => {
                        defmt::info!("BLE link encrypted; restored-bond={}", bond.is_some());
                    }
                    #[cfg(feature = "ble-security")]
                    Either::First(GattConnectionEvent::BondLost) => {
                        defmt::warn!("BLE bond lost; clearing persisted record");
                        let _ = bond_store.clear_bonds();
                        let _ = stack.remove_bond_information(conn.raw().peer_identity());
                        conn.raw().disconnect();
                    }
                    Either::Second(_) => {
                        let mut fragments = BleFidoFragmentQueue::<MAX_FRAGMENTS, MAX_FRAGMENT>::new();


                        let poll_ok = fido.poll_status::<MAX_FRAGMENT>(&mut fragments).is_ok();




                        if poll_ok {


                            if notify_fragments(&server, &conn, &fragments).await.is_err() {
                                fido.on_disconnect();
                                conn.raw().disconnect();
                                break;
                            }


                        } else {


                        }
                    }
                    _ => {}
                }
            }
            drop(conn);


            while !fido.settle_disconnected_backend() {
                Timer::after_millis(10).await;
            }
        }
    })
    .await;
}
