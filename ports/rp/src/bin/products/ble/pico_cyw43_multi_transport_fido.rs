use core::cell::RefCell;

use defmt::{info, warn};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join;
#[cfg(all())]
use embassy_rp::flash::Flash;
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, PIO0};
use embassy_rp::pio::InterruptHandler;
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_rp::{bind_interrupts, dma, peripherals};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
#[cfg(all())]
#[cfg(feature = "chip-rp2040")]
use manekey::ctaphid::crypto::SoftwareClientPinCrypto as MultiClientPinCrypto;

#[cfg(all())]
use manekey::ctaphid::pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider};
use manekey::ctaphid::storage::Storage;

use manekey::ctaphid::trusted::TrustedDispatcher;
use manekey::ctaphid::user_verification::UnavailableUserVerification;
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
use manekey::transport::ble::{
    BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler, BleFidoProtocol, FidoBleProfile,
};
#[cfg(all())]
use manekey_rp::platform::rp::storage::SharedRpFlash;
#[cfg(all(all(), not(feature = "dual-core-transport")))]
use manekey_rp::platform::rp::storage::{SharedFlashStorage, SharedPinUvAuthFlashStorage};
#[cfg(feature = "chip-rp235xa")]
use manekey_rp::platform::rp2350::crypto::ClientPinCrypto as MultiClientPinCrypto;
use panic_probe as _;
use static_cell::StaticCell;
use trouble_host::prelude::*;

#[cfg(feature = "rp-ml-dsa-credential-experimental")]
#[path = "../rp_ml_dsa_experimental.rs"]
mod rp_ml_dsa_experimental;
#[cfg(feature = "rp-ml-dsa-credential-experimental")]
use rp_ml_dsa_experimental::TracingMlDsa44;

fn initialize_stack_watermark() {}

fn update_stack_watermark() {}

#[cfg(feature = "chip-rp2040")]
bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => UsbInterruptHandler<peripherals::USB>;
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>, dma::InterruptHandler<DMA_CH1>;
    #[cfg(feature = "rp-internal-uart")]
    UART0_IRQ => embassy_rp::uart::BufferedInterruptHandler<peripherals::UART0>;
});

#[cfg(feature = "chip-rp235xa")]
bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => UsbInterruptHandler<peripherals::USB>;
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>, dma::InterruptHandler<DMA_CH1>;
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<peripherals::TRNG>;
    #[cfg(feature = "rp-internal-uart")]
    UART0_IRQ => embassy_rp::uart::BufferedInterruptHandler<peripherals::UART0>;
});

include!("pico_cyw43_ble_common.rs");

#[cfg(feature = "rp-internal-uart")]
#[path = "../rp_internal_uart.rs"]
mod pico_cyw43_multi_transport_uart;
mod pico_cyw43_multi_transport_usb;
#[cfg(feature = "usb-ccid-experimental")]
use pico_cyw43_multi_transport_usb::multi_ccid_frontend_task;
use pico_cyw43_multi_transport_usb::{build_usb, multi_usb_device_task, multi_usb_frontend_task};

const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);
const FIDO_PENDING_POLL_MS: u64 = 100;

#[cfg(all(all(), not(feature = "dual-core-transport")))]
type MultiStorageBackend = SharedFlashStorage<'static>;
#[cfg(feature = "dual-core-transport")]
type MultiStorageBackend =
    manekey_rp::platform::rp::storage_mailbox::Core0FlashStorageClient<'static>;

#[cfg(all())]
#[cfg(not(feature = "dual-core-transport"))]
type MultiPinStorage = SharedPinUvAuthFlashStorage<'static>;
#[cfg(feature = "dual-core-transport")]
type MultiPinStorage =
    manekey_rp::platform::rp::storage_mailbox::Core0FlashPinUvAuthStorageClient<'static>;
#[cfg(all())]
type MultiPinUvAuth = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<MultiPinStorage>,
    MultiClientPinCrypto,
    RpEmbassyTokenClock,
>;

#[cfg(all(all(), not(feature = "dual-core-transport")))]
type MultiKeyMedia = manekey_rp::platform::rp::managed_flash::SharedManagedKeyFlashStorage<'static>;
#[cfg(all(all(), feature = "dual-core-transport"))]
type MultiKeyMedia = manekey_rp::platform::rp::storage_mailbox::Core0FlashStorageClient<'static, 7>;
#[cfg(all(all(), feature = "chip-rp2040"))]
type MultiKeyHash = manekey::ctaphid::hash::SoftwareSha256;
#[cfg(all(all(), feature = "chip-rp235xa"))]
type MultiKeyHash = manekey_rp::platform::rp2350::crypto::Hash;
#[cfg(all(all(), not(feature = "rp-ml-dsa-credential-experimental")))]
type MultiPrivateKeyStore =
    manekey_rp::platform::rp::key_store::ClassicalKeys<MultiKeyMedia, MultiKeyHash>;
#[cfg(all(all(), feature = "rp-ml-dsa-credential-experimental"))]
type MultiPrivateKeyStore = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore<
    manekey_rp::platform::rp::key_store::ClassicalKeys<MultiKeyMedia, MultiKeyHash>,
    TracingMlDsa44,
>;

type MultiDispatcher = TrustedDispatcher<
    MultiStorageBackend,
    SelectedUserPresence,
    UnavailableUserVerification,
    MultiPinUvAuth,
    MultiPrivateKeyStore,
    SelectedEntropySource,
    SelectedPresenceObserver,
>;
#[cfg(not(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
)))]
type MultiBackend = MultiDispatcher;
#[cfg(feature = "single-core-task-transport")]
type MultiBackend = manekey::boundary::mailbox_backend::MailboxTrustedBackend<
    manekey::boundary::mailbox::LocalMailboxTransport<
        'static,
        { manekey::ctaphid::trusted::TRUSTED_REQUEST_MAX },
        { manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX },
    >,
>;
#[cfg(feature = "dual-core-transport")]
type MultiBackend = manekey::boundary::mailbox_backend::MailboxTrustedBackend<
    manekey_rp::platform::rp::mailbox::PollingMailboxTransport<
        'static,
        { manekey::ctaphid::trusted::TRUSTED_REQUEST_MAX },
        { manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX },
    >,
>;
type MultiArbiter = IngressArbiter<MultiBackend>;

type SharedArbiter = Mutex<ThreadModeRawMutex, RefCell<MultiArbiter>>;
#[cfg(feature = "rp-internal-uart")]
type InternalUart = embassy_rp::uart::BufferedUart;

#[cfg(all(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
compile_error!("select only one multi-ingress worker execution model");
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
mod pico_cyw43_multi_transport_worker;

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
        let result = self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol
                .handle_write_with_backend::<MAX_FRAGMENT>(fragment, sink, &mut backend)
        });
        update_stack_watermark();
        result
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        let result = self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol
                .poll_with_backend::<MAX_FRAGMENT>(sink, &mut backend)
        });
        update_stack_watermark();
        result
    }

    fn on_disconnect(&mut self) {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol.disconnect_with_backend(&mut backend);
        });
        update_stack_watermark();
    }
}

struct MultiBleRuntime;

impl PicoBleFidoRuntime for MultiBleRuntime {
    const TICK_MS: u64 = FIDO_PENDING_POLL_MS;
}

#[embassy_executor::main]
/// Initialize once with reserved journals and single-core thread-mode arbiter ownership.
/// Worker variants require a live core0 Flash service before managed factory access; local/dual workers are not hardware isolation.
async fn main(spawner: Spawner) {
    info!("MANEKEY PICO W USB + BLE FIDO boot");
    #[cfg(feature = "rp-ml-dsa-credential-experimental")]
    rp_ml_dsa_experimental::initialize();
    initialize_stack_watermark();
    #[cfg(feature = "chip-rp235xa")]
    manekey_rp::platform::rp2350::arm_security::configure_rp2350_normal_access();
    let p = embassy_rp::init(Default::default());
    #[cfg(feature = "chip-rp2040")]
    let entropy = selected_entropy();
    #[cfg(feature = "chip-rp235xa")]
    let entropy = selected_entropy(p.TRNG);

    #[cfg(all())]
    #[allow(unused_mut)]
    let mut flash = Flash::new_blocking(p.FLASH);

    #[cfg(all())]
    static FLASH: StaticCell<SharedRpFlash<'static>> = StaticCell::new();
    #[cfg(all())]
    let flash: &'static SharedRpFlash<'static> =
        FLASH.init(SharedRpFlash::new(RefCell::new(flash)));
    #[cfg(all(
        feature = "up-bootsel-experimental",
        not(feature = "dual-core-transport")
    ))]
    let presence = selected_user_presence(p.BOOTSEL);
    #[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
    let presence = {
        spawner.spawn(
            manekey_rp::platform::rp::user_interface::sample_bootsel_on_core0(p.BOOTSEL).unwrap(),
        );
        selected_user_presence()
    };
    #[cfg(not(feature = "up-bootsel-experimental"))]
    let presence = selected_user_presence(p.PIN_15);

    let make_dispatcher = move || {
        #[cfg(all(all(), not(feature = "dual-core-transport")))]
        #[allow(unused_mut)]
        let mut storage = Storage::new(SharedFlashStorage::new(flash));
        #[cfg(feature = "dual-core-transport")]
        #[allow(unused_mut)]
        let mut storage = Storage::new(MultiStorageBackend::new(
            &pico_cyw43_multi_transport_worker::FLASH_ENDPOINT,
        ));

        #[cfg(all())]
        let pin_uv_auth = StoredPinUvAuthProvider::new_with_crypto_and_clock(
            JournaledPinUvAuthStorage::new({
                #[cfg(not(feature = "dual-core-transport"))]
                {
                    SharedPinUvAuthFlashStorage::new(flash)
                }
                #[cfg(feature = "dual-core-transport")]
                {
                    MultiPinStorage::new(&pico_cyw43_multi_transport_worker::FLASH_ENDPOINT)
                }
            }),
            {
                #[cfg(feature = "chip-rp2040")]
                {
                    MultiClientPinCrypto
                }
                #[cfg(feature = "chip-rp235xa")]
                {
                    #[cfg(feature = "rp2350-sha256-accelerator")]
                    assert!(unsafe {
                        manekey_rp::platform::rp2350::crypto::sha256_known_answers()
                    });
                    unsafe { manekey_rp::platform::rp2350::crypto::client_pin_crypto() }
                }
            },
            RpEmbassyTokenClock,
        );

        #[allow(unused_mut)]
        let mut entropy = entropy;
        #[cfg(all())]
        let key_store = {
            manekey_rp::platform::rp::key_store::open_classical(
                {
                    #[cfg(not(feature = "dual-core-transport"))]
                    {
                        MultiKeyMedia::new(flash)
                    }
                    #[cfg(feature = "dual-core-transport")]
                    {
                        MultiKeyMedia::new(&pico_cyw43_multi_transport_worker::FLASH_ENDPOINT)
                    }
                },
                &mut storage,
                &mut entropy,
                {
                    #[cfg(feature = "chip-rp2040")]
                    {
                        manekey::ctaphid::hash::SoftwareSha256
                    }
                    #[cfg(feature = "chip-rp235xa")]
                    {
                        unsafe { manekey_rp::platform::rp2350::crypto::hash_backend() }
                    }
                },
                cfg!(feature = "rp-flash-managed-key-setup"),
            )
        }
        .expect("RP managed keys");
        #[cfg(all(all(), feature = "rp-ml-dsa-credential-experimental"))]
        let key_store = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore::new(
            key_store,
            TracingMlDsa44::default(),
        );

        TrustedDispatcher::new_with_transports_and_presence_observer(
            storage,
            presence,
            UnavailableUserVerification,
            pin_uv_auth,
            key_store,
            entropy,
            manekey::transport::USB_BLE_TRANSPORTS,
            selected_presence_observer(),
        )
    };
    #[cfg(feature = "single-core-task-transport")]
    let backend = pico_cyw43_multi_transport_worker::start_local(&spawner, make_dispatcher());
    #[cfg(feature = "dual-core-transport")]
    let backend =
        pico_cyw43_multi_transport_worker::start_dual(&spawner, p.CORE1, make_dispatcher, flash);
    #[cfg(not(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )))]
    let backend = make_dispatcher();
    static ARBITER: StaticCell<SharedArbiter> = StaticCell::new();
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(backend))));

    #[cfg(feature = "rp-internal-uart")]
    {
        static TX: StaticCell<[u8; 256]> = StaticCell::new();
        static RX: StaticCell<[u8; 1024]> = StaticCell::new();
        let mut config = embassy_rp::uart::Config::default();
        config.baudrate = 115_200;
        let uart = embassy_rp::uart::BufferedUart::new(
            p.UART0,
            p.PIN_0,
            p.PIN_1,
            Irqs,
            TX.init([0; 256]),
            RX.init([0; 1024]),
            config,
        );

        spawner.spawn(pico_cyw43_multi_transport_uart::multi_internal_task(uart, arbiter).unwrap());
    }

    let usb = build_usb(Driver::new(p.USB, Irqs));

    spawner.spawn(multi_usb_device_task(usb.device).unwrap());
    spawner.spawn(multi_usb_frontend_task(usb.hid, arbiter).unwrap());
    #[cfg(feature = "usb-ccid-experimental")]
    spawner.spawn(multi_ccid_frontend_task(usb.ccid, arbiter).unwrap());

    let (bt_device, control) = init_cyw43_bluetooth(
        &spawner, p.PIN_23, p.PIN_25, p.PIO0, p.PIN_24, p.PIN_29, p.DMA_CH0, p.DMA_CH1,
    )
    .await;

    let controller: ExternalController<_, 10> = ExternalController::new(bt_device);
    #[cfg(feature = "board-ui-experimental")]
    let control = {
        spawner.spawn(cyw43_board_ui_task(control).unwrap());
    };
    run_multi_ble(
        controller,
        control,
        SharedBleFrontend::new(arbiter),
        selected_ble_bond_store(flash),
    )
    .await;
}

/// Sole BLE protocol/bond owner sharing the serialized arbiter; Flash mutations must satisfy cross-core XIP exclusion.
async fn run_multi_ble<C>(
    controller: C,
    mut control: StatusLedControl,
    mut fido: SharedBleFrontend,
    mut bond_store: SelectedBleBondStore,
) -> !
where
    C: Controller,
{
    let profile = FidoBleProfile::manekey();
    let mut resources: HostResources<C, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(profile.address));
    #[cfg(feature = "pico-ble-security")]
    let stack = stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
    let host = stack.build();
    #[cfg(feature = "pico-ble-bond-flash")]
    bond_store.load_bonds(|record| {
        let _ = host.add_bond_information(stored_ble_bond_to_trouble(record));
    });
    #[cfg(feature = "pico-ble-security")]
    let admission = BleBondAdmission::from_bonded_only(cfg!(feature = "pico-ble-bonded-only"));
    let runner = host.runner();
    let mut peripheral = host.peripheral();
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: fido_ble_device_name(&profile),
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();

    let _ = join(ble_runner(runner), async {
        loop {
            match advertise(&mut peripheral, &server, &profile).await {
                Ok(conn) => {
                    info!("multi-transport BLE connected");
                    #[cfg(feature = "pico-ble-security")]
                    {
                        let raw = conn.raw();
                        info!(
                            "BLE peer bonded={} security_level={:?}",
                            raw.is_bonded_peer(),
                            raw.security_level()
                        );
                        if let Err(error) = raw.set_bondable(admission.permits_new_bond()) {
                            warn!("failed to mark BLE connection bondable: {:?}", error);
                        }
                    }
                    #[cfg(feature = "pico-ble-security")]
                    if !admission.permits_peer(conn.raw().is_bonded_peer()) {
                        conn.raw().disconnect();
                        drop(conn);
                        embassy_time::Timer::after_millis(30).await;
                        continue;
                    }
                    let mut runtime = MultiBleRuntime;
                    let _ = gatt_events(
                        &host,
                        &server,
                        &conn,
                        &mut fido,
                        &mut control,
                        &mut runtime,
                        &mut bond_store,
                        #[cfg(feature = "pico-ble-security")]
                        admission,
                    )
                    .await;
                }
                Err(_) => {
                    warn!("multi-transport BLE advertise error");
                    embassy_time::Timer::after_secs(1).await;
                }
            }
        }
    })
    .await;
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(feature = "rp-flash-managed-keys"))]
compile_error!("Public products require rp-flash-managed-keys");
