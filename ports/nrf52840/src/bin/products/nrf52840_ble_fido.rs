#![no_std]
#![no_main]

#[cfg(feature = "nrf-usb-full-ram")]
compile_error!("nrf-usb-full-ram is USB-only and cannot be used with the S140 BLE product");
#[cfg(not(any(any(), feature = "nrf-ble-mpu-product")))]
use core::arch::global_asm;
use core::cell::RefCell;

#[cfg(all(feature = "nrf-ble-mpu-product", any(any(), feature = "nrf-dual-task")))]
compile_error!("MPU BLE product owns its copied worker; do not combine probe/ordinary dual-task");

use cortex_m_rt::entry;
use defmt_rtt as _;
use embassy_executor::Executor;
use embassy_futures::select::select;
use heapless::{String, Vec};
use manekey::ctaphid::{
    entropy::{EntropyError, HmacDrbgEntropy},
    trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
use manekey::presence::TextPresenceObserver;
use manekey::transport;
#[cfg(not(feature = "nrf-multi-transport"))]
use manekey::transport::ble::BleFidoFrontend;
use manekey::transport::ble::{
    BleFidoFragmentQueue, BleFidoProfileHandler, FIDO_SERVICE_REVISION, FIDO2_SERVICE_REVISION_BIT,
    FidoBleProfile, handle_control_point_write_and_drain,
};
use nrf_softdevice::ble::peripheral::{self, ConnectableAdvertisement};
use nrf_softdevice::ble::{Connection, gatt_server};
use nrf_softdevice::{Softdevice, raw};
use nrf52840::board::{BOARD, RedLed};
use nrf52840::entropy::SoftdeviceEntropy;
#[cfg(feature = "nrf-dual-task")]
use nrf52840::fido::{NRF_MAILBOX, NrfLocalTrustedWorker, local_mailbox_backend};
use nrf52840::fido::{NrfSoftdeviceDispatcher, selected_softdevice_crypto_backends};
use nrf52840::presence::{
    BLE_UP_TIMEOUT_POLLS, SelectedUserPresence, configure_selected_user_presence,
    selected_user_presence,
};

use nrf52840::storage::selected_softdevice_storage;
use nrf52840_pac::{FICR, NVMC, Peripherals, RTC1};
use static_cell::StaticCell;

#[cfg(feature = "ble-security")]
mod nrf52840_ble_security;
#[cfg(feature = "ble-security")]
use nrf52840_ble_security::*;
mod nrf52840_ble_runtime;
use nrf52840_ble_runtime::*;

#[cfg(all(feature = "nrf-multi-transport", not(feature = "nrf-ble-mpu-product")))]
mod nrf52840_ble_multi;
#[cfg(feature = "nrf-ble-mpu-product")]
#[path = "nrf52840_ble_mpu_runtime.rs"]
mod nrf52840_ble_multi;
mod nrf52840_ble_poll_tick;
#[cfg(all(feature = "nrf-multi-transport", not(feature = "nrf-ble-mpu-product")))]
use nrf52840_ble_multi::SharedBackend;
#[cfg(feature = "nrf-multi-transport")]
use nrf52840_ble_multi::{SharedArbiter, SharedBleFrontend, usb_fido_task};

const SOFTDEVICE_VECTOR_BASE: u32 = 0x0000_1000;
#[cfg(not(feature = "experimental-ml-dsa-fips204"))]
const BLE_PACKET_LEN: usize = 20;
#[cfg(feature = "experimental-ml-dsa-fips204")]
const BLE_PACKET_LEN: usize = 64;
const MAX_NOTIFY_FRAGMENTS: usize = 20;
#[cfg(feature = "experimental-ml-dsa-fips204")]
const SINK_FRAGMENTS: usize = 1 + manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX
    .saturating_sub(BLE_PACKET_LEN - 3)
    .div_ceil(BLE_PACKET_LEN - 1);
#[cfg(not(feature = "experimental-ml-dsa-fips204"))]
const SINK_FRAGMENTS: usize = MAX_NOTIFY_FRAGMENTS;
const BLE_DEVICE_NAME: &[u8] = b"ManeKey FIDO BLE";
type NotifySink = BleFidoFragmentQueue<SINK_FRAGMENTS, BLE_PACKET_LEN>;
#[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
const DUAL_TASK_GATT_DRAIN_PASSES: usize = 4;

type SelectedDispatcher = NrfSoftdeviceDispatcher<SelectedUserPresence, TextPresenceObserver>;
#[cfg(all(not(feature = "nrf-dual-task"), not(feature = "nrf-multi-transport")))]
type NrfBleBackend = SelectedDispatcher;
#[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
type NrfBleBackend = nrf52840::fido::NrfLocalMailboxBackend;
#[cfg(not(feature = "nrf-multi-transport"))]
type NrfBleFido = BleFidoFrontend<NrfBleBackend>;
#[cfg(feature = "nrf-multi-transport")]
type NrfBleFido = SharedBleFrontend;

#[cfg(not(any(any(), feature = "nrf-ble-mpu-product")))]
global_asm!(
    r#"
    .section .text.SVCall
    .global SVCall
    .type SVCall, %function
    .thumb_func
SVCall:
    tst lr, #4
    ite eq
    mrseq r12, msp
    mrsne r12, psp
    ldr r12, [r12, #24]
    subs r12, r12, #2
    ldrh r12, [r12]
    uxtb r12, r12
    cmp r12, #24
    beq 1f
    movw r12, #0x102c
    movt r12, #0x0000
    ldr r12, [r12]
    bx r12
1:
    movw r12, #0x002c
    movt r12, #0x0000
    ldr r12, [r12]
    bx r12
"#
);

static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static LED: RedLed = RedLed::new();
static SERVER: StaticCell<Server> = StaticCell::new();
static BLE_FIDO: StaticCell<NrfBleFido> = StaticCell::new();

#[nrf_softdevice::gatt_server]
struct Server {
    fido_service: FidoService,
}

#[nrf_softdevice::gatt_service(uuid = "fffd")]
#[cfg(not(feature = "ble-security"))]
struct FidoService {
    #[characteristic(
        uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
        write,
        write_without_response
    )]
    control_point: Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", notify)]
    status: Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read)]
    control_point_length: u16,
    #[characteristic(uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb", read, write)]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read)]
    service_revision: String<8>,
}

#[nrf_softdevice::gatt_service(uuid = "fffd")]
#[cfg(feature = "ble-security")]
struct FidoService {
    #[characteristic(
        uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
        write,
        write_without_response,
        security = "JustWorks"
    )]
    control_point: Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(
        uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb",
        notify,
        security = "JustWorks"
    )]
    status: Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(
        uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        security = "JustWorks"
    )]
    control_point_length: u16,
    #[characteristic(
        uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        write,
        security = "JustWorks"
    )]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read, security = "JustWorks")]
    service_revision: String<8>,
}

#[entry]
/// Initialize static product state once with the matching S140 image and reserved Flash/RAM layout.
/// Exclude independent owners of SoftDevice peripherals, vectors and interrupts.
fn main() -> ! {
    let runtime = initialize();
    let sd = runtime.sd;
    let server = runtime.server;
    let fido = runtime.fido;
    #[cfg(feature = "nrf-multi-transport")]
    let usbd = runtime.usbd;
    #[cfg(feature = "nrf-multi-transport")]
    let arbiter = runtime.arbiter;
    #[cfg(feature = "nrf-dual-task")]
    let worker = runtime.worker;
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(softdevice_task(sd).unwrap());
        #[cfg(all(feature = "nrf-dual-task", feature = "nrf-multi-transport"))]
        spawner.spawn(trusted_worker_task(worker).unwrap());
        #[cfg(feature = "nrf-multi-transport")]
        spawner.spawn(usb_fido_task(usbd, arbiter).unwrap());
        spawner.spawn(
            advertise_task(
                sd,
                server,
                fido,
                #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
                worker,
            )
            .unwrap(),
        );
    });
}
struct Runtime {
    sd: &'static Softdevice,
    server: &'static Server,
    fido: &'static mut NrfBleFido,
    #[cfg(feature = "nrf-multi-transport")]
    usbd: nrf52840_pac::USBD,
    #[cfg(feature = "nrf-multi-transport")]
    arbiter: &'static SharedArbiter,
    #[cfg(feature = "nrf-dual-task")]
    worker: &'static mut NrfLocalTrustedWorker<SelectedDispatcher>,
}
#[inline(never)]
fn initialize() -> Runtime {
    set_vtor(BOARD.app_flash_origin);
    let peripherals = Peripherals::take().unwrap();
    LED.init(peripherals.P0);
    uart_init();

    log("boot");
    configure_selected_user_presence(uart_write_str);
    LED.blink(2);

    prepare_softdevice_bootloader_forwarding();

    let sd_config = nrf_softdevice::Config {
        clock: Some(raw::nrf_clock_lf_cfg_t {
            source: raw::NRF_CLOCK_LF_SRC_RC as u8,
            rc_ctiv: 16,
            rc_temp_ctiv: 2,
            accuracy: raw::NRF_CLOCK_LF_ACCURACY_500_PPM as u8,
        }),
        conn_gatts: Some(raw::ble_gatts_conn_cfg_t {
            hvn_tx_queue_size: MAX_NOTIFY_FRAGMENTS as u8,
        }),
        conn_gatt: Some(raw::ble_gatt_conn_cfg_t {
            att_mtu: (BLE_PACKET_LEN + 3) as u16,
        }),
        gap_device_name: Some(gap_device_name_config()),
        ..Default::default()
    };

    log("enable softdevice");
    set_vtor(SOFTDEVICE_VECTOR_BASE);
    let sd = Softdevice::enable(&sd_config);
    set_vtor(BOARD.app_flash_origin);
    log("softdevice enabled");
    LED.success_pulse();

    let server = match Server::new(sd) {
        Ok(server) => {
            log("gatt server registered");
            server
        }
        Err(_) => {
            log("gatt server register failed");
            LED.error_fast();
        }
    };
    log("gatt init values begin");
    init_fido_service_values(&server);
    log("gatt init values done");
    let server = SERVER.init(server);

    #[cfg(not(feature = "nrf-multi-transport"))]
    log("dispatcher build begin");
    #[cfg(not(feature = "nrf-multi-transport"))]
    let dispatcher =
        match build_dispatcher(sd, peripherals.NVMC, peripherals.FICR, peripherals.RTC1) {
            Ok(dispatcher) => dispatcher,
            Err(_) => {
                log("rng init failed");
                LED.error_fast();
            }
        };
    #[cfg(not(feature = "nrf-multi-transport"))]
    log("dispatcher build done");

    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    static WORKER: StaticCell<NrfLocalTrustedWorker<SelectedDispatcher>> = StaticCell::new();
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    let worker = WORKER.init(NrfLocalTrustedWorker::new(dispatcher));

    #[cfg(feature = "nrf-multi-transport")]
    let initialized =
        initialize_shared_backend(sd, peripherals.NVMC, peripherals.FICR, peripherals.RTC1);
    #[cfg(feature = "nrf-multi-transport")]
    let arbiter = initialized.arbiter;
    #[cfg(all(feature = "nrf-multi-transport", feature = "nrf-dual-task"))]
    let worker = initialized.worker;

    #[cfg(all(not(feature = "nrf-dual-task"), not(feature = "nrf-multi-transport")))]
    let fido_backend = dispatcher;
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    let fido_backend = local_mailbox_backend();

    #[cfg(not(feature = "nrf-multi-transport"))]
    let fido = BLE_FIDO.init(BleFidoFrontend::new(BLE_PACKET_LEN, fido_backend));
    #[cfg(feature = "nrf-multi-transport")]
    let fido = BLE_FIDO.init(SharedBleFrontend::new(arbiter));
    log("ble frontend built");
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    log("boundary=nrf-local-mailbox");
    #[cfg(all(
        feature = "nrf-multi-transport",
        not(feature = "nrf-dual-task"),
        not(feature = "nrf-ble-mpu-product")
    ))]
    log("boundary=direct-usb-ble-arbiter");
    #[cfg(feature = "nrf-ble-mpu-product")]
    log("boundary=nrf-mpu-thread-copy-mailbox");
    #[cfg(all(feature = "nrf-multi-transport", feature = "nrf-dual-task"))]
    log("boundary=nrf-local-mailbox-usb-ccid-ble-arbiter");
    let sd: &'static Softdevice = sd;

    #[cfg(feature = "nrf-ble-mpu-product")]
    nrf52840_ble_multi::initialize_permissions();
    nrf52840_ble_poll_tick::start(peripherals.RTC2);
    #[cfg(feature = "nrf-internal-uart")]
    nrf52840::internal_uart::start();

    Runtime {
        sd,
        server,
        fido,
        #[cfg(feature = "nrf-multi-transport")]
        usbd: peripherals.USBD,
        #[cfg(feature = "nrf-multi-transport")]
        arbiter,
        #[cfg(feature = "nrf-dual-task")]
        worker,
    }
}

#[cfg(feature = "nrf-multi-transport")]
struct SharedRuntime {
    arbiter: &'static SharedArbiter,
    #[cfg(feature = "nrf-dual-task")]
    worker: &'static mut NrfLocalTrustedWorker<SelectedDispatcher>,
}

#[cfg(feature = "nrf-multi-transport")]
#[inline(never)]
fn initialize_shared_backend(
    sd: &'static Softdevice,
    nvmc: nrf52840_pac::NVMC,
    ficr: nrf52840_pac::FICR,
    rtc: nrf52840_pac::RTC1,
) -> SharedRuntime {
    log("dispatcher build begin");
    let dispatcher = match build_dispatcher(sd, nvmc, ficr, rtc) {
        Ok(dispatcher) => dispatcher,
        Err(_) => {
            log("rng init failed");
            LED.error_fast();
        }
    };
    #[cfg(feature = "nrf-ble-mpu-product")]
    {
        return SharedRuntime {
            arbiter: nrf52840_ble_multi::initialize_backend(dispatcher),
        };
    }
    #[cfg(not(feature = "nrf-ble-mpu-product"))]
    {
        #[cfg(feature = "nrf-dual-task")]
        static WORKER: StaticCell<NrfLocalTrustedWorker<SelectedDispatcher>> = StaticCell::new();
        #[cfg(feature = "nrf-dual-task")]
        let worker = WORKER.init(NrfLocalTrustedWorker::new(dispatcher));
        #[cfg(feature = "nrf-dual-task")]
        let backend: SharedBackend = local_mailbox_backend();
        #[cfg(not(feature = "nrf-dual-task"))]
        let backend: SharedBackend = dispatcher;
        static ARBITER: StaticCell<SharedArbiter> = StaticCell::new();
        let arbiter = ARBITER.init(embassy_sync::blocking_mutex::Mutex::new(RefCell::new(
            manekey::frontend::ingress::IngressArbiter::new(backend),
        )));
        log("dispatcher build done");
        SharedRuntime {
            arbiter,
            #[cfg(feature = "nrf-dual-task")]
            worker,
        }
    }
}

fn prepare_softdevice_bootloader_forwarding() {
    log("prepare softdevice forwarding");
    let irq_forward_ret = set_mbr_irq_forwarding(BOARD.app_flash_origin);
    log_word("mbr_irq_forward_ret", irq_forward_ret);
    let mbr_ret = init_softdevice_forwarding();
    log_word("mbr_init_sd_ret", mbr_ret);
    let vector_base_ret =
        unsafe { raw::sd_softdevice_vector_table_base_set(BOARD.app_flash_origin) };
    log_word("sd_vector_base_ret", vector_base_ret);
    if irq_forward_ret != 0 || mbr_ret != 0 || vector_base_ret != 0 {
        LED.error_fast();
    }
}

fn gap_device_name_config() -> raw::ble_gap_cfg_device_name_t {
    raw::ble_gap_cfg_device_name_t {
        write_perm: nrf_softdevice::ble::SecurityMode::NoAccess.into_raw(),
        _bitfield_1: raw::ble_gap_cfg_device_name_t::new_bitfield_1(
            raw::BLE_GATTS_VLOC_STACK as u8,
        ),
        p_value: BLE_DEVICE_NAME.as_ptr() as *mut u8,
        current_len: BLE_DEVICE_NAME.len() as u16,
        max_len: BLE_DEVICE_NAME.len() as u16,
    }
}

fn init_fido_service_values(server: &Server) {
    log("set control point length");
    if server
        .fido_service
        .control_point_length_set(&(BLE_PACKET_LEN as u16))
        .is_err()
    {
        log("set control point length failed");
    }
    log("set revision bitfield");
    if server
        .fido_service
        .service_revision_bitfield_set(&FIDO2_SERVICE_REVISION_BIT)
        .is_err()
    {
        log("set revision bitfield failed");
    }
    log("set revision string");
    let mut revision = String::<8>::new();
    if revision.push_str(FIDO_SERVICE_REVISION).is_err() {
        log("revision string build failed");
    }
    if server.fido_service.service_revision_set(&revision).is_err() {
        log("set revision string failed");
    }
}

fn build_dispatcher(
    sd: &'static Softdevice,
    nvmc: NVMC,
    ficr: FICR,
    rtc1: RTC1,
) -> Result<SelectedDispatcher, EntropyError> {
    let mut entropy = HmacDrbgEntropy::new(SoftdeviceEntropy::new(sd))?;
    let mut records = selected_softdevice_storage(nvmc, uart_write_str);
    let (key_store, pin_uv_auth) =
        selected_softdevice_crypto_backends(ficr, rtc1, uart_write_str, &mut records, &mut entropy);
    Ok(
        TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            selected_user_presence(uart_write_str, true, BLE_UP_TIMEOUT_POLLS),
            UnavailableUserVerification,
            pin_uv_auth,
            key_store,
            entropy,
            #[cfg(not(feature = "nrf-multi-transport"))]
            transport::BLE_TRANSPORTS,
            #[cfg(feature = "nrf-multi-transport")]
            transport::USB_BLE_TRANSPORTS,
            TextPresenceObserver::new(uart_write_str),
        ),
    )
}

#[embassy_executor::task]
async fn advertise_task(
    sd: &'static Softdevice,
    server: &'static Server,
    fido: &'static mut NrfBleFido,
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    worker: &'static mut NrfLocalTrustedWorker<SelectedDispatcher>,
) {
    log("fido advertise task");
    LED.blink(3);

    let profile = FidoBleProfile::manekey();
    let mut adv_data = [0u8; 31];
    let adv_len = encode_adv_or_latch(profile, &mut adv_data);
    let mut scan_data = [0u8; 31];
    let scan_len = encode_scan_or_latch(profile, &mut scan_data);
    let adv = ConnectableAdvertisement::ScannableUndirected {
        adv_data: &adv_data[..adv_len],
        scan_data: &scan_data[..scan_len],
    };
    let adv_config = peripheral::Config::default();

    loop {
        log("advertise start");
        LED.success_pulse();
        match advertise_fido_connectable(sd, adv, &adv_config).await {
            Ok(conn) => {
                log("advertise connected");
                #[cfg(feature = "ble-security")]
                {
                    log("ble security mode on connect");
                    log_security_mode(conn.security_mode());
                    if let Some(flags) = BLE_BOND_CACHE.cached_peer_addr_flags() {
                        log("ble bond cache present");
                        log_word("ble bond cached addr_flags", flags as u32);
                    } else {
                        log("ble bond cache empty");
                    }
                }
                #[cfg(feature = "ble-bonded-only")]
                if !is_allowed_bonded_peer(&conn) {
                    let _ = conn.disconnect();
                    log("ble bonded-only disconnected peer");
                    continue;
                }
                LED.success_pulse();
                run_gatt_connection(
                    &conn,
                    server,
                    fido,
                    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
                    worker,
                )
                .await;
                #[cfg(all(feature = "ble-security", feature = "nrf-flash-storage"))]
                persist_pending_bond_record();
                log("advertise disconnected");
            }
            Err(_) => {
                log("advertise error");
                LED.error_slow();
            }
        }
    }
}

#[cfg(not(feature = "ble-security"))]
async fn advertise_fido_connectable<'a>(
    sd: &'a Softdevice,
    adv: ConnectableAdvertisement<'a>,
    adv_config: &'a peripheral::Config,
) -> Result<Connection, peripheral::AdvertiseError> {
    peripheral::advertise_connectable(sd, adv, adv_config).await
}

#[cfg(feature = "ble-security")]
async fn advertise_fido_connectable<'a>(
    sd: &'a Softdevice,
    adv: ConnectableAdvertisement<'a>,
    adv_config: &'a peripheral::Config,
) -> Result<Connection, peripheral::AdvertiseError> {
    peripheral::advertise_pairable(sd, adv, adv_config, &BLE_SECURITY_HANDLER).await
}

fn encode_adv_or_latch(profile: FidoBleProfile, out: &mut [u8; 31]) -> usize {
    match profile.encode_legacy_advertising_data(out) {
        Ok(len) => len,
        Err(_) => {
            log("adv data encode failed");
            LED.error_fast();
        }
    }
}

fn encode_scan_or_latch(profile: FidoBleProfile, out: &mut [u8; 31]) -> usize {
    match profile.encode_legacy_scan_response(out) {
        Ok(len) => len,
        Err(_) => {
            log("scan data encode failed");
            LED.error_fast();
        }
    }
}

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) {
    sd.run().await;
}

#[cfg(all(feature = "nrf-dual-task", feature = "nrf-multi-transport"))]
#[embassy_executor::task]
async fn trusted_worker_task(worker: &'static mut NrfLocalTrustedWorker<SelectedDispatcher>) {
    let mut previous = nrf52840_ble_poll_tick::current();
    loop {
        let _ = worker.pump_once(&NRF_MAILBOX);
        previous = nrf52840_ble_poll_tick::worker_wait_after(previous).await;
    }
}

/// One connection owns this frontend; ticker and worker must continue while requests are pending.
async fn run_gatt_connection(
    conn: &Connection,
    server: &Server,
    fido: &mut NrfBleFido,
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    worker: &mut NrfLocalTrustedWorker<SelectedDispatcher>,
) {
    struct ConnectionState<'a> {
        fido: &'a mut NrfBleFido,
        tx: manekey::transport::ble::BleNotificationEgress<SINK_FRAGMENTS, BLE_PACKET_LEN>,
        blocked_ticks: u16,
        #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
        worker: &'a mut NrfLocalTrustedWorker<SelectedDispatcher>,
    }

    let state = RefCell::new(ConnectionState {
        fido,
        tx: manekey::transport::ble::BleNotificationEgress::new(),
        blocked_ticks: 0,
        #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
        worker,
    });
    let gatt = gatt_server::run(conn, server, |event| {
        let mut state = state.borrow_mut();
        let state = &mut *state;
        let Some(notify_sink) = state.tx.sink() else {
            let _ = conn.disconnect();
            return;
        };
        handle_fido_gatt_event(
            event,
            state.fido,
            notify_sink,
            #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
            state.worker,
        );
        if send_notifications(conn, server, &mut state.tx).is_err() {
            let _ = conn.disconnect();
        }
    });
    let polling = async {
        let mut previous = nrf52840_ble_poll_tick::current();
        loop {
            previous = nrf52840_ble_poll_tick::wait_after(previous).await;
            let mut state = state.borrow_mut();
            match send_notifications(conn, server, &mut state.tx) {
                Ok(true) => state.blocked_ticks = 0,
                Ok(false) => {
                    state.blocked_ticks += 1;
                    if state.blocked_ticks >= 100 {
                        let _ = conn.disconnect();
                        return;
                    }
                    continue;
                }
                Err(_) => {
                    let _ = conn.disconnect();
                    return;
                }
            }
            #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
            let _ = state.worker.pump_once(&NRF_MAILBOX);
            let ConnectionState { fido, tx, .. } = &mut *state;
            if fido
                .poll_status::<BLE_PACKET_LEN>(tx.sink().unwrap())
                .is_err()
            {
                log("ble periodic poll error");
            }
            if send_notifications(conn, server, tx).is_err() {
                let _ = conn.disconnect();
                return;
            }
        }
    };
    let _ = select(gatt, polling).await;
    nrf52840_ble_poll_tick::clear_waiter();
    let mut connection_state = state.borrow_mut();
    connection_state.fido.on_disconnect();
    #[cfg(feature = "nrf-multi-transport")]
    {
        drop(connection_state);
        let mut previous = nrf52840_ble_poll_tick::current();
        let mut settled = false;
        for _ in 0..8 {
            previous = nrf52840_ble_poll_tick::wait_after(previous).await;
            let mut connection_state = state.borrow_mut();
            if connection_state.fido.settle_disconnected_backend() {
                settled = true;
                break;
            }
        }
        if !settled {
            log("ble disconnect cancel pending");
        }
    }
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    {
        let mut settled = false;
        for _ in 0..8 {
            let _ = connection_state.worker.pump_once(&NRF_MAILBOX);
            if connection_state.fido.settle_disconnected_backend() {
                settled = true;
                break;
            }
        }
        if !settled {
            log("ble disconnect cancel pending");
        }
    }
}

fn handle_fido_gatt_event(
    event: ServerEvent,
    fido: &mut NrfBleFido,
    notify_sink: &mut NotifySink,
    #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
    worker: &mut NrfLocalTrustedWorker<SelectedDispatcher>,
) {
    match event {
        ServerEvent::FidoService(FidoServiceEvent::ControlPointWrite(data)) => {
            log("gatt control point write");
            #[cfg(all(feature = "nrf-dual-task", not(feature = "nrf-multi-transport")))]
            {
                if handle_control_point_write_and_drain::<BLE_PACKET_LEN>(
                    fido,
                    &data,
                    notify_sink,
                    DUAL_TASK_GATT_DRAIN_PASSES,
                    || {
                        let _ = worker.pump_once(&NRF_MAILBOX);
                    },
                )
                .is_err()
                {
                    log("ble fido write/drain error");
                }
            }
            #[cfg(any(not(feature = "nrf-dual-task"), feature = "nrf-multi-transport"))]
            {
                if handle_control_point_write_and_drain::<BLE_PACKET_LEN>(
                    fido,
                    &data,
                    notify_sink,
                    1,
                    || {},
                )
                .is_err()
                {
                    log("ble fido write/drain error");
                }
            }
        }
        ServerEvent::FidoService(FidoServiceEvent::ServiceRevisionBitfieldWrite(_)) => {
            log("gatt revision bitfield write");
        }
        ServerEvent::FidoService(FidoServiceEvent::StatusCccdWrite { notifications }) => {
            fido.on_status_subscription(notifications);
            if notifications {
                log("gatt notify enabled");
            } else {
                log("gatt notify disabled");
            }
        }
    }
}

/// Advances only on controller acceptance; success does not acknowledge peer delivery.
fn send_notifications(
    conn: &Connection,
    server: &Server,
    tx: &mut manekey::transport::ble::BleNotificationEgress<SINK_FRAGMENTS, BLE_PACKET_LEN>,
) -> Result<bool, gatt_server::NotifyValueError> {
    tx.flush(|fragment| {
        let mut value = Vec::<u8, BLE_PACKET_LEN>::new();
        if value.extend_from_slice(fragment).is_err() {
            log("notify value build failed");
            return Err(gatt_server::NotifyValueError::Raw(
                nrf_softdevice::RawError::DataSize,
            ));
        }
        match server.fido_service.status_notify(conn, &value) {
            Ok(()) => Ok(true),
            Err(gatt_server::NotifyValueError::Raw(nrf_softdevice::RawError::Resources)) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    })
}
