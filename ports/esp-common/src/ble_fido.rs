use embassy_futures::{
    join::join,
    select::{Either, select},
};
use embassy_time::Timer;
use esp_hal::{
    gpio::Output,
    interrupt::software::SoftwareInterruptControl,
    peripherals::{BT, SW_INTERRUPT, TIMG0},
    timer::timg::TimerGroup,
};
use esp_radio::ble::controller::BleConnector;
use heapless::Vec;
use log::{info, warn};
use manekey::transport::ble::{
    BleBondAdmission, BleBondStore, BleFidoFragmentQueue, BleFidoProfileHandler,
    FIDO_SERVICE_REVISION, FIDO2_SERVICE_REVISION_BIT, FidoBleProfile, StoredBleBond,
    StoredBleSecurityLevel, handle_control_point_write_at_offset_and_drain,
    notification_fragment_vec,
};
use trouble_host::prelude::*;

pub const BLE_PACKET_LEN: usize = 64;
#[cfg(feature = "ble-security")]
pub const BLE_BOND_MAX_RESTORED: usize = 4;

pub fn profile_for_esp_mac(mac: [u8; 6]) -> FidoBleProfile {
    let mut profile = FidoBleProfile::manekey();

    profile.address = [
        mac[5],
        mac[4],
        mac[3],
        mac[2],
        mac[1],
        (mac[0] & 0x3f) | 0xc0,
    ];
    profile
}

fn profile_for_local_esp() -> FidoBleProfile {
    profile_for_esp_mac(
        esp_hal::efuse::base_mac_address()
            .as_bytes()
            .try_into()
            .expect("ESP base MAC has six bytes"),
    )
}

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
))]
const MAX_NOTIFY_FRAGMENTS: usize = 66;
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
const MAX_NOTIFY_FRAGMENTS: usize = 20;

pub type EspBleController = ExternalController<BleConnector<'static>, 1>;
pub type EspBleHostResources =
    HostResources<EspBleController, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX>;

type NotifySink = BleFidoFragmentQueue<MAX_NOTIFY_FRAGMENTS, BLE_PACKET_LEN>;

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
    let StoredBleBond {
        ltk,
        bd_addr,
        bd_addr_kind,
        irk,
        is_bonded,
        security_level,
    } = bond;
    let kind = AddrKind::new(bd_addr_kind);
    trouble_host::BondInformation::new(
        trouble_host::Identity {
            addr: Address::new(kind, BdAddr::new(bd_addr)),
            irk: irk.and_then(trouble_host::IdentityResolvingKey::from_le_bytes),
        },
        trouble_host::LongTermKey::from_le_bytes(ltk),
        stored_security_level_to_trouble(security_level),
        is_bonded,
    )
}

/// Initializes radio scheduling; this does not provide trusted RAM isolation.
pub fn start_ble_rtos(timg0: TIMG0<'static>, sw_interrupt: SW_INTERRUPT<'static>) {
    let timg0 = TimerGroup::new(timg0);
    let sw_int = SoftwareInterruptControl::new(sw_interrupt);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);
}

pub fn build_ble_controller(bt: BT<'static>) -> EspBleController {
    let connector = BleConnector::new(bt, Default::default()).unwrap();
    ExternalController::new(connector)
}

#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb", write)]
    control_point: Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", notify)]
    status: Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read, value = BLE_PACKET_LEN as u16)]
    control_point_length: u16,
    #[characteristic(uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb", read, write, value = FIDO2_SERVICE_REVISION_BIT)]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read, value = FIDO_SERVICE_REVISION)]
    service_revision: &'static str,
}

#[cfg(feature = "ble-security")]
mod encrypted {
    use super::*;

    #[gatt_server]
    pub(super) struct Server {
        pub(super) fido_service: FidoService,
    }

    #[gatt_service(uuid = "fffd")]
    pub(super) struct FidoService {
        #[characteristic(
            uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
            write,
            permissions(write = encrypted)
        )]
        pub(super) control_point: Vec<u8, BLE_PACKET_LEN>,
        #[characteristic(
            uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb",
            notify,
            permissions(cccd = encrypted)
        )]
        pub(super) status: Vec<u8, BLE_PACKET_LEN>,
        #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read, value = BLE_PACKET_LEN as u16)]
        pub(super) control_point_length: u16,
        #[characteristic(
            uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
            read,
            write,
            value = FIDO2_SERVICE_REVISION_BIT
        )]
        pub(super) service_revision_bitfield: u8,
        #[characteristic(uuid = "2a28", read, value = FIDO_SERVICE_REVISION)]
        pub(super) service_revision: &'static str,
    }
}

pub async fn run_ble_peripheral<C, T>(controller: C, led: Output<'static>, fido: T) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
{
    run_ble_peripheral_with_profile(controller, led, fido, profile_for_local_esp()).await
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted<C, T>(controller: C, led: Output<'static>, fido: T) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
{
    run_ble_peripheral_encrypted_with_bond_store(controller, led, fido, ()).await
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted_with_bond_store<C, T, B>(
    controller: C,
    led: Output<'static>,
    fido: T,
    bond_store: B,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    B: BleBondStore,
{
    run_ble_peripheral_encrypted_with_profile_and_bond_store(
        controller,
        led,
        fido,
        profile_for_local_esp(),
        bond_store,
    )
    .await
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted_with_bond_store_using_resources<C, T, B>(
    controller: C,
    led: Output<'static>,
    fido: T,
    bond_store: B,
    resources: &mut HostResources<C, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX>,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    B: BleBondStore,
{
    run_ble_peripheral_encrypted_with_profile_service_and_bond_store_using_resources(
        controller,
        led,
        fido,
        profile_for_local_esp(),
        || {},
        bond_store,
        resources,
    )
    .await
}

pub async fn run_ble_peripheral_with_service<C, T, S>(
    controller: C,
    led: Output<'static>,
    fido: T,
    service: S,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    S: FnMut(),
{
    run_ble_peripheral_with_profile_and_service(
        controller,
        led,
        fido,
        profile_for_local_esp(),
        service,
    )
    .await
}

pub async fn run_ble_peripheral_with_profile<C, T>(
    controller: C,
    led: Output<'static>,
    fido: T,
    profile: FidoBleProfile,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
{
    run_ble_peripheral_with_profile_and_service(controller, led, fido, profile, || {}).await
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted_with_profile<C, T>(
    controller: C,
    led: Output<'static>,
    fido: T,
    profile: FidoBleProfile,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
{
    run_ble_peripheral_encrypted_with_profile_and_bond_store(controller, led, fido, profile, ())
        .await
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted_with_profile_and_bond_store<C, T, B>(
    controller: C,
    led: Output<'static>,
    fido: T,
    profile: FidoBleProfile,
    bond_store: B,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    B: BleBondStore,
{
    run_ble_peripheral_encrypted_with_profile_service_and_bond_store(
        controller,
        led,
        fido,
        profile,
        || {},
        bond_store,
    )
    .await
}

/// Pairable unencrypted GATT runner; service must be nonblocking and serialized with the frontend.
pub async fn run_ble_peripheral_with_profile_and_service<C, T, S>(
    controller: C,
    mut led: Output<'static>,
    mut fido: T,
    profile: FidoBleProfile,
    mut service: S,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    S: FnMut(),
{
    let address = Address::random(profile.address);
    info!("BLE random address configured");

    let mut resources: HostResources<C, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let host = stack.build();
    let runner = host.runner();
    let mut peripheral = host.peripheral();

    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: core::str::from_utf8(profile.device_name).unwrap_or("ManeKey FIDO BLE"),
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();

    info!("starting FIDO BLE advertising");
    let _ = join(ble_runner(runner), async {
        loop {
            led.set_high();
            match advertise(&mut peripheral, &server, &profile).await {
                Ok(conn) => {
                    info!("FIDO BLE connection established");
                    led.toggle();
                    let _ = gatt_events(
                        #[cfg(feature = "ble-security")]
                        &host,
                        &conn,
                        server.fido_service.control_point.handle,
                        &server.fido_service.status,
                        server.fido_service.control_point_length.handle,
                        server.fido_service.service_revision_bitfield.handle,
                        &mut fido,
                        &mut service,
                        #[cfg(feature = "ble-security")]
                        &mut (),
                        BleBondAdmission::Pairable,
                    )
                    .await;
                    info!("FIDO BLE connection closed");
                }
                Err(e) => {
                    warn!("FIDO BLE advertise error: {:?}", e);
                    led.set_low();
                    Timer::after_secs(1).await;
                }
            }
        }
    })
    .await;

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted_with_profile_and_service<C, T, S>(
    controller: C,
    led: Output<'static>,
    fido: T,
    profile: FidoBleProfile,
    service: S,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    S: FnMut(),
{
    run_ble_peripheral_encrypted_with_profile_service_and_bond_store(
        controller,
        led,
        fido,
        profile,
        service,
        (),
    )
    .await
}

#[cfg(feature = "ble-security")]
pub async fn run_ble_peripheral_encrypted_with_profile_service_and_bond_store<C, T, S, B>(
    controller: C,
    led: Output<'static>,
    fido: T,
    profile: FidoBleProfile,
    service: S,
    bond_store: B,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    S: FnMut(),
    B: BleBondStore,
{
    let mut resources = HostResources::new();
    run_ble_peripheral_encrypted_with_profile_service_and_bond_store_using_resources(
        controller,
        led,
        fido,
        profile,
        service,
        bond_store,
        &mut resources,
    )
    .await
}

#[cfg(feature = "ble-security")]
/// Encrypted GATT with NoInputNoOutput pairing, not authenticated physical identity.
/// Caller owns bond protection; restore/store failures are logged rather than durable-persistence guarantees.
pub async fn run_ble_peripheral_encrypted_with_profile_service_and_bond_store_using_resources<
    C,
    T,
    S,
    B,
>(
    controller: C,
    mut led: Output<'static>,
    mut fido: T,
    profile: FidoBleProfile,
    mut service: S,
    mut bond_store: B,
    resources: &mut HostResources<C, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX>,
) -> !
where
    C: Controller,
    T: BleFidoProfileHandler,
    S: FnMut(),
    B: BleBondStore,
{
    let address = Address::random(profile.address);
    info!("BLE encrypted random address configured");

    let stack = trouble_host::new(controller, resources)
        .set_random_address(address)
        .set_io_capabilities(IoCapabilities::NoInputNoOutput);
    let host = stack.build();
    restore_ble_bonds(&host, &mut bond_store);
    log_stack_bond_count(&host, "after restore");
    let runner = host.runner();
    let mut peripheral = host.peripheral();

    let server = encrypted::Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: core::str::from_utf8(profile.device_name).unwrap_or("ManeKey FIDO BLE"),
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();

    info!("starting encrypted FIDO BLE advertising");

    #[allow(unexpected_cfgs)]
    let admission = BleBondAdmission::from_bonded_only(cfg!(feature = "ble-bonded-only"));
    let _ = join(ble_runner(runner), async {
        loop {
            led.set_high();
            match advertise_encrypted(&mut peripheral, &server, &profile).await {
                Ok(conn) => {
                    info!("encrypted FIDO BLE connection established");
                    let raw = conn.raw();
                    let is_bonded_peer = raw.is_bonded_peer();
                    info!(
                        "BLE bonded_peer={} security_level={:?}",
                        is_bonded_peer,
                        raw.security_level()
                    );
                    if let Err(e) = raw.set_bondable(admission.permits_new_bond()) {
                        warn!("failed to mark BLE connection bondable: {:?}", e);
                    }
                    match raw.bondable() {
                        Ok(bondable) => info!("BLE connection bondable={}", bondable),
                        Err(e) => warn!("failed to read BLE bondable state: {:?}", e),
                    }
                    if !admission.permits_peer(is_bonded_peer) {
                        warn!("BLE bonded-only mode rejected unbonded peer");
                        raw.disconnect();
                        continue;
                    }
                    led.toggle();
                    let _ = gatt_events(
                        &host,
                        &conn,
                        server.fido_service.control_point.handle,
                        &server.fido_service.status,
                        server.fido_service.control_point_length.handle,
                        server.fido_service.service_revision_bitfield.handle,
                        &mut fido,
                        &mut service,
                        &mut bond_store,
                        admission,
                    )
                    .await;
                    info!("encrypted FIDO BLE connection closed");
                }
                Err(e) => {
                    warn!("encrypted FIDO BLE advertise error: {:?}", e);
                    led.set_low();
                    Timer::after_secs(1).await;
                }
            }
        }
    })
    .await;

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "ble-security")]
fn restore_ble_bonds<C: Controller, B: BleBondStore>(
    stack: &Stack<'_, C, DefaultPacketPool>,
    bond_store: &mut B,
) {
    let mut restored = 0usize;
    bond_store.load_bonds(|record| {
        if restored >= BLE_BOND_MAX_RESTORED {
            warn!("BLE bond restore skipped: restore limit reached");
            return;
        }
        match stack.add_bond_information(stored_ble_bond_to_trouble(record)) {
            Ok(()) => {
                restored += 1;
            }
            Err(e) => warn!("BLE bond restore failed: {:?}", e),
        }
    });
    if restored > 0 {
        info!("BLE restored {} bond(s)", restored);
    }
}

#[cfg(feature = "ble-security")]
fn log_stack_bond_count<C: Controller>(stack: &Stack<'_, C, DefaultPacketPool>, context: &str) {
    stack.with_bond_information(|bonds| {
        info!("BLE stack bonds {}: count={}", context, bonds.len());
        for (index, bond) in bonds.iter().enumerate() {
            info!(
                "BLE stack bond[{}] addr={:?} has_irk={} is_bonded={} security_level={:?}",
                index,
                bond.identity.addr,
                bond.identity.irk.is_some(),
                bond.is_bonded,
                bond.security_level
            );
        }
    });
}

async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
    loop {
        if let Err(e) = runner.run().await {
            panic!("BLE runner error: {:?}", e);
        }
    }
}

async fn advertise<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server Server<'values>,
    profile: &FidoBleProfile,
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
    info!("FIDO BLE advertising active");
    Ok(advertiser.accept().await?.with_attribute_server(server)?)
}

#[cfg(feature = "ble-security")]
async fn advertise_encrypted<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server encrypted::Server<'values>,
    profile: &FidoBleProfile,
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
    info!("encrypted FIDO BLE advertising active");
    Ok(advertiser.accept().await?.with_attribute_server(server)?)
}

async fn gatt_events<P: PacketPool, T: BleFidoProfileHandler>(
    #[cfg(feature = "ble-security")] stack: &Stack<'_, impl Controller, DefaultPacketPool>,
    conn: &GattConnection<'_, '_, P>,
    control_point_handle: u16,
    status: &Characteristic<Vec<u8, BLE_PACKET_LEN>>,
    control_point_length_handle: u16,
    service_revision_bitfield_handle: u16,
    fido: &mut T,
    service: &mut impl FnMut(),
    #[cfg(feature = "ble-security")] bond_store: &mut impl BleBondStore,
    admission: BleBondAdmission,
) -> Result<(), Error> {
    let reason = loop {
        match select(conn.next(), Timer::after_millis(100)).await {
            Either::First(GattConnectionEvent::Disconnected { reason }) => break reason,
            #[cfg(feature = "ble-security")]
            Either::First(GattConnectionEvent::PairingComplete {
                security_level,
                bond,
            }) => {
                if !admission.permits_new_bond() {
                    warn!("BLE bonded-only mode rejected fresh pairing");
                    conn.raw().disconnect();
                    continue;
                }
                if let Some(bond) = bond.as_ref() {
                    let record = stored_ble_bond_from_trouble(bond);
                    let encoded = record.encode();
                    let stored = bond_store.store_bond(record);
                    info!(
                        "BLE pairing complete security_level={:?} bonded=true bond_record_len={} has_irk={} stored={}",
                        security_level,
                        encoded.len(),
                        record.irk.is_some(),
                        stored
                    );
                } else {
                    info!(
                        "BLE pairing complete security_level={:?} bonded=false",
                        security_level
                    );
                }
                log_stack_bond_count(stack, "after PairingComplete");
            }
            #[cfg(feature = "ble-security")]
            Either::First(GattConnectionEvent::PairingFailed(e)) => {
                warn!("BLE pairing failed: {:?}", e);
            }
            #[cfg(feature = "ble-security")]
            Either::First(GattConnectionEvent::Encrypted {
                security_level,
                bond,
            }) => {
                info!(
                    "BLE encrypted security_level={:?} bond_present={}",
                    security_level,
                    bond.is_some()
                );
                log_stack_bond_count(stack, "after Encrypted");
            }
            #[cfg(feature = "ble-security")]
            Either::First(GattConnectionEvent::BondLost) => {
                warn!("BLE bond lost");
                let identity = conn.raw().peer_identity();
                let removed = stack.remove_bond_information(identity).is_ok();
                let cleared = bond_store.clear_bonds();
                warn!(
                    "BLE stale bond removed={} persistent_cleared={}",
                    removed, cleared
                );
                log_stack_bond_count(stack, "after BondLost");
                conn.raw().disconnect();
            }
            Either::First(GattConnectionEvent::Gatt { event }) => {
                service();
                let mut notify_sink = NotifySink::new();
                handle_fido_gatt_event(
                    &event,
                    control_point_handle,
                    control_point_length_handle,
                    service_revision_bitfield_handle,
                    fido,
                    &mut notify_sink,
                );

                match event.accept() {
                    Ok(reply) => reply.send().await,
                    Err(e) => warn!("GATT reply error: {:?}", e),
                };

                send_notifications(conn, status, &notify_sink).await;
                service();
            }
            Either::First(_) => {}
            Either::Second(_) => {
                service();
                let mut notify_sink = NotifySink::new();
                if let Err(e) = fido.poll_status::<BLE_PACKET_LEN>(&mut notify_sink) {
                    warn!("BLE FIDO poll error: {:?}", e);
                }
                send_notifications(conn, status, &notify_sink).await;
                service();
            }
        }
    };
    info!("GATT disconnected: {:?}", reason);
    fido.on_disconnect();
    for _ in 0..500 {
        service();
        if fido.settle_disconnected_backend() {
            return Ok(());
        }
        Timer::after_millis(2).await;
    }
    warn!("BLE disconnected backend cancellation did not settle");
    Ok(())
}

fn handle_fido_gatt_event<P: PacketPool, T: BleFidoProfileHandler>(
    event: &GattEvent<'_, '_, P>,
    control_point_handle: u16,
    control_point_length_handle: u16,
    service_revision_bitfield_handle: u16,
    fido: &mut T,
    notify_sink: &mut NotifySink,
) {
    match event {
        GattEvent::Read(event) if event.handle() == control_point_length_handle => {
            info!("GATT read fidoControlPointLength");
        }
        GattEvent::Read(event) if event.handle() == service_revision_bitfield_handle => {
            info!("GATT read fidoServiceRevisionBitfield");
        }
        GattEvent::Write(event) if event.handle() == service_revision_bitfield_handle => {
            event.with_data(|_, data| {
                info!("GATT write fidoServiceRevisionBitfield len={}", data.len());
            });
        }
        GattEvent::Write(event) if event.handle() == control_point_handle => {
            event.with_data(|offset, data| {
                info!("GATT write fidoControlPoint len={}", data.len());
                if let Err(e) = handle_control_point_write_at_offset_and_drain::<BLE_PACKET_LEN>(
                    fido,
                    offset,
                    data,
                    notify_sink,
                    0,
                    || {},
                ) {
                    warn!("BLE FIDO frontend error: {:?}", e);
                }
            });
        }
        _ => {}
    }
}

/// Notification acceptance is not peer acknowledgment; send failure drops the remaining local batch.
async fn send_notifications<P: PacketPool>(
    conn: &GattConnection<'_, '_, P>,
    status: &Characteristic<Vec<u8, BLE_PACKET_LEN>>,
    sink: &NotifySink,
) {
    for (_index, fragment) in sink.fragments().enumerate() {
        let Ok(value) = notification_fragment_vec::<BLE_PACKET_LEN>(fragment) else {
            warn!("notify fragment did not fit heapless Vec");
            continue;
        };
        if status.notify(conn, &value, true).await.is_err() {
            warn!("FIDO status notify failed");
            break;
        }
        #[cfg(any(
            feature = "experimental-ml-dsa-fips204",
            feature = "experimental-ml-dsa-mldsa-native"
        ))]
        {
            if _index % 8 == 0 {
                info!("BLE ML-DSA notify fragment {}", _index);
            }

            Timer::after_millis(100).await;
        }
    }
}
