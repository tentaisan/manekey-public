use super::BleIrqs as Irqs;
use core::cell::RefCell;
use embassy_futures::join::join;
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, PIO0};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use manekey::transport::ble::{
    BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler, FidoBleProfile,
    boundary_slots::{BleBoundarySlots, BlePacket},
};
use manekey_rp::platform::rp::storage::SharedRpFlash;
use static_cell::StaticCell;
use trouble_host::prelude::*;

include!("pico_cyw43_ble_common.rs");

#[cfg(feature = "board-ui-experimental")]
pub type PresenceObserver = SelectedPresenceObserver;
#[cfg(feature = "board-ui-experimental")]
pub fn presence_observer() -> PresenceObserver {
    selected_presence_observer()
}

static SLOTS: Mutex<CriticalSectionRawMutex, RefCell<BleBoundarySlots<8, 20>>> =
    Mutex::new(RefCell::new(BleBoundarySlots::new()));
static EXECUTOR: StaticCell<embassy_executor::raw::Executor> = StaticCell::new();
static mut EXECUTOR_PTR: *const embassy_executor::raw::Executor = core::ptr::null();

/// Exclusively owned privileged radio/PIO/DMA resources; never expose these handles to the unprivileged frontend.
pub struct Hardware {
    pub pwr: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_23>,
    pub cs: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>,
    pub pio: embassy_rp::Peri<'static, PIO0>,
    pub dio: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_24>,
    pub clk: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_29>,
    pub dma_tx: embassy_rp::Peri<'static, DMA_CH0>,
    pub dma_rx: embassy_rp::Peri<'static, DMA_CH1>,
}

/// Initialize once before pumping; retain the privileged Flash owner and copied-slot boundary.
pub fn start(hardware: Hardware, flash: &'static SharedRpFlash<'static>) {
    let executor = EXECUTOR.init(embassy_executor::raw::Executor::new(usize::MAX as *mut ()));
    unsafe {
        EXECUTOR_PTR = executor;
    }
    executor
        .spawner()
        .spawn(service(hardware, flash, executor.spawner()).unwrap());
}

/// # Safety
/// Use the initialized single-core privileged SVC owner; never poll recursively, from IRQs or from wakers.
pub unsafe fn pump() {
    unsafe {
        if let Some(executor) = EXECUTOR_PTR.as_ref() {
            executor.poll();
        }
    }
}
pub fn generation() -> u32 {
    SLOTS.lock(|s| s.borrow().generation())
}
pub fn receive(generation: u32) -> Option<BlePacket> {
    SLOTS.lock(|s| s.borrow_mut().receive(generation))
}
pub fn send(generation: u32, packet: BlePacket) -> bool {
    SLOTS.lock(|s| s.borrow_mut().send(generation, packet))
}

struct Proxy;
impl BleFidoProfileHandler for Proxy {
    fn on_status_subscription(&mut self, enabled: bool) {
        SLOTS.lock(|s| s.borrow_mut().subscription(enabled));
    }
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        _sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        if SLOTS.lock(|s| s.borrow_mut().push_received(fragment)) {
            Ok(0)
        } else {
            Err(BleFidoError::Busy)
        }
    }
    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        let mut count = 0;
        while let Some(packet) = SLOTS.lock(|s| s.borrow_mut().next_notification()) {
            sink.push_fragment(packet.bytes().ok_or(BleFidoError::InvalidLen)?)?;
            count += 1;
        }
        Ok(count)
    }
    fn on_disconnect(&mut self) {
        SLOTS.lock(|s| s.borrow_mut().reset(false));
    }
}
struct Runtime;
impl PicoBleFidoRuntime for Runtime {
    const TICK_MS: u64 = 10;
}

#[embassy_executor::task]
async fn service(
    h: Hardware,
    flash: &'static SharedRpFlash<'static>,
    spawner: embassy_executor::Spawner,
) -> ! {
    let (bt, mut control) = init_cyw43_bluetooth(
        &spawner, h.pwr, h.cs, h.pio, h.dio, h.clk, h.dma_tx, h.dma_rx,
    )
    .await;
    control.gpio_set(0, false).await;
    #[cfg(feature = "board-ui-experimental")]
    let mut control = {
        spawner.spawn(cyw43_board_ui_task(control).unwrap());
        ()
    };

    let controller: ExternalController<_, 10> = ExternalController::new(bt);
    let profile = FidoBleProfile::manekey();
    let mut resources: HostResources<_, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(profile.address))
        .set_io_capabilities(IoCapabilities::NoInputNoOutput);
    let host = stack.build();
    let mut bonds = selected_ble_bond_store(flash);
    bonds.load_bonds(|record| {
        let _ = host.add_bond_information(stored_ble_bond_to_trouble(record));
    });
    let admission = BleBondAdmission::from_bonded_only(true);
    let mut peripheral = host.peripheral();
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: fido_ble_device_name(&profile),
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();

    let _ = join(ble_runner(host.runner()), async {
        loop {
            match advertise(&mut peripheral, &server, &profile).await {
                Ok(conn) => {
                    let _ = conn.raw().set_bondable(false);
                    if !admission.permits_peer(conn.raw().is_bonded_peer()) {
                        conn.raw().disconnect();
                        drop(conn);
                        embassy_time::Timer::after_millis(30).await;
                        continue;
                    }

                    SLOTS.lock(|s| s.borrow_mut().reset(false));
                    let _ = gatt_events(
                        &host,
                        &server,
                        &conn,
                        &mut Proxy,
                        &mut control,
                        &mut Runtime,
                        &mut bonds,
                        admission,
                    )
                    .await;
                }
                Err(_) => embassy_time::Timer::after_secs(1).await,
            }
        }
    })
    .await;
    loop {
        core::hint::spin_loop();
    }
}
