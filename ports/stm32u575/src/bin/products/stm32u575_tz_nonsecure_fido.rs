#![no_std]
#![no_main]

use manekey::boundary::arm_gateway::{ArmGatewaySharedBuffers, ArmSharedGatewayBackend};
use manekey_stm32u575::trustzone;

const _: () = assert!(manekey::security::TRUSTED_RESPONSE_MAX == 4096);
const _: () = assert!(manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX == 4096);

#[unsafe(link_section = ".tz_shared")]
static mut SHARED: ArmGatewaySharedBuffers = ArmGatewaySharedBuffers::new();

#[cfg(not(feature = "trustzone-usb"))]
#[cortex_m_rt::entry]
/// NS UART frontend; initialize NOLOAD shared state once before gateway use and preserve exclusive ownership.
fn main() -> ! {
    let workspace = unsafe {
        core::ptr::addr_of_mut!(SHARED).write(ArmGatewaySharedBuffers::new());
        &mut *core::ptr::addr_of_mut!(SHARED)
    };

    let backend = unsafe { ArmSharedGatewayBackend::new(trustzone::NSC_START, workspace) };

    trustzone::run_uart(backend, || {})
}

#[cfg(feature = "trustzone-usb")]
#[embassy_executor::main]
/// NS USB/UART frontend; requires matching Secure services/attribution and exclusive shared gateway/IRQ state.
/// Initialize NOLOAD shared state once; TX readiness waiting has no timeout.
async fn main(_spawner: embassy_executor::Spawner) {
    use embassy_futures::join::join;
    use embassy_usb::class::hid::{HidReaderWriter, State};
    use manekey::{
        ctaphid::descriptor::{CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE},
        frontend::ingress::IngressArbiter,
        transport::usb::embassy::{SharedUsbArbiter, UsbIngressFrontend, run_hid_ingress_loop},
    };
    use static_cell::StaticCell;
    manekey_stm32u575::nonsecure_usb::start_time();
    manekey_stm32u575::nonsecure_usb::start_uart();

    let workspace = unsafe {
        core::ptr::addr_of_mut!(SHARED).write(ArmGatewaySharedBuffers::new());
        &mut *core::ptr::addr_of_mut!(SHARED)
    };

    let backend = unsafe { ArmSharedGatewayBackend::new(trustzone::NSC_START, workspace) };
    static ARBITER: StaticCell<SharedUsbArbiter<ArmSharedGatewayBackend<'static>>> =
        StaticCell::new();
    let arbiter: &'static SharedUsbArbiter<_> =
        ARBITER.init(embassy_sync::blocking_mutex::Mutex::new(
            core::cell::RefCell::new(IngressArbiter::new(backend)),
        ));
    let mut frontend = UsbIngressFrontend::new(arbiter);
    let mut fifo = [0; 256];
    let driver = manekey_stm32u575::nonsecure_usb::UsbDriver::new(&mut fifo);
    let identity = CtaphidUsbDeviceInfo::new("ManeKey STM32U575 TZ USB FIDO", "stm32u575-tz");
    let mut config = embassy_usb::Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_packet_size_0 = 64;
    config.composite_with_iads = false;
    let mut descriptors = [0; 256];
    let mut bos = [0; 256];
    let mut control = [0; 64];
    let mut state = State::new();
    #[cfg(feature = "usb-ccid")]
    let mut ccid_state = manekey::transport::usb::embassy::CcidUsbState::new();
    let mut builder = embassy_usb::Builder::new(
        driver,
        config,
        &mut descriptors,
        &mut bos,
        &mut [],
        &mut control,
    );
    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
        &mut builder,
        &mut state,
        embassy_usb::class::hid::Config {
            report_descriptor: REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: identity.poll_ms,
            max_packet_size: 64,
            hid_subclass: embassy_usb::class::hid::HidSubclass::No,
            hid_boot_protocol: embassy_usb::class::hid::HidBootProtocol::None,
        },
    );
    #[cfg(feature = "usb-ccid")]
    let ccid = manekey::transport::usb::embassy::CcidUsbClass::new(
        &mut builder,
        &mut ccid_state,
        64,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    );
    let mut device = builder.build();

    let usb = async {
        #[cfg(feature = "usb-ccid")]
        {
            use manekey::transport::usb::embassy::{CcidIoBuffers, run_ccid_ingress_loop};
            static BUFFERS: StaticCell<CcidIoBuffers> = StaticCell::new();
            join(
                device.run(),
                join(
                    run_hid_ingress_loop(hid, &mut frontend),
                    run_ccid_ingress_loop(ccid, arbiter, BUFFERS.init(CcidIoBuffers::new())),
                ),
            )
            .await;
        }
        #[cfg(not(feature = "usb-ccid"))]
        join(device.run(), run_hid_ingress_loop(hid, &mut frontend)).await;
    };
    join(usb, uart(arbiter)).await;
}

#[cfg(feature = "trustzone-usb")]
async fn uart(
    arbiter: &'static manekey::transport::usb::embassy::SharedUsbArbiter<
        ArmSharedGatewayBackend<'static>,
    >,
) -> ! {
    use manekey::{
        ctaphid::trusted::TRUSTED_RESPONSE_MAX,
        frontend::internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    };
    let uart = embassy_stm32::pac::USART1;
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut output = [0; TRUSTED_RESPONSE_MAX + 32];
    loop {
        let response = arbiter.lock(|inner| {
            let mut inner = inner.borrow_mut();
            let _ = frontend.poll_cancel(&mut *inner);

            for _ in 0..64 {
                let byte = match manekey_stm32u575::nonsecure_usb::read_uart() {
                    Ok(Some(byte)) => byte,
                    Ok(None) => return None,
                    Err(()) => {
                        frontend.disconnect(&mut *inner);
                        return None;
                    }
                };
                if let Ok(Some(InterconnectCtap2Outcome::Response { len })) =
                    frontend.push_byte(&mut *inner, byte, &mut output)
                {
                    return Some(InterconnectCtap2Outcome::Response { len });
                }
            }
            None
        });
        if let Some(InterconnectCtap2Outcome::Response { len }) = response {
            for byte in &output[..len] {
                while !uart.isr().read().txe() {
                    embassy_time::Timer::after_micros(100).await;
                }
                uart.tdr().write(|r| r.set_dr(*byte as u16));
            }
        }
        if response.is_none() {
            embassy_time::Timer::after_millis(1).await;
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}
