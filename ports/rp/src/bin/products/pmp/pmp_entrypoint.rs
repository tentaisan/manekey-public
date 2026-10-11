use panic_halt as _;
use rp235x_hal as hal;
use rp235x_hal::Clock;
use rp235x_hal::fugit::RateExtU32;

#[cfg(all(
    feature = "riscv-pmp-ble-mmio-runtime",
    not(feature = "riscv-pmp-ble-monitor-handoff-only"),
    not(any())
))]
compile_error!("PMP MMIO products require handoff-only; bus comparison requires diagnostics");

#[cfg(all(
    feature = "riscv-pmp-usb-internal-ccid",
    feature = "riscv-pmp-ble-monitor-image"
))]
compile_error!("USB-only PMP and split BLE monitor layouts cannot be combined");

#[cfg(all(
    feature = "riscv-pmp-trusted-flash-storage",
    not(any(
        feature = "riscv-pmp-usb-frontend",
        feature = "riscv-pmp-ble-monitor-image"
    ))
))]
compile_error!("PMP trusted flash storage requires a supported M-mode frontend");
#[cfg(all(
    feature = "riscv-pmp-ble-monitor-flash-storage",
    not(feature = "riscv-pmp-ble-monitor-handoff-only")
))]
compile_error!("PMP BLE flash storage requires the handoff-only monitor");
#[cfg(all(
    feature = "riscv-pmp-trusted-pin-uv",
    not(feature = "riscv-pmp-trusted-flash-storage")
))]
compile_error!("PMP PIN/UV requires M-mode trusted flash storage");
#[cfg(all(
    feature = "riscv-pmp-trusted-pin-uv",
    not(feature = "riscv-pmp-trusted-trng")
))]
compile_error!("PMP PIN/UV requires M-mode hardware entropy");

#[cfg(all(
    feature = "riscv-pmp-trusted-bootsel-presence",
    feature = "riscv-pmp-trusted-gpio15-presence"
))]
compile_error!("select exactly one PMP physical presence provider");
#[cfg(all(
    feature = "riscv-pmp-trusted-bootsel-presence",
    feature = "riscv-pmp-ble-monitor-dma-policy"
))]
compile_error!("PMP BOOTSEL sampling requires the polling BLE backend without XIP DMA");
#[cfg(all(
    feature = "riscv-pmp-trusted-ml-dsa-fips204-experimental",
    not(feature = "riscv-pmp-large-machine-stack")
))]
compile_error!("PMP ML-DSA requires the enlarged M-mode RAM and trap-stack layout");
#[cfg(all(
    feature = "riscv-pmp-trusted-ml-dsa-fips204-experimental",
    feature = "riscv-pmp-sha256-accelerator"
))]
compile_error!("select exactly one experimental PMP private-key backend");

#[cfg(any(
    feature = "riscv-pmp-usb-frontend",
    feature = "riscv-pmp-ble-mmio-runtime"
))]
mod pmp_accessctrl;
mod pmp_asm;
mod pmp_boot;
mod pmp_config;
mod pmp_csr;
mod pmp_features;

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
mod pmp_gpio;

mod pmp_led;
mod pmp_machine;
mod pmp_memory;
mod pmp_protocol;
mod pmp_report;
#[cfg(any(
    feature = "riscv-pmp-sha256-accelerator",
    feature = "riscv-client-pin-sha256"
))]
mod pmp_sha256;

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
mod pmp_timer;
mod pmp_trap;
mod pmp_trap_frame;
mod pmp_trusted;
mod pmp_uart;

mod pmp_user;
mod pmp_user_asm;
#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
mod pmp_user_pio;

#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[hal::entry]
/// Exclusive M-mode startup with the matching selected linker policy and reserved peripheral ownership.
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        12_000_000u32,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();
    let mut timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    let uart_pins = (pins.gpio0.into_function(), pins.gpio1.into_function());
    let _uart = hal::uart::UartPeripheral::new(pac.UART0, uart_pins, &mut pac.RESETS)
        .enable(
            hal::uart::UartConfig::new(
                115_200.Hz(),
                hal::uart::DataBits::Eight,
                None,
                hal::uart::StopBits::One,
            ),
            clocks.peripheral_clock.freq(),
        )
        .unwrap();
    let mut led = pins.gpio25.into_push_pull_output();
    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
    let _cyw43_power = pins
        .gpio23
        .into_push_pull_output_in_state(hal::gpio::PinState::Low);
    #[cfg(feature = "riscv-pmp-trusted-gpio15-presence")]
    let _user_presence = pins.gpio15.into_pull_up_input();
    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
    let mut cyw43_dio = pins.gpio24.into_function::<hal::gpio::FunctionPio0>();
    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
    let mut cyw43_clk = pins.gpio29.into_function::<hal::gpio::FunctionPio0>();
    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
    {
        cyw43_dio.set_drive_strength(hal::gpio::OutputDriveStrength::TwelveMilliAmps);
        cyw43_dio.set_slew_rate(hal::gpio::OutputSlewRate::Fast);
        cyw43_clk.set_drive_strength(hal::gpio::OutputDriveStrength::TwelveMilliAmps);
        cyw43_clk.set_slew_rate(hal::gpio::OutputSlewRate::Fast);
    }

    pmp_boot::run_pmp_boot_sequence(
        &mut led,
        &mut timer,
        &mut pac.RESETS,
        #[cfg(feature = "riscv-pmp-trusted-trng")]
        pac.TRNG,
        #[cfg(any(
            feature = "riscv-pmp-usb-frontend",
            feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental"
        ))]
        pac.USB,
        #[cfg(any(
            feature = "riscv-pmp-usb-frontend",
            feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental"
        ))]
        pac.USB_DPRAM,
        #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
        pac.PIO0,
    );
}
