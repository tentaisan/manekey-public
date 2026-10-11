use rp235x_hal as hal;

#[cfg(any(
    feature = "riscv-pmp-usb-frontend",
    feature = "riscv-pmp-ble-mmio-runtime"
))]
use super::pmp_accessctrl;
use super::pmp_features;
use super::pmp_led::{blink_unexpected_trap, led_on_raw};

use super::pmp_machine::{
    enter_u_mode_prepared, init_machine_trap_stack_guard, install_machine_trap_stack,
    install_trap_vector, prepare_u_mode_entry,
};

#[cfg(any(
    feature = "riscv-pmp-sha256-accelerator",
    feature = "riscv-client-pin-sha256"
))]
use super::pmp_sha256;

#[cfg(all(
    feature = "riscv-pmp-ble-mmio-runtime",
    not(feature = "riscv-pmp-ble-monitor-handoff-only")
))]
use super::pmp_uart::uart_put_dec;
use super::pmp_uart::{uart_put_hex, uart_puts};

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
use super::pmp_user_pio;
use super::{pmp_config, pmp_trusted, pmp_user};

pub(super) type BootLed =
    hal::gpio::Pin<hal::gpio::bank0::Gpio25, hal::gpio::FunctionSioOutput, hal::gpio::PullDown>;
pub(super) type BootTimer = hal::Timer<hal::timer::CopyableTimer0>;

/// Run once in M-mode with matching linker regions and exclusive peripherals; initialize protection before U entry.
/// CPU PMP and peripheral attribution do not substitute for DMA-master protection.
pub(super) fn run_pmp_boot_sequence(
    _led: &mut BootLed,
    _timer: &mut BootTimer,
    #[cfg_attr(not(feature = "riscv-pmp-sha256-accelerator"), allow(unused_variables))]
    resets: &mut hal::pac::RESETS,
    #[cfg(feature = "riscv-pmp-trusted-trng")] trng: hal::pac::TRNG,
    #[cfg(any(
        feature = "riscv-pmp-usb-frontend",
        feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental"
    ))]
    usb: hal::pac::USB,
    #[cfg(any(
        feature = "riscv-pmp-usb-frontend",
        feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental"
    ))]
    usb_dpram: hal::pac::USB_DPRAM,
    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")] pio0: hal::pac::PIO0,
) -> ! {
    uart_puts("\r\nBOOT ManeKey PMP\r\n");

    #[cfg(any(
        feature = "riscv-pmp-sha256-accelerator",
        feature = "riscv-client-pin-sha256"
    ))]
    bring_up_sha256_key_store(resets);
    #[cfg(feature = "riscv-pmp-trusted-trng")]
    pmp_accessctrl::configure_pmp_trusted_accessctrl();
    if let Err(diagnostic) = pmp_trusted::init_pmp_trusted_dispatcher(
        #[cfg(feature = "riscv-pmp-trusted-trng")]
        trng,
    ) {
        uart_puts("PMP trusted dispatcher entropy initialization failed diagnostic=");
        uart_put_hex(diagnostic);
        uart_puts("\r\n");
        blink_unexpected_trap();
    }
    #[cfg(feature = "riscv-pmp-usb-frontend")]
    init_usb_frontend(usb, usb_dpram, resets);
    #[cfg(feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental")]
    init_split_multi_transport_usb(usb, usb_dpram, resets);
    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
    init_ble_mmio_policy(pio0, resets);

    configure_machine_trap_and_pmp();

    enter_selected_u_mode_or_halt();
}

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
fn init_ble_mmio_policy(pio0: hal::pac::PIO0, resets: &mut hal::pac::RESETS) {
    pmp_accessctrl::configure_pmp_ble_accessctrl();
    #[cfg(feature = "riscv-pmp-ble-monitor-dma-policy")]
    {
        uart_puts("DMA policy: BLE ACCESSCTRL configured\r\n");
        pmp_accessctrl::configure_pmp_ble_dma_accessctrl();
        uart_puts("DMA policy: DMA/SRAM ACCESSCTRL configured\r\n");
        manekey_rp::platform::rp2350::pmp_dma::bring_up_dma(resets);
        uart_puts("DMA policy: reset released\r\n");
        manekey_rp::platform::rp2350::pmp_dma::configure_split_dma_policy();
        uart_puts("DMA policy: security registers configured\r\n");
    }
    pmp_accessctrl::publish_pmp_ble_gpio_ownership();
    pmp_user_pio::reselect_nonsecure_pio_pins();
    let Some(diagnostics) = pmp_user_pio::init_cyw43_pio_handoff(pio0, resets) else {
        uart_puts("PMP BLE PIO ownership handoff initialization failed\r\n");
        blink_unexpected_trap();
    };
    #[cfg(feature = "riscv-pmp-ble-monitor-handoff-only")]
    {
        let _ = diagnostics;
        uart_puts("M-mode CYW43 transaction deferred to U-mode\r\n");
    }

    uart_puts("PMP BLE PIO0 SM0 initialized; ownership published; ACCESSCTRL configured\r\n");
}

#[cfg(any(
    feature = "riscv-pmp-sha256-accelerator",
    feature = "riscv-client-pin-sha256"
))]
fn bring_up_sha256_key_store(resets: &mut hal::pac::RESETS) {
    pmp_sha256::bring_up_sha256(resets);
    #[cfg(feature = "riscv-client-pin-sha256")]

    assert!(unsafe { manekey_rp::platform::rp2350::riscv_crypto::sha256_known_answers() });
    uart_puts("SHA256 accelerator enabled for M-mode crypto\r\n");
}

#[cfg(feature = "riscv-pmp-usb-frontend")]
fn init_usb_frontend(
    usb: hal::pac::USB,
    usb_dpram: hal::pac::USB_DPRAM,
    resets: &mut hal::pac::RESETS,
) {
    pmp_user::init_usb_frontend_objects(usb, usb_dpram, resets);
    pmp_accessctrl::configure_pmp_usb_accessctrl();
    uart_puts("PMP USB frontend objects initialized in shared memory\r\n");
}

#[cfg(feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental")]
fn init_split_multi_transport_usb(
    usb: hal::pac::USB,
    usb_dpram: hal::pac::USB_DPRAM,
    resets: &mut hal::pac::RESETS,
) {
    manekey_rp::platform::rp2350::pmp_usb::PmpUsbBus::prepare_hardware(
        usb, usb_dpram, true, resets,
    );
    pmp_accessctrl::configure_pmp_usb_accessctrl();
    uart_puts("PMP split USB hardware initialized for U-mode ownership\r\n");
}

fn configure_machine_trap_and_pmp() {
    unsafe {
        uart_puts("installing trap stack/vector\r\n");

        init_machine_trap_stack_guard();
        install_machine_trap_stack();
        install_trap_vector();
        uart_puts("checking PMP readback\r\n");
        if !pmp_config::pmp_config_write_readback_works() {
            uart_puts("PMP readback failed\r\n");
            blink_unexpected_trap();
        }
        uart_puts("configuring PMP policy\r\n");
        if pmp_features::uses_ecall_island_policy() {
            pmp_config::configure_ecall_island_pmp();
        } else {
            blink_unexpected_trap();
        }
    }

    uart_puts("PMP configured\r\n");
}

fn enter_selected_u_mode_or_halt() -> ! {
    unsafe {
        init_machine_trap_stack_guard();
        install_machine_trap_stack();
        install_trap_vector();
        let u_entry = pmp_user::selected_u_mode_entry_addr();
        let mpp = prepare_u_mode_entry(u_entry);

        if mpp != 0 {
            blink_unexpected_trap();
        }
        uart_puts("mret to U\r\n");
        #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
        super::pmp_timer::init_u_mode_timer_service();
        #[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
        {
            manekey_rp::platform::rp2350::pmp_dma::init_dma_irq_service();
        }
        led_on_raw();
        #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
        if !pmp_user_pio::prepare_u_mode_raw_spi_probe() {
            blink_unexpected_trap();
        }
        enter_u_mode_prepared(pmp_user::selected_u_mode_stack_top());
    }
}
