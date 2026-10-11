#![no_std]
#![no_main]

#[path = "../../tz_uart_ns_app.rs"]
mod app;

#[cortex_m_rt::entry]
/// Requires the matching initialized Secure image, NSC gateway and delegated UART/DMA/shared-memory layout.
fn main() -> ! {
    app::run::<()>()
}
