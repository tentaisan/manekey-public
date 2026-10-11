use embassy_nrf::pac::{MPC00_S, SPU00_S, SPU20_S, mpc, spu};

pub const NSC_FLASH_START: u32 = 0x0003_f000;
pub const NSC_FLASH_END: u32 = 0x0003_ffff;
pub const NS_FLASH_START: u32 = 0x0004_0000;

pub const NS_FLASH_END: u32 = 0x0017_5fff;
#[cfg(not(feature = "trustzone-large-layout"))]
pub const NS_RAM_START: u32 = 0x2001_0000;
#[cfg(feature = "trustzone-large-layout")]
pub const NS_RAM_START: u32 = 0x2002_0000;
pub const NS_RAM_END: u32 = 0x2003_ffff;

#[cfg(not(feature = "trustzone-large-layout"))]
pub const NS_SHARED_START: u32 = 0x2003_f000;
#[cfg(feature = "trustzone-large-layout")]
pub const NS_SHARED_START: u32 = 0x2003_e000;
pub const NS_SHARED_END: u32 = 0x2003_ffff;

pub const NS_P2_START: u32 = 0x4005_0400;
pub const NS_P2_END: u32 = 0x4005_07ff;

pub const NS_UARTE21_START: u32 = 0x400c_7000;
pub const NS_UARTE21_END: u32 = 0x400c_7fff;

pub const P2_FEATURE_INDEX: usize = 2;

pub const P2_PERIPHERAL_SLOT: usize = 16;
pub const P2_USER_LED_PIN: usize = 0;
pub const P2_EXTERNAL_UART_RX_PIN: usize = 7;
pub const P2_EXTERNAL_UART_TX_PIN: usize = 8;

pub const UARTE21_PERIPHERAL_SLOT: usize = 7;

/// Secure initialization only; paired SAU/linker regions must match and exclude private journals.
pub fn configure_nonsecure_memory() {
    configure_nonsecure_override(MPC00_S.override_(0), NS_FLASH_START, NS_FLASH_END + 1, true);
    configure_nonsecure_override(MPC00_S.override_(1), NS_RAM_START, NS_RAM_END + 1, false);
}

/// Secure owner delegates only an authorized valid P2 pin; caller owns lifecycle and recovery.
pub fn delegate_p2_pin_to_nonsecure(pin: usize) -> (u32, u32) {
    let permission = SPU00_S.feature().gpio(P2_FEATURE_INDEX).pin(pin);
    let before = permission.read().0;
    let mut requested = spu::regs::Pin(before);
    requested.set_secattr(false);
    permission.write_value(requested);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    (before, permission.read().0)
}

pub fn delegate_p2_peripheral_to_nonsecure() -> (u32, u32) {
    let permission = SPU00_S.periph(P2_PERIPHERAL_SLOT).perm();
    let before = permission.read().0;
    let mut requested = spu::regs::Perm(before);
    requested.set_secattr(false);
    permission.write_value(requested);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    (before, permission.read().0)
}

/// Delegate only the paired external UART/GPIO/DMA frontend; keep crypto and storage Secure.
pub fn delegate_external_uart_to_nonsecure() {
    let permission = SPU20_S.periph(UARTE21_PERIPHERAL_SLOT).perm();
    let mut requested = permission.read();
    requested.set_secattr(false);
    if requested.dma() == spu::vals::Dma::SeparateAttribute {
        requested.set_dmasec(spu::vals::Dmasec::NonSecure);
    }
    permission.write_value(requested);
    let _ = delegate_p2_peripheral_to_nonsecure();
    let _ = delegate_p2_pin_to_nonsecure(P2_EXTERNAL_UART_RX_PIN);
    let _ = delegate_p2_pin_to_nonsecure(P2_EXTERNAL_UART_TX_PIN);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

fn configure_nonsecure_override(region: mpc::Override, start: u32, end: u32, executable: bool) {
    region.config().write_value(mpc::regs::Config(0));
    region.startaddr().write_value(start);
    region.endaddr().write_value(end);

    let mut permissions = mpc::regs::Perm(0);
    permissions.set_read(true);
    permissions.set_write(true);
    permissions.set_execute(executable);
    permissions.set_secattr(mpc::vals::PermSecattr::NonSecure);
    region.perm().write_value(permissions);
    region.permmask().write_value(mpc::regs::Permmask(0x0f));

    let mut config = mpc::regs::Config(0);
    config.set_enable(true);
    region.config().write_value(config);
}
