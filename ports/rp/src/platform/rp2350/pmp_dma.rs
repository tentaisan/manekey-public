#[cfg(any(
    feature = "riscv-pmp-ble-monitor-dma-irq",
    all(feature = "riscv-pmp-ble-user-dma-irq-backend", any())
))]
use core::sync::atomic::AtomicU32;
#[cfg(any(
    feature = "riscv-pmp-ble-monitor-dma-irq",
    all(feature = "riscv-pmp-ble-user-dma-irq-backend", any())
))]
use core::sync::atomic::Ordering;
#[path = "dma_staging.rs"]
mod dma_staging;
use dma_staging::DmaStaging;
#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
use dma_staging::DmaStagingLease;

const DMA_STAGING_WORDS: usize = 514;
#[unsafe(link_section = ".bss.pmp_user_async")]
static DMA_STAGING: DmaStaging<DMA_STAGING_WORDS> = DmaStaging::new();
#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(feature = "riscv-pmp-ble-monitor-dma-policy")]
use rp235x_hal as hal;

const DMA_BASE: usize = 0x5000_0000;
const DMA_CHANNEL_STRIDE: usize = 0x40;
const DMA_SECCFG_CH0: usize = DMA_BASE + 0x480;
const DMA_SECCFG_CH1: usize = DMA_BASE + 0x484;
const DMA_CHAN_ABORT: usize = DMA_BASE + 0x464;
#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
const DMA_INTR: usize = DMA_BASE + 0x400;
#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
const DMA_INTE0: usize = DMA_BASE + 0x404;
#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
const DMA_INTS0: usize = DMA_BASE + 0x40c;
#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
const DMA_SECCFG_IRQ0: usize = DMA_BASE + 0x4c0;
const DMA_MPU_CTRL: usize = DMA_BASE + 0x500;
const DMA_MPU_BAR0: usize = DMA_BASE + 0x504;
const DMA_MPU_LAR0: usize = DMA_BASE + 0x508;
const DMA_MPU_BAR1: usize = DMA_BASE + 0x50c;
const DMA_MPU_LAR1: usize = DMA_BASE + 0x510;
const DMA_MPU_LAR2: usize = DMA_BASE + 0x518;
const DMA_MPU_REGION_STRIDE: usize = 8;

const USER_RAM_BASE: u32 = 0x2004_0000;
const USER_RAM_LIMIT: u32 = 0x2007_ffe0;
const PIO0_BASE: u32 = 0x5020_0000;
const PIO0_LIMIT: u32 = 0x5020_3fe0;

const DMA_SECURITY_NONSECURE_UNPRIVILEGED: u32 = 0x0;
const DMA_MPU_DEFAULT_SECURE_PRIVILEGED: u32 = 0x6;
const DMA_MPU_REGION_NONSECURE_UNPRIVILEGED_ENABLED: u32 = 0x1;

const DMA_READ_ADDR: usize = 0x00;
const DMA_WRITE_ADDR: usize = 0x04;
const DMA_TRANS_COUNT: usize = 0x08;
const DMA_CTRL_TRIG: usize = 0x0c;
const DMA_CTRL_AHB_ERROR: u32 = 1 << 31;
const DMA_CTRL_READ_ERROR: u32 = 1 << 30;
const DMA_CTRL_WRITE_ERROR: u32 = 1 << 29;
const DMA_CTRL_BUSY: u32 = 1 << 26;
const DMA_CTRL_CHAIN_TO_MASK: u32 = 0x0f << 13;
const DMA_CTRL_INCR_WRITE: u32 = 1 << 6;
const DMA_CTRL_INCR_READ: u32 = 1 << 4;
const DMA_CTRL_DATA_SIZE_WORD: u32 = 2 << 2;
const DMA_CTRL_ENABLE: u32 = 1;
const DMA_WAIT_TIMEOUT_US: u32 = 100_000;
const TIMER0_TIMERAWL: usize = 0x400b_0028;
const DMA_TREQ_PIO0_TX0: u32 = 0;
const DMA_TREQ_PIO0_RX0: u32 = 4;
#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
const DMA_RX_CHANNEL_IRQ: u32 = 1 << 1;

const PIO0_TX_FIFO0: u32 = 0x5020_0010;
const PIO0_RX_FIFO0: u32 = 0x5020_0020;
#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
const PIO0_IRQ: usize = 0x5020_0030;
#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
const PIO0_SM0_TRANSACTION_COMPLETE: u32 = 1;

pub const DMA_PIO_EXCHANGE_EXPECTED: u32 = 0x0f;

#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
static DMA_IRQ_GENERATION: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "riscv-pmp-ble-monitor-dma-policy")]
pub fn bring_up_dma(resets: &mut hal::pac::RESETS) {
    resets.reset().modify(|_, w| w.dma().set_bit());
    resets.reset().modify(|_, w| w.dma().clear_bit());
    while resets.reset_done().read().dma().bit_is_clear() {
        core::hint::spin_loop();
    }
}

/// Configure exclusively in M-mode before channel writes lock attribution; reserve channels 0/1 and DMA MPU.
/// CPU PMP alone does not constrain DMA masters.
pub fn configure_split_dma_policy() {
    unsafe {
        write(DMA_SECCFG_CH0, DMA_SECURITY_NONSECURE_UNPRIVILEGED);
        write(DMA_SECCFG_CH1, DMA_SECURITY_NONSECURE_UNPRIVILEGED);
        write(DMA_MPU_CTRL, DMA_MPU_DEFAULT_SECURE_PRIVILEGED);
        write(DMA_MPU_BAR0, USER_RAM_BASE);
        write(
            DMA_MPU_LAR0,
            USER_RAM_LIMIT | DMA_MPU_REGION_NONSECURE_UNPRIVILEGED_ENABLED,
        );
        write(DMA_MPU_BAR1, PIO0_BASE);
        write(
            DMA_MPU_LAR1,
            PIO0_LIMIT | DMA_MPU_REGION_NONSECURE_UNPRIVILEGED_ENABLED,
        );
        for region in 2..8 {
            write(DMA_MPU_LAR2 + (region - 2) * DMA_MPU_REGION_STRIDE, 0);
        }
    }
}

#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
/// # Safety
/// Own DMA IRQ0 and its monitor routing exclusively; initialize before transfers or user entry.
pub unsafe fn init_dma_irq_service() {
    unsafe {
        hal::xh3irq::mask(hal::pac::Interrupt::DMA_IRQ_0);
        write(DMA_INTE0, 0);
        write(DMA_INTR, DMA_RX_CHANNEL_IRQ);
    }
}

#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
pub fn handle_dma_irq0() -> bool {
    let pending = unsafe { read(DMA_INTS0) } & DMA_RX_CHANNEL_IRQ;
    if pending == 0 {
        return false;
    }
    hal::xh3irq::mask(hal::pac::Interrupt::DMA_IRQ_0);
    unsafe {
        write(DMA_INTE0, 0);

        write(DMA_INTR, pending);
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    DMA_IRQ_GENERATION.fetch_add(1, Ordering::Release);
    true
}

#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
pub fn dma_irq_generation() -> u32 {
    DMA_IRQ_GENERATION.load(Ordering::Acquire)
}

#[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
/// Rearm only with both channels idle and chip select high, under the exclusive monitor owner.
pub fn rearm_dma_irq0() {
    unsafe {
        write(DMA_INTR, DMA_RX_CHANNEL_IRQ);
        core::arch::asm!("fence iorw, iorw", options(nostack));
        write(DMA_INTE0, DMA_RX_CHANNEL_IRQ);
        core::arch::asm!("fence iorw, iorw", options(nostack));
        hal::xh3irq::unmask(hal::pac::Interrupt::DMA_IRQ_0);
    }
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
pub fn user_dma_irq_generation() -> u32 {
    let mut result = manekey::boundary::riscv_pmp::DMA_IRQ_STATUS_ECALL_ID;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") result,
            in("a1") 0_u32,
            in("a2") 0_u32,
            options(nostack),
        );
    }
    result
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
pub fn user_rearm_dma_irq0() -> u32 {
    let mut result = manekey::boundary::riscv_pmp::DMA_IRQ_STATUS_ECALL_ID;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") result,
            in("a1") 1_u32,
            in("a2") 0_u32,
            options(nostack),
        );
    }
    result
}

#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
/// Experimental exclusive-channel exchange requiring initialized TIMER0, PIO0/SM0 and valid DMA attribution.
/// Static staging is poisoned if channel stop cannot be confirmed.
pub fn run_pio0_sm0_exchange(write_words: &[u32], read_words: &mut [u32]) -> u32 {
    if write_words.len() > DMA_STAGING_WORDS || read_words.len() > DMA_STAGING_WORDS {
        return 0;
    }
    let Some(mut lease) = DMA_STAGING.acquire() else {
        return 0;
    };
    let result = {
        let (tx, rx) = unsafe { lease.buffers() };
        tx[..write_words.len()].copy_from_slice(write_words);
        unsafe { core::arch::asm!("fence iorw, iorw", options(nostack)) };
        run_pio0_sm0_exchange_staged(&tx[..write_words.len()], &mut rx[..read_words.len()])
    };
    if !dma_channels_stopped() {
        return 0;
    }
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
        read_words.copy_from_slice(&lease.buffers().1[..read_words.len()]);
        lease.release_after_stop();
    }
    result
}

#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
fn dma_channels_stopped() -> bool {
    unsafe {
        read(DMA_CHAN_ABORT) & 3 == 0
            && read(DMA_BASE + DMA_CTRL_TRIG) & DMA_CTRL_BUSY == 0
            && read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_CTRL_TRIG) & DMA_CTRL_BUSY == 0
    }
}

#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
fn run_pio0_sm0_exchange_staged(write_words: &[u32], read_words: &mut [u32]) -> u32 {
    if write_words.is_empty() || read_words.is_empty() {
        return 0;
    }

    configure_channel(
        1,
        PIO0_RX_FIFO0,
        read_words.as_mut_ptr() as u32,
        read_words.len() as u32,
        DMA_TREQ_PIO0_RX0,
        false,
        true,
    );
    configure_channel(
        0,
        write_words.as_ptr() as u32,
        PIO0_TX_FIFO0,
        write_words.len() as u32,
        DMA_TREQ_PIO0_TX0,
        true,
        false,
    );

    let rx_ctrl = wait_channel(1);
    let rx_count = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_TRANS_COUNT) };
    let mut tx_ctrl = unsafe { read(DMA_BASE + DMA_CTRL_TRIG) };
    let mut tx_count = unsafe { read(DMA_BASE + DMA_TRANS_COUNT) };
    if tx_count != 0 {
        tx_ctrl = wait_channel(0);
        tx_count = unsafe { read(DMA_BASE + DMA_TRANS_COUNT) };
    }
    let tx_completed = tx_count == 0;
    let rx_completed = rx_count == 0 && rx_ctrl & DMA_CTRL_BUSY == 0;

    let busy_channels =
        ((tx_ctrl & DMA_CTRL_BUSY != 0) as u32) | (((rx_ctrl & DMA_CTRL_BUSY != 0) as u32) << 1);
    let channels_reusable = busy_channels == 0 || abort_channels(busy_channels);
    let tx_ctrl = unsafe { read(DMA_BASE + DMA_CTRL_TRIG) };
    let rx_ctrl = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_CTRL_TRIG) };
    let mut result = 0;
    if tx_completed && channels_reusable && tx_ctrl & DMA_CTRL_BUSY == 0 {
        result |= 1 << 0;
    }
    if rx_completed && channels_reusable && rx_ctrl & DMA_CTRL_BUSY == 0 {
        result |= 1 << 1;
    }
    if tx_ctrl & (DMA_CTRL_AHB_ERROR | DMA_CTRL_READ_ERROR | DMA_CTRL_WRITE_ERROR) == 0 {
        result |= 1 << 2;
    }
    if rx_ctrl & (DMA_CTRL_AHB_ERROR | DMA_CTRL_READ_ERROR | DMA_CTRL_WRITE_ERROR) == 0 {
        result |= 1 << 3;
    }
    result
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
/// Experimental IRQ exchange requiring the matching monitor event pump and exclusive channels.
/// No completion timeout; cancellation poisons static staging and requires separate PIO/CS recovery.
pub async fn run_pio0_sm0_exchange_irq(
    write_words: &[u32],
    read_words: &mut [u32],
    start_state_machine: impl FnOnce(),
) -> u32 {
    if write_words.len() > DMA_STAGING_WORDS || read_words.len() > DMA_STAGING_WORDS {
        return 0;
    }
    let Some(lease) = DMA_STAGING.acquire() else {
        return 0;
    };
    let mut transfer = DmaTransferLease { lease: Some(lease) };
    let result = {
        let (tx, rx) = unsafe { transfer.lease.as_mut().unwrap().buffers() };
        tx[..write_words.len()].copy_from_slice(write_words);
        unsafe { core::arch::asm!("fence iorw, iorw", options(nostack)) };
        run_pio0_sm0_exchange_irq_staged(
            &tx[..write_words.len()],
            &mut rx[..read_words.len()],
            start_state_machine,
        )
        .await
    };
    if !dma_channels_stopped() {
        return 0;
    }
    let mut lease = transfer.lease.take().unwrap();
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
        read_words.copy_from_slice(&lease.buffers().1[..read_words.len()]);
        lease.release_after_stop();
    }
    result
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
struct DmaTransferLease {
    lease: Option<DmaStagingLease<DMA_STAGING_WORDS>>,
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
impl Drop for DmaTransferLease {
    #[inline(always)]
    fn drop(&mut self) {
        if self.lease.is_some() {
            let _ = abort_channels(3);
            unsafe { core::arch::asm!("fence iorw, iorw", options(nostack)) };
        }
    }
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
async fn run_pio0_sm0_exchange_irq_staged(
    write_words: &[u32],
    read_words: &mut [u32],
    start_state_machine: impl FnOnce(),
) -> u32 {
    if write_words.is_empty() || read_words.is_empty() {
        return 0;
    }

    configure_channel(
        1,
        PIO0_RX_FIFO0,
        read_words.as_mut_ptr() as u32,
        read_words.len() as u32,
        DMA_TREQ_PIO0_RX0,
        false,
        true,
    );
    configure_channel(
        0,
        write_words.as_ptr() as u32,
        PIO0_TX_FIFO0,
        write_words.len() as u32,
        DMA_TREQ_PIO0_TX0,
        true,
        false,
    );

    start_state_machine();

    DmaChannelsComplete.await;
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    let mut tx_ctrl = unsafe { read(DMA_BASE + DMA_CTRL_TRIG) };
    let mut rx_ctrl = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_CTRL_TRIG) };
    let tx_count = unsafe { read(DMA_BASE + DMA_TRANS_COUNT) };
    let rx_count = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_TRANS_COUNT) };
    let busy_channels =
        ((tx_ctrl & DMA_CTRL_BUSY != 0) as u32) | (((rx_ctrl & DMA_CTRL_BUSY != 0) as u32) << 1);
    let channels_reusable = busy_channels == 0 || abort_channels(busy_channels);
    tx_ctrl = unsafe { read(DMA_BASE + DMA_CTRL_TRIG) };
    rx_ctrl = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_CTRL_TRIG) };

    let mut result = 0;
    if tx_count == 0 && channels_reusable && tx_ctrl & DMA_CTRL_BUSY == 0 {
        result |= 1 << 0;
    }
    if rx_count == 0 && channels_reusable && rx_ctrl & DMA_CTRL_BUSY == 0 {
        result |= 1 << 1;
    }
    if tx_ctrl & (DMA_CTRL_AHB_ERROR | DMA_CTRL_READ_ERROR | DMA_CTRL_WRITE_ERROR) == 0 {
        result |= 1 << 2;
    }
    if rx_ctrl & (DMA_CTRL_AHB_ERROR | DMA_CTRL_READ_ERROR | DMA_CTRL_WRITE_ERROR) == 0 {
        result |= 1 << 3;
    }
    result
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
pub fn wait_pio0_sm0_transaction_complete() -> bool {
    unsafe {
        let start = read(TIMER0_TIMERAWL);
        while read(PIO0_IRQ) & PIO0_SM0_TRANSACTION_COMPLETE == 0 {
            if read(TIMER0_TIMERAWL).wrapping_sub(start) >= DMA_WAIT_TIMEOUT_US {
                return false;
            }
            core::hint::spin_loop();
        }
        write(PIO0_IRQ, PIO0_SM0_TRANSACTION_COMPLETE);
    }
    true
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
struct DmaChannelsComplete;

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
impl Future for DmaChannelsComplete {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let tx_ctrl = unsafe { read(DMA_BASE + DMA_CTRL_TRIG) };
        let rx_ctrl = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_CTRL_TRIG) };
        let tx_count = unsafe { read(DMA_BASE + DMA_TRANS_COUNT) };
        let rx_count = unsafe { read(DMA_BASE + DMA_CHANNEL_STRIDE + DMA_TRANS_COUNT) };
        if tx_count == 0
            && rx_count == 0
            && tx_ctrl & DMA_CTRL_BUSY == 0
            && rx_ctrl & DMA_CTRL_BUSY == 0
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
fn abort_channels(mask: u32) -> bool {
    unsafe {
        for channel in 0..2 {
            if mask & (1 << channel) != 0 {
                let ctrl = DMA_BASE + channel * DMA_CHANNEL_STRIDE + DMA_CTRL_TRIG;
                let value = read(ctrl);
                write(
                    ctrl,
                    (value & !(DMA_CTRL_ENABLE | DMA_CTRL_CHAIN_TO_MASK))
                        | ((channel as u32) << 13),
                );
            }
        }
        write(DMA_CHAN_ABORT, mask);
        let start = read(TIMER0_TIMERAWL);
        while read(DMA_CHAN_ABORT) != 0
            && read(TIMER0_TIMERAWL).wrapping_sub(start) < DMA_WAIT_TIMEOUT_US
        {
            for _ in 0..64 {
                core::hint::spin_loop();
            }
        }
        read(DMA_CHAN_ABORT) == 0
    }
}

#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
#[allow(clippy::too_many_arguments)]
fn configure_channel(
    channel: usize,
    source: u32,
    destination: u32,
    count: u32,
    treq: u32,
    increment_read: bool,
    increment_write: bool,
) {
    let base = DMA_BASE + channel * DMA_CHANNEL_STRIDE;
    unsafe {
        write(
            base + DMA_CTRL_TRIG,
            DMA_CTRL_READ_ERROR | DMA_CTRL_WRITE_ERROR,
        );
        write(base + DMA_READ_ADDR, source);
        write(base + DMA_WRITE_ADDR, destination);
        write(base + DMA_TRANS_COUNT, count);
        let increment = if increment_read {
            DMA_CTRL_INCR_READ
        } else {
            0
        } | if increment_write {
            DMA_CTRL_INCR_WRITE
        } else {
            0
        };
        write(
            base + DMA_CTRL_TRIG,
            (treq << 17)
                | ((channel as u32) << 13)
                | increment
                | DMA_CTRL_DATA_SIZE_WORD
                | DMA_CTRL_ENABLE,
        );
    }
}

#[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
fn wait_channel(channel: usize) -> u32 {
    let base = DMA_BASE + channel * DMA_CHANNEL_STRIDE;
    unsafe {
        let start = read(TIMER0_TIMERAWL);
        while read(base + DMA_CTRL_TRIG) & DMA_CTRL_BUSY != 0
            && read(TIMER0_TIMERAWL).wrapping_sub(start) < DMA_WAIT_TIMEOUT_US
        {
            for _ in 0..64 {
                core::hint::spin_loop();
            }
        }
        read(base + DMA_CTRL_TRIG)
    }
}

unsafe fn read(address: usize) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

unsafe fn write(address: usize, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}
