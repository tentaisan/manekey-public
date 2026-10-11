use core::cell::UnsafeCell;
use core::sync::atomic::{Ordering, compiler_fence};

pub const PMP_CYW43_PIO_DESCRIPTOR_MAGIC: u32 = 0x4359_5030;
pub const PMP_CYW43_PIO_ABI_VERSION: u32 = 1;
pub const PMP_CYW43_PIO_STATE_EMPTY: u32 = 0;
pub const PMP_CYW43_PIO_STATE_READY: u32 = 1;

const PIO0_BASE: u32 = 0x5020_0000;
const PIO0_TXF0: u32 = PIO0_BASE + 0x10;
const PIO0_RXF0: u32 = PIO0_BASE + 0x20;
const PIO0_SM0_BASE: u32 = PIO0_BASE + 0xc8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
/// Integer-only PIO0/SM0 descriptor with fixed C layout; validate before MMIO use.
pub struct PmpCyw43PioDescriptor {
    pub magic: u32,
    pub abi_version: u32,
    pub descriptor_size: u32,
    pub state: u32,
    pub pio_block: u32,
    pub state_machine: u32,
    pub pio_base: u32,
    pub tx_fifo_address: u32,
    pub rx_fifo_address: u32,
    pub state_machine_base: u32,
    pub wrap_target: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<PmpCyw43PioDescriptor>() == 48);
const _: () = assert!(core::mem::align_of::<PmpCyw43PioDescriptor>() == 4);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmpCyw43PioDescriptorError {
    InvalidHeader,
    NotReady,
    UnsupportedResource,
    InvalidAddress,
    InvalidWrapTarget,
    ReservedNotZero,
}

#[repr(transparent)]
/// One-shot startup cell; exclude concurrent readers and writers across all tasks, harts and interrupts.
/// Compiler fences do not make concurrent access safe.
pub struct PmpCyw43PioDescriptorSlot {
    descriptor: UnsafeCell<PmpCyw43PioDescriptor>,
}

unsafe impl Sync for PmpCyw43PioDescriptorSlot {}

impl PmpCyw43PioDescriptorSlot {
    pub const fn new() -> Self {
        Self {
            descriptor: UnsafeCell::new(PmpCyw43PioDescriptor::empty()),
        }
    }

    /// # Safety
    /// Exclusively own startup publication; exclude all readers, writers, interrupts and DMA.
    pub unsafe fn publish_before_user(&self, descriptor: PmpCyw43PioDescriptor) -> bool {
        let slot = self.descriptor.get();
        let state = unsafe { core::ptr::addr_of!((*slot).state).read_volatile() };
        if state != PMP_CYW43_PIO_STATE_EMPTY {
            return false;
        }
        unsafe { slot.write_volatile(descriptor) };
        compiler_fence(Ordering::Release);
        true
    }

    #[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
    /// # Safety
    /// Synchronize prior writes to the initialized slot; exclude all writes, including DMA, for this read.
    pub unsafe fn read_after_monitor(
        &self,
    ) -> Result<PmpCyw43PioDescriptor, PmpCyw43PioDescriptorError> {
        compiler_fence(Ordering::Acquire);
        let descriptor = unsafe { self.descriptor.get().read_volatile() };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

impl PmpCyw43PioDescriptor {
    const fn empty() -> Self {
        Self {
            magic: 0,
            abi_version: 0,
            descriptor_size: 0,
            state: PMP_CYW43_PIO_STATE_EMPTY,
            pio_block: 0,
            state_machine: 0,
            pio_base: 0,
            tx_fifo_address: 0,
            rx_fifo_address: 0,
            state_machine_base: 0,
            wrap_target: 0,
            reserved: 0,
        }
    }

    pub const fn pio0_sm0(wrap_target: u8) -> Self {
        Self {
            magic: PMP_CYW43_PIO_DESCRIPTOR_MAGIC,
            abi_version: PMP_CYW43_PIO_ABI_VERSION,
            descriptor_size: core::mem::size_of::<Self>() as u32,
            state: PMP_CYW43_PIO_STATE_READY,
            pio_block: 0,
            state_machine: 0,
            pio_base: PIO0_BASE,
            tx_fifo_address: PIO0_TXF0,
            rx_fifo_address: PIO0_RXF0,
            state_machine_base: PIO0_SM0_BASE,
            wrap_target: wrap_target as u32,
            reserved: 0,
        }
    }

    #[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
    /// Validate fixed PIO0/SM0 addresses and layout; this does not configure hardware access protection.
    pub fn validate(&self) -> Result<(), PmpCyw43PioDescriptorError> {
        if self.magic != PMP_CYW43_PIO_DESCRIPTOR_MAGIC
            || self.abi_version != PMP_CYW43_PIO_ABI_VERSION
            || self.descriptor_size != core::mem::size_of::<Self>() as u32
        {
            return Err(PmpCyw43PioDescriptorError::InvalidHeader);
        }
        if self.state != PMP_CYW43_PIO_STATE_READY {
            return Err(PmpCyw43PioDescriptorError::NotReady);
        }
        if self.pio_block != 0 || self.state_machine != 0 {
            return Err(PmpCyw43PioDescriptorError::UnsupportedResource);
        }
        if self.pio_base != PIO0_BASE
            || self.tx_fifo_address != PIO0_TXF0
            || self.rx_fifo_address != PIO0_RXF0
            || self.state_machine_base != PIO0_SM0_BASE
        {
            return Err(PmpCyw43PioDescriptorError::InvalidAddress);
        }
        if self.wrap_target >= 32 {
            return Err(PmpCyw43PioDescriptorError::InvalidWrapTarget);
        }
        if self.reserved != 0 {
            return Err(PmpCyw43PioDescriptorError::ReservedNotZero);
        }
        Ok(())
    }
}
