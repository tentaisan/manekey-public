// Transfer setup and CS sequencing follow Embassy cyw43-pio; Copyright (c) Embassy project contributors.
// Comparison snapshot: https://github.com/embassy-rs/embassy/blob/0af1937a5ac77f52fea943b677088c38ef9e91c6/cyw43-pio/src/lib.rs
// Original portions: MIT OR Apache-2.0; see vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
// Modified for rp235x-hal polling, validated split-image descriptors and separately owned DMA staging.

use cyw43_riscv::SpiBusCyw43;
use embedded_hal::digital::OutputPin;
use pio::{Instruction, InstructionOperands, JmpCondition, OutDestination, SetDestination};
#[cfg(feature = "riscv-rp2350-hal")]
use rp235x_hal::pio::{Running, Rx, StateMachine, Tx, ValidStateMachine};

use super::pmp_cyw43_pio_abi::{PmpCyw43PioDescriptor, PmpCyw43PioDescriptorError};

const PIO_CTRL_OFFSET: u32 = 0x00;
const PIO_FSTAT_OFFSET: u32 = 0x04;
#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
const PIO_IRQ_OFFSET: u32 = 0x30;
const SM_SHIFTCTRL_OFFSET: u32 = 0x08;
const SM_EXECCTRL_OFFSET: u32 = 0x04;
const SM_INSTR_OFFSET: u32 = 0x10;
const SM0_ENABLE: u32 = 1;
const SM0_RX_EMPTY: u32 = 1 << 8;
const SM0_TX_FULL: u32 = 1 << 16;
const FJOIN_RX: u32 = 1 << 31;
const EXEC_STALLED: u32 = 1 << 31;
#[cfg(all(
    feature = "riscv-pmp-ble-user-dma-backend",
    not(feature = "riscv-pmp-ble-user-dma-irq-backend")
))]
const TIMER0_TIMERAWL: u32 = 0x400b_0028;
#[cfg(all(
    feature = "riscv-pmp-ble-user-dma-backend",
    not(feature = "riscv-pmp-ble-user-dma-irq-backend")
))]
const DMA_STATUS_TIMEOUT_US: u32 = 100_000;
#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
const DMA_IRQ_MAX_READ_WORDS_WITH_STATUS: usize = 514;
const CYW43_BUS_TEST_READ_COMMAND: u32 = (1 << 30) | (0x14 << 11) | 4;
const CYW43_BUS_TEST_READ_COMMAND_SWAPPED: u32 = CYW43_BUS_TEST_READ_COMMAND.rotate_left(16);
pub const CYW43_BUS_TEST_EXPECTED: u32 = 0xfeed_bead;

/// Exclusive configured PIO0/SM0 and CS owner; descriptor validation does not enforce peripheral ownership.
/// Polling waits may be unbounded; DMA cancellation requires separate PIO/CS recovery.
pub struct RiscvCyw43RawPioSpi<CS> {
    descriptor: PmpCyw43PioDescriptor,
    cs: CS,
    #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
    irq_dma_bootstrapped: bool,
}

impl<CS: OutputPin> RiscvCyw43RawPioSpi<CS> {
    #[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
    /// Require monitor configuration, MMIO delegation and CS high before construction.
    pub fn from_initialized_descriptor(
        descriptor: PmpCyw43PioDescriptor,
        cs: CS,
    ) -> Result<Self, PmpCyw43PioDescriptorError> {
        descriptor.validate()?;
        Ok(Self {
            descriptor,
            cs,
            #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
            irq_dma_bootstrapped: false,
        })
    }

    #[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
    /// Check descriptor values only; this is not proof of hardware isolation or exclusive ownership.
    pub fn descriptor_probe_mask(&self) -> u32 {
        let mut mask = 0;
        if self.descriptor.pio_base == 0x5020_0000 {
            mask |= 1 << 0;
        }
        if self.descriptor.tx_fifo_address == 0x5020_0010 {
            mask |= 1 << 1;
        }
        if self.descriptor.rx_fifo_address == 0x5020_0020 {
            mask |= 1 << 2;
        }
        if self.descriptor.state_machine_base == 0x5020_00c8 {
            mask |= 1 << 3;
        }
        if self.descriptor.wrap_target < 32 {
            mask |= 1 << 4;
        }
        mask
    }

    fn read(address: u32) -> u32 {
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }

    fn write(address: u32, value: u32) {
        unsafe { core::ptr::write_volatile(address as *mut u32, value) }
    }

    fn pio_register(&self, offset: u32) -> u32 {
        self.descriptor.pio_base + offset
    }

    fn sm_register(&self, offset: u32) -> u32 {
        self.descriptor.state_machine_base + offset
    }

    fn set_enabled(&self, enabled: bool) {
        let address = self.pio_register(PIO_CTRL_OFFSET);
        let value = Self::read(address);
        Self::write(
            address,
            if enabled {
                value | SM0_ENABLE
            } else {
                value & !SM0_ENABLE
            },
        );
    }

    fn clear_fifos(&self) {
        let address = self.sm_register(SM_SHIFTCTRL_OFFSET);
        let original = Self::read(address);
        Self::write(address, original ^ FJOIN_RX);
        Self::write(address, original);
    }

    fn exec_instruction(&self, operands: InstructionOperands) {
        let instruction = Instruction {
            operands,
            delay: 0,
            side_set: Some(0),
        }
        .encode(pio::SideSet::new(false, 1, false));
        Self::write(self.sm_register(SM_INSTR_OFFSET), instruction as u32);
        while Self::read(self.sm_register(SM_EXECCTRL_OFFSET)) & EXEC_STALLED != 0 {
            core::hint::spin_loop();
        }
    }

    fn tx_write(&self, value: u32) -> bool {
        if Self::read(self.pio_register(PIO_FSTAT_OFFSET)) & SM0_TX_FULL != 0 {
            return false;
        }
        Self::write(self.descriptor.tx_fifo_address, value);
        true
    }

    fn rx_read(&self) -> Option<u32> {
        if Self::read(self.pio_register(PIO_FSTAT_OFFSET)) & SM0_RX_EMPTY != 0 {
            return None;
        }
        Some(Self::read(self.descriptor.rx_fifo_address))
    }

    fn write_scratch(&self, destination: OutDestination, value: u32) {
        while !self.tx_write(value) {
            core::hint::spin_loop();
        }
        self.exec_instruction(InstructionOperands::OUT {
            destination,
            bit_count: 32,
        });
    }

    fn prepare_transfer(&self, write_bits: u32, read_bits: u32) {
        self.set_enabled(false);
        self.clear_fifos();
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        Self::write(self.pio_register(PIO_IRQ_OFFSET), 1);
        self.write_scratch(OutDestination::X, write_bits);
        self.write_scratch(OutDestination::Y, read_bits);
        self.exec_instruction(InstructionOperands::SET {
            destination: SetDestination::PINDIRS,
            data: 1,
        });
        self.exec_instruction(InstructionOperands::JMP {
            condition: JmpCondition::Always,
            address: self.descriptor.wrap_target as u8,
        });
    }

    fn start_transfer(&self, write_bits: u32, read_bits: u32) {
        self.prepare_transfer(write_bits, read_bits);
        self.set_enabled(true);
    }

    #[cfg_attr(feature = "riscv-pmp-ble-user-dma-backend", allow(dead_code))]
    fn write_blocking(&self, write: &[u32]) -> u32 {
        super::cyw43_polling::write(self, write)
    }

    fn read_blocking(&self, command: u32, read: &mut [u32]) -> u32 {
        super::cyw43_polling::read(self, command, read)
    }

    #[cfg(feature = "riscv-pmp-ble-user-dma-backend")]
    async fn write_dma(&self, write: &[u32]) -> u32 {
        assert!(!write.is_empty());
        #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
        self.start_transfer((write.len() * 32 - 1) as u32, 31);
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        self.prepare_transfer((write.len() * 32 - 1) as u32, 31);
        let mut status = [0];
        #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
        let result = super::pmp_dma::run_pio0_sm0_exchange(write, &mut status);
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        let result = super::pmp_dma::run_pio0_sm0_exchange_irq(write, &mut status, || {
            self.set_enabled(true);
        })
        .await;
        if result == super::pmp_dma::DMA_PIO_EXCHANGE_EXPECTED {
            #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
            return unsafe { status.as_ptr().read_volatile() };
            #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
            status[0]
        } else {
            u32::MAX
        }
    }

    #[cfg(feature = "riscv-pmp-ble-user-dma-backend")]
    async fn read_dma(&self, command: u32, read: &mut [u32]) -> u32 {
        if read.is_empty() {
            #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
            self.start_transfer(31, 31);
            #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
            self.prepare_transfer(31, 31);
            let command = [command];
            let mut status = [0];
            #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
            let result = super::pmp_dma::run_pio0_sm0_exchange(&command, &mut status);
            #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
            let result = super::pmp_dma::run_pio0_sm0_exchange_irq(&command, &mut status, || {
                self.set_enabled(true);
            })
            .await;
            return if result == super::pmp_dma::DMA_PIO_EXCHANGE_EXPECTED {
                status[0]
            } else {
                u32::MAX
            };
        }

        #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
        self.start_transfer(31, (read.len() * 32 + 31) as u32);
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        self.prepare_transfer(31, (read.len() * 32 + 31) as u32);
        let command = [command];
        #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
        let result = super::pmp_dma::run_pio0_sm0_exchange(&command, read);
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        let (result, status) = {
            let response_len = read.len() + 1;
            if response_len > DMA_IRQ_MAX_READ_WORDS_WITH_STATUS {
                return u32::MAX;
            }
            let mut response = [0_u32; DMA_IRQ_MAX_READ_WORDS_WITH_STATUS];
            let result = super::pmp_dma::run_pio0_sm0_exchange_irq(
                &command,
                &mut response[..response_len],
                || self.set_enabled(true),
            )
            .await;
            for (index, word) in read.iter_mut().enumerate() {
                *word = unsafe { response.as_ptr().add(index).read_volatile() };
            }
            let status = unsafe { response.as_ptr().add(read.len()).read_volatile() };
            (result, status)
        };
        if result != super::pmp_dma::DMA_PIO_EXCHANGE_EXPECTED {
            return u32::MAX;
        }

        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        {
            return status;
        }

        #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
        {
            let start = Self::read(TIMER0_TIMERAWL);
            loop {
                if let Some(status) = self.rx_read() {
                    return status;
                }
                if Self::read(TIMER0_TIMERAWL).wrapping_sub(start) >= DMA_STATUS_TIMEOUT_US {
                    return u32::MAX;
                }
                core::hint::spin_loop();
            }
        }
    }
}

impl<CS: OutputPin> super::cyw43_polling::PioFifo for RiscvCyw43RawPioSpi<CS> {
    #[inline(always)]
    fn start_transfer(&self, write_bits: u32, read_bits: u32) {
        Self::start_transfer(self, write_bits, read_bits);
    }
    #[inline(always)]
    fn tx_write(&self, word: u32) -> bool {
        Self::tx_write(self, word)
    }
    #[inline(always)]
    fn rx_read(&self) -> Option<u32> {
        Self::rx_read(self)
    }
}

impl<CS: OutputPin> SpiBusCyw43 for RiscvCyw43RawPioSpi<CS> {
    #[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
    async fn cmd_write(&mut self, write: &[u32]) -> u32 {
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        let _ = super::pmp_dma::user_rearm_dma_irq0();
        let _ = self.cs.set_low();
        #[cfg(not(feature = "riscv-pmp-ble-user-dma-backend"))]
        let status = self.write_blocking(write);
        #[cfg(feature = "riscv-pmp-ble-user-dma-backend")]
        let status = self.write_dma(write).await;
        let _ = self.cs.set_high();
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        if !super::pmp_dma::wait_pio0_sm0_transaction_complete() {
            return u32::MAX;
        }
        status
    }

    #[unsafe(link_section = ".text.pmp_user_cyw43_pio")]
    async fn cmd_read(&mut self, command: u32, read: &mut [u32]) -> u32 {
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        if !self.irq_dma_bootstrapped && command == CYW43_BUS_TEST_READ_COMMAND_SWAPPED {
            let _ = self.cs.set_low();
            let status = self.read_blocking(command, read);
            let _ = self.cs.set_high();
            if !super::pmp_dma::wait_pio0_sm0_transaction_complete() {
                return u32::MAX;
            }
            if read.first().copied().unwrap_or_default().rotate_left(16) == CYW43_BUS_TEST_EXPECTED
            {
                self.irq_dma_bootstrapped = true;
            }
            return status;
        }

        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        let _ = super::pmp_dma::user_rearm_dma_irq0();
        let _ = self.cs.set_low();
        #[cfg(not(feature = "riscv-pmp-ble-user-dma-backend"))]
        let status = self.read_blocking(command, read);
        #[cfg(feature = "riscv-pmp-ble-user-dma-backend")]
        let status = self.read_dma(command, read).await;
        let _ = self.cs.set_high();
        #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
        if !super::pmp_dma::wait_pio0_sm0_transaction_complete() {
            return u32::MAX;
        }
        status
    }
}

#[cfg(feature = "riscv-rp2350-hal")]
/// Single-owner polling CYW43 bus; keep state machine, FIFO handles and CS dedicated to this adapter.
pub struct RiscvCyw43PioSpi<SM, CS>
where
    SM: ValidStateMachine,
{
    state_machine: Option<StateMachine<SM, Running>>,
    rx: Rx<SM>,
    tx: Tx<SM>,
    cs: CS,
    wrap_target: u8,
}

#[cfg(feature = "riscv-rp2350-hal")]
impl<SM, CS> RiscvCyw43PioSpi<SM, CS>
where
    SM: ValidStateMachine,
    CS: OutputPin,
{
    /// Use a configured running state machine and its matching FIFO handles and installed wrap target.
    pub fn new(
        state_machine: StateMachine<SM, Running>,
        rx: Rx<SM>,
        tx: Tx<SM>,
        mut cs: CS,
        wrap_target: u8,
    ) -> Self {
        let _ = cs.set_high();
        Self {
            state_machine: Some(state_machine),
            rx,
            tx,
            cs,
            wrap_target,
        }
    }

    /// Transfer initialized owners with CS already high; do not invoke a U-mode CS gateway during M-mode setup.
    pub fn from_initialized_parts(
        state_machine: StateMachine<SM, Running>,
        rx: Rx<SM>,
        tx: Tx<SM>,
        cs: CS,
        wrap_target: u8,
    ) -> Self {
        Self {
            state_machine: Some(state_machine),
            rx,
            tx,
            cs,
            wrap_target,
        }
    }

    fn instruction(operands: InstructionOperands) -> Instruction {
        Instruction {
            operands,
            delay: 0,
            side_set: Some(0),
        }
    }

    fn write_scratch(
        tx: &mut Tx<SM>,
        state_machine: &mut StateMachine<SM, rp235x_hal::pio::Stopped>,
        destination: OutDestination,
        value: u32,
    ) {
        while !tx.write(value) {
            core::hint::spin_loop();
        }
        state_machine.exec_instruction(Self::instruction(InstructionOperands::OUT {
            destination,
            bit_count: 32,
        }));
    }

    fn start_transfer(&mut self, write_bits: u32, read_bits: u32) {
        let mut state_machine = self
            .state_machine
            .take()
            .expect("CYW43 PIO state machine ownership lost")
            .stop();
        state_machine.clear_fifos();

        Self::write_scratch(
            &mut self.tx,
            &mut state_machine,
            OutDestination::X,
            write_bits,
        );
        Self::write_scratch(
            &mut self.tx,
            &mut state_machine,
            OutDestination::Y,
            read_bits,
        );
        state_machine.exec_instruction(Self::instruction(InstructionOperands::SET {
            destination: SetDestination::PINDIRS,
            data: 1,
        }));
        state_machine.exec_instruction(Self::instruction(InstructionOperands::JMP {
            condition: JmpCondition::Always,
            address: self.wrap_target,
        }));

        self.state_machine = Some(state_machine.start());
    }

    fn exchange(&mut self, write: &[u32], read: &mut [u32]) {
        let mut write_index = 0;
        let mut read_index = 0;

        while write_index < write.len() || read_index < read.len() {
            let mut progressed = false;
            if write_index < write.len() && self.tx.write(write[write_index]) {
                write_index += 1;
                progressed = true;
            }
            if read_index < read.len() {
                if let Some(word) = self.rx.read() {
                    read[read_index] = word;
                    read_index += 1;
                    progressed = true;
                }
            }
            if !progressed {
                core::hint::spin_loop();
            }
        }
    }

    fn write_blocking(&mut self, write: &[u32]) -> u32 {
        assert!(!write.is_empty());
        self.start_transfer((write.len() * 32 - 1) as u32, 31);
        let mut status = [0];
        self.exchange(write, &mut status);
        status[0]
    }

    fn read_blocking(&mut self, command: u32, read: &mut [u32]) -> u32 {
        self.start_transfer(31, (read.len() * 32 + 32 - 1) as u32);

        let mut command_pending = true;
        let mut read_index = 0;
        let mut status = 0;
        while command_pending || read_index <= read.len() {
            let mut progressed = false;
            if command_pending && self.tx.write(command) {
                command_pending = false;
                progressed = true;
            }
            if let Some(word) = self.rx.read() {
                if read_index < read.len() {
                    read[read_index] = word;
                } else {
                    status = word;
                }
                read_index += 1;
                progressed = true;
            }
            if !progressed {
                core::hint::spin_loop();
            }
        }
        status
    }
}

#[cfg(feature = "riscv-rp2350-hal")]
impl<SM, CS> SpiBusCyw43 for RiscvCyw43PioSpi<SM, CS>
where
    SM: ValidStateMachine,
    CS: OutputPin,
{
    async fn cmd_write(&mut self, write: &[u32]) -> u32 {
        let _ = self.cs.set_low();
        let status = self.write_blocking(write);
        let _ = self.cs.set_high();
        status
    }

    async fn cmd_read(&mut self, command: u32, read: &mut [u32]) -> u32 {
        let _ = self.cs.set_low();
        let status = self.read_blocking(command, read);
        let _ = self.cs.set_high();
        status
    }
}
