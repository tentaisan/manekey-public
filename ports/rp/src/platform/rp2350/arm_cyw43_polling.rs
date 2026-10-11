// PIO program derived from Embassy cyw43-pio; Copyright (c) Embassy project contributors.
// Underlying Pico SDK portions: Copyright (c) 2020 Raspberry Pi (Trading) Ltd.; BSD-3-Clause, see RP NOTICE.
// Upstream: https://github.com/embassy-rs/embassy/blob/0af1937a5ac77f52fea943b677088c38ef9e91c6/cyw43-pio/src/lib.rs
// Original program: MIT OR Apache-2.0; see vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
// Modified for polling-only operation and numeric PIO branch targets.

use super::cyw43_polling::{self, PioFifo};
use embassy_rp::Peri;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{PIN_24, PIN_29, PIO0};
use embassy_rp::pio::program as pio;
use embassy_rp::pio::{Common, Config, Direction, ShiftDirection, StateMachine};
use pio::{Instruction, InstructionOperands, JmpCondition, OutDestination, SetDestination};

/// Exclusive PIO0/SM0, GP24/GP29 and CS owner using polling without DMA.
/// Require peripheral delegation in Non-Secure mode; FIFO waits have no timeout.
pub struct ArmPollingPioSpi {
    cs: Output<'static>,
    _sm: StateMachine<'static, PIO0, 0>,
    wrap: u8,
}

impl ArmPollingPioSpi {
    /// Reserve the loaded program and pin owners for this adapter's lifetime; exclude concurrent PIO users.
    pub fn new(
        common: &mut Common<'static, PIO0>,
        mut sm: StateMachine<'static, PIO0, 0>,
        cs: Output<'static>,
        dio: Peri<'static, PIN_24>,
        clk: Peri<'static, PIN_29>,
    ) -> Self {
        let program = pio::pio_asm!(
            ".side_set 1",
            ".wrap_target",
            "out pins, 1 side 0",
            "jmp x-- 0 side 1",
            "set pindirs, 0 side 0",
            "nop side 0",
            "in pins, 1 side 1",
            "jmp y-- 4 side 0",
            "wait 1 pin 0 side 0",
            "irq 0 side 0",
            ".wrap",
        );
        let loaded = common.load_program(&program.program);
        let io = common.make_pio_pin(dio);
        let clock = common.make_pio_pin(clk);
        let mut cfg = Config::default();
        cfg.use_program(&loaded, &[&clock]);
        cfg.set_out_pins(&[&io]);
        cfg.set_in_pins(&[&io]);
        cfg.set_set_pins(&[&io]);
        cfg.shift_out.direction = ShiftDirection::Left;
        cfg.shift_out.auto_fill = true;
        cfg.shift_in.direction = ShiftDirection::Left;
        cfg.shift_in.auto_fill = true;
        cfg.clock_divider = 30u8.into();
        cfg.set_input_sync_bypass(&[&io]);
        sm.set_config(&cfg);
        sm.set_pin_dirs(Direction::Out, &[&clock, &io]);
        sm.set_pins(Level::Low, &[&clock, &io]);
        Self {
            cs,
            _sm: sm,
            wrap: loaded.wrap.target,
        }
    }
    fn read(offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((0x5020_0000 + offset) as *const u32) }
    }
    fn write(offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile((0x5020_0000 + offset) as *mut u32, value) }
    }
    fn exec(operands: InstructionOperands) {
        let word = Instruction {
            operands,
            delay: 0,
            side_set: Some(0),
        }
        .encode(pio::SideSet::new(false, 1, false));
        Self::write(0xd8, word as u32);
        while Self::read(0xcc) & (1 << 31) != 0 {
            core::hint::spin_loop();
        }
    }
    fn scratch(&self, destination: OutDestination, value: u32) {
        while !self.tx_write(value) {
            core::hint::spin_loop();
        }
        Self::exec(InstructionOperands::OUT {
            destination,
            bit_count: 32,
        });
    }
}
impl PioFifo for ArmPollingPioSpi {
    fn start_transfer(&self, write_bits: u32, read_bits: u32) {
        Self::write(0, Self::read(0) & !1);
        let shift = Self::read(0xd0);
        Self::write(0xd0, shift ^ (1 << 31));
        Self::write(0xd0, shift);
        self.scratch(OutDestination::X, write_bits);
        self.scratch(OutDestination::Y, read_bits);
        Self::exec(InstructionOperands::SET {
            destination: SetDestination::PINDIRS,
            data: 1,
        });
        Self::exec(InstructionOperands::JMP {
            condition: JmpCondition::Always,
            address: self.wrap,
        });
        Self::write(0, Self::read(0) | 1);
    }
    fn tx_write(&self, word: u32) -> bool {
        if Self::read(4) & (1 << 16) != 0 {
            return false;
        }
        Self::write(0x10, word);
        true
    }
    fn rx_read(&self) -> Option<u32> {
        if Self::read(4) & (1 << 8) != 0 {
            None
        } else {
            Some(Self::read(0x20))
        }
    }
}
impl cyw43::SpiBusCyw43 for ArmPollingPioSpi {
    async fn cmd_write(&mut self, words: &[u32]) -> u32 {
        self.cs.set_low();
        let status = cyw43_polling::write(self, words);
        self.cs.set_high();
        status
    }
    async fn cmd_read(&mut self, command: u32, words: &mut [u32]) -> u32 {
        self.cs.set_low();
        let status = cyw43_polling::read(self, command, words);
        self.cs.set_high();
        status
    }
}
