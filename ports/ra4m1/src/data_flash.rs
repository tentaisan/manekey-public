




/*
 * Third-party references retained for this Rust adaptation:
 * - Controller sequencing: Renesas FSP ra/fsp/src/r_flash_lp/r_flash_lp.c,
 *   revision 6e2675336b37fbd805f0c01d5134adfdab4bf294.
 *   Copyright (c) 2020 - 2026 Renesas Electronics Corporation and/or its affiliates.
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Conditions/disclaimer: ../vendor/renesas-sce5/LICENSE.md,
 *   section "BSD 3-Clause License".
 * - Register widths/offsets: R7FA4M1AB.h in Seeed ArduinoCore-renesas 1.2.0,
 *   variants/XIAORA4M1/includes/ra/fsp/src/bsp/cmsis/Device/RENESAS/Include/.
 *   Copyright (c) 2009-2019 ARM Limited. All rights reserved.
 *   SPDX-License-Identifier: Apache-2.0
 *   License: ../../../LICENSE-APACHE-2.0.
 * Changes: fixed RA4M1 Data Flash-only Rust interface, bounded polling and cleanup;
 * no code Flash, option-setting, access-window or permanent lock operations.
 * Original ManeKey ownership/error/bounds integration retains the port license;
 * the third-party notices do not grant relicensing of referenced material.
 */

const FACI: usize = 0x407e_c000;
pub const SIZE: usize = 8192;
pub const BLOCK: usize = 1024;
const DATA: usize = 0x4010_0000;

pub enum Error {
    Range,
    Timeout,
    Controller(u32),
    Mode,
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Range => f.write_str("Range"),
            Self::Timeout => f.write_str("Timeout"),
            Self::Mode => f.write_str("Mode"),
            Self::Controller(status) => write!(f, "Controller({status:#x})"),
        }
    }
}

// PAC 0.3.2 omits FACI. These private volatile accesses use documented widths;
// callers must keep sole Flash ownership and must not change clocks concurrently.
fn read32(offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((FACI + offset) as *const u32) }
}
fn write32(offset: usize, value: u32) {
    unsafe { core::ptr::write_volatile((FACI + offset) as *mut u32, value) }
}
fn write16(offset: usize, value: u16) {
    unsafe { core::ptr::write_volatile((FACI + offset) as *mut u16, value) }
}
fn write8(offset: usize, value: u8) {
    unsafe { core::ptr::write_volatile((FACI + offset) as *mut u8, value) }
}

fn mode(value: u8) {
    write32(0x180, 0xa5);
    write8(0x100, value);
    write8(0x100, !value);
    write8(0x100, value);
    unsafe { core::ptr::read_volatile((FACI + 0x100) as *const u8) };
}

pub struct DataFlash;

impl DataFlash {

    pub unsafe fn new() -> Self {
        write8(0x90, 1);
        cortex_m::asm::delay(1200);
        Self
    }

    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), Error> {
        // Failed PE cleanup must never expose a controller-mode read as valid data.
        if unsafe { core::ptr::read_volatile((FACI + 0x3fb2) as *const u16) } != 0 {
            return Err(Error::Mode);
        }
        if offset
            .checked_add(output.len())
            .is_none_or(|end| end > SIZE)
        {
            return Err(Error::Range);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile((DATA + offset + index) as *const u8) };
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), Error> {
        if ra_hal::clock::clock_status().flash.to_Hz() != 24_000_000 {
            return Err(Error::Mode);
        }
        write16(0x3fb2, 0xaa80);
        cortex_m::asm::delay(1200);
        mode(0x10);
        // FISR.PCKA encodes FCLK MHz - 1. Preserve startup-area fields.
        write32(0x1d8, (read32(0x1d8) & !0x1f) | 23);
        write8(0x104, 0);
        Ok(())
    }

    fn exit(&mut self) -> Result<(), Error> {
        mode(0x08);
        cortex_m::asm::delay(1200);
        write16(0x3fb2, 0xaa00);
        for _ in 0..100_000 {
            if unsafe { core::ptr::read_volatile((FACI + 0x3fb2) as *const u16) } == 0 {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    fn finish(&mut self, command: u8, error_mask: u32) -> Result<(), Error> {
        write8(0x114, command);
        let mut ready = false;
        for _ in 0..2_000_000 {
            if read32(0x12c) & 0x40 != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(Error::Timeout);
        }
        write8(0x114, 0);
        for _ in 0..100_000 {
            if read32(0x12c) & 0x40 == 0 {
                let status = read32(0x1f0);
                return if status & error_mask == 0 {
                    Ok(())
                } else {
                    Err(Error::Controller(status))
                };
            }
        }
        Err(Error::Timeout)
    }

    fn cleanup(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        if result.is_err() {
            write32(0x124, 1);
            write32(0x124, 0);
        }
        let exit = self.exit();
        result.and(exit)
    }

    pub fn program(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if offset.checked_add(bytes.len()).is_none_or(|end| end > SIZE) {
            return Err(Error::Range);
        }
        self.enter()?;
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == 0xff {
                continue;
            }
            let address = 0xfe00_0000u32 + (offset + index) as u32;
            write16(0x110, (address >> 16) as u16);
            write16(0x108, address as u16);
            write32(0x130, byte as u32);
            if let Err(error) = self.finish(0x81, 0x12) {
                return self.cleanup(Err(error));
            }
        }
        self.cleanup(Ok(()))
    }

    pub fn erase_block(&mut self, offset: usize) -> Result<(), Error> {
        if offset % BLOCK != 0 || offset >= SIZE {
            return Err(Error::Range);
        }
        self.enter()?;
        let start = 0xfe00_0000u32 + offset as u32;
        let end = start + BLOCK as u32 - 1;
        write16(0x110, (start >> 16) as u16);
        write16(0x108, start as u16);
        write32(0x120, end >> 16);
        write16(0x118, end as u16);
        let result = self.finish(0x84, 0x11);
        self.cleanup(result)
    }
}
