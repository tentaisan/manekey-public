// Experimental entropy source; ADC1 is exclusively owned in an RF-free, awake runtime.
// Conditioning/health checks do not establish a certified entropy estimate.

// Portions derived from ESP-IDF bootloader_random_esp32c5.c:
// SPDX-FileCopyrightText: 2024-2025 Espressif Systems (Shanghai) CO LTD
// Portions derived from ESP-IDF v5.5 C5 hal/regi2c_ctrl_ll.h:
// SPDX-FileCopyrightText: 2022-2025 Espressif Systems (Shanghai) CO LTD
// SPDX-License-Identifier: Apache-2.0
// Modified: translated to Rust HAL register access with bounded polling,
// configuration readback and best-effort restoration.
// Other source paths: components/hal/esp32c5/include/hal/adc_ll.h and
// components/soc/esp32c5/include/soc/regi2c_saradc.h (ESP-IDF v5.5).

use esp_hal::{
    delay::Delay,
    peripherals::{ADC1, APB_SARADC, I2C_ANA_MST, MODEM_LPCON, PCR, PMU},
    rng::Rng,
};
use manekey::ctaphid::entropy::{EntropyError, EntropySource};

#[cfg(feature = "ble")]
compile_error!("C5 ADC entropy probe must run without the RF/RTOS runtime");

const SAR: u8 = 0x69;
const POLL_LIMIT: usize = 100_000;

/// Experimental ADC entropy; no certified entropy estimate.
/// Platform must exclusively reserve ADC and related analog/clock/power registers in an awake, RF-free runtime.
/// Configuration readback is not an entropy health guarantee; restoration is best effort.
pub struct C5AdcEntropy<'d> {
    _adc: ADC1<'d>,
    rng: Rng,
    saved: [u32; 8],
    analog: [u8; 6],
    analog_saved: bool,
}

impl<'d> C5AdcEntropy<'d> {
    pub fn new(adc: ADC1<'d>) -> Result<Self, EntropyError> {
        let pcr = PCR::regs();
        let sar = APB_SARADC::regs();
        let mut source = Self {
            _adc: adc,
            rng: Rng::new(),
            saved: [
                pcr.saradc_conf().read().bits(),
                pcr.saradc_clkm_conf().read().bits(),
                PMU::regs().rf_pwc().read().bits(),
                MODEM_LPCON::regs().clk_conf().read().bits(),
                I2C_ANA_MST::regs().ana_conf1().read().bits(),
                sar.ctrl().read().bits(),
                sar.ctrl2().read().bits(),
                sar.sar_patt_tab1().read().bits(),
            ],
            analog: [0; 6],
            analog_saved: false,
        };

        PMU::regs()
            .rf_pwc()
            .modify(|_, w| w.perif_i2c_rstb().clear_bit());
        PMU::regs()
            .rf_pwc()
            .modify(|_, w| w.xpd_perif_i2c().set_bit());
        PMU::regs()
            .rf_pwc()
            .modify(|_, w| w.perif_i2c_rstb().set_bit());
        MODEM_LPCON::regs()
            .clk_conf()
            .modify(|_, w| w.clk_i2c_mst_en().set_bit());
        for (slot, reg) in source.analog.iter_mut().zip([0, 1, 3, 4, 7, 8]) {
            *slot = analog_read(reg)?;
        }
        source.analog_saved = true;
        pcr.saradc_conf().modify(|_, w| w.saradc_rst_en().set_bit());
        pcr.saradc_conf()
            .modify(|_, w| w.saradc_rst_en().clear_bit());
        pcr.saradc_conf()
            .modify(|_, w| w.saradc_reg_rst_en().set_bit());
        pcr.saradc_conf()
            .modify(|_, w| w.saradc_reg_rst_en().clear_bit());
        pcr.saradc_conf()
            .modify(|_, w| w.saradc_reg_clk_en().set_bit());
        unsafe {
            pcr.saradc_clkm_conf().modify(|_, w| {
                w.saradc_clkm_en().set_bit();
                w.saradc_clkm_sel().bits(0);
                w.saradc_clkm_div_num().bits(0);
                w.saradc_clkm_div_a().bits(0);
                w.saradc_clkm_div_b().bits(0)
            });
        }

        analog_field(7, 0x43, 0x40)?;
        analog_field(8, 0x05, 0x05)?;
        analog_field(1, 0x0f, 0x08)?;
        analog_write(0, 0x66)?;
        analog_field(4, 0x0f, 0x08)?;
        analog_write(3, 0x66)?;
        unsafe {
            sar.sar_patt_tab1()
                .modify(|r, w| w.bits((r.bits() & !0xfff000) | (0x1f << 18) | (0x27 << 12)));
            sar.ctrl().modify(|_, w| {
                w.sar_clk_gated().set_bit();
                w.sar_patt_len().bits(1);
                w.sar_clk_div().bits(15)
            });
            sar.ctrl2().modify(|_, w| {
                w.timer_target().bits(200);
                w.timer_en().set_bit()
            });
        }
        Delay::new().delay_millis(10);
        if !source.configuration_matches()? {
            return Err(EntropyError::Unavailable);
        }
        Ok(source)
    }

    pub fn configuration_matches(&self) -> Result<bool, EntropyError> {
        let sar = APB_SARADC::regs();
        Ok(sar.ctrl2().read().timer_en().bit_is_set()
            && sar.ctrl2().read().timer_target().bits() == 200
            && sar.ctrl().read().sar_patt_len().bits() == 1
            && sar.ctrl().read().sar_clk_div().bits() == 15
            && sar.sar_patt_tab1().read().bits() & 0xfff000 == (0x1f << 18) | (0x27 << 12)
            && analog_read(7)? & 0x43 == 0x40
            && analog_read(8)? & 0x05 == 0x05
            && analog_read(0)? == 0x66
            && analog_read(1)? & 0x0f == 8
            && analog_read(3)? == 0x66
            && analog_read(4)? & 0x0f == 8)
    }
}

impl EntropySource for C5AdcEntropy<'_> {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        if !self.configuration_matches()? {
            return Err(EntropyError::Unavailable);
        }
        self.rng.read(output);
        Ok(())
    }
}

impl Drop for C5AdcEntropy<'_> {
    fn drop(&mut self) {
        APB_SARADC::regs()
            .ctrl2()
            .modify(|_, w| w.timer_en().clear_bit());
        if self.analog_saved {
            for (reg, value) in [0, 1, 3, 4, 7, 8].into_iter().zip(self.analog) {
                let _ = analog_write(reg, value);
            }
        }

        unsafe {
            APB_SARADC::regs()
                .sar_patt_tab1()
                .write(|w| w.bits(self.saved[7]));
            APB_SARADC::regs().ctrl().write(|w| w.bits(self.saved[5]));
            APB_SARADC::regs().ctrl2().write(|w| w.bits(self.saved[6]));
            PCR::regs()
                .saradc_clkm_conf()
                .write(|w| w.bits(self.saved[1]));
            PCR::regs().saradc_conf().write(|w| w.bits(self.saved[0]));
            I2C_ANA_MST::regs()
                .ana_conf1()
                .write(|w| w.bits(self.saved[4]));
            PMU::regs().rf_pwc().write(|w| w.bits(self.saved[2]));
            MODEM_LPCON::regs()
                .clk_conf()
                .write(|w| w.bits(self.saved[3]));
        }
    }
}

fn master() -> usize {
    let regs = I2C_ANA_MST::regs();
    let index = if regs.ana_conf2().read().sar_i2c_mst_sel().bit_is_set() {
        0
    } else {
        1
    };
    unsafe {
        regs.ana_conf1().write(|w| {
            w.bits(0x00ffffff);
            w.sar_i2c_rd().clear_bit()
        });
    }
    index
}

fn wait(index: usize) -> Result<(), EntropyError> {
    for _ in 0..POLL_LIMIT {
        if !I2C_ANA_MST::regs().i2c_ctrl(index).read().busy().bit() {
            return Ok(());
        }
    }
    Err(EntropyError::Unavailable)
}

fn analog_read(reg: u8) -> Result<u8, EntropyError> {
    let index = master();
    wait(index)?;
    unsafe {
        I2C_ANA_MST::regs().i2c_ctrl(index).write(|w| {
            w.slave_addr().bits(SAR);
            w.slave_reg_addr().bits(reg)
        });
    }
    wait(index)?;
    Ok(I2C_ANA_MST::regs().i2c_ctrl(index).read().data().bits())
}

fn analog_write(reg: u8, value: u8) -> Result<(), EntropyError> {
    let index = master();
    wait(index)?;
    unsafe {
        I2C_ANA_MST::regs().i2c_ctrl(index).write(|w| {
            w.slave_addr().bits(SAR);
            w.slave_reg_addr().bits(reg);
            w.read_write().set_bit();
            w.data().bits(value)
        });
    }
    wait(index)
}

fn analog_field(reg: u8, mask: u8, value: u8) -> Result<(), EntropyError> {
    analog_write(reg, (analog_read(reg)? & !mask) | value)
}
