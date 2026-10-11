/// Requires the board's 8 MHz HSE bypass input; port owns clock and debug policy.
pub fn config() -> embassy_stm32::Config {
    use embassy_stm32::{rcc, time::Hertz};
    let mut config = embassy_stm32::Config::default();
    config.enable_debug_during_sleep = true;
    config.rcc.hse = Some(rcc::Hse {
        freq: Hertz(8_000_000),
        mode: rcc::HseMode::Bypass,
    });
    config.rcc.pll_src = rcc::PllSource::Hse;
    config.rcc.pll = Some(rcc::Pll {
        prediv: rcc::PllPreDiv::Div8,
        mul: rcc::PllMul::Mul192,
        divp: Some(rcc::PllPDiv::Div2),
        divq: Some(rcc::PllQDiv::Div4),
        divr: None,
    });
    config.rcc.sys = rcc::Sysclk::Pll1P;
    config.rcc.apb1_pre = rcc::APBPrescaler::Div2;
    config.rcc.ls = rcc::LsConfig::default_lsi();
    config
}
