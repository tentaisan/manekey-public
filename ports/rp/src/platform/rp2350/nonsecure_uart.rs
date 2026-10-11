use embedded_io_async::{ErrorKind, ErrorType, Read, Write};

/// Polling Non-Secure UART0 owner; waits yield without a wall-clock timeout.
pub struct NonsecureUart;

impl NonsecureUart {
    /// # Safety
    /// Secure firmware must initialize UART0 at 115200/8N1 and delegate UART0/GP0/GP1.
    /// Exclusively own it; exclude competing readers, interrupts and DMA.
    pub unsafe fn from_secure_handoff() -> Self {
        Self
    }
}

impl ErrorType for NonsecureUart {
    type Error = ErrorKind;
}

impl Read for NonsecureUart {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while rp_pac::UART0.uartfr().read().rxfe() {
            embassy_time::Timer::after_micros(100).await;
        }
        let mut len = 0;
        while len < buffer.len() && !rp_pac::UART0.uartfr().read().rxfe() {
            let data = rp_pac::UART0.uartdr().read();
            if data.oe() || data.be() || data.pe() || data.fe() {
                rp_pac::UART0.uartrsr().write(|w| w.set_oe(true));
                return Err(ErrorKind::Other);
            }
            buffer[len] = data.data();
            len += 1;
        }
        Ok(len)
    }
}

impl Write for NonsecureUart {
    async fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        for byte in buffer {
            while rp_pac::UART0.uartfr().read().txff() {
                embassy_time::Timer::after_micros(100).await;
            }
            rp_pac::UART0.uartdr().write(|w| w.set_data(*byte));
        }
        Ok(buffer.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        while rp_pac::UART0.uartfr().read().busy() {
            embassy_time::Timer::after_micros(100).await;
        }
        Ok(())
    }
}
