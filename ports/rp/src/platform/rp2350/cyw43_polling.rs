/// Exclusive FIFO transaction owner; serialize callers and exclude competing IRQ/DMA/core access.
pub trait PioFifo {
    fn start_transfer(&self, write_bits: u32, read_bits: u32);
    fn tx_write(&self, word: u32) -> bool;
    fn rx_read(&self) -> Option<u32>;
}

#[inline(always)]
/// Blocking CYW43 FIFO write; words must be nonempty and bit length must fit u32.
/// No wall-clock timeout is supplied.
pub fn write(bus: &impl PioFifo, words: &[u32]) -> u32 {
    assert!(!words.is_empty());
    bus.start_transfer((words.len() * 32 - 1) as u32, 31);
    let mut sent = 0;
    let mut status = None;
    while sent < words.len() || status.is_none() {
        if sent < words.len() && bus.tx_write(words[sent]) {
            sent += 1;
        }
        if status.is_none() {
            status = bus.rx_read();
        }
        core::hint::spin_loop();
    }
    status.unwrap()
}

#[inline(always)]
/// Blocking command/payload/status exchange; bit length must fit u32.
/// No wall-clock timeout is supplied; peripheral ownership remains with the adapter.
pub fn read(bus: &impl PioFifo, command: u32, words: &mut [u32]) -> u32 {
    bus.start_transfer(31, (words.len() * 32 + 31) as u32);
    let mut command_pending = true;
    let mut received = 0;
    let mut status = 0;
    while command_pending || received <= words.len() {
        if command_pending && bus.tx_write(command) {
            command_pending = false;
        }
        if let Some(word) = bus.rx_read() {
            if received < words.len() {
                words[received] = word;
            } else {
                status = word;
            }
            received += 1;
        }
        core::hint::spin_loop();
    }
    status
}
