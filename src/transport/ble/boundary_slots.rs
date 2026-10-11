use crate::transport::boundary_link::{CopyLinkSlots, CopyPacket};
pub type BlePacket = CopyPacket<64>;

/// Copied link queues; callers provide exclusion and peripheral isolation.
/// Reset does not erase payload bytes; generation is not authentication.
pub struct BleBoundarySlots<const RX: usize, const TX: usize> {
    slots: CopyLinkSlots<64, RX, TX>,
}
impl<const RX: usize, const TX: usize> BleBoundarySlots<RX, TX> {
    pub const fn new() -> Self {
        Self {
            slots: CopyLinkSlots::new(),
        }
    }
    pub fn generation(&self) -> u32 {
        self.slots.generation()
    }

    pub fn reset(&mut self, subscribed: bool) {
        self.slots.reset(subscribed);
    }
    pub fn subscription(&mut self, enabled: bool) {
        self.slots.set_active(enabled);
    }
    pub fn push_received(&mut self, bytes: &[u8]) -> bool {
        !bytes.is_empty() && self.slots.push_received(bytes)
    }
    pub fn receive(&mut self, generation: u32) -> Option<BlePacket> {
        self.slots.receive(generation)
    }
    pub fn send(&mut self, generation: u32, packet: BlePacket) -> bool {
        packet.len != 0 && self.slots.send(generation, packet)
    }
    pub fn next_notification(&mut self) -> Option<BlePacket> {
        self.slots.take_transmit()
    }
    pub fn peek_notification(&self) -> Option<&BlePacket> {
        self.slots.peek_transmit()
    }
}
