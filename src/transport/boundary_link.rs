use heapless::Deque;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CopyPacket<const CAPACITY: usize> {
    pub len: u32,
    pub data: [u8; CAPACITY],
}
impl<const CAPACITY: usize> CopyPacket<CAPACITY> {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            data: [0; CAPACITY],
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let len = u32::try_from(bytes.len()).ok()?;
        if bytes.len() > CAPACITY {
            return None;
        }
        let mut packet = Self::empty();
        packet.len = len;
        packet.data[..bytes.len()].copy_from_slice(bytes);
        Some(packet)
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        self.data.get(..self.len as usize)
    }
}

/// Bounded copy queues; callers enforce isolation and exclusive access.
/// Reset does not erase packet bytes. Generation is not authentication.
pub struct CopyLinkSlots<const CAPACITY: usize, const RX: usize, const TX: usize> {
    generation: u32,
    active: bool,
    rx: Deque<CopyPacket<CAPACITY>, RX>,
    tx: Deque<CopyPacket<CAPACITY>, TX>,
}
impl<const CAPACITY: usize, const RX: usize, const TX: usize> CopyLinkSlots<CAPACITY, RX, TX> {
    pub const fn new() -> Self {
        Self {
            generation: 1,
            active: false,
            rx: Deque::new(),
            tx: Deque::new(),
        }
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn reset(&mut self, active: bool) {
        self.generation = self.generation.wrapping_add(1);
        self.active = active;
        self.rx.clear();
        self.tx.clear();
    }
    pub fn set_active(&mut self, active: bool) {
        if self.active != active {
            self.reset(active);
        }
    }

    pub fn push_received(&mut self, bytes: &[u8]) -> bool {
        if !self.active {
            return false;
        }
        let Some(packet) = CopyPacket::from_slice(bytes) else {
            return false;
        };
        if self.rx.push_back(packet).is_err() {
            self.reset(self.active);
            return false;
        }
        true
    }
    pub fn receive(&mut self, generation: u32) -> Option<CopyPacket<CAPACITY>> {
        if generation != self.generation {
            return None;
        }
        self.rx.pop_front()
    }
    pub fn send(&mut self, generation: u32, packet: CopyPacket<CAPACITY>) -> bool {
        generation == self.generation
            && self.active
            && packet.bytes().is_some()
            && self.tx.push_back(packet).is_ok()
    }
    pub fn take_transmit(&mut self) -> Option<CopyPacket<CAPACITY>> {
        self.tx.pop_front()
    }

    pub fn peek_transmit(&self) -> Option<&CopyPacket<CAPACITY>> {
        self.tx.front()
    }
}
