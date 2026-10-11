use crate::frontend::ccid::CCID_HEADER_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CcidBulkError {
    EmptyPacket,
    MessageTooLong,
    LengthMismatch,
}

/// Bounded CCID message assembly; reset does not erase payload bytes.
pub struct CcidBulkAssembler<const N: usize> {
    buffer: [u8; N],
    used: usize,
    expected: usize,
}

impl<const N: usize> Default for CcidBulkAssembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CcidBulkAssembler<N> {
    pub const fn new() -> Self {
        Self {
            buffer: [0; N],
            used: 0,
            expected: 0,
        }
    }

    pub fn reset(&mut self) {
        self.used = 0;
        self.expected = 0;
    }

    /// Returns a complete message; reset before starting the next message.
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<&[u8]>, CcidBulkError> {
        if packet.is_empty() {
            self.reset();
            return Err(CcidBulkError::EmptyPacket);
        }
        let next = self.used.saturating_add(packet.len());
        if next > N {
            self.reset();
            return Err(CcidBulkError::MessageTooLong);
        }
        self.buffer[self.used..next].copy_from_slice(packet);
        self.used = next;
        if self.expected == 0 && self.used >= CCID_HEADER_LEN {
            let payload = u32::from_le_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]) as usize;
            self.expected = CCID_HEADER_LEN.saturating_add(payload);
        }
        if self.expected > N {
            self.reset();
            return Err(CcidBulkError::MessageTooLong);
        }
        if self.expected != 0 && self.used > self.expected {
            self.reset();
            return Err(CcidBulkError::LengthMismatch);
        }
        if self.expected != 0 && self.used == self.expected {
            return Ok(Some(&self.buffer[..self.used]));
        }
        Ok(None)
    }
}
