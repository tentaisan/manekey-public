#[derive(Default)]
pub struct CcidAbortControl {
    pending: Option<(u8, u8)>,
}

impl CcidAbortControl {
    pub const fn new() -> Self {
        Self { pending: None }
    }

    pub fn request(&mut self, request: u8, value: u16, length: u16, data: &[u8]) -> bool {
        let candidate = (value as u8, (value >> 8) as u8);
        if request != 1
            || length != 0
            || !data.is_empty()
            || candidate.0 != 0
            || self.pending.is_some_and(|current| current != candidate)
        {
            return false;
        }
        self.pending = Some(candidate);
        true
    }

    pub fn take(&mut self) -> Option<(u8, u8)> {
        self.pending.take()
    }

    pub fn reset(&mut self) {
        self.pending = None;
    }
}
