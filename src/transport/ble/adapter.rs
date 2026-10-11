use super::BleFidoError;

pub trait BleFidoFragmentSink {
    fn push_fragment(&mut self, fragment: &[u8]) -> Result<(), BleFidoError>;
}

pub struct BleFidoFragmentQueue<const MAX_FRAGMENTS: usize, const FRAGMENT_LEN: usize> {
    fragments: [[u8; FRAGMENT_LEN]; MAX_FRAGMENTS],
    lens: [usize; MAX_FRAGMENTS],
    count: usize,
}

impl<const MAX_FRAGMENTS: usize, const FRAGMENT_LEN: usize>
    BleFidoFragmentQueue<MAX_FRAGMENTS, FRAGMENT_LEN>
{
    pub const fn new() -> Self {
        Self {
            fragments: [[0; FRAGMENT_LEN]; MAX_FRAGMENTS],
            lens: [0; MAX_FRAGMENTS],
            count: 0,
        }
    }

    pub fn fragments(&self) -> impl Iterator<Item = &[u8]> {
        self.fragments[..self.count]
            .iter()
            .zip(self.lens[..self.count].iter())
            .map(|(fragment, len)| &fragment[..*len])
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }
}

impl<const MAX_FRAGMENTS: usize, const FRAGMENT_LEN: usize> BleFidoFragmentSink
    for BleFidoFragmentQueue<MAX_FRAGMENTS, FRAGMENT_LEN>
{
    fn push_fragment(&mut self, fragment: &[u8]) -> Result<(), BleFidoError> {
        if self.count >= MAX_FRAGMENTS || fragment.len() > FRAGMENT_LEN {
            return Err(BleFidoError::FragmentTooLong);
        }
        self.fragments[self.count][..fragment.len()].copy_from_slice(fragment);
        self.lens[self.count] = fragment.len();
        self.count += 1;
        Ok(())
    }
}

pub struct BleNotificationEgress<const MAX: usize, const LEN: usize> {
    queue: BleFidoFragmentQueue<MAX, LEN>,
    offset: usize,
}
impl<const MAX: usize, const LEN: usize> BleNotificationEgress<MAX, LEN> {
    pub const fn new() -> Self {
        Self {
            queue: BleFidoFragmentQueue::new(),
            offset: 0,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.queue.count == 0
    }
    pub fn sink(&mut self) -> Option<&mut BleFidoFragmentQueue<MAX, LEN>> {
        if self.is_empty() {
            Some(&mut self.queue)
        } else {
            None
        }
    }
    pub fn clear(&mut self) {
        self.queue.clear();
        self.offset = 0;
    }
    /// Transport acceptance is not peer delivery acknowledgment.
    /// A false result or error retains the unsent tail.
    pub fn flush<E>(
        &mut self,
        mut transmit: impl FnMut(&[u8]) -> Result<bool, E>,
    ) -> Result<bool, E> {
        while let Some(fragment) = self.queue.fragments().nth(self.offset) {
            if !transmit(fragment)? {
                return Ok(false);
            }
            self.offset += 1;
        }
        self.clear();
        Ok(true)
    }
}

pub fn notification_fragment_vec<const FRAGMENT_LEN: usize>(
    fragment: &[u8],
) -> Result<heapless::Vec<u8, FRAGMENT_LEN>, BleFidoError> {
    let mut value = heapless::Vec::<u8, FRAGMENT_LEN>::new();
    value
        .extend_from_slice(fragment)
        .map_err(|_| BleFidoError::FragmentTooLong)?;
    Ok(value)
}

pub trait BleFidoProfileHandler {
    fn on_status_subscription(&mut self, _enabled: bool) {}

    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError>;

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError>;

    fn on_disconnect(&mut self) {}

    fn settle_disconnected_backend(&mut self) -> bool {
        true
    }
}

impl<T: BleFidoProfileHandler + ?Sized> BleFidoProfileHandler for &mut T {
    fn on_status_subscription(&mut self, enabled: bool) {
        (**self).on_status_subscription(enabled);
    }
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        (**self).handle_control_point_write::<MAX_FRAGMENT>(fragment, sink)
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        (**self).poll_status::<MAX_FRAGMENT>(sink)
    }

    fn on_disconnect(&mut self) {
        (**self).on_disconnect();
    }

    fn settle_disconnected_backend(&mut self) -> bool {
        (**self).settle_disconnected_backend()
    }
}

pub fn drain_pending_status<const MAX_FRAGMENT: usize>(
    fido: &mut impl BleFidoProfileHandler,
    sink: &mut impl BleFidoFragmentSink,
    passes: usize,
) -> Result<usize, BleFidoError> {
    let mut total = 0usize;
    for _ in 0..passes {
        let produced = fido.poll_status::<MAX_FRAGMENT>(sink)?;
        total += produced;
        if produced == 0 {
            break;
        }
    }
    Ok(total)
}

pub fn handle_control_point_write_and_drain<const MAX_FRAGMENT: usize>(
    fido: &mut impl BleFidoProfileHandler,
    fragment: &[u8],
    sink: &mut impl BleFidoFragmentSink,
    drain_passes: usize,
    mut before_poll: impl FnMut(),
) -> Result<usize, BleFidoError> {
    let mut total = fido.handle_control_point_write::<MAX_FRAGMENT>(fragment, sink)?;
    for _ in 0..drain_passes {
        before_poll();
        let produced = fido.poll_status::<MAX_FRAGMENT>(sink)?;
        total += produced;
        if produced == 0 {
            break;
        }
    }
    Ok(total)
}

pub fn handle_control_point_write_at_offset_and_drain<const MAX_FRAGMENT: usize>(
    fido: &mut impl BleFidoProfileHandler,
    offset: usize,
    fragment: &[u8],
    sink: &mut impl BleFidoFragmentSink,
    drain_passes: usize,
    before_poll: impl FnMut(),
) -> Result<usize, BleFidoError> {
    if offset != 0 {
        return Err(BleFidoError::UnsupportedOffset);
    }
    handle_control_point_write_and_drain::<MAX_FRAGMENT>(
        fido,
        fragment,
        sink,
        drain_passes,
        before_poll,
    )
}
