use portable_atomic::{AtomicU8, AtomicU32, Ordering};
use trusted_boundary::{operation, status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MailboxState {
    Idle = 0,
    RequestReady = 1,
    Processing = 2,
    ResponseReady = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Notification {
    pub worker: u8,
    pub state: MailboxState,
}

impl Notification {
    const MAGIC: u16 = 0xdcc0;

    pub const fn new(worker: u8, state: MailboxState) -> Self {
        Self { worker, state }
    }

    pub const fn encode(self) -> u32 {
        ((Self::MAGIC as u32) << 16) | ((self.worker as u32) << 8) | self.state as u32
    }

    pub fn decode(raw: u32) -> Option<Self> {
        if (raw >> 16) as u16 != Self::MAGIC {
            return None;
        }
        Some(Self {
            worker: (raw >> 8) as u8,
            state: MailboxState::from_raw(raw & 0xff)?,
        })
    }
}

impl MailboxState {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Idle),
            1 => Some(Self::RequestReady),
            2 => Some(Self::Processing),
            3 => Some(Self::ResponseReady),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxError {
    InvalidState,
    InvalidTransition,
}

/// Ownership state only, not a hardware isolation or authentication boundary.
pub struct Mailbox {
    state: AtomicU32,
}

pub struct MailboxPool<const N: usize> {
    states: [AtomicU32; N],
}

/// Atomic byte storage; caller obeys phase ownership for coherent messages.
/// Reuse does not erase old payload bytes.
pub struct SharedMailbox<const REQUEST: usize, const RESPONSE: usize> {
    request_len: AtomicU32,
    response_len: AtomicU32,
    request: [AtomicU8; REQUEST],
    response: [AtomicU8; RESPONSE],
}

/// One serialized producer/consumer exchange; callers check phase before reading or writing.
/// A failed transition does not undo preceding payload writes.
pub struct MailboxEndpoint<const REQUEST: usize, const RESPONSE: usize> {
    operation: AtomicU32,
    status: AtomicU32,
    pub mailbox: SharedMailbox<REQUEST, RESPONSE>,
    pub state: Mailbox,
}

/// Return a response length within the supplied buffer; overlength may panic the worker.
pub trait MailboxService {
    fn process(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, MailboxError>;
}

/// Authorize operations before dispatch and return a response length within the supplied buffer.
pub trait MailboxOperationService {
    fn process_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<(u32, usize), MailboxError>;
}

pub struct BorrowedMailboxService<'a, S: ?Sized>(&'a mut S);

impl<S: MailboxOperationService + ?Sized> MailboxOperationService
    for BorrowedMailboxService<'_, S>
{
    fn process_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<(u32, usize), MailboxError> {
        self.0.process_operation(operation_code, request, response)
    }
}

pub struct LocalMailboxWorker<S, const REQUEST: usize, const RESPONSE: usize> {
    service: S,
    request: [u8; REQUEST],
    response: [u8; RESPONSE],
}

impl<S: MailboxOperationService, const REQUEST: usize, const RESPONSE: usize>
    LocalMailboxWorker<S, REQUEST, RESPONSE>
{
    pub const fn new(service: S) -> Self {
        Self {
            service,
            request: [0; REQUEST],
            response: [0; RESPONSE],
        }
    }

    pub fn pump_once(
        &mut self,
        endpoint: &MailboxEndpoint<REQUEST, RESPONSE>,
    ) -> Result<bool, MailboxError> {
        endpoint.pump_operation_once(&mut self.service, &mut self.request, &mut self.response)
    }
}

impl<'a, S: MailboxOperationService + ?Sized, const REQUEST: usize, const RESPONSE: usize>
    LocalMailboxWorker<BorrowedMailboxService<'a, S>, REQUEST, RESPONSE>
{
    pub fn from_ref(service: &'a mut S) -> Self {
        Self::new(BorrowedMailboxService(service))
    }
}

/// Submission is not completion; poll for a response and reconcile transport failure before reuse.
pub trait MailboxClientTransport {
    fn submit_operation(&mut self, operation_code: u32, request: &[u8])
    -> Result<(), MailboxError>;

    fn try_receive_response(
        &mut self,
        response: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MailboxError>;
}

/// Cooperative copied exchange, not hardware isolation; caller preserves single producer/consumer ownership.
pub struct LocalMailboxTransport<'a, const REQUEST: usize, const RESPONSE: usize> {
    endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>,
}

impl<'a, const REQUEST: usize, const RESPONSE: usize> LocalMailboxTransport<'a, REQUEST, RESPONSE> {
    pub const fn new(endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>) -> Self {
        Self { endpoint }
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxClientTransport
    for LocalMailboxTransport<'_, REQUEST, RESPONSE>
{
    fn submit_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        self.endpoint.submit_operation(operation_code, request)
    }

    fn try_receive_response(
        &mut self,
        response: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MailboxError> {
        if self.endpoint.state()? == MailboxState::ResponseReady {
            self.endpoint.take_status_response(response).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxEndpoint<REQUEST, RESPONSE> {
    /// Service errors can leave Processing state; caller provides recovery and private-buffer cleanup.
    pub fn pump_once<S: MailboxService>(
        &self,
        service: &mut S,
        request: &mut [u8; REQUEST],
        response: &mut [u8; RESPONSE],
    ) -> Result<bool, MailboxError> {
        if self.state.state()? != MailboxState::RequestReady {
            return Ok(false);
        }
        let request_len = self.take_request(request)?;
        let response_len = service.process(&request[..request_len], response)?;
        self.publish_response(&response[..response_len])?;
        Ok(true)
    }

    /// Service errors can leave Processing state; caller provides recovery and private-buffer cleanup.
    pub fn pump_operation_once<S: MailboxOperationService>(
        &self,
        service: &mut S,
        request: &mut [u8; REQUEST],
        response: &mut [u8; RESPONSE],
    ) -> Result<bool, MailboxError> {
        if self.state.state()? != MailboxState::RequestReady {
            return Ok(false);
        }
        let operation_code = self.operation();
        let request_len = self.take_request(request)?;
        let (status_code, response_len) =
            service.process_operation(operation_code, &request[..request_len], response)?;
        self.publish_status_response(status_code, &response[..response_len])?;
        Ok(true)
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxEndpoint<REQUEST, RESPONSE> {
    pub const fn new() -> Self {
        Self {
            operation: AtomicU32::new(operation::SUBMIT_CBOR),
            status: AtomicU32::new(status::OK),
            mailbox: SharedMailbox::new(),
            state: Mailbox::new(),
        }
    }

    pub fn submit(&self, request: &[u8]) -> Result<(), MailboxError> {
        self.operation
            .store(operation::SUBMIT_CBOR, Ordering::Relaxed);
        self.mailbox.write_request(request)?;
        self.state.publish_request()
    }

    pub fn submit_operation(
        &self,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        self.operation.store(operation_code, Ordering::Relaxed);
        self.mailbox.write_request(request)?;
        self.state.publish_request()
    }

    pub fn take_request(&self, out: &mut [u8]) -> Result<usize, MailboxError> {
        self.state.begin_processing()?;
        self.mailbox.read_request(out)
    }

    pub fn publish_response(&self, response: &[u8]) -> Result<(), MailboxError> {
        self.status.store(status::OK, Ordering::Relaxed);
        self.mailbox.write_response(response)?;
        self.state.publish_response()
    }

    pub fn publish_status_response(
        &self,
        status_code: u32,
        response: &[u8],
    ) -> Result<(), MailboxError> {
        self.status.store(status_code, Ordering::Release);
        self.mailbox.write_response(response)?;
        self.state.publish_response()
    }

    pub fn take_response(&self, out: &mut [u8]) -> Result<usize, MailboxError> {
        let size = self.mailbox.read_response(out)?;
        self.state.release()?;
        Ok(size)
    }

    pub fn take_status_response(&self, out: &mut [u8]) -> Result<(u32, usize), MailboxError> {
        let status_code = self.status.load(Ordering::Acquire);
        let size = self.mailbox.read_response(out)?;
        self.state.release()?;
        Ok((status_code, size))
    }

    pub fn operation(&self) -> u32 {
        self.operation.load(Ordering::Acquire)
    }

    pub fn state(&self) -> Result<MailboxState, MailboxError> {
        self.state.state()
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> Default for MailboxEndpoint<REQUEST, RESPONSE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> SharedMailbox<REQUEST, RESPONSE> {
    pub const fn new() -> Self {
        Self {
            request_len: AtomicU32::new(0),
            response_len: AtomicU32::new(0),
            request: [const { AtomicU8::new(0) }; REQUEST],
            response: [const { AtomicU8::new(0) }; RESPONSE],
        }
    }

    pub fn write_request(&self, data: &[u8]) -> Result<(), MailboxError> {
        Self::write(&self.request, &self.request_len, data)
    }

    pub fn read_request(&self, out: &mut [u8]) -> Result<usize, MailboxError> {
        Self::read(&self.request, &self.request_len, out)
    }

    pub fn write_response(&self, data: &[u8]) -> Result<(), MailboxError> {
        Self::write(&self.response, &self.response_len, data)
    }

    pub fn read_response(&self, out: &mut [u8]) -> Result<usize, MailboxError> {
        Self::read(&self.response, &self.response_len, out)
    }

    fn write<const N: usize>(
        slot: &[AtomicU8; N],
        len: &AtomicU32,
        data: &[u8],
    ) -> Result<(), MailboxError> {
        if data.len() > N {
            return Err(MailboxError::InvalidState);
        }
        for (index, byte) in data.iter().copied().enumerate() {
            slot[index].store(byte, Ordering::Relaxed);
        }
        len.store(data.len() as u32, Ordering::Release);
        Ok(())
    }

    fn read<const N: usize>(
        slot: &[AtomicU8; N],
        len: &AtomicU32,
        out: &mut [u8],
    ) -> Result<usize, MailboxError> {
        let size = len.load(Ordering::Acquire) as usize;
        if size > N || out.len() < size {
            return Err(MailboxError::InvalidState);
        }
        for (index, byte) in out.iter_mut().take(size).enumerate() {
            *byte = slot[index].load(Ordering::Relaxed);
        }
        Ok(size)
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> Default for SharedMailbox<REQUEST, RESPONSE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> MailboxPool<N> {
    pub const fn new() -> Self {
        Self {
            states: [const { AtomicU32::new(MailboxState::Idle as u32) }; N],
        }
    }

    pub fn state(&self, worker: usize) -> Result<MailboxState, MailboxError> {
        let state = self.states.get(worker).ok_or(MailboxError::InvalidState)?;
        MailboxState::from_raw(state.load(Ordering::Acquire)).ok_or(MailboxError::InvalidState)
    }

    pub fn transition(
        &self,
        worker: usize,
        from: MailboxState,
        to: MailboxState,
    ) -> Result<(), MailboxError> {
        let state = self.states.get(worker).ok_or(MailboxError::InvalidState)?;
        state
            .compare_exchange(from as u32, to as u32, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| MailboxError::InvalidTransition)
    }

    pub fn try_claim(&self) -> Option<usize> {
        for (worker, state) in self.states.iter().enumerate() {
            if state
                .compare_exchange(
                    MailboxState::Idle as u32,
                    MailboxState::RequestReady as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(worker);
            }
        }
        None
    }
}

impl<const N: usize> Default for MailboxPool<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(MailboxState::Idle as u32),
        }
    }

    pub fn state(&self) -> Result<MailboxState, MailboxError> {
        MailboxState::from_raw(self.state.load(Ordering::Acquire)).ok_or(MailboxError::InvalidState)
    }

    pub fn publish_request(&self) -> Result<(), MailboxError> {
        self.transition(MailboxState::Idle, MailboxState::RequestReady)
    }

    pub fn begin_processing(&self) -> Result<(), MailboxError> {
        self.transition(MailboxState::RequestReady, MailboxState::Processing)
    }

    pub fn publish_response(&self) -> Result<(), MailboxError> {
        self.transition(MailboxState::Processing, MailboxState::ResponseReady)
    }

    pub fn release(&self) -> Result<(), MailboxError> {
        self.transition(MailboxState::ResponseReady, MailboxState::Idle)
    }

    fn transition(&self, from: MailboxState, to: MailboxState) -> Result<(), MailboxError> {
        self.state
            .compare_exchange(from as u32, to as u32, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| MailboxError::InvalidTransition)
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}
