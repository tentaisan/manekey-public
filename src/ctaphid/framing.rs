use super::{
    Response,
    channel::{CONT_HEADER_SIZE, CONT_PAYLOAD_SIZE, INIT_HEADER_SIZE, INIT_PAYLOAD_SIZE},
    descriptor::REPORT_SIZE,
};

pub const MAX_WIRE_MESSAGE_SIZE: usize = INIT_PAYLOAD_SIZE + 128 * CONT_PAYLOAD_SIZE;

pub fn for_each_response_report<E>(
    response: Response<'_>,
    sink: impl FnMut(&[u8; REPORT_SIZE]) -> Result<(), E>,
) -> Result<(), E> {
    let Response::Msg { cid, cmd, data } = response;
    for_each_message_report(cid, cmd, data, sink)
}

/// Emits bounded reports until the sink fails; oversized payloads emit no reports.
/// Sink acceptance does not acknowledge peer delivery.
pub fn for_each_message_report<E>(
    cid: u32,
    cmd: u8,
    data: &[u8],
    mut sink: impl FnMut(&[u8; REPORT_SIZE]) -> Result<(), E>,
) -> Result<(), E> {
    let mut reports = message_reports(cid, cmd, data);
    while let Some(report) = reports.next() {
        sink(&report)?;
    }

    Ok(())
}

pub fn response_reports(response: Response<'_>) -> ResponseReportIter<'_> {
    let Response::Msg { cid, cmd, data } = response;
    message_reports(cid, cmd, data)
}

/// Returns no reports when the payload exceeds MAX_WIRE_MESSAGE_SIZE.
pub fn message_reports(cid: u32, cmd: u8, data: &[u8]) -> ResponseReportIter<'_> {
    let valid = data.len() <= MAX_WIRE_MESSAGE_SIZE;
    ResponseReportIter {
        cid,
        cmd,
        data,
        offset: if valid { 0 } else { data.len() },
        sequence: 0,
        emitted_init: !valid,
    }
}

/// Bounded copied-report queue; clearing state does not erase payload bytes.
pub struct ReportQueue<const CAPACITY: usize> {
    reports: [[u8; REPORT_SIZE]; CAPACITY],
    index: usize,
    count: usize,
}

impl<const CAPACITY: usize> ReportQueue<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            reports: [[0u8; REPORT_SIZE]; CAPACITY],
            index: 0,
            count: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Replaces the queue; returns false without partial output if the message cannot fit.
    pub fn queue_response(&mut self, response: Option<Response<'_>>) -> bool {
        self.index = 0;
        self.count = 0;
        let Some(response) = response else {
            return true;
        };
        let Response::Msg { data, .. } = response;
        let needed = 1 + data
            .len()
            .saturating_sub(INIT_PAYLOAD_SIZE)
            .div_ceil(CONT_PAYLOAD_SIZE);
        if data.len() > MAX_WIRE_MESSAGE_SIZE || needed > CAPACITY {
            return false;
        }
        for report in response_reports(response) {
            self.reports[self.count] = report;
            self.count += 1;
        }
        true
    }

    pub fn current(&self) -> Option<&[u8; REPORT_SIZE]> {
        (self.index < self.count).then(|| &self.reports[self.index])
    }

    pub fn advance(&mut self) {
        if self.index < self.count {
            self.index += 1;
        }
        if self.index >= self.count {
            self.clear();
        }
    }

    pub fn clear(&mut self) {
        self.index = 0;
        self.count = 0;
    }
}

pub struct ResponseReportIter<'a> {
    cid: u32,
    cmd: u8,
    data: &'a [u8],
    offset: usize,
    sequence: u8,
    emitted_init: bool,
}

impl Iterator for ResponseReportIter<'_> {
    type Item = [u8; REPORT_SIZE];

    fn next(&mut self) -> Option<Self::Item> {
        if !self.emitted_init {
            self.emitted_init = true;
            let mut packet = [0u8; REPORT_SIZE];
            packet[..4].copy_from_slice(&self.cid.to_be_bytes());
            packet[4] = self.cmd;
            packet[5] = (self.data.len() >> 8) as u8;
            packet[6] = self.data.len() as u8;
            let first_len = self.data.len().min(INIT_PAYLOAD_SIZE);
            packet[INIT_HEADER_SIZE..INIT_HEADER_SIZE + first_len]
                .copy_from_slice(&self.data[..first_len]);
            self.offset = first_len;
            return Some(packet);
        }

        if self.offset >= self.data.len() {
            return None;
        }

        let mut continuation = [0u8; REPORT_SIZE];
        continuation[..4].copy_from_slice(&self.cid.to_be_bytes());
        continuation[4] = self.sequence;
        let len = (self.data.len() - self.offset).min(CONT_PAYLOAD_SIZE);
        continuation[CONT_HEADER_SIZE..CONT_HEADER_SIZE + len]
            .copy_from_slice(&self.data[self.offset..self.offset + len]);
        self.offset += len;
        self.sequence = self.sequence.wrapping_add(1);
        Some(continuation)
    }
}
