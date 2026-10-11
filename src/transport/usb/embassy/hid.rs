use crate::ctaphid::descriptor::REPORT_SIZE;
use crate::ctaphid::framing::{MAX_WIRE_MESSAGE_SIZE, message_reports};
use crate::ctaphid::{HidCtaphidApp, Response};
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Ticker};
use embassy_usb::class::hid::HidReaderWriter;
use embassy_usb::driver::Driver;

pub struct HidTransport<'d, D: Driver<'d>> {
    hid: HidReaderWriter<'d, D, REPORT_SIZE, REPORT_SIZE>,
}

impl<'d, D: Driver<'d>> HidTransport<'d, D> {
    pub fn new(hid: HidReaderWriter<'d, D, REPORT_SIZE, REPORT_SIZE>) -> Self {
        Self { hid }
    }

    /// Rejects reports whose length differs from REPORT_SIZE.
    pub async fn read(&mut self) -> Result<[u8; REPORT_SIZE], ()> {
        let mut buf = [0u8; REPORT_SIZE];

        match self.hid.read(&mut buf).await {
            Ok(len) => complete_report(buf, len),
            Err(_) => Err(()),
        }
    }

    pub async fn write(&mut self, buf: &[u8; REPORT_SIZE]) -> Result<(), ()> {
        match self.hid.write(buf).await {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

fn complete_report(buf: [u8; REPORT_SIZE], received_len: usize) -> Result<[u8; REPORT_SIZE], ()> {
    if received_len == REPORT_SIZE {
        Ok(buf)
    } else {
        Err(())
    }
}

async fn write_message<'d, D: Driver<'d>>(
    hid: &mut HidReaderWriter<'d, D, REPORT_SIZE, REPORT_SIZE>,
    cid: u32,
    cmd: u8,
    data: &[u8],
) -> Result<(), ()> {
    if data.len() > MAX_WIRE_MESSAGE_SIZE {
        return Err(());
    }
    for report in message_reports(cid, cmd, data) {
        hid.write(&report).await.map_err(|_| ())?;
    }

    Ok(())
}

pub struct FramedSender;

impl FramedSender {
    pub async fn send<'d, D: Driver<'d>>(
        transport: &mut HidTransport<'d, D>,
        cid: u32,
        cmd: u8,
        data: &[u8],
    ) -> Result<(), ()> {
        write_message(&mut transport.hid, cid, cmd, data).await
    }
}

/// Runs HID I/O and polling. Send failures are not retried by this loop.
pub async fn run_ctaphid_loop<'d, D, A>(
    transport: &mut HidTransport<'d, D>,
    app: &mut A,
    poll_interval: Duration,
) -> !
where
    D: Driver<'d>,
    A: HidCtaphidApp,
{
    let mut poll_ticker = Ticker::every(poll_interval);

    loop {
        let response = match select(transport.read(), poll_ticker.next()).await {
            Either::First(Ok(buf)) => app.handle_hid_report(buf),
            Either::First(Err(_)) => {
                poll_ticker.next().await;
                continue;
            }
            Either::Second(()) => app.poll_hid(),
        };

        if let Some(Response::Msg { cid, cmd, data }) = response {
            let _ = FramedSender::send(transport, cid, cmd, data).await;
        }
    }
}
