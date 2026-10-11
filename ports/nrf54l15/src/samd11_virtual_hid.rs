use embassy_nrf::buffered_uarte::BufferedUarte;
use embassy_time::{Duration, Ticker};
use embedded_io_async::Write;
use manekey::{
    ctaphid::descriptor::REPORT_SIZE,
    frontend::{
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressId, IngressKind},
    },
    transport::samd11_bridge::{Samd11CtaphidBridge, Samd11CtaphidBridgeInput},
};

use crate::ble_ingress::BleProductArbiter;

fn record_link(index: usize, increment: u32) {
    let _ = (index, increment);
}

const FRAME_CAPACITY: usize = 80;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const VIRTUAL_HID_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);

async fn write_report(
    uart: &mut BufferedUarte<'static>,
    link: &mut Samd11CtaphidBridge,
    next_sequence: &mut u16,
    report: &[u8; REPORT_SIZE],
) -> Result<(), ()> {
    let mut frame = [0; FRAME_CAPACITY];
    let len = link
        .encode_report(*next_sequence, report, &mut frame)
        .map_err(|_| ())?;
    uart.write_all(&frame[..len]).await.map_err(|_| ())?;
    *next_sequence = next_sequence.wrapping_add(1);
    Ok(())
}

#[embassy_executor::task]
/// One virtual CTAPHID UART owner sharing the thread-mode arbiter; no borrow crosses an await.
/// UART acceptance is not peer delivery or evidence of a programmed USB bridge.
pub async fn task(mut uart: BufferedUarte<'static>, arbiter: &'static BleProductArbiter) {
    record_link(0, 1);
    let mut reports = CtaphidReportFrontend::new();
    let mut link = Samd11CtaphidBridge::new();
    let mut next_sequence = 0u16;
    let mut bytes = [0u8; REPORT_SIZE];
    let mut ticker = Ticker::every(POLL_INTERVAL);

    loop {
        match embassy_futures::select::select(uart.read(&mut bytes), ticker.next()).await {
            embassy_futures::select::Either::First(Ok(len)) => {
                record_link(1, len as u32);
                for byte in &bytes[..len] {
                    match link.push_link_byte(*byte) {
                        Ok(Some(Samd11CtaphidBridgeInput::Report(report))) => {
                            record_link(2, 1);
                            arbiter.lock(|cell| {
                                let mut arbiter = cell.borrow_mut();
                                reports.handle_report(&mut arbiter, VIRTUAL_HID_INGRESS, *report);
                            });
                        }
                        Ok(Some(Samd11CtaphidBridgeInput::LinkReset)) => {
                            arbiter.lock(|cell| {
                                let mut arbiter = cell.borrow_mut();
                                reports.on_link_lost(&mut arbiter, VIRTUAL_HID_INGRESS);
                            });
                        }
                        Ok(Some(Samd11CtaphidBridgeInput::Poll)) => {
                            arbiter.lock(|cell| {
                                let mut arbiter = cell.borrow_mut();
                                reports.poll(&mut arbiter, VIRTUAL_HID_INGRESS);
                            });
                        }
                        Ok(None) => {}
                        Err(_) => {
                            record_link(3, 1);
                        }
                    }
                }
            }
            embassy_futures::select::Either::First(Err(_)) => {
                record_link(4, 1);
                link = Samd11CtaphidBridge::new();
                arbiter
                    .lock(|cell| reports.on_link_lost(&mut cell.borrow_mut(), VIRTUAL_HID_INGRESS));
            }
            embassy_futures::select::Either::Second(()) => {
                arbiter.lock(|cell| {
                    let mut arbiter = cell.borrow_mut();
                    reports.poll(&mut arbiter, VIRTUAL_HID_INGRESS);
                });
            }
        }

        while let Some(report) = reports.current_report().copied() {
            if write_report(&mut uart, &mut link, &mut next_sequence, &report)
                .await
                .is_err()
            {
                link = Samd11CtaphidBridge::new();
                arbiter
                    .lock(|cell| reports.on_link_lost(&mut cell.borrow_mut(), VIRTUAL_HID_INGRESS));
                break;
            }
            reports.advance_report();
            record_link(5, 1);
        }
    }
}
