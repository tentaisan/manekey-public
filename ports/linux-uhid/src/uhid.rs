// SPDX-License-Identifier: AGPL-3.0-only

use manekey::ctaphid::{
    Response, descriptor::DEFAULT_USB_PID as CTAPHID_DEFAULT_USB_PID,
    descriptor::DEFAULT_USB_VID as CTAPHID_DEFAULT_USB_VID,
    descriptor::REPORT_DESCRIPTOR as CTAPHID_REPORT_DESCRIPTOR,
    descriptor::REPORT_SIZE as CTAPHID_REPORT_SIZE, framing::for_each_response_report,
};
use std::fs::File;
use std::io::{self, Write};
use std::time::{Duration, Instant};

pub const UHID_EVENT_SIZE: usize = 4376;
const UHID_DATA_MAX: usize = 4096;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
pub const UHID_OUTPUT: u32 = 6;
const BUS_USB: u16 = 0x03;
const VID: u32 = CTAPHID_DEFAULT_USB_VID as u32;
const PID: u32 = CTAPHID_DEFAULT_USB_PID as u32;

pub fn create_device(uhid: &mut File) -> io::Result<()> {
    let mut event = [0u8; UHID_EVENT_SIZE];
    event[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
    write_c_string(&mut event[4..4 + 128], b"ManeKey UHID virtual FIDO");
    write_c_string(&mut event[4 + 128..4 + 128 + 64], b"manekey/uhid");
    write_c_string(
        &mut event[4 + 128 + 64..4 + 128 + 64 + 64],
        b"manekey-virtual",
    );

    let rd_size_offset = 4 + 256;
    event[rd_size_offset..rd_size_offset + 2]
        .copy_from_slice(&(CTAPHID_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes());
    event[rd_size_offset + 2..rd_size_offset + 4].copy_from_slice(&BUS_USB.to_ne_bytes());
    event[rd_size_offset + 4..rd_size_offset + 8].copy_from_slice(&VID.to_ne_bytes());
    event[rd_size_offset + 8..rd_size_offset + 12].copy_from_slice(&PID.to_ne_bytes());
    event[rd_size_offset + 12..rd_size_offset + 16].copy_from_slice(&1u32.to_ne_bytes());
    event[rd_size_offset + 16..rd_size_offset + 20].copy_from_slice(&0u32.to_ne_bytes());

    let rd_data_offset = 4 + 276;
    event[rd_data_offset..rd_data_offset + CTAPHID_REPORT_DESCRIPTOR.len()]
        .copy_from_slice(CTAPHID_REPORT_DESCRIPTOR);

    write_event(uhid, &event, Duration::from_secs(1))
}

fn write_c_string(out: &mut [u8], value: &[u8]) {
    let len = value.len().min(out.len().saturating_sub(1));
    out[..len].copy_from_slice(&value[..len]);
}

pub fn output_report(event: &[u8]) -> Option<[u8; CTAPHID_REPORT_SIZE]> {
    let size_offset = 4 + UHID_DATA_MAX;
    if event.len() < size_offset + 2 {
        return None;
    }
    let size = u16::from_ne_bytes(event[size_offset..size_offset + 2].try_into().ok()?) as usize;
    let data = event.get(4..4 + size)?;

    let mut report = [0u8; CTAPHID_REPORT_SIZE];
    match size {
        CTAPHID_REPORT_SIZE => report.copy_from_slice(data),

        size if size == CTAPHID_REPORT_SIZE + 1 && data[0] == 0 => {
            report.copy_from_slice(&data[1..1 + CTAPHID_REPORT_SIZE]);
        }
        _ => return None,
    }
    Some(report)
}

/// Retries complete events for up to one second each; short writes fail.
/// Kernel acceptance does not acknowledge peer delivery.
pub fn write_response(uhid: &mut File, response: Response<'_>) -> io::Result<()> {
    for_each_response_report(response, |packet| write_input_report(uhid, packet))
}

fn write_input_report(uhid: &mut File, report: &[u8; CTAPHID_REPORT_SIZE]) -> io::Result<()> {
    let mut event = [0u8; 4 + 2 + CTAPHID_REPORT_SIZE];
    event[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
    event[4..6].copy_from_slice(&(CTAPHID_REPORT_SIZE as u16).to_ne_bytes());
    event[6..6 + CTAPHID_REPORT_SIZE].copy_from_slice(report);
    write_event(uhid, &event, Duration::from_secs(1))
}

fn write_event(writer: &mut impl Write, event: &[u8], timeout: Duration) -> io::Result<()> {
    let started = Instant::now();
    loop {
        match writer.write(event) {
            Ok(length) if length == event.len() => return Ok(()),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "UHID event not written",
                ));
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "partial UHID event write",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                if started.elapsed() >= timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "UHID event write timeout",
                    ));
                }
                if error.kind() == io::ErrorKind::WouldBlock {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Err(error) => return Err(error),
        }
    }
}
