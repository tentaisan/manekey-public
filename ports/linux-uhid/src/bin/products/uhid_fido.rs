// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use manekey::ctaphid::{
    Ctaphid,
    key_store::FlashPrivateKeyStore,
    pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider},
    storage::Storage,
    user_verification::UnavailableUserVerification,
};
use manekey::presence::NoPresenceObserver;
use manekey_linux_uhid::backend::{
    FilePinStorage, FileStorage, HostPresence, HostPresenceControl, HostTokenClock, OsEntropy,
};

#[path = "../../uhid.rs"]
mod uhid;

fn confirmation_input(control: HostPresenceControl) {
    let mut input = io::stdin().lock();
    let mut line = Vec::with_capacity(64);
    let mut oversized = false;
    loop {
        let mut byte = [0];
        if input.read_exact(&mut byte).is_err() {
            return;
        }
        if byte[0] == b'\n' {
            if !oversized {
                let request = std::str::from_utf8(&line)
                    .ok()
                    .and_then(|line| line.trim().strip_prefix("confirm "))
                    .and_then(|request| request.parse::<u64>().ok());
                if let Some(request) = request {
                    let _ = control.confirm(request);
                }
            }
            line.clear();
            oversized = false;
        } else if line.len() < 64 {
            line.push(byte[0]);
        } else {
            oversized = true;
        }
    }
}

fn main() -> io::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let directory = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| io::Error::other("usage: uhid-fido STORAGE_DIRECTORY [UHID_PATH]"))?,
    );
    let path = arguments.next().unwrap_or_else(|| "/dev/uhid".into());
    if arguments.next().is_some() {
        return Err(io::Error::other("unexpected argument"));
    }
    let _root = FileStorage::open(&directory)?;
    let credentials = FileStorage::open(directory.join("credentials"))?;
    let pin = StoredPinUvAuthProvider::new_with_clock(
        JournaledPinUvAuthStorage::new(FilePinStorage::open(&directory)?),
        HostTokenClock::new(),
    );
    let (presence, control) = HostPresence::new(30_000);
    let mut authenticator = Ctaphid::new_with_presence_observer(
        Storage::new(credentials),
        presence,
        UnavailableUserVerification,
        pin,
        FlashPrivateKeyStore,
        OsEntropy::open()?,
        NoPresenceObserver,
    );

    let mut device = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(0o4000)
        .open(path)?;
    uhid::create_device(&mut device)?;
    eprintln!(
        "Host-controlled authenticator; plaintext storage relies on the host OS. No hardware isolation."
    );
    let input_control = control.clone();
    let _ = thread::spawn(move || confirmation_input(input_control));
    let mut last_request = None;
    let mut event = [0; uhid::UHID_EVENT_SIZE];
    loop {
        match device.read(&mut event) {
            Ok(0) => return Err(io::Error::other("UHID device closed")),
            Ok(len) => {
                if len >= 4
                    && u32::from_ne_bytes(event[..4].try_into().unwrap()) == uhid::UHID_OUTPUT
                {
                    if let Some(report) = uhid::output_report(&event[..len]) {
                        if let Some(response) = authenticator.handle_raw(report) {
                            uhid::write_response(&mut device, response)?;
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        if let Some(response) = authenticator.poll() {
            uhid::write_response(&mut device, response)?;
        }
        let request = control.pending_request();
        if request != last_request {
            if let Some(request) = request {
                eprint!("Confirm request {request}: type confirm {request}\n");
                io::stderr().flush()?;
            }
            last_request = request;
        }
        thread::sleep(Duration::from_millis(10));
    }
}
