use crate::ctaphid::channel::{ChannelError, Message};
mod cmd {
    pub const PING: u8 = 0x01;
    pub const LOCK: u8 = 0x04;
    pub const INIT: u8 = 0x06;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3b;
    pub const ERROR: u8 = 0x3f;

    pub const RESPONSE_FLAG: u8 = 0x80;
}

mod error {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
}

mod version {
    pub const CTAPHID_PROTOCOL: u8 = 2;
    pub const MAJOR: u8 = 0;
    pub const MINOR: u8 = 1;
    pub const BUILD: u8 = 0;
}

mod capability {
    pub const CBOR: u8 = 0x04;
}

mod keepalive_status {
    pub const UP_NEEDED: u8 = 0x02;
}

pub enum Response<'a> {
    Msg { cid: u32, cmd: u8, data: &'a [u8] },
}

fn error_response<'a>(cid: u32, code: u8, buf: &'a mut [u8]) -> Response<'a> {
    buf[0] = code;
    Response::Msg {
        cid,
        cmd: cmd::ERROR | cmd::RESPONSE_FLAG,
        data: &buf[..1],
    }
}

pub(crate) fn keepalive_up_needed_response<'a>(cid: u32, buf: &'a mut [u8]) -> Response<'a> {
    buf[0] = keepalive_status::UP_NEEDED;
    Response::Msg {
        cid,
        cmd: cmd::KEEPALIVE | cmd::RESPONSE_FLAG,
        data: &buf[..1],
    }
}

pub(crate) fn cbor_status_response<'a>(cid: u32, status: u8, buf: &'a mut [u8]) -> Response<'a> {
    buf[0] = status;
    Response::Msg {
        cid,
        cmd: cmd::CBOR | cmd::RESPONSE_FLAG,
        data: &buf[..1],
    }
}

pub(crate) const CANCEL_COMMAND: u8 = cmd::CANCEL;

pub fn channel_error<'a>(cid: u32, err: ChannelError, buf: &'a mut [u8]) -> Response<'a> {
    let code = match err {
        ChannelError::InvalidLen => error::INVALID_LEN,
        ChannelError::InvalidSeq => error::INVALID_SEQ,
        ChannelError::MessageTimeout => error::MSG_TIMEOUT,
        ChannelError::ChannelBusy => error::CHANNEL_BUSY,
    };

    error_response(cid, code, buf)
}

/// Compatibility handler using a fixed INIT channel identifier, not a channel allocator.
/// Requires at least 17 output bytes and enough space for a PING payload.
pub fn handle_transport<'a>(msg: Message, buf: &'a mut [u8]) -> Response<'a> {
    match msg.cmd {
        cmd::LOCK => error_response(msg.cid, error::INVALID_CMD, buf),
        cmd::INIT => {
            if msg.data.len() != 8 {
                return error_response(msg.cid, error::INVALID_LEN, buf);
            }

            buf[0..8].copy_from_slice(&msg.data[0..8]);

            let new_cid: u32 = 0x12345678;
            buf[8..12].copy_from_slice(&new_cid.to_be_bytes());

            buf[12] = version::CTAPHID_PROTOCOL;
            buf[13] = version::MAJOR;
            buf[14] = version::MINOR;
            buf[15] = version::BUILD;
            buf[16] = capability::CBOR;

            Response::Msg {
                cid: msg.cid,
                cmd: cmd::INIT | cmd::RESPONSE_FLAG,
                data: &buf[..17],
            }
        }

        cmd::PING => {
            buf[..msg.data.len()].copy_from_slice(msg.data);

            Response::Msg {
                cid: msg.cid,
                cmd: cmd::PING | cmd::RESPONSE_FLAG,
                data: &buf[..msg.data.len()],
            }
        }

        _ => {
            return error_response(msg.cid, error::INVALID_CMD, buf);
        }
    }
}
