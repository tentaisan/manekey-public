use super::channel::{CONT_HEADER_SIZE, INIT_HEADER_SIZE};
use super::descriptor::REPORT_SIZE;

#[derive(Debug)]

pub enum Packet<'a> {
    Init {
        cid: u32,

        cmd: u8,

        len: u16,

        data: &'a [u8],
    },

    Cont {
        cid: u32,

        seq: u8,

        data: &'a [u8],
    },
}

impl Packet<'_> {
    pub fn cid(&self) -> u32 {
        match self {
            Packet::Init { cid, .. } => *cid,
            Packet::Cont { cid, .. } => *cid,
        }
    }
}

/// Parses a fixed-size report; message assembly validates length and sequence.
pub fn parse_packet(buf: &[u8; REPORT_SIZE]) -> Packet<'_> {
    let cid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    let b4 = buf[4];

    if b4 & 0x80 != 0 {
        let cmd = b4;
        let len = u16::from_be_bytes([buf[5], buf[6]]);

        Packet::Init {
            cid,
            cmd,
            len,
            data: &buf[INIT_HEADER_SIZE..REPORT_SIZE],
        }
    } else {
        let seq = b4;

        Packet::Cont {
            cid,
            seq,
            data: &buf[CONT_HEADER_SIZE..REPORT_SIZE],
        }
    }
}
