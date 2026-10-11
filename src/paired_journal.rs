
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const HEADER: usize = 64;
const MAGIC: &[u8; 8] = b"MKPAIR01";
const COMMIT: &[u8; 4] = b"CMIT";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    Invalid,
    Poisoned,
}



pub trait Banks {
    // Two exclusively owned, independently erasable banks, each at least HEADER + 2*N.
    // Offsets/lengths are multiples of four; backend owns geometry and ordered I/O.
    fn read(&mut self, bank: usize, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;
    fn erase(&mut self, bank: usize) -> Result<(), Error>;
    fn program(&mut self, bank: usize, offset: usize, bytes: &[u8]) -> Result<(), Error>;
}

pub struct PairedJournal<B, const N: usize> {
    // SHA-256 detects corruption, not adversarial authenticity, confidentiality or rollback.
    // Physical power-loss behavior depends on the backend and needs separate validation.
    backend: B,
    active: Option<usize>,
    header: [u8; HEADER],
    pending: Option<(usize, usize)>,
    staged: Zeroizing<[u8; N]>,
    poisoned: bool,
}

impl<B: Banks, const N: usize> PairedJournal<B, N> {
    pub fn open(mut backend: B, owner: [u8; 8]) -> Result<Self, Error> {
        if N < 20 || N % 4 != 0 {
            return Err(Error::Invalid);
        }
        let mut active = None;
        let mut selected = [0xff; HEADER];
        let mut nonblank = false;
        for bank in 0..2 {
            let mut h = [0; HEADER];
            backend.read(bank, 0, &mut h)?;
            let mut scratch = Zeroizing::new([0; N]);
            let mut hash = Self::hash_header(&h);
            let mut blank = h.iter().all(|b| *b == 0xff);
            for channel in 0..2 {
                backend.read(bank, HEADER + channel * N, &mut *scratch)?;
                blank &= scratch.iter().all(|b| *b == 0xff);
                hash.update(&*scratch);
            }
            nonblank |= !blank;
            // A valid local bank never authorizes overwriting a foreign committed bank.
            if &h[..8] == MAGIC && &h[16..20] == COMMIT && h[56..] != owner {
                return Err(Error::Invalid);
            }
            if &h[..8] != MAGIC
                || h[56..] != owner
                || &h[16..20] != COMMIT
                || !h[20..22].iter().all(|p| *p <= 1 || *p == 0xff)
                || h[22..24] != [0xff; 2]
                || hash.finalize().as_slice() != &h[24..56]
            {
                continue;
            }
            let sequence = u64::from_le_bytes(h[8..16].try_into().unwrap());
            let previous = u64::from_le_bytes(selected[8..16].try_into().unwrap());
            if active.is_some() && sequence == previous {
                return Err(Error::Invalid);
            }
            if active.is_none() || sequence > previous {
                active = Some(bank);
                selected = h;
            }
        }
        if active.is_none() && nonblank {
            return Err(Error::Invalid);
        }
        if active.is_none() {
            selected[..8].copy_from_slice(MAGIC);
            selected[8..16].copy_from_slice(&0u64.to_le_bytes());
            selected[56..].copy_from_slice(&owner);
        }
        Ok(Self {
            backend,
            active,
            header: selected,
            pending: None,
            staged: Zeroizing::new([0xff; N]),
            poisoned: false,
        })
    }

    fn hash_header(h: &[u8; HEADER]) -> Sha256 {
        let mut hash = Sha256::new();
        hash.update(&h[..16]);
        hash.update(&h[20..24]);
        hash.update(&h[56..]);
        hash
    }

    fn check(&self, channel: usize, page: usize) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if channel >= 2 || page >= 2 {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn read(&mut self, channel: usize, page: usize, bytes: &mut [u8; N]) -> Result<(), Error> {
        self.check(channel, page)?;
        bytes.fill(0xff);
        if let Some(bank) = self.active {
            if self.header[20 + channel] == page as u8 {
                self.backend.read(bank, HEADER + channel * N, bytes)?;
            }
        }
        Ok(())
    }

    pub fn stage(&mut self, channel: usize, page: usize, bytes: &[u8; N]) -> Result<(), Error> {
        self.check(channel, page)?;
        if self.pending.is_some() {
            return Err(Error::Invalid);
        }
        self.staged.copy_from_slice(bytes);
        self.pending = Some((channel, page));
        Ok(())
    }

    pub fn commit(&mut self, channel: usize, page: usize) -> Result<(), Error> {
        self.check(channel, page)?;
        if self.pending != Some((channel, page)) {
            return Err(Error::Invalid);
        }
        self.staged[16..20].copy_from_slice(COMMIT);
        self.publish(channel, page as u8)
    }

    pub fn clear(&mut self, channel: usize) -> Result<(), Error> {
        // Publishes logical deletion; old-bank bytes may remain, so this is not secure erase.
        self.check(channel, 0)?;
        if self.pending.is_some() {
            return Err(Error::Invalid);
        }
        self.staged.fill(0xff);
        self.publish(channel, 0xff)
    }

    fn publish(&mut self, channel: usize, page: u8) -> Result<(), Error> {
        self.poisoned = true;
        let sequence = u64::from_le_bytes(self.header[8..16].try_into().unwrap())
            .checked_add(1)
            .ok_or(Error::Invalid)?;
        let target = self.active.map_or(0, |bank| 1 - bank);
        let mut h = self.header;
        h[8..16].copy_from_slice(&sequence.to_le_bytes());
        h[16..20].fill(0xff);
        h[20 + channel] = page;
        let peer = 1 - channel;
        let mut scratch = Zeroizing::new([0xff; N]);
        if let Some(bank) = self.active {
            self.backend.read(bank, HEADER + peer * N, &mut *scratch)?;
        }
        let mut hash = Self::hash_header(&h);
        for c in 0..2 {
            hash.update(if c == channel {
                &*self.staged
            } else {
                &*scratch
            });
        }
        h[24..56].copy_from_slice(&hash.finalize());
        self.backend.erase(target)?;
        self.backend.program(target, 0, &h)?;
        self.backend
            .program(target, HEADER + channel * N, &*self.staged)?;
        self.backend.program(target, HEADER + peer * N, &*scratch)?;
        self.backend.program(target, 16, COMMIT)?;
        let mut verify = [0; HEADER];
        self.backend.read(target, 0, &mut verify)?;
        h[16..20].copy_from_slice(COMMIT);
        if verify != h {
            return Err(Error::Io);
        }
        let mut check = Self::hash_header(&verify);
        for c in 0..2 {
            self.backend.read(target, HEADER + c * N, &mut *scratch)?;
            check.update(&*scratch);
        }
        if check.finalize().as_slice() != &h[24..56] {
            return Err(Error::Io);
        }
        self.header = h;
        self.active = Some(target);
        self.pending = None;
        self.staged.fill(0xff);
        self.poisoned = false;
        Ok(())
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}




























































































































































