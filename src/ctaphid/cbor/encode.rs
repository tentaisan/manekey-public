fn write_uint(buf: &mut [u8], value: u64) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }

    if value < 24 {
        buf[0] = value as u8;
        Some(1)
    } else if value <= 0xff {
        if buf.len() < 2 {
            return None;
        }
        buf[0] = 0x18;
        buf[1] = value as u8;
        Some(2)
    } else if value <= 0xffff {
        if buf.len() < 3 {
            return None;
        }
        buf[0] = 0x19;
        buf[1] = ((value >> 8) & 0xff) as u8;
        buf[2] = (value & 0xff) as u8;
        Some(3)
    } else if value <= 0xffffffff {
        if buf.len() < 5 {
            return None;
        }
        buf[0] = 0x1a;
        buf[1] = ((value >> 24) & 0xff) as u8;
        buf[2] = ((value >> 16) & 0xff) as u8;
        buf[3] = ((value >> 8) & 0xff) as u8;
        buf[4] = (value & 0xff) as u8;
        Some(5)
    } else {
        if buf.len() < 9 {
            return None;
        }
        buf[0] = 0x1b;
        buf[1] = ((value >> 56) & 0xff) as u8;
        buf[2] = ((value >> 48) & 0xff) as u8;
        buf[3] = ((value >> 40) & 0xff) as u8;
        buf[4] = ((value >> 32) & 0xff) as u8;
        buf[5] = ((value >> 24) & 0xff) as u8;
        buf[6] = ((value >> 16) & 0xff) as u8;
        buf[7] = ((value >> 8) & 0xff) as u8;
        buf[8] = (value & 0xff) as u8;
        Some(9)
    }
}

fn write_map_len(buf: &mut [u8], len: u8) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }

    if len < 24 {
        buf[0] = 0xa0 | len;
        Some(1)
    } else {
        None
    }
}

fn write_array_len(buf: &mut [u8], len: u8) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }

    if len < 24 {
        buf[0] = 0x80 | len;
        Some(1)
    } else {
        None
    }
}

fn write_text(buf: &mut [u8], value: &[u8]) -> Option<usize> {
    let len = value.len();

    if len < 24 {
        if buf.len() < 1 + len {
            return None;
        }

        buf[0] = 0x60 | (len as u8);
        buf[1..1 + len].copy_from_slice(value);

        Some(1 + len)
    } else if len <= 0xff {
        if buf.len() < 2 + len {
            return None;
        }

        buf[0] = 0x78;
        buf[1] = len as u8;
        buf[2..2 + len].copy_from_slice(value);

        Some(2 + len)
    } else if len <= 0xffff {
        if buf.len() < 3 + len {
            return None;
        }

        buf[0] = 0x79;
        buf[1] = ((len >> 8) & 0xff) as u8;
        buf[2] = (len & 0xff) as u8;
        buf[3..3 + len].copy_from_slice(value);

        Some(3 + len)
    } else if len <= 0xffffffff {
        if buf.len() < 5 + len {
            return None;
        }

        buf[0] = 0x7a;
        buf[1] = ((len >> 24) & 0xff) as u8;
        buf[2] = ((len >> 16) & 0xff) as u8;
        buf[3] = ((len >> 8) & 0xff) as u8;
        buf[4] = (len & 0xff) as u8;
        buf[5..5 + len].copy_from_slice(value);

        Some(5 + len)
    } else {
        None
    }
}

fn write_bytes(buf: &mut [u8], value: &[u8]) -> Option<usize> {
    let len = value.len();

    if len < 24 {
        if buf.len() < 1 + len {
            return None;
        }

        buf[0] = 0x40 | (len as u8);
        buf[1..1 + len].copy_from_slice(value);

        Some(1 + len)
    } else if len <= 0xff {
        if buf.len() < 2 + len {
            return None;
        }

        buf[0] = 0x58;
        buf[1] = len as u8;
        buf[2..2 + len].copy_from_slice(value);

        Some(2 + len)
    } else if len <= 0xffff {
        if buf.len() < 3 + len {
            return None;
        }

        buf[0] = 0x59;
        buf[1] = ((len >> 8) & 0xff) as u8;
        buf[2] = (len & 0xff) as u8;
        buf[3..3 + len].copy_from_slice(value);

        Some(3 + len)
    } else if len <= 0xffffffff {
        if buf.len() < 5 + len {
            return None;
        }

        buf[0] = 0x5a;
        buf[1] = ((len >> 24) & 0xff) as u8;
        buf[2] = ((len >> 16) & 0xff) as u8;
        buf[3] = ((len >> 8) & 0xff) as u8;
        buf[4] = (len & 0xff) as u8;
        buf[5..5 + len].copy_from_slice(value);

        Some(5 + len)
    } else {
        None
    }
}

fn write_bool(buf: &mut [u8], value: bool) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }

    buf[0] = if value { 0xf5 } else { 0xf4 };
    Some(1)
}

fn write_negint(buf: &mut [u8], value: i8) -> Option<usize> {
    if buf.is_empty() || value >= 0 {
        return None;
    }

    let n = (-1 - value) as u8;

    if n < 24 {
        buf[0] = 0x20 | n;
        Some(1)
    } else if buf.len() >= 2 {
        buf[0] = 0x38;
        buf[1] = n;
        Some(2)
    } else {
        None
    }
}

/// Bounded CBOR writer; errors do not roll back prior fields.
/// Map and array headers support fewer than 24 elements.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    pub fn write_raw_u8(&mut self, value: u8) -> Option<()> {
        if self.offset >= self.buf.len() {
            return None;
        }

        self.buf[self.offset] = value;
        self.offset += 1;
        Some(())
    }

    pub fn write_raw_bytes(&mut self, value: &[u8]) -> Option<()> {
        if self.buf.len() < self.offset + value.len() {
            return None;
        }

        self.buf[self.offset..self.offset + value.len()].copy_from_slice(value);
        self.offset += value.len();
        Some(())
    }

    pub fn write_uint(&mut self, value: u64) -> Option<()> {
        let n = write_uint(&mut self.buf[self.offset..], value)?;
        self.offset += n;
        Some(())
    }

    pub fn write_negint(&mut self, value: i8) -> Option<()> {
        let n = write_negint(&mut self.buf[self.offset..], value)?;
        self.offset += n;
        Some(())
    }

    pub fn write_map_len(&mut self, len: u8) -> Option<()> {
        let n = write_map_len(&mut self.buf[self.offset..], len)?;
        self.offset += n;
        Some(())
    }

    pub fn write_array_len(&mut self, len: u8) -> Option<()> {
        let n = write_array_len(&mut self.buf[self.offset..], len)?;
        self.offset += n;
        Some(())
    }

    pub fn write_text(&mut self, value: &[u8]) -> Option<()> {
        let n = write_text(&mut self.buf[self.offset..], value)?;
        self.offset += n;
        Some(())
    }

    pub fn write_bytes(&mut self, value: &[u8]) -> Option<()> {
        let n = write_bytes(&mut self.buf[self.offset..], value)?;
        self.offset += n;
        Some(())
    }

    pub fn write_bool(&mut self, value: bool) -> Option<()> {
        let n = write_bool(&mut self.buf[self.offset..], value)?;
        self.offset += n;
        Some(())
    }

    pub fn finish(self) -> &'a [u8] {
        &self.buf[..self.offset]
    }
}
