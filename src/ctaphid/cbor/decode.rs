const MAX_SKIP_DEPTH: usize = 16;

fn read_len(data: &[u8], major: u8) -> Option<(usize, &[u8])> {
    if data.is_empty() {
        return None;
    }

    if data[0] & 0xe0 != major {
        return None;
    }

    let (value, rest) = read_uint_argument(data)?;

    if value > usize::MAX as u64 {
        return None;
    }

    Some((value as usize, rest))
}

fn read_uint_argument(data: &[u8]) -> Option<(u64, &[u8])> {
    if data.is_empty() {
        return None;
    }

    let additional = data[0] & 0x1f;

    if additional < 24 {
        Some((additional as u64, &data[1..]))
    } else if additional == 24 {
        if data.len() < 2 {
            return None;
        }

        Some((data[1] as u64, &data[2..]))
    } else if additional == 25 {
        if data.len() < 3 {
            return None;
        }

        Some((u16::from_be_bytes([data[1], data[2]]) as u64, &data[3..]))
    } else if additional == 26 {
        if data.len() < 5 {
            return None;
        }

        Some((
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64,
            &data[5..],
        ))
    } else if additional == 27 {
        if data.len() < 9 {
            return None;
        }

        Some((
            u64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]),
            &data[9..],
        ))
    } else {
        None
    }
}

fn read_map_len(data: &[u8]) -> Option<(usize, &[u8])> {
    read_len(data, 0xa0)
}

fn read_uint(data: &[u8]) -> Option<(u64, &[u8])> {
    if data.is_empty() {
        return None;
    }

    if data[0] & 0xe0 != 0x00 {
        return None;
    }

    read_uint_argument(data)
}

fn read_bytes(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = read_len(data, 0x40)?;
    if rest.len() < len {
        return None;
    }

    Some((&rest[..len], &rest[len..]))
}

fn read_negint(data: &[u8]) -> Option<(i64, &[u8])> {
    if data.is_empty() {
        return None;
    }

    if data[0] & 0xe0 != 0x20 {
        return None;
    }

    let (value, rest) = read_uint_argument(data)?;

    if value > i64::MAX as u64 {
        return None;
    }

    let n = value as i64;
    Some((-1 - n, rest))
}

fn read_bool(data: &[u8]) -> Option<(bool, &[u8])> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        0xf4 => Some((false, &data[1..])),
        0xf5 => Some((true, &data[1..])),
        _ => None,
    }
}

fn skip_value(data: &[u8]) -> Option<&[u8]> {
    skip_value_with_depth(data, MAX_SKIP_DEPTH)
}

fn skip_value_with_depth(data: &[u8], depth: usize) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }

    if depth == 0 {
        return None;
    }

    let major = data[0] & 0xe0;

    match major {
        0x00 | 0x20 => {
            let (_, rest) = read_uint_argument(data)?;
            Some(rest)
        }

        0x40 | 0x60 => {
            let (len, rest) = read_len(data, major)?;
            if rest.len() < len {
                return None;
            }

            Some(&rest[len..])
        }

        0x80 => {
            let (len, mut rest) = read_len(data, 0x80)?;
            for _ in 0..len {
                rest = skip_value_with_depth(rest, depth - 1)?;
            }
            Some(rest)
        }

        0xa0 => {
            let (len, mut rest) = read_len(data, 0xa0)?;
            for _ in 0..len {
                rest = skip_value_with_depth(rest, depth - 1)?;
                rest = skip_value_with_depth(rest, depth - 1)?;
            }
            Some(rest)
        }

        0xe0 => {
            let (_, rest) = read_uint_argument(data)?;
            Some(rest)
        }

        _ => None,
    }
}

fn read_array_len(data: &[u8]) -> Option<(usize, &[u8])> {
    read_len(data, 0x80)
}

fn read_text(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = read_len(data, 0x60)?;
    if rest.len() < len {
        return None;
    }

    Some((&rest[..len], &rest[len..]))
}

/// Bounded definite-length CBOR reader; not a canonical-encoding validator.
/// Text is returned as bytes; callers validate UTF-8 where required.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    pub fn read_map_len(&mut self) -> Option<usize> {
        let (value, rest) = read_map_len(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn read_array_len(&mut self) -> Option<usize> {
        let (value, rest) = read_array_len(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn read_uint(&mut self) -> Option<u64> {
        let (value, rest) = read_uint(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn read_negint(&mut self) -> Option<i64> {
        let (value, rest) = read_negint(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn read_bool(&mut self) -> Option<bool> {
        let (value, rest) = read_bool(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn read_text(&mut self) -> Option<&'a [u8]> {
        let (value, rest) = read_text(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn read_bytes(&mut self) -> Option<&'a [u8]> {
        let (value, rest) = read_bytes(self.rest)?;
        self.rest = rest;
        Some(value)
    }

    pub fn skip_value(&mut self) -> Option<()> {
        self.rest = skip_value(self.rest)?;
        Some(())
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.rest
    }
}
