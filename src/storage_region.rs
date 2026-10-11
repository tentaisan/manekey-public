






#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Bounds arithmetic only; callers own Flash geometry, alignment, permissions and I/O.
pub struct FixedPageRegion {
    base: usize,
    page_size: usize,
    page_count: usize,
}

impl FixedPageRegion {

    pub const fn new(base: usize, page_size: usize, page_count: usize) -> Self {
        Self {
            base,
            page_size,
            page_count,
        }
    }







    pub const fn from_end(total_size: usize, page_size: usize, page_count: usize) -> Self {
        // Unchecked arithmetic can panic or wrap; use checked_from_end for external values.
        let len = page_size * page_count;
        Self {
            base: total_size - len,
            page_size,
            page_count,
        }
    }




    pub fn checked_from_end(
        total_size: usize,
        page_size: usize,
        page_count: usize,
    ) -> Option<Self> {
        let len = page_size.checked_mul(page_count)?;
        let base = total_size.checked_sub(len)?;
        Some(Self {
            base,
            page_size,
            page_count,
        })
    }


    pub const fn base(&self) -> usize {
        self.base
    }


    pub const fn page_size(&self) -> usize {
        self.page_size
    }


    pub const fn page_count(&self) -> usize {
        self.page_count
    }


    pub const fn len(&self) -> usize {
        // Unchecked multiplication; checked_len rejects overflow.
        self.page_size * self.page_count
    }


    pub fn checked_len(&self) -> Option<usize> {
        self.page_size.checked_mul(self.page_count)
    }


    pub fn end(&self) -> Option<usize> {
        self.checked_len()
            .and_then(|len| self.base.checked_add(len))
    }


    pub const fn is_empty(&self) -> bool {
        self.page_count == 0 || self.page_size == 0
    }


    pub fn contains_range(&self, offset: usize, len: usize) -> bool {
        let Some(end) = self.end() else {
            return false;
        };
        let Some(request_end) = offset.checked_add(len) else {
            return false;
        };
        offset >= self.base && request_end <= end
    }





    pub fn contains_single_page_range(&self, offset: usize, len: usize) -> bool {
        if len == 0 || self.page_size == 0 || !self.contains_range(offset, len) {
            return false;
        }

        let Some(relative_offset) = offset.checked_sub(self.base) else {
            return false;
        };
        let page = relative_offset / self.page_size;
        let Some(page_start) = self.page_offset(page) else {
            return false;
        };
        let Some(page_end) = page_start.checked_add(self.page_size) else {
            return false;
        };
        offset.checked_add(len).is_some_and(|end| end <= page_end)
    }


    pub fn page_offset(&self, page: usize) -> Option<usize> {
        if page >= self.page_count {
            return None;
        }
        self.page_size
            .checked_mul(page)
            .and_then(|offset| self.base.checked_add(offset))
    }


    pub fn page_offset_for_len(&self, page: usize, len: usize) -> Option<usize> {
        // Bounds the entire region, not one page; the requested span may cross pages.
        let offset = self.page_offset(page)?;
        self.contains_range(offset, len).then_some(offset)
    }
}




pub fn is_repeated_pattern(buf: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return false;
    }

    let chunks = buf.chunks_exact(pattern.len());
    if !chunks.remainder().is_empty() {
        return false;
    }
    chunks.into_iter().all(|chunk| chunk == pattern)
}


pub fn normalize_repeated_erased_pattern(buf: &mut [u8], pattern: &[u8], erased_value: u8) -> bool {
    // Pattern equality is not proof of physical erasure. Use only for the controller's
    // documented erased readback; this helper does not validate Flash or secret deletion.
    if !is_repeated_pattern(buf, pattern) {
        return false;
    }
    buf.fill(erased_value);
    true
}








































































































