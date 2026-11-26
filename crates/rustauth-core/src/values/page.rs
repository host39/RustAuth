//! `Page`: offset pagination for list operations.

/// An offset and a limit. The limit is clamped to `1..=Page::MAX_LIMIT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Page {
    offset: u64,
    limit: u32,
}

impl Page {
    pub const DEFAULT_LIMIT: u32 = 50;
    pub const MAX_LIMIT: u32 = 100;

    pub fn new(offset: u64, limit: u32) -> Self {
        Self {
            offset,
            limit: limit.clamp(1, Self::MAX_LIMIT),
        }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::new(0, Self::DEFAULT_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_the_limit() {
        assert_eq!(Page::new(0, 0).limit(), 1);
        assert_eq!(Page::new(0, 500).limit(), 100);
        assert_eq!(Page::new(20, 10), Page::new(20, 10));
        assert_eq!(Page::default().limit(), 50);
        assert_eq!(Page::default().offset(), 0);
    }
}
