//! String helpers for display — avoid panicking on UTF-8 boundaries.

/// Truncate `s` to at most `max_bytes` UTF-8 bytes without splitting a scalar value.
#[must_use]
pub fn truncate_max_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        s
    } else {
        let end = s.floor_char_boundary(max_bytes);
        &s[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_ascii_short_unchanged() {
        assert_eq!(truncate_max_bytes("hello", 8), "hello");
    }

    #[test]
    fn truncate_ascii_long() {
        assert_eq!(truncate_max_bytes("helloworld", 5), "hello");
    }

    #[test]
    fn truncate_cjk_no_panic_and_char_aligned() {
        let s = "田田田";
        assert_eq!(s.len(), 9);
        let t = truncate_max_bytes(s, 8);
        assert!(t.len() <= 8);
        assert_eq!(t, "田田");
    }

    #[test]
    fn truncate_empty_max_zero() {
        assert_eq!(truncate_max_bytes("x", 0), "");
    }
}
