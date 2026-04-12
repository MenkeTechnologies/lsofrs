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

    #[test]
    fn truncate_emoji_four_byte_char_split_mid_glyph() {
        let s = "a🎉b";
        assert_eq!(s.len(), 6);
        let t = truncate_max_bytes(s, 2);
        assert_eq!(t, "a");
        let t2 = truncate_max_bytes(s, 5);
        assert_eq!(t2, "a🎉");
    }

    #[test]
    fn truncate_max_bytes_equals_full_len_unchanged() {
        let s = "exact";
        assert_eq!(truncate_max_bytes(s, s.len()), s);
    }

    #[test]
    fn truncate_grapheme_cluster_not_special_cased_still_safe() {
        // "e" + combining acute — two Unicode scalars; truncation is scalar-safe not grapheme-safe
        let s = "e\u{0301}";
        assert_eq!(s.len(), 3);
        assert_eq!(truncate_max_bytes(s, 1), "e");
    }

    #[test]
    fn truncate_utf8_max_one_past_ascii_prefix_keeps_ascii_only() {
        assert_eq!(truncate_max_bytes("ab田", 3), "ab");
    }

    #[test]
    fn truncate_empty_string_any_limit() {
        assert_eq!(truncate_max_bytes("", 0), "");
        assert_eq!(truncate_max_bytes("", 100), "");
    }
}
