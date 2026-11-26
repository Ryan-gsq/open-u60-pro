pub fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_preserves_byte_width_and_uses_lowercase() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(hex_lower(&[0, 1, 15, 128, 255]), "00010f80ff");
        assert_eq!(hex_lower("Guesté".as_bytes()), "4775657374c3a9");
        let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255];
        assert_eq!(hex_lower(&nonce), "000102030405060708090a0b0c0d0eff");
    }

    #[test]
    fn panic_message_accepts_both_string_payloads_and_preserves_the_fallback() {
        assert_eq!(panic_message(&"literal"), "literal");
        assert_eq!(panic_message(&String::from("owned")), "owned");
        assert_eq!(panic_message(&42), "a panic");
    }
}
