//! # Implement PKCS#7 padding

/// Implement PKCS#7 padding
#[cfg(test)]
pub mod test {
    use crate::aes128;

    /// Solution to the challenge (see source)
    pub fn implement_pkcs7_padding() {
        let text = "YELLOW SUBMARINE";

        let mut bytes = text.as_bytes().to_vec();

        aes128::pkcs_pad(20, &mut bytes);

        assert_eq!(
            b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec(),
            bytes
        );
    }

    #[test]
    pub fn test_implement_pkcs7_padding() {
        implement_pkcs7_padding();
    }
}