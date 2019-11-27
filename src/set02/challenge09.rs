//! # Implement PKCS#7 padding
//! 
//! PKCS: Public Key Cryptography Standards  
//! I don't actually know what this means yet.
//! 
//! Anywho, block ciphers encrypt groups of _N_ bytes at a time.  
//! What happens when the length of the plain text is not an integer multiple of
//! _N_? PADDING!!
//! 
//! PKCS#7 defines (among other things) how to do said padding.

/// Add padding to the input as ordained by PKCS#7
pub fn pkcs_pad(block_size: u8, input: &mut Vec<u8>) {
    let count = block_size - (input.len() % block_size as usize) as u8;

    let mut pad_bytes = vec![count; count as usize];

    input.append(&mut pad_bytes);
}

/// Implement PKCS#7 padding
#[cfg(test)]
pub mod test {
    use crate::set02::challenge09;

    /// Solution to the challenge (see source)
    pub fn implement_pkcs7_padding() {
        let text = "YELLOW SUBMARINE";

        let mut bytes = text.as_bytes().to_vec();

        challenge09::pkcs_pad(20, &mut bytes);

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