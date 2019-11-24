//! # AES in ECB mode



/// AES in ECB mode
#[cfg(test)]
pub mod tests {
    use crate::radix;

    use openssl::symm;

    use std::fs;
    use std::path;

    /// Solution to the challenge (see source)
    pub fn aes_in_ecb_mode() {
        let key = "YELLOW SUBMARINE";

        let cipher_text = fs::read_to_string(
            path::PathBuf::from("./src/set01/input/_aes_in_ecb_mode.txt")
        ).expect("could not open file");

        // Get rid of the new lines
        let cipher_text = cipher_text.replace("\r\n", "");
        let cipher_text = cipher_text.replace("\n", "");

        let cipher_text_bytes = radix::base64_to_bytes(&cipher_text);

        let cipher = symm::Cipher::aes_128_ecb();

        let plain_text_bytes = symm::decrypt(
            cipher, 
            key.as_bytes(),
            None,
            &cipher_text_bytes
        ).expect("unable to decrypt");

        let plain_text = String::from_utf8(plain_text_bytes).unwrap();

        assert!(
            plain_text.starts_with("I'm back and I'm ringin' the bell")
        );
    }

    #[test]
    pub fn test_aes_in_ecb_mode() {
        aes_in_ecb_mode();
    }
}

