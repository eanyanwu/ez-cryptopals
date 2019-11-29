//! # Implement CBC mode


/// Implement CBC mode
#[cfg(test)]
pub mod test {
    use std::fs;
    use std::path::PathBuf;

    use crate::radix;
    use crate::aes128;

    /// Solution to the challenge (see source)
    pub fn implement_cbc_mode() {
        let contents = fs::read_to_string(
            PathBuf::from("./src/set02/input/_implement_cbc_mode.txt")
        ).expect("could not read file");

        // remove new lines
        let contents = contents.replace("\n", "");
        let contents = contents.replace("\r\n", "");

        let content_bytes = radix::base64_to_bytes(
            &contents
        );

        let plain_text = aes128::cbc_decrypt(
            b"YELLOW SUBMARINE",
            &[0; 16], 
            &content_bytes);

        assert!(
            std::str::from_utf8(
                &plain_text
            ).unwrap()
            .starts_with("I'm back and I'm ringin' the bell")
        );
        
    }

    #[test]
    pub fn test_implement_cbc_mode() {
        implement_cbc_mode();
    }
}