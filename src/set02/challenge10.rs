//! # Implement CBC mode
//! 
//! I have already seen one mode of operation before, ECB
//! Here I am to implement a second (and better) one: CBC (Cipher Block 
//! Chaining)




/// Implement CBC mode
#[cfg(test)]
pub mod test {
    use std::fs;
    use std::path::PathBuf;

    use crate::aes128;

    /// Solution to the challenge (see source)
    pub fn implement_cbc_mode() {
        let contents = fs::read_to_string(
            PathBuf::from("./src/set02/input/_implement_cbc_mode.txt")
        ).expect("could not read file");

        let content_bytes = contents.as_bytes().to_vec();

        let plain_text = aes128::cbc_decrypt(
            b"YELLOW SUBMARINE",
            &[0; 16], 
            &content_bytes);

            unsafe {
                println!(
                    "{}", 
                    std::str::from_utf8_unchecked(&plain_text));
            }
        
    }

    #[test]
    pub fn test_implement_cbc_mode() {
        implement_cbc_mode();
    }
}