//! # Implement CBC mode
//! 
//! From what I am understanding, block ciphers are only designed to provide
//! confidentiality for the block they encrypt.    
//! If I need to encrypt more than a block, which is often the case, I need to
//! layer an algorithm on top of the block cipher that determines how to 
//! construct the subsequent blocks in a hopefully still secure manner.  
//! This _layered_ algorithm is called the cipher's _mode of operation_
//! 
//! I have already seen one before ~ ECB (stands for Electronic Code Book)  
//! Here we are to implement a second (and better) one: CBC (Cipher Block 
//! Chaining)

/// Implement CBC mode
#[cfg(test)]
pub mod test {
    use std::fs;
    use std::path::PathBuf;

    /// Solution to the challenge (see source)
    pub fn implement_cbc_mode() {
        let contents = fs::read_to_string(
            PathBuf::from("./src/set02/input/_implement_cbc_mode.txt")
        ).expect("could not read file");

        println!("{}", contents);
    }

    #[test]
    pub fn test_implement_cbc_mode() {
        implement_cbc_mode();
    }
}