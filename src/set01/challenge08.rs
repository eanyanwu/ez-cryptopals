//! # Detect AES in ECB mode
//! 
//! Though ECB is the "default" mode of AES, it is also the least secure.  
//! Because no additional transformations are made on the plain text apart from 
//! encrypting it, identical plain texts will be encrypted to identical cipher 
//! texts. This is bad because patterns in the plain text could still appear 
//! in the cipher text. 
//! 
//! For this challenge, we detect if the cipher-text was created using ECB by 
//! looking for the cipher text with the most identical blocks within it.


/// Detect AES in ECB mode
#[cfg(test)]
pub mod test {
    use std::io;
    use std::io::prelude::*;
    use std::fs;
    use std::path;
    use std::convert::TryFrom;
    
    use crate::radix;


    /// Solution to the challenge (see source)
    pub fn detect_aes_in_ecb_mode() {
        let path_to_file = path::PathBuf::from(
            "./src/set01/input/_detect_aes_in_ecb_mode.txt"
        );

        let f = fs::File::open(&path_to_file).expect("could not open the file");

        let reader = io::BufReader::new(f);

        let mut best_guess = (0, u32::max_value(), Vec::new());

        for (i, line) in reader.lines().enumerate() {
            let line = line.unwrap();

            let bytes = radix::base16_to_bytes(&line);

            // We break up the lines into 16-byte chunks 
            // Coincidentally, rust has a 128-bit type.
            // We then sort, then dedup the list of 128-bit chunks.
            // The list of chunks with the least amount of elements corresponds
            // to the line that was most likely to have been encrypted with ECB

            let mut chunks = bytes.chunks(16)
                    .map(|bytes| {
                        u128::from_le_bytes(
                            <[u8; 16]>::try_from(bytes).unwrap()
                        )
                    })
                    .collect::<Vec<u128>>();

            chunks.sort();
            chunks.dedup();

            if chunks.len() <= best_guess.1 as usize {
                best_guess = (i, chunks.len() as u32, bytes);
            }

        }

        assert_eq!(132, best_guess.0);
        assert_eq!(7, best_guess.1);
    }

    #[test]
    pub fn test_detect_aes_in_ecb_mode() {
        detect_aes_in_ecb_mode();
    }
}