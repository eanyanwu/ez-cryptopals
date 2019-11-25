//! # Detect AES in ECB mode
//! 
//! Unfortunately, the wording in this is too similar to challenge04, 
//! which makes it seem like you need to actually figure out what the key is.
//! 
//! I tried doing this, then realized my mistake. The AES cipher we are using
//! uses a 128-bit key. It would take _some time_ for my laptop to brute force 
//! that. 
//! 
//! Since I managed to solve challenge06, I didn't feel bad looking at other 
//! people's solutions to this challenge...and I'm glad I did.
//! 
//! Apprently, others are just detecting if ECB was used for the cipher. No one
//! is attempting to find the 128-bit key...
//! 
//! In retrospect...this makes sense. It would be odd if the creators of this
//! challenges expected me to break a mode of the Advanced Encryption Standard
//! at this point. 
//! 
//! However, I do wish it was worded a bit better. I sent an email to the 
//! Cryptography Services group. We'll see what comes of it.



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