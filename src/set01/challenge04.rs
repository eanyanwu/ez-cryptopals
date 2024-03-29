//! # Detect single-character XOR
//! 
//! For this challenge, we are given a text file with multiple lines.
//! Each line is a hexadecimal string, and according to the prompt, one of the 
//! strings is actually cipher text that has been created by XORing some text 
//! with one character.
//! 
//! We are to find it.
//! 
//! We could assume each line was XORed and use the solution to challenge03 on 
//! all of them.  
//! This will give us the most probable english sentence per line ~ with a 
//! score.  
//! The highest scoring sentence across all the lines would be the most 
//! probably english sentence of them all?



/// Detect single-character XOR
#[cfg(test)]
pub mod test {
    use std::io;
    use std::io::prelude::*;
    use std::fs;
    use std::path;

    use crate::radix;
    use crate::set01::challenge03;

    /// Solution to the challenge (see source)
    pub fn detect_single_character_xor() {
        let path_to_file = path::PathBuf::from(
            "./src/set01/input/_detect_single_character_xor.txt"
        );

        let f = fs::File::open(&path_to_file).expect("could not open the file");

        let reader = io::BufReader::new(f);

        let mut best_guess = (0, 0, Vec::new());

        for (_, line) in reader.lines().enumerate() {
            let line = line.unwrap();

            let bytes = radix::base16_to_bytes(&line);

            let brute_force_xor_result = challenge03::break_single_byte_xor(&bytes).remove(0);

            if brute_force_xor_result.get_score() > best_guess.0 {
                best_guess = (
                    brute_force_xor_result.get_score(),
                    brute_force_xor_result.get_key(), 
                    brute_force_xor_result.get_result().to_vec()
                );
            }
        }
                
        assert_eq!(
            "Now that the party is jumping\n",
            std::str::from_utf8(&best_guess.2).unwrap()
        );
    }

    #[test]
    pub fn test_detect_single_character_xor() {
        detect_single_character_xor();
    }
}