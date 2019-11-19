//! # Single-byte XOR cipher
//! 
//! The XOR operation preserves byte frequency.  
//! Say a sequence of bytes had 10 occurences of the byte 0b0000_1111  
//! If I XOR each byte in that sequence with the byte 0b1111_1111  
//! we will end up with a sequence that has 10 occurencs of the byte 0b1111_0000  
//! 
//! The XOR operation is also reversible.   
//! Say you have the byte 0b0000_1111 and you xor it with 0b1111_1111, you get 0b1111_0000  
//! If you XOR it again with 0b1111_1111, you'll get your original byte 0b0000_1111!  
//! 
//! A straightforward way to figure out what the original text was is to
//! (a) xor every possible byte with our input string. This will give us every possible original string.
//! (b) score all our strings based on character frequency and choose the one that is most likely to be english


use std::collections::HashMap;

use crate::set01::challenge02;

pub struct EnglishAsciiScorer {
    weights: HashMap<u8, u8>
}

impl EnglishAsciiScorer {
    /// Create a new scorer
    pub fn new() -> Self {
        EnglishAsciiScorer {
            weights: [
                (b'e', 13), (b'E', 13),
                (b't', 12), (b'T', 12),
                (b'a', 11), (b'A', 11),
                (b'o', 10), (b'O', 10),
                (b'i', 9), (b'I', 9),
                (b'n', 8), (b'N', 8),
                (b' ', 7),
                (b's', 6), (b'S', 6),
                (b'h', 5), (b'H', 5),
                (b'r', 4), (b'R', 4),
                (b'd', 3), (b'D', 3),
                (b'l', 2), (b'L', 2),
                (b'u', 1), (b'U', 1),
            ].iter()
            .cloned()
            .collect()
        }
    }

    /// Score a single ascii byte based on the weights provided
    pub fn score_ascii_byte(&self, byte: &u8) -> u8 {
        if self.weights.contains_key(byte) { self.weights[byte] } else { 0 } 
    }
}

pub struct SingleByteXorDecodeResult {
    result: Vec<u8>,
    score: u32
}

impl SingleByteXorDecodeResult {
    pub fn new(score: u32, result: Vec<u8>) -> Self {
        SingleByteXorDecodeResult{ score, result }
    }

    pub fn get_result(&self) -> &[u8] {
        &self.result
    }

    pub fn get_score(&self) -> u32 {
        self.score
    }
}

/// Make a guess at what might be the original plain-text of the input 
/// The guess is made by xoring every possible byte with the input,
/// then picking the one that looks the most like English based on character frequency rules.
pub fn decode_single_byte_xor(input: &[u8]) -> SingleByteXorDecodeResult {
    let all_possible_xor_results = xor_with_every_possible_byte(input);

    let mut best = (0, Vec::new());

    for result in all_possible_xor_results {
        let score = score_english_ascii_text(&result);

        if score > best.0 {
            best = (score, result);
        }
    }

    SingleByteXorDecodeResult::new(best.0, best.1)
}

/// Grade a sequence of bytes  
/// The higher the grade, the more likely this sequence corresponds to an english ascii text
/// 
/// This grading is done using the approximate order of frequency of the 12 most commonly used 
/// letters in the English language.
pub fn score_english_ascii_text(input: &[u8]) -> u32 {
    let scorer = EnglishAsciiScorer::new();

    input.iter()
            .map(|byte| scorer.score_ascii_byte(byte) as u32)
            .sum()

}

/// Xor every possible single byte with the input and return all results
pub fn xor_with_every_possible_byte(input: &[u8]) -> Vec<Vec<u8>> {
    let mut results = Vec::new();

    for byte in 0..=0b1111_1111 {
        // We use the xor_bytes function from the previous challenge.
        // Since we are only xoring one byte, we can just repeat it for the length of the input 
        results.push(challenge02::xor_bytes(input, &vec![byte; input.len()]));
    }

    results
}

/// Single-byte XOR cipher
#[cfg(test)]
pub mod test {
    use crate::set01::challenge01;
    use crate::set01::challenge03;

    /// Solution to the challenge (see source)
    pub fn single_byte_xor_cipher() {
        let input_ascii_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let bytes = challenge01::base16_to_bytes(input_ascii_hex);

        let best_guess = challenge03::decode_single_byte_xor(&bytes);

        assert_eq!(
            "Cooking MC's like a pound of bacon",
            std::str::from_utf8(best_guess.get_result()).unwrap()
        );
    }

    #[test]
    pub fn test_single_byte_xor_cipher() {
        single_byte_xor_cipher();
    }

    #[test]
    pub fn test_scorer() {
        let scorer = challenge03::EnglishAsciiScorer::new();

        assert_eq!(13, scorer.score_ascii_byte(&b'e'));
        assert_eq!(12, scorer.score_ascii_byte(&b't'));
        assert_eq!(11, scorer.score_ascii_byte(&b'a'));
        assert_eq!(10, scorer.score_ascii_byte(&b'o'));
        assert_eq!(9, scorer.score_ascii_byte(&b'i'));
        assert_eq!(8, scorer.score_ascii_byte(&b'n'));
        assert_eq!(7, scorer.score_ascii_byte(&b' '));
        assert_eq!(6, scorer.score_ascii_byte(&b's'));
        assert_eq!(5, scorer.score_ascii_byte(&b'h'));
        assert_eq!(4, scorer.score_ascii_byte(&b'r'));
        assert_eq!(3, scorer.score_ascii_byte(&b'd'));
        assert_eq!(2, scorer.score_ascii_byte(&b'l'));
        assert_eq!(1, scorer.score_ascii_byte(&b'u'));
        assert_eq!(0, scorer.score_ascii_byte(&b'y'));
    }
}