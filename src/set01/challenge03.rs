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

pub struct EnglishAsciiScorer<'a> {
    letter_ranking: &'a [u8],
}

impl<'a> EnglishAsciiScorer<'a> {
    /// Create a new scorer
    pub fn new() -> Self {
        // Using http://norvig.com/mayzner.html
        // I also added the space character due to a bug where two plain text results scored the same
        // One was a version of the other, but with a key difference of 32, somehow causing the letters to switch cases.
        // The only other difference was that one version had spaces as expected, and the other didn't (it had symbols instead)
        // So i'm making the hypothesis (backed by some random internet article) that the SPACE character is an imporant part of the language
        // and more frequent than the e character
        EnglishAsciiScorer {
            letter_ranking: " etaoinsrhldcumfpgwybvkxjqz".as_bytes(),
        }
    }

    /// Grade a sequence of bytes  
    /// The higher the grade, the more likely this sequence corresponds to an english ascii text
    /// 
    /// This grading is done using the approximate order of frequency of the 12 most commonly used 
    /// letters in the English language.
    pub fn score_ascii_text(&self, input: &[u8]) -> u32 {
        input.iter()
            .map(|byte| self.score_ascii_byte(byte) as u32)
            .sum()
    }

    /// Score a single ascii byte based on the weights provided
    fn score_ascii_byte(&self, byte: &u8) -> u8 {
        let byte = byte.to_ascii_lowercase();

        for (index, letter) in self.letter_ranking.iter().enumerate() {
            if letter == &byte {
                // Phew seems like a dangerous cast?
                // Not to worry: The length of the letter ranking slice will not be larger than a u8 because 
                // there are not enough letters in the alphabet.
                return (self.letter_ranking.len() - index) as u8
            }
        }

        0
    }
}

pub struct SingleByteXorDecodeResult {
    key: u8,
    result: Vec<u8>,
    score: u32
}

impl SingleByteXorDecodeResult {
    pub fn new(score: u32, key: u8, result: &[u8]) -> Self {
        SingleByteXorDecodeResult{ score, key,  result: result.to_vec() }
    }

    pub fn get_key(&self) -> u8 {
        self.key
    }

    pub fn get_result(&self) -> &[u8] {
        &self.result
    }

    pub fn get_score(&self) -> u32 {
        self.score
    }
}

/// Try to decode a single-xor cipher by brute force (i.e xoring every possible byte with the input)
/// The results are returned, sorted by a scoring "algorithm"
/// The algorithm scores a piece of text higher depending on how much it "looks like English" based on 
/// character frequency rules.
pub fn decode_single_byte_xor(input: &[u8]) -> Vec<SingleByteXorDecodeResult> {
    // Xor with every possible byte
    let mut all_possible_xor_results = HashMap::new();

     for byte in 0..=255 {
        // We use the xor_bytes function from the previous challenge.
        // Since we are only xoring one byte, we can just repeat it for the length of the input 
        all_possible_xor_results.insert(byte, challenge02::xor_bytes(input, &vec![byte; input.len()]));
    }

    let scorer = EnglishAsciiScorer::new();

    let mut scores = Vec::new();

    for (key, result) in all_possible_xor_results.iter() {
        scores.push(
            SingleByteXorDecodeResult::new(
                scorer.score_ascii_text(result), 
                key.clone(), 
                result));
    }

    // Sort the results from best score to worst
    scores.sort_by(|a, b| b.score.cmp(&a.score));

    scores
}



/// Single-byte XOR cipher
#[cfg(test)]
pub mod test {
    use crate::radix;
    use crate::set01::challenge03;

    /// Solution to the challenge (see source)
    pub fn single_byte_xor_cipher() {
        let input_ascii_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let bytes = radix::base16_to_bytes(input_ascii_hex);

        let best_guess = challenge03::decode_single_byte_xor(&bytes).remove(0);

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

        assert_eq!(26, scorer.score_ascii_byte(&b'e'));
        assert_eq!(26, scorer.score_ascii_byte(&b'E'));
       
        assert_eq!(21, scorer.score_ascii_byte(&b'n'));
        assert_eq!(21, scorer.score_ascii_byte(&b'N'));

        assert_eq!(3, scorer.score_ascii_byte(&b'j'));
        assert_eq!(3, scorer.score_ascii_byte(&b'J'));

        assert_eq!(1, scorer.score_ascii_byte(&b'z'));
        assert_eq!(1, scorer.score_ascii_byte(&b'Z'));

        assert_eq!(0, scorer.score_ascii_byte(&b')'));
    }
}