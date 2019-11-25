//! # Single-byte XOR cipher
//! 
//! The XOR operation is deterministic. This means that given two bytes, XORing
//! them together will _always_ give the same result.
//! 
//! In a single-byte XOR cipher, all the bytes are being XORed by the same key.
//! This means that a given plain-text byte will always result in the same 
//! cipher-text byte.
//! 
//! Since the english language has a certain letter frequency, it is possible 
//! to automagically figure out if a block of text _probably_ contains english
//! 
//! So! A straightforward way to figure out what the original text was is to
//! (a) XOR every possible byte with our input string. This will give us every
//! possible original string.
//! (b) score all our strings based on character frequency and choose the one 
//! that is most likely to be english

use crate::set01::challenge02;

pub struct EnglishAsciiScorer<'a> {
    char_ranking: &'a [u8],
}

impl<'a> EnglishAsciiScorer<'a> {
    /// Create a new scorer
    pub fn new() -> Self {
        // Using http://norvig.com/mayzner.html
       
        EnglishAsciiScorer {
            char_ranking: " etaoinsrhldcumfpgwybvkxjqz".as_bytes(),
        }
    }

    /// Grade a sequence of bytes  
    /// The higher the grade, the more likely this sequence corresponds to an english ascii text
    /// 
    /// This grading is done using the approximate order of frequency of the 12 most commonly used 
    /// letters in the English language.
    pub fn score_ascii_text(&self, input: &[u8]) -> i32 {
        input.iter()
            .map(|byte| self.score_ascii_byte(byte))
            .sum()
    }

    /// Score a single ascii byte based on the weights provided
    fn score_ascii_byte(&self, byte: &u8) -> i32 {
        let byte = byte.to_ascii_lowercase();

        for (index, letter) in self.char_ranking.iter().enumerate() {
            if letter == &byte {
                // Phew seems like a dangerous cast?
                // Not to worry: The length of the letter ranking slice will not be larger than a u8 because 
                // there are not enough letters in the alphabet.
                return (self.char_ranking.len() - index) as i32
            }
        }

        -1
    }
}

pub struct SingleByteXorDecryptionAttempt {
    key: u8,
    result: Vec<u8>,
    score: i32
}

impl SingleByteXorDecryptionAttempt {
    pub fn new(score: i32, key: u8, result: &[u8]) -> Self {
        SingleByteXorDecryptionAttempt{ score, key,  result: result.to_vec() }
    }

    pub fn get_key(&self) -> u8 {
        self.key
    }

    pub fn get_result(&self) -> &[u8] {
        &self.result
    }

    pub fn get_score(&self) -> i32 {
        self.score
    }
}

/// Try to break a single-xor cipher by brute force (i.e xoring every possible
/// byte with the input)  
/// 
/// The results are returned, sorted by a scoring "algorithm".  
/// The algorithm scores a piece of text higher depending on how much it "looks 
/// like English" based on character frequency rules.
pub fn break_single_byte_xor(input: &[u8]) -> 
Vec<SingleByteXorDecryptionAttempt>
{
    let scorer = EnglishAsciiScorer::new();

    let mut scores = Vec::new();

    // Xor with every possible byte
     for byte in 0..=255 {
        // We use the xor_bytes function from the previous challenge.
        // Since we are only xoring one byte, we can just repeat it for the length of the input 
        let plain_text_bytes = challenge02::xor_bytes(
            input, 
            &vec![byte; input.len()]
        );

        let score = scorer.score_ascii_text(&plain_text_bytes);

        scores.push(SingleByteXorDecryptionAttempt::new(
            score,
            byte,
            &plain_text_bytes
        ));
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

        let best_guess = challenge03::break_single_byte_xor(&bytes).remove(0);

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
       
        assert_eq!(1, scorer.score_ascii_byte(&b'z'));
        assert_eq!(1, scorer.score_ascii_byte(&b'Z'));

        assert!(scorer.score_ascii_byte(&b')') < 0);
    }
}