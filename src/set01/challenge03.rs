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
    bigram_ranking: HashMap<String, i32>,
    letter_ranking: HashMap<u8, i32>
}

impl EnglishAsciiScorer {
    /// Create a new scorer
    pub fn new() -> Self {
        // Using http://norvig.com/mayzner.html
       
        EnglishAsciiScorer {
            bigram_ranking: [
                (String::from("TH"), 356),
                (String::from("HE"), 307),
                (String::from("IN"), 243),
                (String::from("ER"), 205),
                (String::from("AN"), 199),
                (String::from("RE"), 185),
                (String::from("ON"), 176),
                (String::from("AT"), 149),
                (String::from("EN"), 145),
                (String::from("ND"), 135),
                (String::from("TI"), 134),
                (String::from("ES"), 134),
                (String::from("OR"), 128),
                (String::from("TE"), 120),
                (String::from("OF"), 117),
                (String::from("ED"), 117),
                (String::from("IS"), 113),
                (String::from("IT"), 112),
                (String::from("AL"), 109),
                (String::from("AR"), 107),
                (String::from("ST"), 105),
                (String::from("TO"), 104),
                (String::from("NT"), 104),
                (String::from("NG"), 095),
                (String::from("SE"), 093),
                (String::from("HA"), 093),
                (String::from("AS"), 087),
                (String::from("OU"), 087),
                (String::from("IO"), 083),
                (String::from("LE"), 083),
                (String::from("VE"), 083),
                (String::from("CO"), 079),
                (String::from("ME"), 079),
                (String::from("DE"), 076),
                (String::from("HI"), 076),
                (String::from("RI"), 073),
                (String::from("RO"), 073),
                (String::from("IC"), 070),
                (String::from("NE"), 069),
                (String::from("EA"), 069),
                (String::from("RA"), 069),
                (String::from("CE"), 065),
                (String::from("LI"), 062),
                (String::from("CH"), 060),
                (String::from("LL"), 058),
                (String::from("BE"), 058),
                (String::from("MA"), 057),
                (String::from("SI"), 055),
                (String::from("OM"), 055),
                (String::from("UR"), 054),
            ].iter()
            .cloned()
            .collect(),

            letter_ranking: [
                (b' ',1300),
                (b'E',1249),
                (b'T', 928),
                (b'A', 804),
                (b'O', 764),
                (b'I', 757),
                (b'N', 723),
                (b'S', 651),
                (b'R', 628),
                (b'H', 505),
                (b'L', 407),
                (b'D', 382),
                (b'C', 334),
                (b'U', 273),
                (b'M', 251),
                (b'F', 240),
                (b'P', 214),
                (b'G', 187),
                (b'W', 168),
                (b'Y', 166),
                (b'B', 148),
                (b'V', 105),
                (b'K', 054),
                (b'X', 023),
                (b'J', 016),
                (b'Q', 012),
                (b'Z', 009),
                (b'.', 0),
                (b',', 0),
            ].iter()
            .cloned()
            .collect()
        }
    }

    /// Grade a sequence of bytes  
    /// The higher the grade, the more likely this sequence corresponds to an english ascii text
    /// 
    /// This grading is done using the approximate order of frequency of the 12 most commonly used 
    /// letters in the English language.
    pub fn score_ascii_text(&self, input: &[u8]) -> i32 {
        let mut sum = 0;

        for (bigram, score) in self.bigram_ranking.iter() {
            let bigram_bytes = bigram.as_bytes();

            let mut position = Some(0);

            while position != None {
                position = index_of(&input.to_ascii_uppercase(), bigram_bytes, position.unwrap() + 1);

                if position.is_some() {
                    sum += score
                }
            }

        }

        sum 
    }

    /// Score a single ascii byte based on the weights provided
    fn score_ascii_byte(&self, byte: &u8) -> i32 {
        let byte = byte.to_ascii_uppercase();

        // valid letter ~ reward
        if self.letter_ranking.contains_key(&byte) {
            self.letter_ranking[&byte]
        }
        else {
            -300
        }
    }
}

pub struct SingleByteXorDecodeResult {
    key: u8,
    result: Vec<u8>,
    score: i32
}

impl SingleByteXorDecodeResult {
    pub fn new(score: i32, key: u8, result: &[u8]) -> Self {
        SingleByteXorDecodeResult{ score, key,  result: result.to_vec() }
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

/// Finds the next occurence of `pattern` in `slice` after `start_index`
/// 
/// # Panics
/// 
/// Will panic if `pattern` is longer than `slice`
/// Will panic if `start_index` is not a valid index of `slice`
pub fn index_of(slice: &[u8], pattern: &[u8], start_index: usize) -> Option<usize> {
    if pattern.len() > slice.len() {
        panic!("error: pattern (len {}) is longer than slice (len {}", pattern.len(), slice.len());
    }

    if start_index >= slice.len() {
        panic!("error: start_index {} is not valid index into the slice of length {}", start_index, slice.len());
    }

    let mut slice_index = start_index;
    let mut pattern_index = 0;

    while slice_index < slice.len() {
        while slice[slice_index] == pattern[pattern_index] {
            // If we get to the end of the pattern, we have matched!
            if pattern_index == pattern.len() - 1 {
                // We found the pattern 
                return Some(slice_index - pattern_index);
            }

            // If we get to the end of the slice, we have not matched :/ 
            if slice_index == slice.len() - 1 {
                slice_index -= pattern_index;
                pattern_index = 0;

                break;
            }

            slice_index += 1;
            pattern_index += 1;
        }

        slice_index += 1;
    }

    None
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

        assert_eq!(1249, scorer.score_ascii_byte(&b'e'));
        assert_eq!(1249, scorer.score_ascii_byte(&b'E'));
       
        assert_eq!(9, scorer.score_ascii_byte(&b'z'));
        assert_eq!(9, scorer.score_ascii_byte(&b'Z'));

        assert!(scorer.score_ascii_byte(&b')') < 0);
    }

    #[test]
    pub fn test_index_of() {
        // Normal match
        assert_eq!(Some(1), challenge03::index_of(&[1,2,3,4,5,6], &[2,3,4], 0));

        // Match that almost gets to the end then fails
        assert_eq!(None, challenge03::index_of(&[1,2,3,4,2,4], &[2,3,4,5], 0));

        // Almost matches, the first time, then matches the second time.
        assert_eq!(Some(5), challenge03::index_of(&[1,2,3,4,1,3,4,5], &[3,4,5], 0));

        // Two matches, but we get the second because we specify a start index after the first
        assert_eq!(Some(6), challenge03::index_of(&[1,2,3,4,1,2,3,4], &[3,4], 4));


    }
}