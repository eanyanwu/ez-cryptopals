//! Break repeating-key XOR
//!
//! This one is actually reeeallly interesting and, dare I say it? FUN?
//! 
//! Disclaimer, since the challenge basically outlined the steps for solving this one, I did not feel 
//! it cheating to look up more about the repeating XOR cipher (also called the Vigenère cipher).
//! Doing so was helpful because it explained the reasoning behind the solution which i think is more fun than the solution itself.
//! 
//! The repeating XOR cipher was created as a response to the fact that the single character cipher (also called Caesar ciphers) could be 
//! broken by "frequency analysis". This is what we did earlier when we were "scoring" byte sequences. 
//! By using a repeating XOR pattern, the cipher text counterpart of a plain text character won't show up with the same frequency (if that makes sense)
//! 
//! HOWEVER. The weakness of the repeating XOR cipher is in its repeating nature. If an attacker (me) guesses the key length, they can treat the cipher
//! as "interwoven" Caesar ciphers, which can be broken individually individually using frequency analysis
//! 
//! The hard part is guessing the key. The challenge suggests that we can do so by comparing the edit distance between 2 KEYSIZE_GUESS blocks. The guess 
//! with the lowest disstance is probably the key. This _kinda_ makes sense in a vague sort of way. If two blocks were XORed by the same key, their edit
//! distance would be lower than if the were not? It's not intuitive, but I _could_ see how that is the case...maybe


use crate::set01::challenge02;

/// Compute the edit distance between to sequence of bytes
/// 
/// Key realization! If you XOR two bits together
/// You get "1" if they are different and "0" if they are the same
/// 
/// So with that piece of knowledge, we can first XOR the two sequences together
/// Then count the number of 1 bits we get in the result
/// 
/// For counting the number of bits, we loop through each byte in the XORed result
/// For each byte, we use a bit mask to get the bit on the far-right side. We add that to the
/// current running count of our edit distance then shift right.
pub fn edit_distance(lhs: &[u8], rhs: &[u8]) -> u32 {
    let xor_result = challenge02::xor_bytes(lhs, rhs);

    let mut edit_distance = 0;

    // For each byte  in the result, count the number of bits that are set
    for mut byte in xor_result {
        for _ in 0..8 {
            edit_distance += (byte & 0b0000_0001) as u32;
            byte = byte >> 1;
        }
    }

    edit_distance
}


/// Break repeating-key XOR
#[cfg(test)]
pub mod test {
    use crate::set01::challenge06;

    /// Solution to the challenge (see source)
    pub fn break_repeating_key_xor() {
    }

    #[test]
    pub fn test_break_repeating_key_xor() {
        break_repeating_key_xor();
    }

    #[test]
    fn test_edit_distance() {
        assert_eq!(3, challenge06::edit_distance(&[0b1101_0011], &[0b0111_0010]));
        assert_eq!(37, challenge06::edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
    }
}