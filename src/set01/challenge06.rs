//! # Break repeating-key XOR
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
//! 
//! Note: Turns out the challenge was a bit misleading about how many KEYSIZE chunks you might need to use to take a good guess at the key
//! 2 and 4 are not enough ~ go higher!


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

/// Count off each byte up to `count` in a repeating manner then split bytes with the s
pub fn count_off_and_partition(count: u32, bytes: &[u8]) -> Vec<Vec<u8>> {
    if count == 0 {
        panic!("error: invalid count. must be greater than zero");
    }
    // If the count is 1, no splitting apart happens, all the bytes stay in the same vector
    else if count == 1 {
        vec![bytes.to_vec()]
    }
    else {
        let mut result = vec![vec![]; count as usize];
        for (index, value) in bytes.iter().cloned().enumerate() {
            let vector_index = index % count as usize;
            result[vector_index].push(value);
        }

        result
    }
}


/// Break repeating-key XOR
#[cfg(test)]
pub mod test {
    use std::fs;
    use std::path;

    use crate::radix;
    use crate::set01::challenge02;
    use crate::set01::challenge03;
    use crate::set01::challenge05;
    use crate::set01::challenge06;

    /// Solution to the challenge (see source)
    pub fn break_repeating_key_xor() {
        let contents = fs::read_to_string(
            path::PathBuf::from(
                "./src/set01/input/_break_repeating_key_xor.txt")
            )
            .expect("could not open the file");

        // Get rid of the new lines
        let contents = contents.replace("\r\n", "");
        let contents = contents.replace("\n", "");

        let bytes = radix::base64_to_bytes(&contents);

        // 1st Step: Try to make a guess as to what the key size might be
        let min_keysize: u32 = 2;
        let max_keysize: u32 = 40;

        let mut edit_distance_map = vec![(0,0); max_keysize as usize - min_keysize as usize + 1];
        
        for keysize in min_keysize..=max_keysize {
            // The wording of the challenge is prettty misleaing,
            // I ended up using the averaging technique (which seemed suggested as an afterthought)
            // and also averaging across more than 4 blocks to get a better guess
            let mut edit_distances = Vec::new();

            let chunks_start: u32 = 0;
            let chunks_end: u32 = 10;

            for i in chunks_start..chunks_end {
                let first_chunk_start = (i * keysize) as usize;
                let first_chunk_end = ((i + 1) * keysize) as usize;
                let second_chunk_start = ((i + 1) * keysize) as usize;
                let second_chunk_end = ((i + 2) * keysize) as usize;

                let first_chunk = &bytes[first_chunk_start..first_chunk_end];
                let second_chunk = &bytes[second_chunk_start..second_chunk_end];

                edit_distances.push(challenge06::edit_distance(first_chunk, second_chunk));
            }

            let sum_edit_distances: u32 = edit_distances.iter().sum();

            // Multiplying the edit distance by a 1000 in order to avoid figuring out floating-point math
            // This should be ok as I don't need the exact numbers, only the relative ordering.
            let average_edit_distance = sum_edit_distances * 1000 / chunks_end / keysize;

            edit_distance_map[keysize as usize - min_keysize as usize] = (average_edit_distance, keysize);
        }
        
        edit_distance_map.sort_by(|p1, p2| p1.0.cmp(&p2.0));

        // 2nd step: Break the repeating key xor.
        // One way to do this is to take our keysize guess and use it to break up the cipher text
        // into chunks that would have been encrypted by the same byte
        let mut potential_plain_text = Vec::new();

        for key_size_guess in edit_distance_map.into_iter().take(3) {
            let keysize = key_size_guess.1;

            let transposed_input = challenge06::count_off_and_partition(keysize, &bytes);
            
            let mut key = Vec::new();
            for i in 0..keysize {
                let guess = challenge03::decode_single_byte_xor(&transposed_input[i as usize]).remove(0);
                key.push(guess.get_key());
            }

            let repeating_key = challenge05::repeat(&key, bytes.len());
            let result = challenge02::xor_bytes(&bytes, &repeating_key);

            match String::from_utf8(result) {
                Ok(t) => potential_plain_text.push(t),
                Err(_) => potential_plain_text.push(String::from("not valid utf8")),
            }
        }

        assert!(
            potential_plain_text.iter()
                                .any(|text| { 
                                    text.contains("I'm back and I'm ringin' the bell")
                                })
        );

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

    #[test]
    fn test_count_off_and_partition() {
        assert_eq!(
            vec![vec![1,2,3]],
            challenge06::count_off_and_partition(1, &vec![1,2,3])
        );

        assert_eq!(
            vec![vec![1,3,5], vec![2,4]],
            challenge06::count_off_and_partition(2, &vec![1,2,3,4,5])
        );

        assert_eq!(
            vec![vec![1,4,7], vec![2,5,8], vec![3,6,9]],
            challenge06::count_off_and_partition(3, &vec![1,2,3,4,5,6,7,8,9])
        );
    }
}