//! # An ECB/CBC detection oracle
//! 
//! I already know that I can detect ecb if there are repeated blocks. 
//! So i just need to give the oracle enough repeating plain text blocks 
//! to guarantee that there will be two identical blocks in the output if
//! ecb was indeed used.
//!
//! Note: I cheated a little bit here. After some time of thinking and not 
//! coming up with anything, I took a look at other solutions, which helped 
//! me understand that I had mis-understood the challenge.  
//! I didn't realize I could come up with my own plain-text here.  
//! I started the challenge thinking the point was to figure out what mode was
//! being used when I have not access to the plain text. I think the point is
//! actually to figure out how a given "encryptor" works from the outside. So
//! for example, given a service that encrypts your data, what things can I do
//! learn more about what encryption it is using.

use crate::aes128;

use openssl::rand;
use std::convert::TryFrom;

pub struct OracleResult {
    cipher_text: Vec<u8>,
    cipher_mode: aes128::CipherMode
}

/// Generate some cipher text, encrypted with an unknown key, using 
/// cipher mode specified
pub fn cipher_text_oracle(msg: &[u8]) -> OracleResult 
{
    let random_key = aes128::get_random_key();
    
    let mut buf1 = [0 as u8; 1];
    let mut buf2 = [0 as u8; 1];

    rand::rand_bytes(&mut buf1).unwrap();
    rand::rand_bytes(&mut buf2).unwrap();

    let prefix_count = (buf1[0] % 6) + 5;
    let suffix_count = (buf2[0] % 6) + 5;

    let mut prefix_buf = vec![0 as u8; prefix_count as usize];
    let mut suffix_buf = vec![0 as u8; suffix_count as usize];

    rand::rand_bytes(&mut prefix_buf).unwrap();
    rand::rand_bytes(&mut suffix_buf).unwrap();

    let mut padded_msg = Vec::new();
    padded_msg.append(&mut prefix_buf);
    padded_msg.append(&mut msg.to_vec());
    padded_msg.append(&mut suffix_buf);

    let mut buf = [0 as u8; 1];
    rand::rand_bytes(&mut buf).unwrap();

    let chance = buf[0] % 2;
    let mode;

    let result = if chance == 0 {
        mode = aes128::CipherMode::ECB;
        aes128::ecb_encrypt(&random_key, &padded_msg)
    }
    else {
        mode = aes128::CipherMode::CBC;
        let mut init_vector = [0 as u8; 16];
        rand::rand_bytes(&mut init_vector).unwrap();
        aes128::cbc_encrypt(&random_key, &init_vector, &padded_msg)
    };

    OracleResult { cipher_mode: mode, cipher_text: result }
}

/// Detect which AES mode was used to encrypt the cipher text
/// 
/// This assumes that the input text had enough repeating bytes
/// that would cause ECB mode to have two consecutive repeating blocks.
/// 
/// Note: I am bit lazy, and instead of checking for consecutive
/// identical blocks, 
/// i am just checking to see if the length after removing identical blocks
/// is the same as before. 
/// The assumption here is that the padding we add before and after does not 
/// ever equal all A's (it could, but it's a pretty low probability)
pub fn detect_cipher_mode(cipher_text: &[u8]) -> aes128::CipherMode {
    
    if any_identical_consecutive_blocks(16, cipher_text) {
        aes128::CipherMode::ECB
    }        
    else {
        aes128::CipherMode::CBC
    }
}

/// Returns `true` if there are any consecutive blocks of length `len` in the 
/// message
pub fn any_identical_consecutive_blocks(len: usize, msg: &[u8]) -> bool {
    let chunks = msg.chunks(len).collect::<Vec<&[u8]>>();

    let mut counter = 0;
    loop {
        if counter + 1 < chunks.len() {
            let curr_chunk = chunks[counter];
            let next_chunk = chunks[counter + 1];
            
            if curr_chunk == next_chunk {
                break true
            }
            else {
                counter += 1;
            }
        }
        else {
            break false
        }
    }
}


/// An ECB/CBC detection oracle
pub mod test {
    use crate::set02::challenge11;

    /// Solution to the challenge (see source)
    pub fn an_ecb_cbc_detection_oracle() {

        // If we used ECB mode, we would detect repeating blocks
        let plain_text = b"AAAAAAAAAAA\
        AAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAA";

        for _ in 0..100 {
            let oracle_result = challenge11::cipher_text_oracle(
                plain_text
            );

            assert_eq!(
                oracle_result.cipher_mode,
                challenge11::detect_cipher_mode(&oracle_result.cipher_text)
            );
        }
    }

    #[test]
    pub fn test_an_ecb_cbc_detection_oracle() {
        an_ecb_cbc_detection_oracle();
    }

    #[test]
    pub fn test_any_identical_consecutive_blocks() {
        let msg1 = b"0";
        let msg2 = b"00";
        let msg3 = b"0A0";

        let msg4 = b"abcd0A0Aefjg";
        let msg5 = b"0Abcd0A";
        
        // There is only one chunk of length 1
        assert!(
            !challenge11::any_identical_consecutive_blocks(1, msg1)
        );

        // There are two consecutive `0` characters
        assert!(
            challenge11::any_identical_consecutive_blocks(1, msg2)
        );

        // There are no consecutive identical characters
        assert!(
            !challenge11::any_identical_consecutive_blocks(1, msg3)
        );
        
        // The blocks `0A` `0A` appear together
        assert!(
            challenge11::any_identical_consecutive_blocks(2, msg4)
        );

        // No consecutive blocks of length 2
        assert!(
            !challenge11::any_identical_consecutive_blocks(2, msg5)
        );
    }
}
