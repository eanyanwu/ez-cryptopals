//! Byte-at-a-time ECB decryption (Simple)
//!
//! Toughest one yet x.x  
//! The mantra for figuring this one is "Guessing at a block size boundary"  
//! The two key ideas are (a) aes in ecb mode produces identical ciphertex
//! given the same plain text and (b) iterating through all the values of a
//! single byte is easy.  
//! 
//! We start by creating a buffer full of characters we come up with. For 
//! simplicity, my buffer has only the character A. 
//! 
//! Next we create 256 buffers that are identical to our original buffer
//! except for the last byte. Feed all those plain texts into
//! the oracle and record what the result is for each one.
//! 
//! Next, we drop the last byte from our original buffer and feed that into the
//! oracle. The result will be equal to one of the cipher texts we generated
//! earlier by try the 256 plain texts. Additionally, the last byte of the 
//! corresponding plain text will be the first byte of the message.
//! 
//! It does feel like this is a made up excercise. However I could see how the
//! technique of "pulling" out a hidden message byte-by-byte could be helpful.
//! 

use crate::radix;
use crate::aes128;

pub fn cipher_text_oracle(key: &[u8; 16], msg: &[u8]) -> Vec<u8> 
{
    // secret message we have to append to the string
    let secret = "\
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
    YnkK";

    let mut secret_bytes = radix::base64_to_bytes(secret);

    let mut padded_msg = Vec::new();
    padded_msg.append(&mut msg.to_vec());
    padded_msg.append(&mut secret_bytes);

    aes128::ecb_encrypt(&key, &padded_msg)
}

/// The process is as follows:
/// 
/// - Start with a plain text that is one-character long
/// - Record the length of the ciphertext we get for that plain text
/// - Repeatedly increase the size of the plain text by one, encrypt and compare
/// the result to the original length
/// - Do this until the length of the current cipher text is different from
/// that of the original. The difference will be the block size.
/// 
/// Disclaimer: I previously used a different (and less precise) technique to
/// detect the block size. However, after I solved this challenge, I could not
/// help but check online for other solutions and found this much better one.
pub fn detect_cipher_block_size() -> usize {
    let key = [0; 16];
    let mut plain_text = vec![b'A'];
    let original_length = cipher_text_oracle(&key, &plain_text).len();
    let mut current_length = original_length;

    while current_length == original_length {
        plain_text.push(b'A');
        current_length = cipher_text_oracle(&key, &plain_text).len();
    }


    current_length - original_length
}

#[cfg(test)]
pub mod test {
    use crate::aes128;
    use crate::set02::challenge11;
    use crate::set02::challenge12;

    use std::collections::HashMap;

    /// Solution to the challenge (see soource)
    pub fn byte_at_a_time_ecb_decryption() {
        let random_key = b"0123456789abcdef";
        
        // First discover the block size
        let block_size = challenge12::detect_cipher_block_size();

        // we should have found a block size of 16
        assert_eq!(16, block_size);

        // Detect that the oracle is using ECB mode
        let mode = challenge11::detect_cipher_mode(
            &challenge12::cipher_text_oracle(
                random_key,
                &vec![b'A'; block_size * 2]
        ));

        assert_eq!(aes128::CipherMode::ECB, mode);

        // At this point, we have confirmed the oracle is indeed using AES ECB
        // encryption, and we know the block size.
        // Now for the magic trick..

        let mut secret_message = Vec::new();

        // I arrived at this number by trial-and-error.
        // Nothing scholarly
        let shifting_buffer_len = block_size * 8;

        for x in 1..=shifting_buffer_len {
            let mut brute_force_table = HashMap::new();
            let shifted_input_len = shifting_buffer_len - x;
            let mut shifted_input = Vec::new();
            
            for _ in 0..shifted_input_len {
                shifted_input.push(b'A');
            }

            print!("{} ", shifted_input_len);
            
            // Prepare the brute-force table
            for i in 0..=255 {
                let mut curr = shifted_input.clone();

                // Add the bytes of the secret message we know of
                curr.append(&mut secret_message.clone());

                // For my own sanity
                assert_eq!(curr.len(), shifting_buffer_len - 1);

                curr.push(i);
                
                let mut oracle_result = challenge12::cipher_text_oracle(
                    random_key,
                    &curr
                );

                oracle_result.split_off(shifting_buffer_len);

                brute_force_table.insert(
                    oracle_result,
                    curr
                );
            }

            // Ask the oracle for the encryption of our shifted input
            let mut oracle_result = challenge12::cipher_text_oracle(
                random_key,
                &shifted_input
            );

            oracle_result.split_off(shifting_buffer_len);

            let mut plain_text = brute_force_table.remove(&oracle_result)
                                                    .unwrap();
            secret_message.push(plain_text.pop().unwrap());
        }
        
        assert_eq!(
            "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just",
            std::str::from_utf8(&secret_message).unwrap()
        );
    }

    #[test]
    pub fn test_byte_at_a_time_ecb_decryption() {
        byte_at_a_time_ecb_decryption(); 
    }

    pub fn test_detect_cipher_block_size() {
        assert_eq!(16, challenge12::detect_cipher_block_size());
    }
}
