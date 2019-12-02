//! Byte-at-a-time ECB decryption (Simple)
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

#[cfg(test)]
pub mod test {
    use crate::aes128;
    use crate::set02::challenge11;
    use crate::set02::challenge12;

    pub fn byte_at_a_time_ecb_decryption() {
        let random_key = b"0123456789abcdef";
        
        // First discover the block size
        let mut block_size = 0;

        // I'll try ~ 50 block sizes
        for i in 1..=50 {
            // For each block I'll create a message that _should_ result in a 
            // repeating block if my block size guess is correct
            let my_msg = vec![b'A'; i * 2];

            let cipher_text = challenge12::cipher_text_oracle(
                random_key,
                &my_msg
            );

            if challenge11::any_identical_consecutive_blocks(i, &cipher_text) 
            {
                block_size = i;
                break;
            }
        }

        // we should have found a block size of 16
        assert_eq!(16, block_size);

        // Detect that the oracle is using ECB mode
        let msg = vec![b'A'; block_size * 2];
        let cipher_text = challenge12::cipher_text_oracle(
            random_key,
            &msg
        );

        let mode = challenge11::detect_cipher_mode(&cipher_text);

        assert_eq!(aes128::CipherMode::ECB, mode);
    }

    #[test]
    pub fn test_byte_at_a_time_ecb_decryption() {
        byte_at_a_time_ecb_decryption(); 
    }
}
