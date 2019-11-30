//! An ECB/CBC detection oracle

use crate::aes128;
use openssl::rand;

/// Generate some cipher text, encrypted with an unknown key, using 
/// cipher mode specified
pub fn cipher_text_oracle(mode: aes128::CipherMode, msg: &[u8]) -> Vec<u8> {
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

    match mode {
        aes128::CipherMode::ECB => {
            aes128::ecb_encrypt(&random_key, &padded_msg)
        },
        aes128::CipherMode::CBC => {
            let mut init_vector = [0 as u8; 16];
            rand::rand_bytes(&mut init_vector).unwrap();
            aes128::cbc_encrypt(&random_key, &init_vector, &padded_msg)
        }
    }
}

pub fn detect_cipher_mode(cipher_text: &[u8]) -> aes128::CipherMode {
    aes128::CipherMode::CBC
}


/// An ECB/CBC detection oracle
pub mod test {
    use crate::aes128;
    use crate::set02::challenge11;

    /// Solution to the challenge (see source)
    pub fn an_ecb_cbc_detection_oracle() {
        let plain_text = "I double dare you to detect what AES mode I am in";

        // Make sure we can recognize random cbc
        for _ in 0..10 {
            let cbc_cipher_text = challenge11::cipher_text_oracle(
                aes128::CipherMode::CBC,
                plain_text.as_bytes()
            );

            assert_eq!(
                aes128::CipherMode::CBC,
                challenge11::detect_cipher_mode(&cbc_cipher_text)
            );
        }
       // Make sure we can recognize random ecb
        for _ in 0..10 {
            let ecb_cipher_text = challenge11::cipher_text_oracle(
                aes128::CipherMode::ECB,
                plain_text.as_bytes()
            );

            assert_eq!(
                aes128::CipherMode::ECB,
                challenge11::detect_cipher_mode(&ecb_cipher_text)
            );
        }
    }

    #[test]
    pub fn test_an_ecb_cbc_detection_oracle() {
        an_ecb_cbc_detection_oracle();
    }
}