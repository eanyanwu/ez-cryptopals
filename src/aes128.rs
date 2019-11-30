//! # Implementations of a few AES cipher modes
//!
//! From what I am understanding, block ciphers are only designed to provide
//! confidentiality for the block they encrypt.    
//! If I need to encrypt more than a block, which is often the case, I need to
//! layer an algorithm on top of the block cipher that determines how to 
//! construct the subsequent blocks in a hopefully still secure manner.  
//! This _layered_ algorithm is called the cipher's _mode of operation_
//! 
//! ## ECB
//! 
//! ECB is one such mode of operation. It stands for Electronic Code Book.
//! Calling it a "mode of operation" is actually not helpful. ECB just uses the 
//! AES algorithm to decrypt/encrypt for every block that is fed to it. Nothing 
//! fancy is done.
//! 
//! ## CBC
//! 
//! CBC is another mode of operation. It stands for Cipher Block Chaining.
//! Contrary to ECB, CBC actually does stuff to the input apart from feeding it
//! through the block cipher. More specifically, it XORs the previous block 
//! of cipher text with the current block of plain text, hence the "Chain" part
//! of its name



use openssl::{symm, rand};
use std::convert::TryFrom;

use crate::set01::challenge02;

pub const BLOCK_SIZE: usize = 16;


#[derive(Debug, PartialEq)]
pub enum CipherMode {
    ECB, CBC
}

//////////////////////
/* CIPHER MODE: CBC */
//////////////////////

/// Encrypt a message with AES in Cipher Block Chaining mode
pub fn cbc_encrypt(
    key: &[u8; BLOCK_SIZE],
    init_vector: &[u8; BLOCK_SIZE],
    msg: &[u8]) -> Vec<u8>
{
    // Since we only encrypt in blocks of 16, we need to ensure the message 
    // length is an integer multiple of BLOCK_SIZE.
    // The agreed way of doing this is using the PKCS#7 padding
    let mut msg = msg.to_vec();

    pkcs_pad(BLOCK_SIZE as u8, &mut msg);

    assert_eq!(0, msg.len() % BLOCK_SIZE);

    let mut cipher_text: Vec<[u8; 16]> = Vec::new();

    let mut prev_cipher_text = init_vector.clone();

    for block in (&msg[..]).chunks(BLOCK_SIZE) {
        // Create an 'intermediate block' that is the result of XORing the
        // previous encrypted block with the current plain-text block.
        // In the case of the first block, we use the initialization vector
        // as a a fake "previous encrypted block"
        let intermediate_block = challenge02::xor_bytes(
            &prev_cipher_text, 
            block);

        // encrypt the "intermediate block"
        let cipher_text_block = encrypt_block(
            key,
            &<[u8; 16]>::try_from(&intermediate_block[..]).unwrap()
        );

        // The current cipher text block will be XORed against the next plain
        // text block
        prev_cipher_text = cipher_text_block.clone();

        cipher_text.push(cipher_text_block);
    }

    cipher_text.iter()
                .flatten()
                .cloned()
                .collect::<Vec<u8>>()
}

/// Decrypt a message with AES in Cipher Block Chaining mode
pub fn cbc_decrypt(
    key: &[u8; 16],
    init_vector: &[u8; 16],
    msg: &[u8])
    -> Vec<u8>
{
    let mut plain_text: Vec<Vec<u8>> = Vec::new();

    let mut prev_cipher_text = init_vector.clone();

    for block in msg.chunks(BLOCK_SIZE) {
        let block = <[u8; 16]>::try_from(&block[..]).unwrap();

        // Decrypt!
        let intermediate_block = decrypt_block(
            key,
            &block
        );

        // Xor our intermediate block with the previous cipher text block
        let plain_text_block = challenge02::xor_bytes(
            &intermediate_block,
            &prev_cipher_text);
        
        // The current cipher text block becomes the previous one
        prev_cipher_text = block;

        plain_text.push(plain_text_block);
    }

    let mut plain_text = plain_text.into_iter()
                                    .flatten()
                                    .collect::<Vec<u8>>();

    // Remove padding that was added
    
    pkcs_unpad(BLOCK_SIZE as u8, &mut plain_text);

    plain_text    
}


//////////////////////
/* CIPHER MODE: ECB */
//////////////////////


/// Encrypt a message using the Electronic Code Book cipher mode
pub fn ecb_encrypt(
    key: &[u8; BLOCK_SIZE],
    msg: &[u8]) 
    -> Vec<u8>
{
    // Since we only encrypt in blocks of 16, we need to ensure the message 
    // length is an integer multiple of BLOCK_SIZE.
    // The agreed way of doing this is using the PKCS#7 padding
    let mut msg = msg.to_vec();

    pkcs_pad(BLOCK_SIZE as u8, &mut msg);

    assert_eq!(0, msg.len() % BLOCK_SIZE);

    // Now that i am are sure msg is an integer multiple of the block size,
    // encrypt!
    let mut cipher_text = Vec::new();

    for block in (&msg[..]).chunks(BLOCK_SIZE) {
        let block = <[u8; BLOCK_SIZE]>::try_from(
            block
        ).unwrap();

        let cipher_block = encrypt_block(
            key,
            &block
        );

        cipher_text.push(cipher_block);
    }

    cipher_text.iter()
                .flatten()
                .cloned()
                .collect::<Vec<u8>>()
}

/// Decrypt a message using the Electronic Code Book cipher mode
pub fn ecb_decrypt(
    key: &[u8; BLOCK_SIZE],
    msg: &[u8])
    -> Vec<u8>
{
    assert_eq!(0, msg.len() % BLOCK_SIZE);

    let mut plain_text = Vec::new();

    for block in msg.chunks(BLOCK_SIZE) {
        let block = <[u8; BLOCK_SIZE]>::try_from(
            block
        ).unwrap();

        let plain_block = decrypt_block(
            key,
            &block
        );

        plain_text.push(plain_block)
    }

    let mut plain_text = plain_text.iter()
                                .flatten()
                                .cloned()
                                .collect::<Vec<u8>>();

    // Unpad!
    pkcs_unpad(BLOCK_SIZE as u8, &mut plain_text);

    plain_text
}

///////////////////////
/* PADDING FUNCTIONS */
///////////////////////


/// Add padding to the input as ordained by PKCS#7
/// The input is padded to to a multiple of the block size
pub fn pkcs_pad(block_size: u8, input: &mut Vec<u8>) {
    let count = block_size - (input.len() % block_size as usize) as u8;

    let mut pad_bytes = vec![count; count as usize];

    input.append(&mut pad_bytes);
}

/// Remove any pkcs padding present in the input
pub fn pkcs_unpad(block_size: u8, input: &mut Vec<u8>) {
    // Assert that the input is an integer multiple of the block size
    assert_eq!(0, input.len() % block_size as usize);

    // Check the last byte
    let last_byte = input.last().unwrap().clone();

    // Make sure the last byte is between 0 and the block size
    assert!(last_byte > 0 && last_byte <= block_size);

    // The value of last byte will correspond to how many padding bytes we have
    input.split_off(input.len() - last_byte as usize);
}


///////////////////////////////////////////////////
/* FUNCTIONS THAT OPERATE ON AN INDIVIDUAL BLOCK */
///////////////////////////////////////////////////

/// Encrypt a single 16-byte block using the AES algorithm
/// 
/// I disable padding because the functions that call this function
/// will take care of it.
/// Since this is operating on single blocks, I enforce that the input
/// and output are exactly 16 bytes. 
pub fn encrypt_block(
    key: &[u8; BLOCK_SIZE],
    block: &[u8; BLOCK_SIZE])
    -> [u8; BLOCK_SIZE]
{
    let mut encrypter = symm::Crypter::new(
        symm::Cipher::aes_128_ecb(),
        symm::Mode::Encrypt,
        &key[..],
        None).unwrap();

    encrypter.pad(false);

    // openssl's API forces us to make the buffer at least 
    // `input.len() + block_size` long (i.e. 16 + 16)
    // The extra 16 bytes is to accomodate for ciphers where the output
    // might be longer than the input.
    // This will not be the case for the cipher modes I will implement here.
    // So I get rid of the extra 16 bytes (they will all be zero) later.
    let mut cipher_text_block = [0 as u8; BLOCK_SIZE * 2];

    // encrypt this block!
    encrypter.update(
        &block[..],
        &mut cipher_text_block[..]
    ).unwrap();

    encrypter.finalize(
        &mut cipher_text_block[..]
    ).unwrap();

    // For peace of mind, assert that the lower 16 bytes are all zero
    assert_eq!(
        &cipher_text_block[BLOCK_SIZE..BLOCK_SIZE * 2],
        &vec![0 as u8; BLOCK_SIZE][..]
    );

    <[u8; BLOCK_SIZE]>::try_from(&cipher_text_block[0..BLOCK_SIZE]).unwrap()
}

/// Decrypt a 16-byte block using the AES algorithm
pub fn decrypt_block(
    key: &[u8; BLOCK_SIZE],
    block: &[u8; BLOCK_SIZE])
    -> [u8; BLOCK_SIZE] 
{
    let mut decrypter = symm::Crypter::new(
        symm::Cipher::aes_128_ecb(),
        symm::Mode::Decrypt,
        &key[..],
        None).unwrap();

    decrypter.pad(false);

    let mut plain_text_block = [0 as u8; BLOCK_SIZE * 2];

    // decrypt!
    decrypter.update(
        &block[..],
        &mut plain_text_block[..]
    ).unwrap();

    decrypter.finalize(
        &mut plain_text_block[..]
    ).unwrap();

    // For peace of mind, assert that the lower 16 bytes are all zero
    assert_eq!(
        &plain_text_block[BLOCK_SIZE..BLOCK_SIZE * 2],
        &vec![0 as u8; BLOCK_SIZE][..]
    );

    <[u8; BLOCK_SIZE]>::try_from(&plain_text_block[0..BLOCK_SIZE]).unwrap()
}

/// Generate a random 128-bit AES key
pub fn get_random_key() -> [u8; 16] {
    let mut buffer = [0 as u8; 16];

    rand::rand_bytes(&mut buffer).unwrap();

    buffer
}


#[cfg(test)]
pub mod test {
    use crate::aes128;
    use crate::radix;

    #[test]
    pub fn test_cbc_encrypt_then_decrypt() {
        let input = b"YELLOW SUBMARINE";
        let key = b"YELLOW SUBMARINE";

        let cipher_text = aes128::cbc_encrypt(
            key,
            &[0; 16],
            input
        );

        // notice that because of padding, the cipher text is longer than the 
        // input
        assert_eq!(32, cipher_text.len());

        assert_eq!(
            "0apPZXiSZUL7tt2HbNIFCNyi2E9IlqAKtd7NEJ0c6pk=",
            radix::bytes_to_base64(
                &cipher_text[..]
            )
        );

        // Decrypt
        let plain_text = aes128::cbc_decrypt(
            key,
            &[0; 16],
            &cipher_text[..]
        );

        assert_eq!(
            "YELLOW SUBMARINE",
            std::str::from_utf8(&plain_text).unwrap()
        );
    }

    #[test]
    pub fn test_ecb_encrypt_then_decrypt() {
        let input = b"YELLOW SUBMARINE";
        let key = b"YELLOW SUBMARINE";

        let cipher_text = aes128::ecb_encrypt(
            key,
            input
        );

        // notice that because of padding, the cipher text is longer than the 
        // input
        assert_eq!(32, cipher_text.len());

        assert_eq!(
            "0apPZXiSZUL7tt2HbNIFCGD6NnB+RfSZ26DyW5IjAaU=",
            radix::bytes_to_base64(
                &cipher_text[..]
            )
        );

        // Decrypt
        let plain_text = aes128::ecb_decrypt(
            key,
            &cipher_text[..]
        );

        assert_eq!(
            "YELLOW SUBMARINE",
            std::str::from_utf8(&plain_text).unwrap()
        );
    }

    #[test]
    pub fn test_encrypt_then_decrypt_block() {
        let block = b"YELLOW SUBMARINE";
        let key = b"YELLOW SUBMARINE";

        let cipher_text = aes128::encrypt_block(
            key,
            block
        );

        assert_eq!(
            "0apPZXiSZUL7tt2HbNIFCA==",
            radix::bytes_to_base64(
                &cipher_text[..]
            )
        );

        let decrypt_result = aes128::decrypt_block(
            &key,
            &cipher_text
        );

        assert_eq!(
            block,
            &decrypt_result
        );
    }
    
    #[test]
    pub fn test_pad_unpad() {
        let mut text = b"YELLOW SUBMA".to_vec();

        aes128::pkcs_pad(
            aes128::BLOCK_SIZE as u8,
            &mut text
        );

        assert_eq!(
            b"YELLOW SUBMA\x04\x04\x04\x04".to_vec(),
            text
        );

        aes128::pkcs_unpad(
            aes128::BLOCK_SIZE as u8,
            &mut text
        );

        assert_eq!(
            b"YELLOW SUBMA".to_vec(),
            text
        );
    }
}