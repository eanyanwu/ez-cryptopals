//! # Fixed XOR
//! 
//! The "XOR" operator! It's symbol is: ^
//! Here are the rules:  
//! 0 ^ 0 = 0
//! 0 ^ 1 = 1 
//! 1 ^ 0 = 1
//! 1 ^ 1 = 0
//! In english: At least one of the sides must be the 1 bit  
//! The inputs to this chellenge are two hexadecimal ascii strings.  
//! So before we can do the XOR, we need to convert both to actual sequence of bytes.  
//! Luckly, we have done this in the previous challenge!


use crate::set01::challenge01;

/// Xor to sequences of bytes together  
/// 
/// Panics
/// 
/// Will panic if the slices are not of the same length
pub fn xor_bytes(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len(), "error: both slices must be of same length");

    let mut result = Vec::new();

    for i in 0..lhs.len() {
        result.push(lhs[i] ^ rhs[i]);
    }

    result
}

/// Convert a sequence of bytes into a string containing
/// the ascii hexadecimal representation of said bytes.
fn bytes_to_ascii_hex(bytes: &[u8]) -> String {
    // We loop through the bytes.
    // For each byte, we seperate into two tetrads (a tetrad is 4 bits the same way an octet is 8 bits)
    // We convert each tetrad into its ascii hexadecimal character

    let ascii_bytes = bytes.iter()
                            .flat_map(|byte| vec![(byte & 0b1111_0000) >> 4, byte & 0b0000_1111])
                            .map(|tetrad| tetrad_to_ascii_hex(&tetrad))
                            .collect::<Vec<u8>>();

    String::from_utf8(ascii_bytes).unwrap()
}

/// Convert a tetrad (4-bits)  number into the single hexadecimal character
fn tetrad_to_ascii_hex(byte: &u8) -> u8 {
    match byte {
        0..=9 => challenge01::START_ASCII_DIGIT + byte,
        10..=15 => challenge01::START_ASCII_LOALPHA + byte - 10,
        _ => panic!("error: {} is not a valid value that can be represented by one hexadecimal character", byte),
    }
}

/// Fixed XOR
pub mod test {
    use crate::set01::challenge01;
    use crate::set01::challenge02;

    /// Solution to the challenge
    pub fn fixed_xor() {
        let left_hand_side = "1c0111001f010100061a024b53535009181c";
        let right_hand_side = "686974207468652062756c6c277320657965";

        let expected_result = "746865206b696420646f6e277420706c6179";

        let lhs_bytes = challenge01::ascii_hex_to_bytes(left_hand_side);
        let rhs_bytes = challenge01::ascii_hex_to_bytes(right_hand_side);

        let xored_bytes = challenge02::xor_bytes(&lhs_bytes, &rhs_bytes);
        
        assert_eq!(expected_result, challenge02::bytes_to_ascii_hex(&xored_bytes));

    }

    #[test]
    pub fn test_fixed_xor() {
        fixed_xor();
    }

    #[test]
    fn test_xor_bytes() {
        assert_eq!(vec![0], challenge02::xor_bytes(&[0], &[0]));
        assert_eq!(vec![1], challenge02::xor_bytes(&[1], &[0]));
        assert_eq!(vec![1], challenge02::xor_bytes(&[0], &[1]));
        assert_eq!(vec![0], challenge02::xor_bytes(&[1], &[1]));
    }

    #[test]
    fn test_bytes_to_ascii_hex() {
        assert_eq!(
            "0123456789abcdef", 
            challenge02::bytes_to_ascii_hex(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        );
    }
    #[test]
    fn test_tetrad_to_ascii_hex() {
        assert_eq!(b'0', challenge02::tetrad_to_ascii_hex(&0));
        assert_eq!(b'9', challenge02::tetrad_to_ascii_hex(&9));
        assert_eq!(b'a', challenge02::tetrad_to_ascii_hex(&10));
        assert_eq!(b'f', challenge02::tetrad_to_ascii_hex(&15));
    }
}