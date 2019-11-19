//! # Convert hex to base64
//! 
//! Hexadecimal (a.k.a Base16): a system for representing binary numbers as characters 0-9 and a-f  
//! Base64: A system for representing binary numbers as printable characters (you can think of it as more compact than Base16)
//! Both are ways of representing numbers. So the conversion involves two steps:  
//! (a) Converting a hexadecimal text to its binary number representation  
//! (b) Converting the binary number to its Base64 representation.
//! 
//! Update: I finally realized that hexadecimal is also called base16
//! Everything makes sense now. I was having serious problems understanding how base64 and hexadecimal printing were conceptually different.
//! Turns out they are not! Base64 just has more characters to use than Base16 (hence the numbers 16 and 64 in the name!)
//! So in the challenges that follow, hexadecimal and base16 are used interchangeably


pub const START_ASCII_DIGIT: u8 = 48;
pub const START_ASCII_UPALPHA: u8 = 65;
pub const START_ASCII_LOALPHA: u8 = 97;

const START_BASE64_UPALPHA: u8 = 0;
const START_BASE64_LOALPHA: u8 = 26;
const START_BASE64_DIGIT: u8 = 52;

/// Convert a hexadecimal string (base16) to the sequence of binary numbers it represents
pub fn base16_to_bytes(hex_text: &str) -> Vec<u8> {
    let mut s = hex_text.to_string();

    // If the hexadecimal string is of an un-even length,
    // there is a leading 0 we should add
    // e.g. 0x123 is the same as 0x0123
    // This makes the rest of the process straightforward
    if s.len() % 2 != 0 {
        s.insert(0, '0');
    }

    // 1st pass: Convert each hex digit to a u8 
    let first_pass = s.as_bytes()
            .iter()
            .map(base16_to_tetrad)
            .collect::<Box<[u8]>>();


    // 2nd pass: Smash up each two consecutive u8 into one
    first_pass.as_ref()
                .chunks(2)
                .map(|chunk| chunk[0] << 4 | chunk[1])
                .collect::<Vec<u8>>()
}

/// Convert a sequence of binary numbers to a Base64 representation
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let base64_ascii_characters = bytes.chunks(3)
            .flat_map(|bytes| {
                if bytes.len() == 3 {
                    // bit manipulation to extract 4 6-bit numbers
                    // out of 3 8-bit numbers
                    let first_sextet = bytes[0] >> 2;
                    let second_sextet = ((bytes[0] & 0b0000_0011) << 4) | ((bytes[1] & 0b1111_0000) >> 4);
                    let third_sextet = ((bytes[1] & 0b0000_1111) << 2) | ((bytes[2] & 0b1100_0000) >> 6);
                    let fourth_sextet = bytes[2] & 0b0011_1111;

                    vec![
                        byte_to_base64(&first_sextet),
                        byte_to_base64(&second_sextet),
                        byte_to_base64(&third_sextet),
                        byte_to_base64(&fourth_sextet)
                    ]
                }
                else if bytes.len() == 2 {
                    // bit manipulation to extract 3 6-bit numbers
                    // out of 2 8-bit numbers (with padding)
                    let first_sextet = bytes[0] >> 2;
                    let second_sextet = ((bytes[0] & 0b0000_0011) << 4) | ((bytes[1] & 0b1111_0000) >> 4);
                    let third_sextet = (bytes[1] & 0b0000_1111) << 2;

                    vec![
                        byte_to_base64(&first_sextet),
                        byte_to_base64(&second_sextet),
                        byte_to_base64(&third_sextet),
                        b'=',
                    ]
                }
                else {
                    // bit manipulation to extract 2 6-bit numbers
                    // out of 1 8-bit numbers (with padding)
                    let first_sextet = bytes[0] >> 2;
                    let second_sextet = (bytes[0] & 0b0000_0011) << 4;

                    vec![
                        byte_to_base64(&first_sextet),
                        byte_to_base64(&second_sextet),
                        b'=',
                        b'=',
                    ]
                }
            })
            .collect::<Vec<u8>>();

    // If the `unwrap` panics, that would be programmer (me) error
    String::from_utf8(base64_ascii_characters).unwrap()
}

/// Convert a single hexadecimal character into the binary tetrad (4-bits) number it stands for
/// The input is a `u8` because a hexadecimal character is valid ascii, which
/// can be represented in a byte
fn base16_to_tetrad(base16_char: &u8) -> u8 {
    // Here, we could have manually mapped every single ascii hex character to its number
    // like so b'0' -> b'0', b'1' -> 1 ... b'a' -> 10
    // That would make for a lengthy method.
    // An alternative is to use the fact that the ascii represetation of text encodes
    // the digit characters and alphabet characters in sequence.
    
    match base16_char {
        // Range of ascii hexadecimal "digit" characters
        48..=57 => base16_char - START_ASCII_DIGIT,

        // Range of ascii hexadecimal "alphabet" characters
        65..=70 => base16_char - START_ASCII_UPALPHA + 10, // lowercase
        97..=102 => base16_char - START_ASCII_LOALPHA + 10, // uppercase

        // Huh??
        _ => panic!("error: not a valid hexadecimal character"),
    }
}

/// Convert a number to its base64 representation  
/// Due to how the base64 system works, the number can only be 6-bits long  
/// The remaining two bits on the left must be set to zero.    
/// 
/// # Panics
/// 
/// Will panic if `num` uses more than 6 bits
fn byte_to_base64(num: &u8) -> u8 {
    match num {
        0..=25 => START_ASCII_UPALPHA + num - START_BASE64_UPALPHA,
        26..=51 => START_ASCII_LOALPHA + num - START_BASE64_LOALPHA,
        52..=61 => START_ASCII_DIGIT + num - START_BASE64_DIGIT,
        62 => 43, // Plus sign
        63 =>  47, // Forward slash
        _ => panic!("error: `num` is not a 6-bit number")
    }
}

/// Convert hex to base64
#[cfg(test)]
pub mod test {
    use crate::set01::challenge01;

    //// Solution to the challenge (see source)
    pub fn convert_hex_to_base64() {
        let hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base_64_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = challenge01::base16_to_bytes(hex_input);
        let actual_base64_output = challenge01::bytes_to_base64(&bytes);

        assert_eq!(expected_base_64_output, actual_base64_output);
    }

    #[test]
    pub fn test_convert_hex_to_base64() {
        convert_hex_to_base64();
    }

    #[test]
    fn test_base16_to_tetrad() {
        assert_eq!(0, challenge01::base16_to_tetrad(&b'0'));
        assert_eq!(9, challenge01::base16_to_tetrad(&b'9'));

        assert_eq!(10, challenge01::base16_to_tetrad(&b'a'));
        assert_eq!(10, challenge01::base16_to_tetrad(&b'A'));

        assert_eq!(15, challenge01::base16_to_tetrad(&b'f'));
        assert_eq!(15, challenge01::base16_to_tetrad(&b'F'));
    }

    #[test]
    fn test_base16_to_bytes()
    {
        assert_eq!(vec![0x01,0x23,0x45,0x67,0x89], challenge01::base16_to_bytes("0123456789"));
        assert_eq!(vec![0xab,0xcd,0xef], challenge01::base16_to_bytes("abcdef"));
        assert_eq!(vec![0x01, 0x23], challenge01::base16_to_bytes("123"));
    }

    #[test]
    fn test_byte_to_base64() {
        assert_eq!(b'A', challenge01::byte_to_base64(&0));
        assert_eq!(b'Z', challenge01::byte_to_base64(&25));

        assert_eq!(b'a', challenge01::byte_to_base64(&26));
        assert_eq!(b'z', challenge01::byte_to_base64(&51));

        assert_eq!(b'0', challenge01::byte_to_base64(&52));
        assert_eq!(b'9', challenge01::byte_to_base64(&61));

        assert_eq!(b'+', challenge01::byte_to_base64(&62));
        assert_eq!(b'/', challenge01::byte_to_base64(&63));
    }

    #[test]
    fn test_bytes_to_ascii_base64() {
        // Big thanks to wikipedia for these test cases :) 
        // https://en.wikipedia.org/wiki/Base64#Examples
        assert_eq!(String::from("TWFu"), challenge01::bytes_to_base64(&[b'M', b'a', b'n']));
        assert_eq!(String::from("TWE="), challenge01::bytes_to_base64(&[b'M', b'a']));
        assert_eq!(String::from("TQ=="), challenge01::bytes_to_base64(&[b'M']));
    }
}