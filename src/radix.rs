//! Radix Conversions
//! 
//! After getting to a point in the cryptopals challenges, one realizes these are used very frequently
//! So I have gathered them all in this here module for ease of use/organization

pub const START_ASCII_DIGIT: u8 = 48;
pub const END_ASCII_DIGIT: u8 = START_ASCII_DIGIT + 9;
pub const START_ASCII_UPALPHA: u8 = 65;
pub const END_ASCII_UPALPHA: u8 = START_ASCII_UPALPHA + 25;
pub const START_ASCII_LOALPHA: u8 = 97;
pub const END_ASCII_LOALPHA: u8 = START_ASCII_LOALPHA + 25;

const START_BASE64_UPALPHA: u8 = 0;
const START_BASE64_LOALPHA: u8 = 26;
const START_BASE64_DIGIT: u8 = 52;

/// Convert a base16 to the sequence of binary numbers it represents
pub fn base16_to_bytes(base16_str: &str) -> Vec<u8> {
    let mut s = base16_str.to_string();

    // If the base16 string is of an un-even length,
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

/// Convert a base64 string to the sequence of binary numbers it represents 
pub fn base64_to_bytes(base64_str: &str) -> Vec<u8> {
    // Base64 strings seem to always be in multiples of 4 sextets because of padding. Nice
    // We can use that to make the conversion easier

    if base64_str.len() % 4 != 0 {
        panic!("error: invalid the base64 string - length is not a multiple of 4. Length: {}", base64_str.len());
    }

    base64_str.as_bytes()
                .iter()
                .map(base64_to_sextet)
                .collect::<Box<[Option<u8>]>>()
                .chunks(4)
                .flat_map(|bytes| {
                    // 2 padding characters -> we are decoding into 1 bytes
                    if bytes[0].is_some() && bytes[1].is_some() && bytes[2].is_none()  && bytes[3].is_none() {
                        let first_byte = (bytes[0].unwrap() << 2) | ((bytes[1].unwrap() & 0b0011_0000) >> 4);

                        vec![
                            first_byte
                        ]
                    }
                    // 1 padding character -> we are decoding into 2 bytes
                    else if bytes[0].is_some() && bytes[1].is_some() && bytes[2].is_some()  && bytes[3].is_none() {
                        let first_byte = (bytes[0].unwrap() << 2) | ((bytes[1].unwrap() & 0b0011_0000) >> 4);
                        let second_byte = ((bytes[1].unwrap() & 0b0000_1111) << 4) | ((bytes[2].unwrap() & 0b0011_1100) >> 2);

                        vec![
                            first_byte,
                            second_byte
                        ]
                    }
                    // no padding -> we are decoding into 3 bytes
                    else if bytes[0].is_some() && bytes[1].is_some() && bytes[2].is_some()  && bytes[3].is_some() {
                        let first_byte = (bytes[0].unwrap() << 2) | ((bytes[1].unwrap() & 0b0011_0000) >> 4);
                        let second_byte = ((bytes[1].unwrap() & 0b0000_1111) << 4) | ((bytes[2].unwrap() & 0b0011_1100) >> 2);
                        let third_byte = ((bytes[2].unwrap() & 0b0000_0011) << 6) | bytes[3].unwrap();

                        vec![
                            first_byte,
                            second_byte,
                            third_byte
                        ]
                    }
                    else {
                        panic!("error: invalid base64 string. make sure there are no rogue padding characters");
                    }
                })
                .collect::<Vec<u8>>()
}


/// Convert a sequence of binary numbers to a Base16 representation
pub fn bytes_to_base16(bytes: &[u8]) -> String {
    // We loop through the bytes.
    // For each byte, we seperate into two tetrads (a tetrad is 4 bits the same way an octet is 8 bits)
    // We convert each tetrad into its ascii hexadecimal character

    let ascii_bytes = bytes.iter()
                            .flat_map(|byte| vec![(byte & 0b1111_0000) >> 4, byte & 0b0000_1111])
                            .map(|tetrad| tetrad_to_base16(&tetrad))
                            .collect::<Vec<u8>>();

    String::from_utf8(ascii_bytes).unwrap()
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
                        sextet_to_base64(&first_sextet),
                        sextet_to_base64(&second_sextet),
                        sextet_to_base64(&third_sextet),
                        sextet_to_base64(&fourth_sextet)
                    ]
                }
                else if bytes.len() == 2 {
                    // bit manipulation to extract 3 6-bit numbers
                    // out of 2 8-bit numbers (with padding)
                    let first_sextet = bytes[0] >> 2;
                    let second_sextet = ((bytes[0] & 0b0000_0011) << 4) | ((bytes[1] & 0b1111_0000) >> 4);
                    let third_sextet = (bytes[1] & 0b0000_1111) << 2;

                    vec![
                        sextet_to_base64(&first_sextet),
                        sextet_to_base64(&second_sextet),
                        sextet_to_base64(&third_sextet),
                        b'=',
                    ]
                }
                else {
                    // bit manipulation to extract 2 6-bit numbers
                    // out of 1 8-bit numbers (with padding)
                    let first_sextet = bytes[0] >> 2;
                    let second_sextet = (bytes[0] & 0b0000_0011) << 4;

                    vec![
                        sextet_to_base64(&first_sextet),
                        sextet_to_base64(&second_sextet),
                        b'=',
                        b'=',
                    ]
                }
            })
            .collect::<Vec<u8>>();

    // If the `unwrap` panics, that would be programmer (me) error
    String::from_utf8(base64_ascii_characters).unwrap()
}


/// Convert a single base16 character into the tetrad (4-bits) number it stands for
/// 
/// # Panics
/// 
/// Will panic if `base16_char` is not a valid hexadecimal character
fn base16_to_tetrad(base16_char: &u8) -> u8 {
    // Here, we could have manually mapped every single ascii hex character to its number
    // like so b'0' -> b'0', b'1' -> 1 ... b'a' -> 10
    // That would make for a lengthy method.
    // An alternative is to use the fact that the ascii represetation of text encodes
    // the digit characters and alphabet characters in sequence.
    
    match base16_char {
        // Range of ascii "digit" characters
        START_ASCII_DIGIT..=END_ASCII_DIGIT => base16_char - START_ASCII_DIGIT,

        // Range of ascii hexadecimal "alphabet" characters
        START_ASCII_UPALPHA..=70 => base16_char - START_ASCII_UPALPHA + 10, // lowercase
        START_ASCII_LOALPHA..=102 => base16_char - START_ASCII_LOALPHA + 10, // uppercase

        // Huh??
        _ => panic!("error: `base16_char` not a valid base16 character: {}", base16_char),
    }
}

/// Convert a tetrad (4-bits)  number into the single hexadecimal character
/// 
/// # Panics
/// 
/// Will panic if `num` is more than 4 bits
fn tetrad_to_base16(num: &u8) -> u8 {
    match num {
        0..=9 => START_ASCII_DIGIT + num,
        10..=15 => START_ASCII_LOALPHA + num - 10,
        _ => panic!("error: `num` is not a 4-bit number: {}", num),
    }
}

/// Converts a single base64 character into the sextet (6-bits) number it stands for
/// A base64 character can be can be a padding character (i.e. "="), which does not actually represent anything  
/// So the method returns an Option::None in such situations
/// # Panics 
/// 
/// Will panic if `base64_char` is not a valid base64 character
fn base64_to_sextet(base64_char: &u8) -> Option<u8> {
    match base64_char {
        START_ASCII_DIGIT..=END_ASCII_DIGIT => Some(base64_char - START_ASCII_DIGIT + START_BASE64_DIGIT),

        START_ASCII_UPALPHA..=END_ASCII_UPALPHA => Some(base64_char - START_ASCII_UPALPHA + START_BASE64_UPALPHA),
        START_ASCII_LOALPHA..=END_ASCII_LOALPHA => Some(base64_char - START_ASCII_LOALPHA + START_BASE64_LOALPHA),
        43 => Some(62), // Plus Sign,
        47 => Some(63), // Forward slash
        61 => None, // base64 strings will have a padding character which will be disposed off when decoding. 
        _ => panic!("error: `base64_char` is not a valid base64 character: {}", base64_char),
    }
}

/// Convert a number to its base64 representation  
/// Due to how the base64 system works, the number can only be 6-bits long  
/// The remaining two bits on the left must be set to zero.    
/// 
/// # Panics
/// 
/// Will panic if `num` uses more than 6 bits
fn sextet_to_base64(num: &u8) -> u8 {
    match num {
        0..=25 => START_ASCII_UPALPHA + num - START_BASE64_UPALPHA,
        26..=51 => START_ASCII_LOALPHA + num - START_BASE64_LOALPHA,
        52..=61 => START_ASCII_DIGIT + num - START_BASE64_DIGIT,
        62 => 43, // Plus sign
        63 =>  47, // Forward slash
        _ => panic!("error: `num` is not a 6-bit number: {}", num)
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::radix;

    #[test]
    fn test_base16_to_bytes()
    {
        assert_eq!(vec![0x01,0x23,0x45,0x67,0x89], radix::base16_to_bytes("0123456789"));
        assert_eq!(vec![0xab,0xcd,0xef], radix::base16_to_bytes("abcdef"));
        assert_eq!(vec![0x01, 0x23], radix::base16_to_bytes("123"));
    }

    /// Test! Test! Test
    /// I did not test this method enough and it cost me days of trying to track down what was going wrong
    /// with the decryption upstream
    #[test]
    fn test_base64_to_bytes() {
        assert_eq!(b"Man".to_vec(), radix::base64_to_bytes("TWFu"));
        assert_eq!(b"Ma".to_vec(), radix::base64_to_bytes("TWE="));
        assert_eq!(b"M".to_vec(), radix::base64_to_bytes("TQ=="));
    
        assert_eq!(
            b"Without padding".to_vec(),
            radix::base64_to_bytes("V2l0aG91dCBwYWRkaW5n")
        );
        
        assert_eq!(
            b"With one padding!".to_vec(), 
            radix::base64_to_bytes("V2l0aCBvbmUgcGFkZGluZyE=")
        );

        assert_eq!(
            b"With two paddings padding!!!".to_vec(),
            radix::base64_to_bytes("V2l0aCB0d28gcGFkZGluZ3MgcGFkZGluZyEhIQ==")
        );
    }

    #[test]
    fn test_bytes_to_base16() {
        assert_eq!(
            "0123456789abcdef", 
            radix::bytes_to_base16(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        );
    }

    #[test]
    fn test_bytes_to_base64() {
        // Big thanks to wikipedia for these test cases :) 
        // https://en.wikipedia.org/wiki/Base64#Examples
        assert_eq!("TWFu", radix::bytes_to_base64(&[b'M', b'a', b'n']));
        assert_eq!("TWE=", radix::bytes_to_base64(&[b'M', b'a']));
        assert_eq!("TQ==", radix::bytes_to_base64(&[b'M']));
    }

    #[test]
    fn test_tetrad_to_base16() {
        assert_eq!(b'0', radix::tetrad_to_base16(&0));
        assert_eq!(b'9', radix::tetrad_to_base16(&9));
        assert_eq!(b'a', radix::tetrad_to_base16(&10));
        assert_eq!(b'f', radix::tetrad_to_base16(&15));
    }

    #[test]
    fn test_base16_to_tetrad() {
        assert_eq!(0, radix::base16_to_tetrad(&b'0'));
        assert_eq!(9, radix::base16_to_tetrad(&b'9'));

        assert_eq!(10, radix::base16_to_tetrad(&b'a'));
        assert_eq!(10, radix::base16_to_tetrad(&b'A'));

        assert_eq!(15, radix::base16_to_tetrad(&b'f'));
        assert_eq!(15, radix::base16_to_tetrad(&b'F'));
    }

    #[test]
    fn test_sextet_to_base64() {
        assert_eq!(b'A', radix::sextet_to_base64(&0));
        assert_eq!(b'Z', radix::sextet_to_base64(&25));

        assert_eq!(b'a', radix::sextet_to_base64(&26));
        assert_eq!(b'z', radix::sextet_to_base64(&51));

        assert_eq!(b'0', radix::sextet_to_base64(&52));
        assert_eq!(b'9', radix::sextet_to_base64(&61));

        assert_eq!(b'+', radix::sextet_to_base64(&62));
        assert_eq!(b'/', radix::sextet_to_base64(&63));
    }

    #[test]
    fn test_base64_to_sextet() {
        assert_eq!(Some(0), radix::base64_to_sextet(&b'A'));
        assert_eq!(Some(25), radix::base64_to_sextet(&b'Z'));

        assert_eq!(Some(26), radix::base64_to_sextet(&b'a'));
        assert_eq!(Some(51), radix::base64_to_sextet(&b'z'));

        assert_eq!(Some(52), radix::base64_to_sextet(&b'0'));
        assert_eq!(Some(61), radix::base64_to_sextet(&b'9'));

        assert_eq!(Some(62), radix::base64_to_sextet(&b'+'));
        assert_eq!(Some(63), radix::base64_to_sextet(&b'/'));

        assert_eq!(None, radix::base64_to_sextet(&b'='));
    }
}