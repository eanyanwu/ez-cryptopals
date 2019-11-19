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



/// Convert hex to base64
#[cfg(test)]
pub mod test {
    use crate::radix;

    //// Solution to the challenge (see source)
    pub fn convert_hex_to_base64() {
        let hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base_64_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = radix::base16_to_bytes(hex_input);
        let actual_base64_output = radix::bytes_to_base64(&bytes);

        assert_eq!(expected_base_64_output, actual_base64_output);
    }

    #[test]
    pub fn test_convert_hex_to_base64() {
        convert_hex_to_base64();
    }    
}