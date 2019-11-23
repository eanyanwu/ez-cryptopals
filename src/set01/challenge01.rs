//! # Convert hex to base64
//! 
//! ## 1. On Numbers and their Visual Representations: 
//! 
//! The human race has come up with multiple ways to represent the abstract
//! concept of "numbers" visually.  
//! We are taught at an early age that "numbers" are the characters 0123456789.
//! Turns out this is not the whole story.
//! 
//! To make things a bit less confusing, when I refer to to actual numbers, 
//! instead of typing "1", I will type "one" to make it clear that I mean the 
//! underlying number, regardless of how it is represented. 
//! 
//! The representation we have been taught is called "base-10". And the mapping
//! of number to base-10 representation looks like this:
//! zero    -> 0  
//! one     -> 1  
//! two     -> 2  
//! ...
//! nine    -> 9  
//! ten     -> 10  
//! 
//! There are others! 
//! 
//! _Base-16 (Also known as hexadecimal)_  
//! zero    -> 0  
//! one     -> 1  
//! two     -> 2  
//! ...  
//! nine    -> 9  
//! ten     -> a (or A)  
//! eleven  -> b (or B)  
//! ...  
//! fifteen -> f (or f)   
//! 
//! _Base-64_  
//! zero    -> A  
//! one     -> B  
//! ...
//! twenty-six -> a  
//! sixty-three -> /  
//!  
//! How you "count" in each representation is beyond the scope of this readme.
//! 
//! ## 2. On the display of text by a Computer
//! 
//! In a computer, it's numbers all the way down. If you could peek inside one, 
//! you won't see any text, or images. You'll only see numbers flying about. A
//! "one" here, a "two" there, a "three hundred and twenty four" way over there.
//! 
//! We humans are visual folk. We like to see stuff. None of this abstract
//! "number" stuff. So, we made screens. When a screen receives
//! the number "sixty-five", it will display the particular arragement of dots
//! that look like what we know as the character "A"
//! 
//! There are multiple standards for mapping numbers to generic characters. The 
//! most popular is called ASCII ~ which is what we will be assuming in these
//! challenges.
//! 
//! ## 3. Bringing everything together
//! 
//! When this challenge says "convert a base-16 string to a base-64 string", it 
//! is asking us do two things:
//!  
//! (a) to convert the input base-16 ASCII text into numbers. This is the 
//! reverse of the mapping I showed earlier.    
//! (b) to conver the numbers into base-64 ascii text. This is the mapping I
//! showed earlier.
//! 
//! Fair enough, but we said numbers are abstract. How can a computer convert
//! a concrete base-16 representation of a number into the abstract number?
//! 
//! Great question! It cannot :0  
//! Instead, we pick a number representation that is easy for computers to use
//! as an alternative. Surprise! That representation is base-2 or _binary_
//! 


/// Convert hex to base64
#[cfg(test)]
pub mod test {
    use crate::radix;

    /// Solution to the challenge (see source)
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