//! # Implement repeating-key XOR
//! 
//! Given the way I implemented the normal fixed byte xor, this one is easy.
//! I simply need to create a sequence of bytes by repeating the key as many times as needed
//! to match the length of the thing we are trying to XOR

/// Return the result of repeating the input byte sequence until we get to `count` bytes
pub fn repeat(bytes: &[u8], mut count: usize) -> Vec<u8> {
    if count == bytes.len() {
        bytes.to_vec()
    }
    else if count < bytes.len() {
        bytes[0..count].to_vec()
    }
    else {
        let mut result = Vec::with_capacity(count);

        let mut slice_index = 0;

        let slice_length = bytes.len();

        while count > 0 {
            result.push(bytes[slice_index]);

            slice_index = (slice_index + 1) % slice_length;

            count -= 1;
        }

        result
    }
}

/// Implement repeating-key XOR
#[cfg(test)]
pub mod test {
    use crate::radix;
    use crate::set01::challenge02;
    use crate::set01::challenge05;

    /// Solution to the challenge (see source)
    pub fn implement_repeating_key_xor() {
        let plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";

        let plain_text_bytes = plain_text.as_bytes();
        let repeating_key = challenge05::repeat(key.as_bytes(), plain_text_bytes.len());

        let cipher = challenge02::xor_bytes(plain_text_bytes, &repeating_key);

        assert_eq!(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
            radix::bytes_to_base16(&cipher)
        );
    }

    #[test]
    pub fn test_implement_repeating_key_xor() {
        implement_repeating_key_xor();
    }

    #[test]
    fn test_repeat() {
        // The count is equal to the original byte sequence
        assert_eq!(vec![1,2,3], challenge05::repeat(&[1,2,3], 3));

        // The count is less than the original byte sequence
        assert_eq!(vec![1,2], challenge05::repeat(&[1,2,3], 2));

        // The count is a multiple of the original byte sequence
        assert_eq!(vec![1,2,3,1,2,3], challenge05::repeat(&[1,2,3], 6));

        // The count is greater than the original byte sequence (but is not a multiple)
        assert_eq!(vec![1,2,3,4,1,2], challenge05::repeat(&[1,2,3,4], 6));
    }

}