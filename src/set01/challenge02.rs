//! # Fixed XOR
//! 
//! The "XOR" operator! It's symbol is: ^  
//! Here are the rules:  
//! 0 ^ 0 = 0  
//! 0 ^ 1 = 1     
//! 1 ^ 0 = 1  
//! 1 ^ 1 = 0  
//! 
//! In english: The result is a 1 if the two sides are different. It is a 0
//! otherwise.


/// Xor two sequences of bytes together  
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

/// Fixed XOR
pub mod test {
    use crate::radix;
    use crate::set01::challenge02;

    /// Solution to the challenge (see source)
    pub fn fixed_xor() {
        let left_hand_side = "1c0111001f010100061a024b53535009181c";
        let right_hand_side = "686974207468652062756c6c277320657965";

        let expected_result = "746865206b696420646f6e277420706c6179";

        let lhs_bytes = radix::base16_to_bytes(left_hand_side);
        let rhs_bytes = radix::base16_to_bytes(right_hand_side);

        let xored_bytes = challenge02::xor_bytes(&lhs_bytes, &rhs_bytes);
        
        assert_eq!(expected_result, radix::bytes_to_base16(&xored_bytes));

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
}