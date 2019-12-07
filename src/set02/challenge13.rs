//! ECB cut-and-paste
//! 

use crate::aes128;

/// Expands a query string of the form:  
/// "hello=world&hello=people"  
/// into the form  
/// {  
///     'hello': 'world',  
///     'hello': 'people'  
/// }  
/// 
/// No guarantees are made as to what the output will look like if the input 
/// contains the characters '&' or '=' in weird places.
pub fn expand_query_string(qs: &str) -> String {
    let mut expanded = String::from("{");

    let pairs = qs.split('&');

    for pair in pairs {
        expanded.push('\n');
        
        let mut pair = pair.split('=');
        let key = pair.next();
        let value = pair.next();

        if key.is_none() || value.is_none() {
            panic!("error: invalid query string");
        }
        else {
            let (key, value) = (key.unwrap(), value.unwrap());

            expanded.push_str(
                &(format!("\t'{}': '{}',", key, value))
            );
        }
    }

    // remove the last comma
    expanded.pop();

    expanded.push_str("\n}");

    expanded
}

/// Create a query string for the given email address
/// Any '&' and '=' characters in the email will be EATEN
pub fn profile_for(email: &str) -> String {
    // eat the meta-characters
    let email = email.replace("&", "").replace("=", "");

    format!("email={}&uid=10&role=user", email)
}

/// Encrypt the encoded user profile under the key; "provide" that to the 
/// "attacker"
pub fn encrypt(profile: &str, key: &[u8; 16]) -> Vec<u8> {
    aes128::ecb_encrypt(
        key,
        profile.as_bytes()
    )
}

/// Decrypt the encoded user profile and parse it.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 16]) -> String {
    let plainbytes = aes128::ecb_decrypt(
        key,
        ciphertext
    );

    let plaintext = String::from_utf8(plainbytes).unwrap();

    expand_query_string(&plaintext)
}

/// ECB cut-and-paste
#[cfg(test)]
pub mod test {
    use crate::aes128;
    use crate::set02::challenge13;
    
    /// Solution to the challenge (see source)
    pub fn ecb_cut_and_paste() {
    }

    #[test]
    pub fn test_ecb_cut_and_paste() {
        ecb_cut_and_paste();
    }

    #[test]
    pub fn test_profile_for() {
        let res = challenge13::profile_for(
            "hello@test.com"
        );

        assert_eq!(
            "email=hello@test.com&uid=10&role=user",
            res
        );

        let res = challenge13::profile_for(
            "bad&email@hacker=com"
        );

        assert_eq!(
            "email=bademail@hackercom&uid=10&role=user",
            res
        );
    }

    #[test]
    pub fn test_expand_query_string() {
        // 1 key-value pair
        let res = challenge13::expand_query_string(
            "hello=world"
        );

        assert_eq!(
            "{\n\
            \t'hello': 'world'\n\
            }",
            res
        );

        // 2 key-value pairs
        let res = challenge13::expand_query_string(
            "hello=world&and=everyone else"
        );

        assert_eq!(
            "{\n\
            \t'hello': 'world',\n\
            \t'and': 'everyone else'\n\
            }",
            res
        );
    }

    #[test]
    pub fn test_encrypt_then_decrypt() {
        let key = aes128::get_random_key();
        let email = "hello@example.com";

        let profile = challenge13::profile_for(email);

        let ciphertext = challenge13::encrypt(
            &profile,
            &key
        );

        let plaintext = challenge13::decrypt(
            &ciphertext,
            &key
        );

        assert_eq!(
            "{\n\
            \t'email': 'hello@example.com',\n\
            \t'uid': '10',\n\
            \t'role': 'user'\n\
            }",
            plaintext
        );
    }
}