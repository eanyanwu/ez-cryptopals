//! ECB cut-and-paste
//! 

use crate::aes128;

const SOME_KEY: &[u8; 16] = b"YELLOW SUBMARINE";

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
    println!("{}", qs);
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
pub fn encrypt(profile: &str) -> Vec<u8> {
    aes128::ecb_encrypt(
        SOME_KEY,
        profile.as_bytes()
    )
}

/// Decrypt the encoded user profile and parse it.
pub fn decrypt(ciphertext: &[u8]) -> String {
    let plainbytes = aes128::ecb_decrypt(
        SOME_KEY,
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
        // First step: M
        // Make a cipher text block that is an encryption of the text "admin"

        let mut inject = String::from("");

        let profile = challenge13::profile_for(&inject);
        let mut original_email_block = challenge13::encrypt(&profile);
        original_email_block.split_off(16);

        let mut previous_email_block = original_email_block.clone();
        let mut current_email_block = Vec::new();

        while previous_email_block != current_email_block {
            inject.push_str("A");
            let profile = challenge13::profile_for(&inject);

            previous_email_block = current_email_block.clone();
            
            current_email_block = challenge13::encrypt(&profile);
            current_email_block.split_off(16);
        }

        // Adding the last character did not modify the block, nice
        // So we pop it off, because we now know that any subsequent characters
        // will start at the begining of the next block
        inject.pop();

        let mut txt_to_inject = b"admin".to_vec();
        aes128::pkcs_pad(16, &mut txt_to_inject);

        let txt_to_inject = std::str::from_utf8(&txt_to_inject).unwrap();

        inject.push_str(txt_to_inject);

        let malicious_profile = challenge13::profile_for(&inject);
        let ciphertext = challenge13::encrypt(&malicious_profile);

        let mut encrypted_admin_block = (&ciphertext[16..32]).to_vec();


        // Second, create a ciphertext where the last block only contains
        // the plain text "user" + padding
        let mut inject = String::from("");
        let profile = challenge13::profile_for(&inject);
        let original_ciphertext_len = challenge13::encrypt(&profile).len();
        let mut current_ciphertext_len = original_ciphertext_len;

        while original_ciphertext_len == current_ciphertext_len {
            inject.push('A');
            let profile = challenge13::profile_for(&inject);
            current_ciphertext_len = challenge13::encrypt(&profile).len();
        }

        let adminuser = String::from_utf8(
            vec![b'A'; inject.len() + 4]
        ).unwrap();

        let adminprofile = challenge13::profile_for(&adminuser);

        let mut ciphertext = challenge13::encrypt(&adminprofile);

        ciphertext.split_off(
            ciphertext.len() - 16
        );

        ciphertext.append(&mut encrypted_admin_block);


        let admin_profile = challenge13::decrypt(
            &ciphertext
        );

        assert_eq!(
            "{\n\
            \t'email': 'AAAAAAAAAAAAA',\n\
            \t'uid': '10',\n\
            \t'role': 'admin'\n\
            }",
            admin_profile
        );
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
        let email = "hello@example.com";

        let profile = challenge13::profile_for(email);

        let ciphertext = challenge13::encrypt(
            &profile,
        );

        let plaintext = challenge13::decrypt(
            &ciphertext,
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