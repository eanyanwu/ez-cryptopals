//! ECB cut-and-paste
//! 
//! Let's set the scene:  
//! A user Alice wants to set up an account at code.com  
//! The registration form, among other things, takes her email and sencds it 
//! to a web service. This web service creates a json profile for Alice (think 
//! a json web token), encrypts it, and sends the ciphertext back to Alice.  
//! The idea is that this encrypted token can help the web service identify  
//! Alice in subsequent requests.
//! 
//! But Alice is greedy. Alice wants to gain admin access to code.com.  
//! Thankfully! The code for code.com is opensource, so alice knows the  
//! structure of the json profile that is created. Gaining admin access is  
//! as simple as somehow modifying her encrypted token in such a way that when  
//! decypted, the "role" field says "admin"
//! 
//! Doing this when the AES cipher mode is ECB is actually very doable....  
//! I demonstrate it below

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
        //
        // FIRST STEP:
        // Make a cipher text block that is an encryption of the text "admin"

        // To do this, I need prefix the word 'admin' with some characters 
        // in such a way that it starts at the begining fo the second block.
        // To find how many characters are needed for the prefix, I repeatedly  
        // increase its size until the block stops changing. 
        let mut prefix = String::from("");

        let mut original_email_block = challenge13::encrypt(
            &challenge13::profile_for(&prefix)
        );

        original_email_block.split_off(16);

        let mut previous_email_block = original_email_block.clone();
        let mut current_email_block = Vec::new();

        while previous_email_block != current_email_block {
            prefix.push_str("A");

            previous_email_block = current_email_block.clone();
            
            current_email_block = challenge13::encrypt(
                &challenge13::profile_for(&prefix)
            );

            current_email_block.split_off(16);
        }

        // Adding the last character did not modify the block, nice
        // So we pop it off, because we now know that any subsequent characters
        // will start at the begining of the next block
        prefix.pop();

        // Now that I have the correct prefix, I can create a block with the  
        // characters 'admin' in it (plus padding to fill the block)
        let mut txt_to_inject = b"admin".to_vec();
        aes128::pkcs_pad(16, &mut txt_to_inject);

        let txt_to_inject = std::str::from_utf8(&txt_to_inject).unwrap();

        prefix.push_str(txt_to_inject);

        let ciphertext = challenge13::encrypt(
            &challenge13::profile_for(&prefix)
        );

        // Save this for later!
        let mut encrypted_admin_block = (&ciphertext[16..32]).to_vec();

        //
        // SECOND STEP:
        // Create a ciphertext where the last block only contains
        // the plain text "user"

        // To do this, i need to figure out the length of a prefix that 
        // will get me to hit the next block size boundary. I then add 
        // 4 characters to that prefix so that the new block only has 
        // the word "user"
        let mut prefix = String::from("");

        let original_ciphertext_len = challenge13::encrypt(
            &challenge13::profile_for(&prefix)
        ).len();

        let mut current_ciphertext_len = original_ciphertext_len;

        while original_ciphertext_len == current_ciphertext_len {
            prefix.push('A');

            current_ciphertext_len = challenge13::encrypt(
                &challenge13::profile_for(&prefix)
            ).len();
        }

        prefix.push_str("AAAA");

        let mut ciphertext = challenge13::encrypt(
            &challenge13::profile_for(&prefix)
        );

        //
        // THIRD STEP:
        // Drop the last block that has the words "user" and replace it with  
        // previously created block that had the words "admin"
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