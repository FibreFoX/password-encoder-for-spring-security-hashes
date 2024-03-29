use crate::PasswordEncoder;
use hex::decode;
use md5::{Digest, Md5};

#[derive(Debug)]
pub struct Md5PasswordEncoder {
    salt_prefix: String,
    salt_suffix: String,
    salt_byte_size: u32,
}

impl Default for Md5PasswordEncoder {
    fn default() -> Md5PasswordEncoder {
        Md5PasswordEncoder {
            // https://github.com/spring-projects/spring-security/blob/0e3ee8990299436223c3037afb096f454f17ef5e/crypto/src/main/java/org/springframework/security/crypto/password/MessageDigestPasswordEncoder.java#L87
            salt_prefix: String::from("{"),
            salt_suffix: String::from("}"),
            // https://github.com/spring-projects/spring-security/blob/a4e13c520b351c48378d0287167e53cfc581de46/crypto/src/main/java/org/springframework/security/crypto/keygen/Base64StringKeyGenerator.java#L31
            salt_byte_size: 32,
        }
    }
}

fn extract_salt(salt_prefix: &String, salt_suffix: &String, encoded_password: &String) -> Option<String> {
    // salt is optional :(
    let prefix_length = salt_prefix.len();
    if encoded_password.starts_with(salt_prefix) {
        // looks like we have salt ... but needs suffix
        if !encoded_password.contains(salt_suffix) {
            // no salt
        }
        // get first position of suffix
        let position_of_suffix = encoded_password.find(salt_suffix);
        if position_of_suffix.is_some() {
            // finally extract salt
            let position = position_of_suffix.unwrap();
            let salt = &encoded_password.clone().into_bytes()[prefix_length..position];
            return Some(String::from_utf8(salt.to_vec()).unwrap());
        }
    }
    None
}

#[cfg(test)]
mod salt_tests {
    use super::extract_salt;

    #[test]
    fn can_find_salt_with_proper_prefix_with_proper_suffix() {
        let encoded_password_with_proper_format = String::from("{thisissalt}2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_some());

        assert_eq!(found_salt.unwrap(), String::from("thisissalt"));
    }

    #[test]
    fn unable_to_find_salt_with_proper_prefix_but_missing_suffix() {
        let encoded_password_with_proper_format = String::from("{thisissalt2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_none());
    }

    #[test]
    fn unable_to_find_salt_with_proper_suffix_but_missing_prefix() {
        let encoded_password_with_proper_format = String::from("thisissalt}2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_none());
    }

    #[test]
    fn unable_to_find_salt_without_salt_markers() {
        let encoded_password_with_proper_format = String::from("thisissalt2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_none());
    }

    #[test]
    fn can_find_salt_with_multiple_prefixes_with_proper_suffix() {
        let encoded_password_with_proper_format = String::from("{{thisissalt}2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_some());

        assert_eq!(found_salt.unwrap(), String::from("{thisissalt"));
    }

    #[test]
    fn can_find_salt_with_multiple_suffixes_with_proper_prefix() {
        let encoded_password_with_proper_format = String::from("{thisissalt}}2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_some());

        assert_eq!(found_salt.unwrap(), String::from("thisissalt"));
    }

    #[test]
    fn can_find_salt_with_multiple_suffixes_with_multiple_prefixes() {
        let encoded_password_with_proper_format = String::from("{{thisissalt}}2a4e7104c2780098f50ed5a84bb2323d");
        let prefix = String::from("{");
        let suffix = String::from("}");

        let found_salt = extract_salt(&prefix, &suffix, &encoded_password_with_proper_format);

        assert!(found_salt.is_some());

        assert_eq!(found_salt.unwrap(), String::from("{thisissalt"));
    }
}

impl PasswordEncoder for Md5PasswordEncoder {
    fn matches_spring_security_hash(&self, unencoded_password: &String, encoded_password: &String) -> bool {
        let salt = extract_salt(&self.salt_prefix, &self.salt_suffix, &encoded_password);
        let mut password_to_hash = String::from(unencoded_password);
        let mut encoded_password_to_compare_against = String::from(encoded_password);

        if salt.is_some() {
            let found_salt = salt.unwrap();
            password_to_hash.push_str(&self.salt_prefix);
            password_to_hash.push_str(found_salt.as_str());
            password_to_hash.push_str(&self.salt_suffix);
            // strip salt from encoded_password
            encoded_password_to_compare_against = encoded_password[(&self.salt_prefix.len() + found_salt.as_str().len() + &self.salt_suffix.len())..].to_string();
        }

        let mut hasher = Md5::new();
        hasher.update(password_to_hash.as_bytes());
        let md5_hash_bytes = hasher.finalize();

        return match decode(encoded_password_to_compare_against) {
            Ok(encoded_password_string) => {
                // let md5_bytes = &md5_hash_bytes[..];
                // println!("{:?}", &md5_bytes);
                // println!("{:?}", &encoded_password_string);
                // encoded_password_string == md5_bytes
                encoded_password_string == &md5_hash_bytes[..]
            }
            Err(err) => false,
        };
    }

    fn encode_spring_security_hash(&self, unencoded_password: &String) -> Option<String> {
        // TODO find easy way to generated salt
        None
    }
}

#[cfg(test)]
mod tests {
    use super::Md5PasswordEncoder;
    use super::PasswordEncoder;

    #[test]
    fn matches_correct_password_with_salt() {
        let encoder: Md5PasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let encoded_password = String::from("{thisissalt}2a4e7104c2780098f50ed5a84bb2323d");

        let result = encoder.matches_spring_security_hash(&unencoded_password, &encoded_password);

        assert!(result);
    }

    #[test]
    fn matches_correct_password_no_salt() {
        let encoder: Md5PasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let encoded_password = String::from("5f4dcc3b5aa765d61d8327deb882cf99");

        let result = encoder.matches_spring_security_hash(&unencoded_password, &encoded_password);

        assert!(result);
    }

    #[test]
    fn matches_correct_password_no_salt_uppercased() {
        let encoder: Md5PasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let encoded_password = String::from("5F4DCC3B5AA765D61D8327DEB882CF99");

        let result = encoder.matches_spring_security_hash(&unencoded_password, &encoded_password);

        assert!(result);
    }
}
