use crate::PasswordEncoder;
use md4::{Md4, Digest};
use hex::decode;

#[derive(Debug)]
pub struct Md4PasswordEncoder {
    salt_prefix: String,
    salt_suffix: String,
    salt_byte_size: u32,
}

impl Default for Md4PasswordEncoder {
    fn default() -> Md4PasswordEncoder {
        Md4PasswordEncoder {
            // https://github.com/spring-projects/spring-security/blob/a4e13c520b351c48378d0287167e53cfc581de46/crypto/src/main/java/org/springframework/security/crypto/password/Md4PasswordEncoder.java#L83
            salt_prefix: String::from("{"),
            salt_suffix: String::from("}"),
            // https://github.com/spring-projects/spring-security/blob/a4e13c520b351c48378d0287167e53cfc581de46/crypto/src/main/java/org/springframework/security/crypto/keygen/Base64StringKeyGenerator.java#L31
            salt_byte_size: 32
        }
    }
}

fn extract_salt(salt_prefix: &String, salt_suffix: &String,encoded_password: &String) -> Option<String>{
    // salt is optional :(
    if encoded_password.starts_with(salt_prefix) {
        // looks like we have salt ... but needs suffix
        if !encoded_password.contains(salt_suffix) {
            // no salt
        }
        // TODO finally extract salt
    }
    None
}

impl PasswordEncoder for Md4PasswordEncoder {
    fn matches_spring_security_hash(&self, unencoded_password: &String, encoded_password: &String) -> bool {
        let salt = extract_salt(&self.salt_prefix, &self.salt_suffix, &encoded_password);
        if salt.is_none() {
            // no salt, so we can check direct
            let mut hasher = Md4::new();

            hasher.update(unencoded_password.as_bytes());
            let md4_hash_bytes = hasher.finalize();

            return match decode(encoded_password) {
                Ok(encoded_password_string) => {
                    encoded_password_string == &md4_hash_bytes[..]
                },
                _ => false
            }
        }
        false
    }

    fn encode_spring_security_hash(&self, unencoded_password: &String) -> Option<String> {
        // TODO find easy way to generated salt
        None
    }
}

#[cfg(test)]
mod tests {
    use super::PasswordEncoder;
    use super::Md4PasswordEncoder;

    #[test]
    fn matches_correct_password_with_salt() {
        let encoder: Md4PasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let encoded_password = String::from("{thisissalt}6cc7924dad12ade79dfb99e424f25260");

        let result = encoder.matches_spring_security_hash(&unencoded_password, &encoded_password);

        assert!(result);
    }

    #[test]
    fn matches_correct_password_no_salt() {
        let encoder: Md4PasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let encoded_password = String::from("8a9d093f14f8701df17732b2bb182c74");

        let result = encoder.matches_spring_security_hash(&unencoded_password, &encoded_password);

        assert!(result);
    }

    #[test]
    fn matches_correct_password_no_salt_uppercased() {
        let encoder: Md4PasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let encoded_password = String::from("8A9D093F14F8701DF17732B2BB182C74");

        let result = encoder.matches_spring_security_hash(&unencoded_password, &encoded_password);

        assert!(result);
    }
}
