use crate::PasswordEncoder;
use bcrypt::{hash_with_result, verify, Version};

#[derive(Default, Clone, Copy, Debug)]
pub struct BCryptPasswordEncoder {}

impl PasswordEncoder for BCryptPasswordEncoder {
    fn matches_spring_security_hash(
        &self,
        unencoded_password: &String,
        encoded_password: &String,
    ) -> bool {
        let result = verify(unencoded_password, encoded_password);
        if result.is_err() {
            // println!("Got error: {}", &result.unwrap_err());
            false
        } else {
            result.unwrap()
        }
    }

    fn encode_spring_security_hash(&self, unencoded_password: &String) -> Option<String> {
        // https://github.com/spring-projects/spring-security/blob/dc85ce016603bf32f1cb474e5399bc74a1fc0b73/crypto/src/main/java/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java#L100
        let default_cost = 10;
        // https://github.com/spring-projects/spring-security/blob/dc85ce016603bf32f1cb474e5399bc74a1fc0b73/crypto/src/main/java/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java#LL79C8-L79C26
        let default_version = Version::TwoA;

        match hash_with_result(unencoded_password, default_cost) {
            Ok(hash_parts) => Some(hash_parts.format_for_version(default_version)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BCryptPasswordEncoder, PasswordEncoder};

    #[test]
    fn check_when_no_rounds_then_true() {
        // not sure why, but no costs is or was allowed in spring security ...
        // https://github.com/spring-projects/spring-security/blob/dd4ce248883ef911e7384c46289c882eb30e3dd6/crypto/src/test/java/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoderTests.java#L218
        let correct_password = String::from("password");
        let stored_password =
            String::from("$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue");
        let encoder: BCryptPasswordEncoder = Default::default();

        // would fly through on spring ... sorry pal, too insecure
        assert!(!encoder.matches_spring_security_hash(&correct_password, &stored_password));
    }

    #[test]
    fn encode_empty_password() {
        let encoder: BCryptPasswordEncoder = Default::default();

        let unencoded_password = String::from("");

        let encoded_password = encoder.encode_spring_security_hash(&unencoded_password);

        assert!(encoded_password.is_some());
        assert!(encoded_password.unwrap().starts_with("$2a$10$"));
    }

    #[test]
    fn matches_password() {
        let encoder: BCryptPasswordEncoder = Default::default();

        let unencoded_password = String::from("password");
        let stored_encoded_password =
            String::from("$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG");

        assert!(encoder.matches_spring_security_hash(&unencoded_password, &stored_encoded_password));
    }

    #[test]
    fn no_matche_for_wrong_password() {
        let encoder: BCryptPasswordEncoder = Default::default();

        let unencoded_password = String::from("wrongpassword");
        let stored_encoded_password =
            String::from("$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG");

        assert!(
            !encoder.matches_spring_security_hash(&unencoded_password, &stored_encoded_password)
        );
    }
}
