use crate::PasswordEncoder;

#[derive(Debug, Default)]
pub struct NoOpPasswordEncoder;

impl PasswordEncoder for NoOpPasswordEncoder {
    fn matches_spring_security_hash(&self, unencoded_password: &String, encoded_password: &String) -> bool {
        unencoded_password.eq(encoded_password)
    }

    fn encode_spring_security_hash(&self, unencoded_password: &String) -> Option<String> {
        Some(unencoded_password.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::PasswordEncoder;
    use crate::encoder::noop::NoOpPasswordEncoder;

    #[test]
    fn encode_works() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let given_password = String::from("Hello");

        let encoded_password = encoder.encode_spring_security_hash(&given_password).unwrap();

        assert_eq!(encoded_password, given_password);
    }

    #[test]
    fn encode_works_with_empty_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let given_password = String::from("");

        let encoded_password = encoder.encode_spring_security_hash(&given_password).unwrap();

        assert_eq!(encoded_password, given_password);
    }

    #[test]
    fn matches_fails_on_wrong_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let wrong_password = String::from("Wrong");
        let stored_password = String::from("Hello");

        let result = encoder.matches_spring_security_hash(&wrong_password, &stored_password);

        assert!(!result, "password should not match");
    }

    #[test]
    fn matches_works_on_correct_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let correct_password = String::from("Hello");
        let stored_password = String::from("Hello");

        let result = encoder.matches_spring_security_hash(&correct_password, &stored_password);

        assert!(result, "password should match stored one");
    }

    #[test]
    fn matches_works_on_empty_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let correct_password = String::from("");
        let stored_password = String::from("");

        let result = encoder.matches_spring_security_hash(&correct_password, &stored_password);

        assert!(result, "password should match stored one even if empty");
    }
}
