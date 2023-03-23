use crate::PasswordEncoder;

#[derive(Default)]
pub struct NoOpPasswordEncoder {}

impl PasswordEncoder for NoOpPasswordEncoder {
    fn matches(&self,  raw_password: String, encoded_password: String) -> bool {
        encoded_password.eq(&raw_password)
    }

    fn encode(&self, raw_password: String) -> Option<String> {
        Some(raw_password.clone())
    }
}


#[cfg(test)]
mod tests {
    use super::{NoOpPasswordEncoder, PasswordEncoder};

    #[test]
    fn encode_works() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let given_password = String::from("Hello");

        let encoded_password = encoder.encode(given_password).unwrap();

        assert_eq!(encoded_password, "Hello");
    }

    #[test]
    fn encode_works_with_empty_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let given_password = String::from("");

        let encoded_password = encoder.encode(given_password).unwrap();

        assert_eq!(encoded_password, "".to_owned());
    }

    #[test]
    fn matches_fails_on_wrong_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let wrong_password = String::from("Wrong");
        let stored_password = String::from("Hello");

        let result = encoder.matches(wrong_password, stored_password);

        assert!(!result, "password should not match");
    }

    #[test]
    fn matches_works_on_correct_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let correct_password = String::from("Hello");
        let stored_password = String::from("Hello");

        let result = encoder.matches(correct_password, stored_password);

        assert!(result, "password should match stored one");
    }

    #[test]
    fn matches_works_on_empty_password() {
        let encoder: NoOpPasswordEncoder = Default::default();

        let correct_password = String::from("");
        let stored_password = String::from("");

        let result = encoder.matches(correct_password, stored_password);

        assert!(result, "password should match stored one even if empty");
    }
}
