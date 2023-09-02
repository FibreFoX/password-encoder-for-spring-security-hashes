use crate::encoder::bcrypt::BCryptPasswordEncoder;
use crate::encoder::md4::Md4PasswordEncoder;
use crate::encoder::md5::Md5PasswordEncoder;
use crate::encoder::noop::NoOpPasswordEncoder;
use crate::PasswordEncoder;
// use std::collections::HashMap;

#[derive(Debug)]
pub struct DelegatingPasswordEncoder {
    id_prefix: String,
    id_suffix: String,
    default_encoder: String,
    // encoders: HashMap<String, Box<dyn PasswordEncoder>>,
}

impl Default for DelegatingPasswordEncoder {
    fn default() -> DelegatingPasswordEncoder {
        /* let mut config = */
        DelegatingPasswordEncoder {
            id_prefix: String::from("{"),
            id_suffix: String::from("}"),
            default_encoder: String::from("bcrypt"),
            // encoders: HashMap::new(),
        }
        /*
        config.encoders.insert(
            String::from("noop"),
            Box::new(crate::encoder::noop::NoOpPasswordEncoder {}),
        );
        config
         */
    }
}

// somehow I have so much trouble to have this using dyn trait mechanics ... still learning Rust :D
/*
fn get_encoder_for_id<'a>(
    encoder_id: &'a String,
    encoders: &'a HashMap<String, Box<dyn PasswordEncoder>>,
) -> Option<&'a Box<dyn PasswordEncoder>> {
    if !encoders.contains_key(encoder_id) {
        return None;
    }
    encoders.get(encoder_id)
}

#[cfg(test)]
mod test_get_encoder_for_id {
    use super::get_encoder_for_id;
    use crate::PasswordEncoder;
    use std::collections::HashMap;
    use std::ops::Deref;

    #[test]
    fn no_encoders_in_map() {
        let encoder_id = String::from("noop");
        let encoders: HashMap<String, Box<dyn PasswordEncoder>> = HashMap::new();
        let result = get_encoder_for_id(&encoder_id, &encoders);
        assert!(result.is_none(), "should not find any encoder in empty list");
    }

    #[test]
    fn no_matching_encoders_in_map(){
        let encoder_id = String::from("noop");
        let different_encoder_id = String::from("different");
        let mut encoders: HashMap<String, Box<dyn PasswordEncoder>> = HashMap::new();
        encoders.insert(
            different_encoder_id,
            Box::new(crate::encoder::noop::NoOpPasswordEncoder {}),
        );

        let result = get_encoder_for_id(&encoder_id, &encoders);
        // assert_eq! does not work, so use matches! inside
        // this was a GIANT rabbit whole to follow the Box<dyn Trait> bunny
        // https://users.rust-lang.org/t/issues-in-asserting-result/61198/2
        assert!(result.is_none(), "should not find encoder as it is not in the list");
    }

    #[test]
    fn finds_encoders_in_map(){
        let encoder_id = String::from("noop");
        let noop_encoder_box = Box::new(crate::encoder::noop::NoOpPasswordEncoder {});
        let mut encoders: HashMap<String, Box<dyn PasswordEncoder>> = HashMap::new();
        encoders.insert(
            encoder_id.clone(),
            noop_encoder_box,
        );

        let result = get_encoder_for_id(&encoder_id, &encoders);
        assert_eq!(result.unwrap().deref(), noop_encoder_box.deref(), "should find the encoder");
    }

    #[test]
    fn finds_the_wanted_encoders_in_map(){
        let encoder_id = String::from("noop");
        let noop_encoder = crate::encoder::noop::NoOpPasswordEncoder {};
        let noop_encoder_box = Box::new(noop_encoder);

        let different_encoder_id = String::from("bcrypt");
        let different_encoder = crate::encoder::bcrypt::BCryptPasswordEncoder {};
        let different_encoder_box = Box::new(different_encoder);

        let mut encoders: HashMap<String, Box<dyn PasswordEncoder>> = HashMap::new();
        encoders.insert(
            encoder_id.clone(),
            noop_encoder_box,
        );
        encoders.insert(
            different_encoder_id.clone(),
            different_encoder_box,
        );

        let result = get_encoder_for_id(&different_encoder_id, &encoders);

        // assert_eq! does not work, so use matches! inside
        // this was a GIANT rabbit whole to follow the Box<dyn Trait> bunny
        // https://users.rust-lang.org/t/issues-in-asserting-result/61198/2
        assert_ne!(result.unwrap() as *const _, &noop_encoder as *const _, "should not find an unwanted encoder");
        assert_eq!(result.unwrap() as *const _, &different_encoder as *const _, "should find the wanted encoder, not just any");
    }
}
 */

fn get_encoder_id_from_encoded_password(encoded_password: &String, id_prefix: &String, id_suffix: &String) -> Option<String> {
    if !encoded_password.starts_with(id_prefix) || !encoded_password.contains(id_suffix) {
        return None;
    }

    encoded_password
        .find(id_suffix)
        .and_then(|suffix_position| encoded_password.get(id_prefix.len()..suffix_position))
        .map(|found_id| found_id.to_string())
}

#[cfg(test)]
mod test_get_encoder_id_from_encoded_password_single_char_marker {
    use super::get_encoder_id_from_encoded_password;

    #[test]
    fn no_encoder_id() {
        let encoded_password = String::from("no_encoder_id");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id"
        );
    }

    #[test]
    fn no_encoder_id_when_not_having_suffix() {
        let encoded_password = String::from("{no_encoder_id_but_with_prefix");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id"
        );
    }

    #[test]
    fn no_encoder_id_when_not_starting_with_prefix() {
        let encoded_password = String::from("no_encoder_id_but_with_suffix}");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id"
        );
    }

    #[test]
    fn finds_encoder_id() {
        let encoded_password = String::from("{encoder_id}");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("encoder_id".to_string()),
            "should find encoder id"
        );
    }

    #[test]
    fn finds_encoder_id_with_full_encoded_password_string() {
        let encoded_password = String::from("{noop}Password");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("noop".to_string()),
            "should find encoder id from full encoded string"
        );
    }

    #[test]
    fn finds_empty_encoder_id() {
        let encoded_password = String::from("{}");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("".to_string()),
            "should find encoder id"
        );
    }

    #[test]
    fn finds_encoder_id_with_multiple_prefixes_at_beginning() {
        let encoded_password = String::from("{{encoder_id}");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("{encoder_id".to_string()),
            "should find encoder id with '{{' at the beginning"
        );
    }

    #[test]
    fn finds_encoder_id_with_multiple_suffixes_at_ending() {
        let encoded_password = String::from("{encoder_id}}");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("encoder_id".to_string()),
            "should find encoder id without having any '}}' at the ending, because the first suffix wins"
        );
    }
}

#[cfg(test)]
mod test_get_encoder_id_from_encoded_password_multiple_chars_marker {
    use super::get_encoder_id_from_encoded_password;

    #[test]
    fn no_encoder_id() {
        let encoded_password = String::from("no_encoder_id");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id"
        );
    }

    #[test]
    fn no_encoder_id_when_not_having_suffix() {
        let encoded_password = String::from("{no_encoder_id_but_with_prefix");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id"
        );
    }

    #[test]
    fn no_encoder_id_when_not_starting_with_prefix() {
        let encoded_password = String::from("no_encoder_id_but_with_suffix}");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id"
        );
    }

    #[test]
    fn no_encoder_id_when_prefix_and_suffix_are_wrong() {
        let encoded_password = String::from("{encoder_id}");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            None,
            "should not find encoder id as prefix/suffix is wrong"
        );
    }

    #[test]
    fn finds_encoder_id() {
        let encoded_password = String::from("{{encoder_id}}");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("encoder_id".to_string()),
            "should find encoder id"
        );
    }

    #[test]
    fn finds_encoder_id_with_full_encoded_password_string() {
        let encoded_password = String::from("{{noop}}Password");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("noop".to_string()),
            "should find encoder id from full encoded string"
        );
    }

    #[test]
    fn finds_encoder_id_with_multiple_prefixes_at_beginning() {
        let encoded_password = String::from("{{{{encoder_id}}");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("{{encoder_id".to_string()),
            "should find encoder id with '{{' at the beginning"
        );
    }

    #[test]
    fn finds_encoder_id_with_multiple_suffixes_at_ending() {
        let encoded_password = String::from("{{encoder_id}}}}");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id_from_encoded_password(&encoded_password, &prefix, &suffix),
            Some("encoder_id".to_string()),
            "should find encoder id without having any '}}' at the ending, because the first suffix wins"
        );
    }
}

fn with_delegation_marker(resulting_password_hash: Option<String>, encoder_id: String, id_prefix: &String, id_suffix: &String) -> Option<String> {
    if resulting_password_hash.is_none() {
        return None;
    }

    Some(id_prefix.to_owned() + &encoder_id + id_suffix + &*resulting_password_hash.unwrap())
}

fn without_delegation_marker(encoded_password_hash: &String, encoder_id: &String, id_prefix: &String, id_suffix: &String) -> String {
    encoded_password_hash[(id_prefix.len() + encoder_id.len() + id_suffix.len())..].to_string()
}

impl PasswordEncoder for DelegatingPasswordEncoder {
    fn matches_spring_security_hash(&self, unencoded_password: &String, encoded_password: &String) -> bool {
        // find encoder id
        let encoder_id = get_encoder_id_from_encoded_password(&encoded_password, &self.id_prefix, &self.id_suffix);
        match encoder_id {
            Some(encoder_id) => match encoder_id.as_str() {
                "noop" => {
                    let encoder: NoOpPasswordEncoder = Default::default();
                    encoder.matches_spring_security_hash(
                        &unencoded_password,
                        &without_delegation_marker(&encoded_password, &encoder_id, &self.id_prefix, &self.id_suffix),
                    )
                }
                "bcrypt" => {
                    let encoder: BCryptPasswordEncoder = Default::default();
                    encoder.matches_spring_security_hash(
                        &unencoded_password,
                        &without_delegation_marker(&encoded_password, &encoder_id, &self.id_prefix, &self.id_suffix),
                    )
                }
                "MD4" => {
                    let encoder: Md4PasswordEncoder = Default::default();
                    encoder.matches_spring_security_hash(
                        &unencoded_password,
                        &without_delegation_marker(&encoded_password, &encoder_id, &self.id_prefix, &self.id_suffix),
                    )
                }
                "MD5" => {
                    let encoder: Md5PasswordEncoder = Default::default();
                    encoder.matches_spring_security_hash(
                        &unencoded_password,
                        &without_delegation_marker(&encoded_password, &encoder_id, &self.id_prefix, &self.id_suffix),
                    )
                }
                _ => todo!(),
            },
            None => false,
        }
    }

    fn encode_spring_security_hash(&self, unencoded_password: &String) -> Option<String> {
        return match self.default_encoder.as_str() {
            "noop" => {
                let encoder: NoOpPasswordEncoder = Default::default();
                with_delegation_marker(
                    encoder.encode_spring_security_hash(&unencoded_password),
                    "noop".to_string(),
                    &self.id_prefix,
                    &self.id_suffix,
                )
            }
            "bcrypt" => {
                let encoder: BCryptPasswordEncoder = Default::default();
                with_delegation_marker(
                    encoder.encode_spring_security_hash(&unencoded_password),
                    "bcrypt".to_string(),
                    &self.id_prefix,
                    &self.id_suffix,
                )
            }
            "MD4" => {
                let encoder: Md4PasswordEncoder = Default::default();
                with_delegation_marker(
                    encoder.encode_spring_security_hash(&unencoded_password),
                    "MD4".to_string(),
                    &self.id_prefix,
                    &self.id_suffix,
                )
            }
            "MD5" => {
                let encoder: Md5PasswordEncoder = Default::default();
                with_delegation_marker(
                    encoder.encode_spring_security_hash(&unencoded_password),
                    "MD%".to_string(),
                    &self.id_prefix,
                    &self.id_suffix,
                )
            }
            _ => {
                // TODO
                None
            }
        };
    }
}
