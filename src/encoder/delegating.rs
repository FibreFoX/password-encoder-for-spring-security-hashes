use crate::PasswordEncoder;
use std::collections::HashMap;

pub struct DelegatingPasswordEncoder {
    id_prefix: String,
    id_suffix: String,
    default_encoder: String,
    encoders: HashMap<String, Box<dyn PasswordEncoder>>,
}

impl Default for DelegatingPasswordEncoder {
    fn default() -> DelegatingPasswordEncoder {
        let mut config = DelegatingPasswordEncoder {
            id_prefix: "{".to_string(),
            id_suffix: "}".to_string(),
            default_encoder: "noop".to_string(),
            encoders: HashMap::new(),
        };
        config.encoders.insert(
            "noop".to_string(),
            Box::new(crate::encoder::noop::NoOpPasswordEncoder {}),
        );
        config
    }
}

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

    #[test]
    fn no_encoders_in_map() {
        let encoder_id = String::from("noop");
        let encoders: HashMap<String, Box<dyn PasswordEncoder>> = HashMap::new();
        let result = get_encoder_for_id(&encoder_id, &encoders);
        // assert_eq! does not work, so use matches! inside
        // this was a GIANT rabbit whole to follow the Box<dyn Trait> bunny
        // https://users.rust-lang.org/t/issues-in-asserting-result/61198/2
        assert!(matches!(result, None), "should not find any encoder in empty list");
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
        assert!(matches!(result, None), "should not find encoder as it is not in the list");
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
        // assert_eq! does not work, so use matches! inside
        // this was a GIANT rabbit whole to follow the Box<dyn Trait> bunny
        // https://users.rust-lang.org/t/issues-in-asserting-result/61198/2
        assert!(matches!(result, Some(noop_encoder_box)), "should find the encoder");
    }
}

fn get_encoder_id(
    encoded_password: &String,
    id_prefix: &String,
    id_suffix: &String,
) -> Option<String> {
    if !encoded_password.starts_with(id_prefix) || !encoded_password.contains(id_suffix) {
        return None;
    }

    encoded_password
        .find(id_suffix)
        .and_then(|suffix_position| encoded_password.get(id_prefix.len()..suffix_position))
        .map(|found_id| found_id.to_string())
}

#[cfg(test)]
mod test_get_encoder_id_single_char_marker {
    use super::get_encoder_id;

    #[test]
    fn no_encoder_id() {
        let encoded_password = String::from("no_encoder_id");
        let prefix = String::from("{");
        let suffix = String::from("}");
        assert_eq!(
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
            Some("encoder_id".to_string()),
            "should find encoder id without having any '}}' at the ending, because the first suffix wins"
        );
    }
}

#[cfg(test)]
mod test_get_encoder_id_multiple_chars_marker {
    use super::get_encoder_id;

    #[test]
    fn no_encoder_id() {
        let encoded_password = String::from("no_encoder_id");
        let prefix = String::from("{{");
        let suffix = String::from("}}");
        assert_eq!(
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
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
            get_encoder_id(&encoded_password, &prefix, &suffix),
            Some("encoder_id".to_string()),
            "should find encoder id without having any '}}' at the ending, because the first suffix wins"
        );
    }
}

impl PasswordEncoder for DelegatingPasswordEncoder {
    fn matches(&self, raw_password: String, encoded_password: String) -> bool {
        // find encoder id
        let encoder_id = get_encoder_id(&encoded_password, &self.id_prefix, &self.id_suffix);
        match encoder_id {
            Some(encoder_id) => todo!(),
            None => false,
        }
    }

    fn encode(&self, raw_password: String) -> Option<String> {
        todo!()
    }

    fn upgrade_encoding(&self, encoded_password: String) -> bool {
        todo!()
    }
}
