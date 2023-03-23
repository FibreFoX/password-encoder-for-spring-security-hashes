use crate::PasswordEncoder;

pub struct DelegatingPasswordEncoder {
    id_prefix: String,
    id_suffix: String,
}

impl Default for DelegatingPasswordEncoder {
    fn default() -> DelegatingPasswordEncoder {
        DelegatingPasswordEncoder {
            id_prefix: "{".to_string(),
            id_suffix: "}".to_string(),
        }
    }
}

impl PasswordEncoder for DelegatingPasswordEncoder {
    fn matches(&self,  raw_password: String, encoded_password: String) -> bool {
        todo!()
    }

    fn encode(&self,  raw_password: String) -> Option<String> {
        todo!()
    }

    fn upgrade_encoding(&self,  encoded_password: String) -> bool {
        todo!()
    }
}
