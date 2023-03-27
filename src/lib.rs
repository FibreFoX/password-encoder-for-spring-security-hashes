#![forbid(unsafe_code)]
pub mod encoder;

pub trait PasswordEncoder {
    fn matches(&self, raw_password: String, encoded_password: String) -> bool;

    /// If password can be encoded, this might return the encoded password hash
    fn encode(&self, raw_password: String) -> Option<String>;

    fn upgrade_encoding(&self, encoded_password: String) -> bool {
        false
    }
}
