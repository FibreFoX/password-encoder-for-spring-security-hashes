#![forbid(unsafe_code)]
pub mod encoder;

pub trait PasswordEncoder {
    fn matches_spring_security_hash(
        &self,
        unencoded_password: &String,
        encoded_password: &String,
    ) -> bool;

    /// If password can be encoded, this might return the encoded password hash
    fn encode_spring_security_hash(&self, unencoded_password: &String) -> Option<String>;
}

pub enum Encoder {
    ARGON2,
    BCRYPT,
    LDAP,
    MD4,
    MD5,
    NOOP,
    PBKDF2,
    SCRYPT,
    SHA1,
    SHA256,
    STANDARD,
    DELEGATING,
}

impl Encoder {
    fn to_string(&self) -> String {
        match self {
            Encoder::ARGON2 => "argon".to_string(),
            Encoder::BCRYPT => "bcrypt".to_string(),
            Encoder::LDAP => "ldap".to_string(),
            Encoder::MD4 => "md4".to_string(),
            _ => "".to_string(),
        }
    }
}
