#[derive(Debug)]
pub struct StandardPasswordEncoder {
    iterations: u32,
}

impl Default for StandardPasswordEncoder {
    fn default() -> StandardPasswordEncoder {
        StandardPasswordEncoder {
            // https://github.com/spring-projects/spring-security/blob/0e3ee8990299436223c3037afb096f454f17ef5e/crypto/src/main/java/org/springframework/security/crypto/password/StandardPasswordEncoder.java#LL53C48-L53C52
            iterations: 1024
        }
    }
}
