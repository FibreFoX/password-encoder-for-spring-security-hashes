use password_encoder_for_spring_security_hashes::encoder::md4::Md4PasswordEncoder;
use password_encoder_for_spring_security_hashes::PasswordEncoder;

#[test]
fn crate_delegating_encode_default() {
    let given_password = String::from("Hello");

    let encoder: Md4PasswordEncoder = Default::default();

    let encoded_password = encoder
        .encode_spring_security_hash(&given_password)
        .unwrap();

    assert_ne!(encoded_password, given_password);

    assert!(encoder.matches_spring_security_hash(&given_password, &encoded_password));
}
