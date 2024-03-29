use password_encoder_for_spring_security_hashes::encoder::noop::NoOpPasswordEncoder;
use password_encoder_for_spring_security_hashes::PasswordEncoder;

#[test]
fn crate_noop_encode() {
    let given_password = String::from("Hello");

    let encoder: NoOpPasswordEncoder = Default::default();

    let encoded_password = encoder.encode_spring_security_hash(&given_password).unwrap();

    // NOOP is special, others should be _ne
    assert_eq!(encoded_password, given_password);

    assert!(encoder.matches_spring_security_hash(&given_password, &encoded_password));
}
