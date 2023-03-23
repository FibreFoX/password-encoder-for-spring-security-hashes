use spring_password_encoders::PasswordEncoder;
use spring_password_encoders::encoder::noop::NoOpPasswordEncoder;

#[test]
fn crate_noop_encode() {
    let given_password = String::from("Hello");

    let encoder: NoOpPasswordEncoder = Default::default();

    let encoded_password = encoder.encode(given_password).unwrap();

    assert_eq!(encoded_password, "Hello");
}
