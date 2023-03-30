use spring_password_encoders::encoder::noop::NoOpPasswordEncoder;
use spring_password_encoders::PasswordEncoder;

#[test]
fn crate_noop_encode() {
    let given_password = String::from("Hello");

    let encoder: NoOpPasswordEncoder = Default::default();

    let encoded_password = encoder.encode(given_password).unwrap();

    assert_eq!(encoded_password, "Hello");
}
