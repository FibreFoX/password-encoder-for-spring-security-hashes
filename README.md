# Password encoders for Spring Security hashes in Rust

Using a web server in Rust is easy, simply choose between [Rocket](https://rocket.rs/) or [Actix](https://actix.rs/) (or
others). But what about handling password hashes generated
from [Spring Security](https://spring.io/projects/spring-security)? I could not find anything, so this library is meant
to fill the gap.

**Note/Warning:** This is a learning project (yet)! I'm usually developing with Java, this is an experiment to migrate a
Spring Boot project to run with Rust built systems.

## Usage

Add dependency to your `Cargo.toml`:

```toml
[dependencies]
password-encoder-for-spring-security-hashes = "0.1.0"
```

Creating a password hash:

```rust
use password_encoder_for_spring_security_hashes::PasswordEncoder;
use password_encoder_for_spring_security_hashes::encoder::delegating::DelegatingPasswordEncoder;

fn main() {
    let encoder: DelegatingPasswordEncoder = Default::default();

    let some_entered_password = String::from("SomeSecurePassword");

    let password_hash_to_store = encoder.encode_spring_security_hash(&some_entered_password);
}
```

Checking if password matches:

```rust
use password_encoder_for_spring_security_hashes::PasswordEncoder;
use password_encoder_for_spring_security_hashes::encoder::delegating::DelegatingPasswordEncoder;

fn main() {
    let encoder: DelegatingPasswordEncoder = Default::default();

    let some_entered_password = String::from("NotVerySecretPassword");
    let some_stored_password_hash = String::from("{noop}NotVerySecretPassword");

    if encoder.matches_spring_security_hash(&some_stored_password_hash, &some_stored_password_hash) {
        println!("(insecure) passwords do match");
    }
}
```

## Supported encoders

| identifier | Spring Security password encoder class                  | matches | encode | delegated | 
|------------|---------------------------------------------------------|:-------:|:------:|:---------:|
|            | o.s.s.c.password.DelegatingPasswordEncoder              |   ✅    |   ✅   |     -     |
| argon2     | o.s.s.c.argon2.Argon2PasswordEncoder                    |   ✏️    |   ✏️   |    ✏️     |
| bcrypt     | o.s.s.c.bcrypt.BCryptPasswordEncoder                    |    ✅    |   ✅    |     ✅     |
| pbkdf2     | o.s.s.c.password.Pbkdf2PasswordEncoder                  |   ✏️    |   ✏️   |    ✏️     |
| scrypt     | o.s.s.c.scrypt.SCryptPasswordEncoder                    |   ✏️    |   ✏️   |    ✏️     |
| ldap       | o.s.s.c.password.LdapShaPasswordEncoder                 |   ✏️    |   ✏️   |    ✏️     |
| MD4        | o.s.s.c.password.Md4PasswordEncoder                     |   ✏️    |   ✏️   |    ✏️     |
| MD5        | o.s.s.c.password.MessageDigestPasswordEncoder (md5)     |   ✏️    |   ✏️   |    ✏️     |
| SHA-1      | o.s.s.c.password.MessageDigestPasswordEncoder (sha-1)   |   ✏️    |   ✏️   |    ✏️     |
| SHA-256    | o.s.s.c.password.MessageDigestPasswordEncoder (sha-256) |   ✏️    |   ✏️   |    ✏️     |
| noop       | o.s.s.c.password.NoOpPasswordEncoder                    |    ✅    |   ✅    |     ✅     |
| sha256     | o.s.s.c.password.StandardPasswordEncoder                |   ✏️    |   ✏️   |    ✏️     |

**Note:** the replacement for `DelegatingPasswordEncoder` will support all the encoders listed above (depending on their status)

### Icon legend

✏️: implementation planned / work in progress  
✅: implemented

## License

Apache-2.0

"Spring", "Spring Boot" and "Spring Security" are [trademarks](https://spring.io/trademarks) of Pivotal Software, Inc.
