# Handling Spring Security password hashes in Rust

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
spring-password-encoders = "0.1.0"
```

Creating a password hash:

```rust
// TODO
```

Checking if password matches:

```rust
// TODO
```

## Supported encoders

| identifier | Spring Security password encoder class                                              | matches | encode |
|------------|-------------------------------------------------------------------------------------|:-------:|:------:|
|            | org.springframework.security.crypto.password.DelegatingPasswordEncoder              |   ✏️    |   ✏️   |
| argon2     | org.springframework.security.crypto.argon2.Argon2PasswordEncoder                    |   ✏️    |   ✏️   |
| bcrypt     | org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder                    |   ✏️    |   ✏️   |
| pbkdf2     | org.springframework.security.crypto.password.Pbkdf2PasswordEncoder                  |   ✏️    |   ✏️   |
| scrypt     | org.springframework.security.crypto.scrypt.SCryptPasswordEncoder                    |   ✏️    |   ✏️   |
| ldap       | org.springframework.security.crypto.password.LdapShaPasswordEncoder                 |   ✏️    |   ✏️   |
| MD4        | org.springframework.security.crypto.password.Md4PasswordEncoder                     |   ✏️    |   ✏️   |
| MD5        | org.springframework.security.crypto.password.MessageDigestPasswordEncoder (md5)     |   ✏️    |   ✏️   |
| SHA-1      | org.springframework.security.crypto.password.MessageDigestPasswordEncoder (sha-1)   |   ✏️    |   ✏️   |
| SHA-256    | org.springframework.security.crypto.password.MessageDigestPasswordEncoder (sha-256) |   ✏️    |   ✏️   |
| noop       | org.springframework.security.crypto.password.NoOpPasswordEncoder                    |    ✅    |   ✅    |
| sha256     | org.springframework.security.crypto.password.StandardPasswordEncoder                |   ✏️    |   ✏️   |

**Note:** the replacement for `DelegatingPasswordEncoder` supports all the encoders listed above (depending on their status)

### Icon legend

✏️: implementation planned / work in progress
✅: implemented

## License

Apache-2.0

"Spring", "Spring Boot" and "Spring Security" are [trademarks](https://spring.io/trademarks) of Pivotal Software, Inc.
