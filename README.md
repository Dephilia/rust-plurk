# rust-plurk

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Plurk API 2.0 + Oauth1 Library in Rust

The library has its own OAuth 1.0 implementation for Plurk API 2.0 usage.

- [Plurk API 2.0](https://www.plurk.com/API)
- [OAuth Core 1.0a](https://oauth.net/core/1.0a/)

The OAuth implementation is limited to, and will not implement other feature in OAuth 1.0 specification.
1. HMAC-SHA1
2. OAuth 1.0
3. With timestamp & nonce

## Usage

### Example

```toml
[dependencies]
rust-plurk = { git = https://github.com/Dephilia/rust-plurk.git }
```

TBD

### Test app

Current, the library has a console test app.

```bash
cargo build --features build-binary --release

# For help
./target/release/plurk -h

# Call API with key file
./target/release/plurk -t "key.toml" -i "/APP/Users/me"
```

The key file should be in the format:

```toml
[consumer]
key = "aabbcc"
secret = "112233"

[token]
key = "ddeeff"
secret = "445566"
```

## License

Distributed under the Apache-2.0 License. See LICENSE for more information.
