# zymic_core

[![crates-badge][crates-badge]][crates-url]
[![docs-badge][docs-badge]][docs-url]
[![mit-badge][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/zymic_core
[crates-url]: https://crates.io/crates/zymic_core
[docs-badge]: https://docs.rs/zymic_core/badge.svg
[docs-url]: https://docs.rs/zymic_core
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/dpottavio/zymic/blob/main/LICENSE

Core library providing the primitives and streaming APIs for the Zymic
authenticated encryption format. It implements the `ZymicStream` type
and frame-based AEAD encryption/decryption with support for both `std`
and `no_std` environments.

## Features

- **`std`** (default): Enables `std::io::{Read, Write, Seek}` support
  for streaming APIs.

- **`no_std`**: Available by disabling the default `std` feature.

- **`serde`**: Adds `serde` serialization support for the `ByteArray`
  type.

- **`os_rng`**: Enables an RNG-agnostic constructor for `ByteArray`
  (`try_from_crypto_rand`), requiring `rand::TryCryptoRng +
  rand::TryRngCore`.

## License

All code and documentation in this repository is licensed under the
[MIT License](https://opensource.org/license/MIT).

You are free to use, modify, and distribute this project in accordance
with the terms of that license.
