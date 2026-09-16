# 🔒 zymic_core

[![crates-badge][crates-badge]][crates-url]
[![docs-badge][docs-badge]][docs-url]
[![mit-badge][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/zymic_core
[crates-url]: https://crates.io/crates/zymic_core
[docs-badge]: https://docs.rs/zymic_core/badge.svg
[docs-url]: https://docs.rs/zymic_core
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/dpottavio/zymic/blob/main/LICENSE

An implementation of the Zymic authenticated encryption format for
protecting data at rest. It provides streaming encryption and
decryption through Rust’s `std::io` traits, plus lower-level frame APIs
for `no_std` environments with allocation support. Large streams can be
processed with bounded memory.

Zymic is a variant of the [STREAM online authenticated-encryption
construction](https://eprint.iacr.org/2015/189.pdf). For more
information regarding the design and format of Zymic, see the source
repo's main
[README](https://github.com/dpottavio/zymic#-design-principles).

See [API documentation][docs-url] for usage examples.

## ⚖️  License

This crate is licensed under the [MIT
License](https://opensource.org/license/MIT).
