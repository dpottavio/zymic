# Zymic

Zymic is a streaming authenticated encryption format for securing
data at rest.  It uses AEAD (Authenticated Encryption with Associated
Data) to provide both confidentiality and integrity. The format is
[openly specified](./DESIGN.md), with a reference implementation in
Rust.

This repro contains the following Rust crates:

| Crate Name | crates.io | Rust Docs | Description
|------------|-----------|-----------|------------|
| [zymic_cli](./cli/README.md)  |  [![cli-crates-badge][cli-crates-badge]][cli-crates-url] | [![cli-docs-badge][cli-docs-badge]][cli-docs-url] | CLI for encrypting files | 
| [zymic_core](./core/README.md)  |  [![core-crates-badge][core-crates-badge]][core-crates-url] | [![core-docs-badge][core-docs-badge]][core-docs-url] | Core library | 

[cli-crates-badge]: https://img.shields.io/crates/v/zymic_cli
[cli-crates-url]: https://crates.io/crates/zymic_cli
[cli-docs-badge]: https://docs.rs/zymic_cli/badge.svg
[cli-docs-url]: https://docs.rs/zymic_cli

[core-crates-badge]: https://img.shields.io/crates/v/zymic_core
[core-crates-url]: https://crates.io/crates/zymic_core
[core-docs-badge]: https://docs.rs/zymic_core/badge.svg
[core-docs-url]: https://docs.rs/zymic_core

## License

All code and documentation in this repository is licensed under the
[MIT License](https://opensource.org/license/MIT).

You are free to use, modify, and distribute this project in accordance
with the terms of that license.
