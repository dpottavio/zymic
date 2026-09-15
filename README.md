# Zymic

Zymic is a streaming Authenticated Encryption format for securing data
at rest. It's a variant of the
[STREAM](https://eprint.iacr.org/2015/189.pdf) construction and uses
AEAD (Authenticated Encryption with Associated Data) to provide both
confidentiality and integrity. The format is [openly
specified](./DESIGN.md), with a reference implementation in Rust.

## Design Principles

The Zymic format is fully [documented](./DESIGN.md) in this repo. Its
core design principles are summarized below.

* **STREAM Foundation**: Based on [STREAM online
  authenticated-encryption
  construction](https://eprint.iacr.org/2015/189.pdf), which has a
  formal security analysis.

* **Stream Oriented**: Encrypt and authenticate data streams,
  including very large ones.

* **Authenticated Encryption**: All encrypted data is authenticated,
  providing both confidentiality and integrity.

* **Key Separation**: Each encoded data stream is encrypted with a
   one-time Data Key derived from a Parent Key. A compromised Data Key
   does not compromise the Parent Key or Data Keys used by other
   streams.

* **Key Commitment**: Encoded streams are cryptographically bound to
  their Parent Key, with the design intended to prevent a stream from
  successfully authenticating under a different Parent Key.

* **Immutability**: Encoded streams must not be modified in
  place. Modifications to plaintext require a new encoded stream.

* **Resource Efficiency**: Streams can be processed with modest,
  bounded memory requirements regardless of their overall size.

## Rust Crates

This repository contains the following Rust crates:

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
