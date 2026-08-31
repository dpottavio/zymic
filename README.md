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

## Version 2

Version 2 of the format is on `main` and is currently a
work-in-progress. The new format contains the following improvements:

* Streams are now immutable. In v1, an attacker could replay an older
  frame or stream, rolling back its invocation counter. If the
  application subsequently modified and re-encrypted that data, it
  could reuse a previously used AEAD nonce. In v2, modifications must
  be encoded as a new stream with a fresh Data Key, preventing this
  rollback-induced nonce reuse.

* Frame headers have been reduced from 16 bytes to 8 bytes. Now that
  streams are immutable, the 8 byte invocation count is no longer
  needed.

* The HKDF routine for generating data keys and header MAC has been
  simplified to two expand functions.

⚠️ The new format is not backward compatible with v1. Read-only
support of v1 data is supported going forward via the `v1` feature
flag.

## License

All code and documentation in this repository is licensed under the
[MIT License](https://opensource.org/license/MIT).

You are free to use, modify, and distribute this project in accordance
with the terms of that license.
