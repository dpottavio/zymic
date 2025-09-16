# Zymic

Zymic is an authenticated, streaming encryption format for securing
data at rest.  It uses AEAD (Authenticated Encryption with Associated
Data) to provide both confidentiality and integrity. The format is
[openly specified](./DESIGN.md), with a reference implementation in
Rust.

[![mit-badge][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/dpottavio/zymic/blob/main/LICENSE

This repro contains the following Rust crates:

- `zymic_core` — the core library with the `ZymicStream`
  implementation and low-level primitives for encrypting/decrypting
  data in the Zymic frame format using authenticated symmetric
  encryption.

- `zymic_cli` — a command-line wrapper around `zymic_core` for easy
  file and stream encryption on the shell.

## Getting started

- Design: see [`DESIGN.md`](./DESIGN.md).
- Library users: see [`zymic_core`](./zymic_core/README.md).
- CLI users: see [`zymic_cli`](./zymic_cli/README.md).

## License

All code and documentation in this repository is licensed under the
[MIT License](https://opensource.org/license/MIT).

You are free to use, modify, and distribute this project in accordance
with the terms of that license.
