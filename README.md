# Zymic

Zymic is an authenticated, streaming encryption format for securing
data at rest.  It uses AEAD (Authenticated Encryption with Associated
Data) to provide both confidentiality and integrity. The format is
[openly specified](./DESIGN.md), with a reference implementation in
Rust.

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

Licensed under the MIT License. See
[LICENSE](https://opensource.org/license/MIT).
