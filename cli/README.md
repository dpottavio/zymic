# Zymic CLI

[![crates-badge][crates-badge]][crates-url]
[![docs-badge][docs-badge]][docs-url]
[![mit-badge][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/zymic_cli
[crates-url]: https://crates.io/crates/zymic_cli
[docs-badge]: https://docs.rs/zymic_cli/badge.svg
[docs-url]: https://docs.rs/zymic_cli
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/dpottavio/zymic/blob/main/LICENSE

Encrypt and decrypt files using the Zymic format.

`zymic` is a command-line tool for encrypting data with a
password-protected key file. Each stream is encrypted with a unique
one-time key, and decryption verifies integrity to detect any
tampering, truncation, or reordering.

`zymic` functions as a stream filter: it can operate on individual
files or through `stdin`/`stdout`. To encrypt a directory or multiple
files, first package them into a single archive (e.g., `tar`, `zip`).

## Install

### From Source (Linux/macOS/Windows)

1. [Install Rust](https://www.rust-lang.org/learn/get-started).

2. Install the `zymic` cli:
```bash
cargo install --locked zymic_cli
```

Cargo places binaries in your user bin dir:

* Linux/macOS: `~/.cargo/bin` (add to `PATH` if needed)

* Windows: `%USERPROFILE%\.cargo\bin` (rustup usually adds this
  automatically)

### From Tarball (Linux)

1. Obtain the tarball and `SHA256SUM.txt` files from the GitHub
   release page.

2. Extract files.
```bash
tar axf zymic-<version>-<platform>.tar.gz
```

3. (Optional) Verify SHA256 checksums.
```bash
sha256sum -c SHA256SUM.txt
```

4. Run the install script.
```bash
cd zymic-<version>-<version>
./install.sh
```

The default destination of the installation (`/usr/local`) may be
overriden by setting the `PREFIX` environment variable.
```bash
PREFIX="$HOME/.local" ./install.sh
```

## Quick start

```bash
# Create a key (prompts for a new password)
zymic key new # creates ~/.zymic/zymic_key.json by default

# Encrypt a file
zymic enc foo.txt

# Decrypt a file
zymic dec foo.txt.zym
```
## Usage

```
Usage: zymic <COMMAND>

Commands:
  dec   Decrypt data
  enc   Encrypt data
  key   Key file sub-commands
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Subcommands

### `enc`

Encrypt data.

```
Usage: zymic enc [OPTIONS] [FILE]

Arguments:
  [FILE]  File to encrypt, or '-' to encrypt from stdin (defaults to stdin)

Options:
  -o, --output <OUTPUT>  Output file, or '-' to write to stdout
  -k, --key <KEY>        Key file path
  -f, --force            Overwrite files without any check
  -h, --help             Print help
```

Default output is `FILE` + "`.zym`" (e.g., `foo.txt` → `foo.txt.zym`)

### `dec`

Decrypt data.

```
Usage: zymic dec [OPTIONS] [FILE]

Arguments:
  [FILE]  File to decrypt, or '-' to decrypt from stdin (defaults to stdin)

Options:
  -o, --output <OUTPUT>  Output file, or '-' to write to stdout
  -k, --key <KEY>        Key file path
  -f, --force            Overwrite files without any check
  -h, --help             Print help

```

Default output strips the `.zym` extension from the `FILE` (e.g.,
`foo.txt.zym` → `foo.txt`).

### `key new`

Create a new key file.

```
Usage: zymic key new [OPTIONS]

Options:
  -k, --key <KEY>
          new key file path (defaults to ${HOME}/.zymic/zymic_key.json)

  -a, --argon-config <ARGON_CONFIG>
          Argon2 hash parameter setting. This argument tunes the
          resources required to compute the Argon2 hash from the
          user-provided password. It's a proof of work step to
          limit the ability of an attacker to mine the user's
          key password.

          [default: cpu]

          Possible values:
          - cpu: CPU intensive Argon2 configuration.

          - mem: Memory intensive Argon2 configuration.

          - min: This setting uses the least amount of resources.
            It is the least secure but most performant setting.
            This should only be used for testing purposes.

  -h, --help
          Print help (see a summary with '-h')
```

### `key info`

Display key file metadata information

```
Usage: zymic key info [OPTIONS]

Options:
  -k, --key <KEY>  Key file path (defaults to ${HOME}/.zymic/zymic_key.json)
  -c, --check      Perform an authentication check. (password required)
  -h, --help       Print help
```

### `key password`

Change password for a key file.

```
Usage: zymic key password [OPTIONS]

Options:
  -k, --key <KEY>  Key file path (defaults to ${HOME}/.zymic/zymic_key.json)
  -h, --help       Print help
```

### Environment Variables

`ZYMIC_DIR` overrides the default configuration directory used to
locate the key file. If unset, the default is `$HOME/.zymic` (on
Linux/macOS) or `%USERPROFILE%\.zymic` (on Windows).

### Exit Status

* 0: Success.

* non-zero: An error occurred (invalid arguments, I/O error, integrity
  check failed, bad password, etc.)

### Files

* Default key path: `$ZYMIC_DIR/zymic_key.json`

* Default config directory if ZYMIC_DIR is not set: `$HOME/.zymic`

## Key File

`zymic` uses a password-protected key file to encrypt and decrypt
data. The key file contains a Parent Key, from which a unique,
one-time Data Key is derived for each stream.  The Data Key is then
used to encrypt the input file.

The key file is required for decryption.  If the key file is lost, any
data encrypted with it is permanently unrecoverable.

## Examples

```bash
# Encrypt a file to the default output (adds ".zym"):
zymic enc foo.txt

# Decrypt a file to the default output (strips ".zym"):
zymic dec foo.txt.zym

# Encrypt with explicit output:
zymic enc -o secret.zym foo.txt

# Stream from stdin to a file:
tar cf - src | zymic enc -o src.tar.zym

# Stream from a file to stdout:
zymic dec -o - src.tar.zym | tar xf -

```

## License

All code and documentation in this repository is licensed under the
[MIT License](https://opensource.org/license/MIT).

You are free to use, modify, and distribute this project in accordance
with the terms of that license.
