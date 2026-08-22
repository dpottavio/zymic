// SPDX-License-Identifier: MIT
use crate::{
    error::{Error, ErrorKind},
    key::{ArgonSetting, KeyFile},
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indoc::indoc;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    ffi::OsStr,
    fmt, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
use zymic_core::{
    key::{ParentKey, ParentKeyId, ParentKeySecret},
    stream::{
        CryptoAlgorithm, FrameLength, Header, HeaderBuilder, HeaderBytes, HeaderNonce, ZymicStream,
    },
};

#[derive(Parser)]
#[command(
    name = "zymic",
    display_name = env!("CARGO_PKG_NAME"),
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_DESCRIBE"), ")"),
    about = "Simple file encryption tool.",
    after_help = indoc! {r#"
Examples:

- Create a key file:
  zymic key new

- Encrypt your data:
  zymic enc my_data.txt

- Decrypt your data:
  zymic dec my_data.txt.zym

- Display encrypted file information:
  zymic info my_data.txt.zym
"#})]
pub struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(after_help = indoc! {r#"
Examples:

- Decrypt a file:
  zymic dec foo.txt.zym

- Decrypt a legacy version 1 file:
  zymic dec --v1 foo.txt.zym

- Decrypt stdin and write to stdout:
  zymic dec < foo.txt.zym > foo.txt                                     
"#})]
    /// Decrypt data.
    Dec(DecArgs),
    #[command(after_help = indoc! {r#"
Examples:

- Encrypt a file
  zymic enc foo.txt

- Encrypt stdout as a filter
  tar cf - foo/ | zymic enc -o foo.tar.zym

- Encrypt stdin and write to stdout
  zymic enc < foo.txt > foo.txt.zym
"#})]
    /// Encrypt data.
    Enc(EncArgs),
    #[command(after_help = indoc! {r#"
Examples:

- Display encrypted file information:
  zymic info foo.txt.zym
"#})]
    /// Display encrypted file header information.
    Info(InfoArgs),
    /// Key file sub-commands.
    Key(KeyArgs),
}

#[derive(Args)]
struct KeyArgs {
    #[command(subcommand)]
    cmd: KeyCommand,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Create a new key file.
    #[command(after_help = indoc! {r#"
Examples:

- Create a new key file in ${HOME}/.zymic
  zymic key new

- Create a new key file in /tmp
  zymic key new -k /tmp/my_key
"#})]
    New(NewKeyFileArgs),
    /// Display key file metadata information.
    Info(KeyInfoArgs),
    /// Change password for a key file.
    Password(KeyFileArgs),
}

#[derive(Args)]
struct KeyFileArgs {
    /// Key file path (defaults to ${HOME}/.zymic/zymic_key.json)
    #[arg(short, long)]
    key: Option<PathBuf>,
}

#[derive(Args)]
struct KeyInfoArgs {
    /// Key file path (defaults to ${HOME}/.zymic/zymic_key.json)
    #[arg(short, long)]
    key: Option<PathBuf>,

    /// Perform an authentication check. (password required)
    #[arg(short, long, default_value_t = false)]
    check: bool,
}

#[derive(Debug, ValueEnum, Clone, Copy)]
enum ArgonArg {
    #[value(help = "CPU intensive Argon2 configuration.\n")]
    Cpu,
    #[value(help = "Memory intensive Argon2 configuration.\n")]
    Mem,
    #[value(help = indoc! {r#"
This setting uses the least amount of resources.
It is the least secure but most performant setting.
This should only be used for testing purposes.
"#})]
    Min,
}

#[derive(Args)]
struct NewKeyFileArgs {
    /// new key file path (defaults to ${HOME}/.zymic/zymic_key.json)
    #[arg(short, long)]
    key: Option<PathBuf>,
    #[arg(short, long, help = indoc! {r#"
Argon2 hash parameter setting. This argument tunes the
resources required to compute the Argon2 hash from the
user-provided password. It's a proof of work step to
limit the ability of an attacker to mine the user's key
password.
"#},
    default_value_t = ArgonArg::Cpu)]
    argon_config: ArgonArg,
}

#[derive(Args)]
struct DecArgs {
    /// File to decrypt, or '-' to decrypt from stdin (defaults to stdin)
    file: Option<PathBuf>,
    /// Output file, or '-' to write to stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Key file path
    #[arg(short, long)]
    key: Option<PathBuf>,
    /// Overwrite files without any check
    #[arg(short, long)]
    force: bool,
    /// Decrypt using the legacy version 1 format
    #[arg(long)]
    v1: bool,
}

#[derive(Args)]
struct EncArgs {
    /// File to encrypt, or '-' to encrypt from stdin (defaults to stdin)
    file: Option<PathBuf>,
    /// Output file, or '-' to write to stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short, long)]
    /// Key file path
    key: Option<PathBuf>,
    /// Overwrite files without any check
    #[arg(short, long)]
    force: bool,
}

#[derive(Args)]
struct InfoArgs {
    /// Encrypted file to inspect
    file: PathBuf,
    /// Authenticate the header (password required)
    #[arg(short, long)]
    auth: bool,
    /// Key file path (only used with --auth)
    #[arg(short, long, requires = "auth")]
    key: Option<PathBuf>,
}

/// CLI general input and output arguments.
struct IoArgs {
    // Data to read into the cipher.
    input: Box<dyn io::Read>,
    // Data to write from the cipher.
    output: Box<dyn io::Write>,
}

const KEY_PASSWORD_PROMPT: &str = "enter key password:";
const REENTER_KEY_PASSWORD_PROMPT: &str = "re-enter key password:";
const KEY_NEW_PASSWORD_PROMPT: &str = "enter new key password:";

impl fmt::Display for ArgonArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::Cpu => write!(f, "cpu"),
            Self::Mem => write!(f, "mem"),
            Self::Min => write!(f, "min"),
        }
    }
}

impl ArgonArg {
    /// Return the ArgonSetting instance this argument corresponds to.
    fn to_setting(self) -> ArgonSetting {
        match self {
            Self::Cpu => ArgonSetting::Cpu,
            Self::Mem => ArgonSetting::Mem,
            Self::Min => ArgonSetting::Min,
        }
    }
}

/// Return the configuration directory path if it exists.
///
/// This path may be overridden by setting the ZYMIC_DIR environment
/// variable. Otherwise, the default location is ${HOME}/.zymic.
fn config_path() -> Option<PathBuf> {
    if let Ok(dir_var) = env::var("ZYMIC_DIR") {
        Some(PathBuf::from(dir_var))
    } else if let Some(home_dir) = dirs::home_dir() {
        let mut dir = home_dir;
        dir.push(".zymic");
        Some(dir)
    } else {
        None
    }
}

/// Return a default key path located in the zymic config directory.
fn config_key_path() -> Result<PathBuf, Error> {
    let mut path = config_path().ok_or_else(|| Error::new(ErrorKind::KeyNotFound))?;
    path.push("zymic_key");
    path.set_extension("json");
    Ok(path)
}

/// Return the path to the key. If `path` is None, the function will
/// try to find the key in the config directory. Return Error if a key
/// cannot be found or the `path` parameter is invalid.
fn resolve_key_path(path: Option<PathBuf>) -> Result<PathBuf, Error> {
    let key_path = match path {
        Some(path) => path,
        None => config_key_path()?,
    };
    if !key_path.exists() {
        return Err(Error::new(ErrorKind::KeyNotFound));
    }
    Ok(key_path)
}

/// Set the key file permissions. Currently only supports UNIX
/// platforms.
fn set_key_permission(path: &PathBuf) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn create_file(out_path: &Path, force: bool) -> Result<fs::File, Error> {
    let mut open_opts = fs::OpenOptions::new();
    open_opts
        .write(true)
        .create(force) // --force, create if missing
        .truncate(force) // --force, overwrite if exists
        .create_new(!force); // no force flag, fail if exists
    #[cfg(unix)]
    open_opts.mode(0o600);
    let file = open_opts.open(out_path)?;
    Ok(file)
}

/// Return an io::Write instance from an output path argument.
fn out_path_to_io(out_path: &Path, force: bool) -> Result<Box<dyn io::Write>, Error> {
    if out_path.is_dir() {
        Err(Error::new(ErrorKind::OutputIsDir))
    } else if !is_path_stdio(out_path.as_os_str()) {
        Ok(Box::new(create_file(out_path, force)?))
    } else {
        Ok(Box::new(io::stdout()))
    }
}

/// Return true of the `path` represents a standard in or out argument.
fn is_path_stdio(path: &OsStr) -> bool {
    path == OsStr::new("-")
}

/// Return a `PathBuf` that represents standard in or out argument.
fn stdio_path() -> PathBuf {
    PathBuf::from("-")
}

/// Return an IoArgs instance suitable for encryption.
fn enc_args_to_io(
    in_path: Option<PathBuf>,
    out_path: Option<PathBuf>,
    force: bool,
) -> Result<IoArgs, Error> {
    let in_path = in_path.unwrap_or_else(stdio_path);

    let input: Box<dyn io::Read> = if !is_path_stdio(in_path.as_os_str()) {
        if in_path.is_dir() {
            return Err(Error::new(ErrorKind::DirNotSupported));
        }
        Box::new(fs::OpenOptions::new().read(true).open(&in_path)?)
    } else {
        Box::new(io::stdin())
    };

    let output = out_path.map_or_else(
        || {
            let io: Box<dyn io::Write> = if !is_path_stdio(in_path.as_os_str()) {
                // Use the input file path plus the zym extension as the
                // output path.
                let mut path = PathBuf::from(&in_path);
                if let Some(name) = path.file_name() {
                    path.set_file_name(format!("{}.zym", name.to_string_lossy()));
                    let file = create_file(path.as_path(), force)?;
                    Box::new(file)
                } else {
                    Box::new(io::stdout())
                }
            } else {
                Box::new(io::stdout())
            };
            Ok::<Box<dyn io::Write>, Error>(io)
        },
        |path| {
            let io = out_path_to_io(&path, force)?;
            Ok(io)
        },
    )?;

    Ok(IoArgs { input, output })
}

/// Return an IoArgs instance sutable for decryption.
fn dec_args_to_io(
    in_path: Option<PathBuf>,
    out_path: Option<PathBuf>,
    force: bool,
) -> Result<IoArgs, Error> {
    let in_path = in_path.unwrap_or_else(stdio_path);

    let input: Box<dyn io::Read> = if !is_path_stdio(in_path.as_os_str()) {
        if in_path.is_dir() {
            return Err(Error::new(ErrorKind::DirNotSupported));
        }
        if let Some(ext) = in_path.extension() {
            if ext != "zym" {
                return Err(Error::new(ErrorKind::InvalidExtension));
            }
        } else {
            return Err(Error::new(ErrorKind::InvalidExtension));
        }
        Box::new(fs::OpenOptions::new().read(true).open(&in_path)?)
    } else {
        Box::new(io::stdin())
    };

    let output = out_path.map_or_else(
        || {
            let io: Box<dyn io::Write> = if !is_path_stdio(in_path.as_os_str()) {
                // Use the input file path minus the zym extension as the
                // output path.
                let mut path = PathBuf::from(&in_path);
                path.set_extension("");
                let file = create_file(path.as_path(), force)?;
                Box::new(file)
            } else {
                Box::new(io::stdout())
            };
            Ok::<Box<dyn std::io::Write>, Error>(io)
        },
        |path| {
            let io = out_path_to_io(&path, force)?;
            Ok(io)
        },
    )?;

    Ok(IoArgs { input, output })
}

/// Decrypt a stream encoded using the current format.
fn decrypt_v2<R, W>(input: &mut R, output: &mut W, key: &ParentKey) -> Result<(), Error>
where
    R: io::Read + ?Sized,
    W: io::Write + ?Sized,
{
    let mut header_bytes = HeaderBytes::default();
    input.read_exact(&mut header_bytes)?;
    let header = Header::from_bytes(key, header_bytes)?;

    let mut buf_writer = io::BufWriter::new(output);
    let mut reader = ZymicStream::new(input, &header);
    io::copy(&mut reader, &mut buf_writer)?;
    reader.is_eof_or_err()?;
    buf_writer.flush()?;
    Ok(())
}

/// Decode and print header fields.
fn print_header_info(bytes: &HeaderBytes) {
    const VERSION_OFFSET: usize = 4;
    const ALGORITHM_OFFSET: usize = 5;
    const FRAME_LEN_OFFSET: usize = 7;
    const PARENT_KEY_ID_OFFSET: usize = 32;

    let algorithm = u16::from_le_bytes([bytes[ALGORITHM_OFFSET], bytes[ALGORITHM_OFFSET + 1]]);
    let frame_len = bytes[FRAME_LEN_OFFSET];
    let parent_key_id = &bytes[PARENT_KEY_ID_OFFSET..PARENT_KEY_ID_OFFSET + ParentKeyId::LEN];

    println!("version:\t{}", bytes[VERSION_OFFSET]);
    if algorithm == CryptoAlgorithm::Aes256GcmHkdfSha256 as u16 {
        println!("algorithm:\t{}", CryptoAlgorithm::Aes256GcmHkdfSha256);
    } else {
        println!("algorithm:\t{algorithm}");
    }
    if let Some(frame_len) = 1usize.checked_shl(frame_len.into()) {
        println!("frame-length:\t{frame_len}");
    } else {
        println!("frame-length:\t2^{frame_len}");
    }
    print!("parent-key-id:\t");
    for (index, byte) in parent_key_id.iter().enumerate() {
        print!("{byte:02x}");
        if index + 1 < parent_key_id.len() {
            print!(":");
        }
    }
    println!();
}

/// Decrypt a stream encoded using the legacy version 1 format.
fn decrypt_v1<R, W>(input: &mut R, output: &mut W, key: &ParentKey) -> Result<(), Error>
where
    R: io::Read + ?Sized,
    W: io::Write + ?Sized,
{
    use zymic_core::stream::v1::{Header, HeaderBytes, Reader};

    let mut header_bytes = HeaderBytes::default();
    input.read_exact(&mut header_bytes)?;
    let header = Header::from_bytes(key, header_bytes)?;

    let mut buf_writer = io::BufWriter::new(output);
    let mut reader = Reader::new(input, &header);
    io::copy(&mut reader, &mut buf_writer)?;
    reader.is_eof_or_err()?;
    buf_writer.flush()?;
    Ok(())
}

pub fn handle_input() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Key(args) => match args.cmd {
            KeyCommand::New(args) => {
                let key_path = match args.key {
                    Some(path) => path,
                    None => config_key_path()?,
                };
                if key_path.exists() {
                    return Err(Error::new(ErrorKind::KeyExists(format!(
                        "{}",
                        key_path.display()
                    ))));
                }
                println!("creating key: {}", key_path.display());

                let password = Zeroizing::new(rpassword::prompt_password(KEY_PASSWORD_PROMPT)?);
                let password_chk =
                    Zeroizing::new(rpassword::prompt_password(REENTER_KEY_PASSWORD_PROMPT)?);
                if password != password_chk {
                    return Err(Error::new(ErrorKind::PasswordMismatch));
                }
                let id = ParentKeyId::try_from_fill(getrandom::fill)?;
                let secret = ParentKeySecret::try_from_fill(getrandom::fill)?;

                let key_file =
                    KeyFile::new(id, &secret, args.argon_config.to_setting(), &password)?;

                if let Some(parent) = key_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = create_file(&key_path, false)?;
                serde_json::to_writer(file, &key_file)?;
                set_key_permission(&key_path)?;
            }
            KeyCommand::Info(args) => {
                let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
                let file = fs::OpenOptions::new().read(true).open(&key_path)?;
                let key: KeyFile = serde_json::from_reader(file)?;
                if args.check {
                    let password = Zeroizing::new(rpassword::prompt_password(KEY_PASSWORD_PROMPT)?);
                    let _ = key.unwrap(&password)?;
                }
                println!("path:\t{}\n{key}", key_path.display());
            }
            KeyCommand::Password(args) => {
                let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
                println!("changing password for key: {}", key_path.display());

                let file = fs::OpenOptions::new().read(true).open(&key_path)?;
                let mut key: KeyFile = serde_json::from_reader(file)?;
                let old_password = Zeroizing::new(rpassword::prompt_password(KEY_PASSWORD_PROMPT)?);

                let new_password =
                    Zeroizing::new(rpassword::prompt_password(KEY_NEW_PASSWORD_PROMPT)?);
                if new_password == old_password {
                    return Err(Error::new(ErrorKind::PasswordNoChange));
                }
                let new_password_chk =
                    Zeroizing::new(rpassword::prompt_password(REENTER_KEY_PASSWORD_PROMPT)?);
                if new_password != new_password_chk {
                    return Err(Error::new(ErrorKind::PasswordMismatch));
                }

                key.rewrap(&old_password, &new_password)?;
                let file = fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&key_path)?;
                serde_json::to_writer(file, &key)?;
                set_key_permission(&key_path)?;
            }
        },
        Command::Enc(args) => {
            let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
            let file = fs::OpenOptions::new().read(true).open(&key_path)?;
            let key_file: KeyFile = serde_json::from_reader(file)?;
            let password = Zeroizing::new(rpassword::prompt_password(KEY_PASSWORD_PROMPT)?);
            let parent_key = key_file.unwrap(&password)?;

            let mut io_args = enc_args_to_io(args.file, args.output, args.force)?;

            let nonce = HeaderNonce::try_from_fill(getrandom::fill)?;

            let header = HeaderBuilder::new(&parent_key, &nonce)
                .with_frame_len(FrameLength::Len64KiB)
                .build();
            let header_bytes = header.bytes();
            io_args.output.write_all(header_bytes)?;

            let mut writer = ZymicStream::new(io_args.output, &header);
            let mut buf_reader = io::BufReader::new(io_args.input);
            io::copy(&mut buf_reader, &mut writer)?;
            writer.eof()?;
        }
        Command::Info(args) => {
            let mut input = fs::OpenOptions::new().read(true).open(args.file)?;
            let mut header_bytes = HeaderBytes::default();
            input.read_exact(&mut header_bytes)?;
            if args.auth {
                let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
                let file = fs::OpenOptions::new().read(true).open(&key_path)?;
                let key_file: KeyFile = serde_json::from_reader(file)?;
                let password = Zeroizing::new(rpassword::prompt_password(KEY_PASSWORD_PROMPT)?);
                let parent_key = key_file.unwrap(&password)?;
                Header::from_bytes(&parent_key, header_bytes.clone())?;
            }
            print_header_info(&header_bytes);
        }
        Command::Dec(args) => {
            let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
            let file = fs::OpenOptions::new().read(true).open(&key_path)?;
            let key_file: KeyFile = serde_json::from_reader(file)?;
            let password = Zeroizing::new(rpassword::prompt_password(KEY_PASSWORD_PROMPT)?);
            let key = key_file.unwrap(&password)?;

            let mut io_args = dec_args_to_io(args.file, args.output, args.force)?;
            if args.v1 {
                decrypt_v1(&mut *io_args.input, &mut *io_args.output, &key)?;
            } else {
                decrypt_v2(&mut *io_args.input, &mut *io_args.output, &key)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_v1, Cli, Command};
    use clap::Parser;
    use std::{io::Cursor, path::PathBuf};
    use zymic_core::{
        byte_array,
        key::{ParentKey, ParentKeyId, ParentKeySecret},
    };

    // Generated by zymic_core's v1 writer. Keeping the small fixture inline
    // makes the CLI crate's tests self-contained when it is packaged alone.
    const V1_FIXTURE: &[u8] = &[
        46, 122, 121, 109, 1, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 87, 178, 58, 147, 237, 175, 99,
        145, 82, 62, 144, 187, 133, 51, 191, 23, 74, 164, 103, 235, 121, 194, 204, 223, 129, 19,
        140, 159, 168, 204, 201, 142, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0, 193, 99,
        105, 105, 22, 200, 98, 61, 80, 146, 174, 97, 206, 88, 147, 223, 190, 171, 244, 160, 136,
        121, 184, 121, 43, 255, 211, 170, 195, 154, 105, 30, 114, 54, 131, 88, 238, 182, 230, 129,
        251, 153, 21,
    ];

    fn v1_parent_key() -> ParentKey {
        const ID: ParentKeyId = byte_array![1u8; 16];
        const SECRET: ParentKeySecret = byte_array![2u8; 32];
        ParentKey::new(ID, SECRET)
    }

    #[test]
    fn dec_v1_argument() {
        let cli = Cli::try_parse_from(["zymic", "dec", "--v1", "archive.zym"]).unwrap();

        let Command::Dec(args) = cli.cmd else {
            panic!("expected dec command");
        };
        assert!(args.v1);
    }

    #[test]
    fn info_argument() {
        let cli = Cli::try_parse_from([
            "zymic",
            "info",
            "archive.zym",
            "--auth",
            "--key",
            "key.json",
        ])
        .unwrap();

        let Command::Info(args) = cli.cmd else {
            panic!("expected info command");
        };
        assert_eq!(args.file, PathBuf::from("archive.zym"));
        assert!(args.auth);
        assert_eq!(args.key, Some(PathBuf::from("key.json")));
    }

    #[test]
    fn info_defaults_to_unauthenticated() {
        let cli = Cli::try_parse_from(["zymic", "info", "archive.zym"]).unwrap();

        let Command::Info(args) = cli.cmd else {
            panic!("expected info command");
        };
        assert!(!args.auth);
        assert_eq!(args.key, None);
    }

    #[test]
    fn dec_v1_fixture() {
        let mut input = Cursor::new(V1_FIXTURE);
        let mut output = Vec::new();

        decrypt_v1(&mut input, &mut output, &v1_parent_key()).unwrap();

        assert_eq!(output, b"v1 invocation compatibility");
    }
}
