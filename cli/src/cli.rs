// SPDX-License-Identifier: MIT
use crate::{
    error::{Error, ErrorKind},
    key::{ArgonSetting, KeyFile},
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indoc::indoc;
use std::{
    env,
    ffi::OsStr,
    fmt, fs, io,
    path::{Path, PathBuf},
};
use zymic_core::{
    key::{ParentKeyId, ParentKeySecret},
    stream::{Header, HeaderBuilder, HeaderBytes, HeaderNonce, ZymicStream},
    OsRng,
};

#[derive(Parser)]
#[command(
    name = "zymic",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_DESCRIBE"), ")"),
    about = "Stream-oriented encryption CLI",
    after_help = indoc! {r#"
Examples:

- Create a key file:
  zymic key new

- Encrypt your data:
  zymic enc my_data.txt

- Decrypt your data:
  zymic dec my_data.txt.zym
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
    let file = fs::OpenOptions::new()
        .write(true)
        .create(force) // --force, create if missing
        .truncate(force) // --force, overwrite if exists
        .create_new(!force) // no force flag, fail if exists
        .open(out_path)?;
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

                let password = rpassword::prompt_password(KEY_PASSWORD_PROMPT)?;
                let password_chk = rpassword::prompt_password(REENTER_KEY_PASSWORD_PROMPT)?;
                if password != password_chk {
                    return Err(Error::new(ErrorKind::PasswordMismatch));
                }
                let id = ParentKeyId::try_from_crypto_rand(&mut OsRng)?;
                let secret = ParentKeySecret::try_from_crypto_rand(&mut OsRng)?;

                let key_file =
                    KeyFile::new(id, &secret, args.argon_config.to_setting(), &password)?;

                if let Some(parent) = key_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&key_path)?;
                serde_json::to_writer(file, &key_file)?;
                set_key_permission(&key_path)?;
            }
            KeyCommand::Info(args) => {
                let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
                let file = fs::OpenOptions::new().read(true).open(&key_path)?;
                let key: KeyFile = serde_json::from_reader(file)?;
                if args.check {
                    let password = rpassword::prompt_password(KEY_PASSWORD_PROMPT)?;
                    let _ = key.unwrap(&password)?;
                }
                println!("path:\t{}\n{key}", key_path.display());
            }
            KeyCommand::Password(args) => {
                let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
                println!("changing password for key: {}", key_path.display());

                let file = fs::OpenOptions::new().read(true).open(&key_path)?;
                let mut key: KeyFile = serde_json::from_reader(file)?;
                let old_password = rpassword::prompt_password(KEY_PASSWORD_PROMPT)?;

                let new_password = rpassword::prompt_password(KEY_NEW_PASSWORD_PROMPT)?;
                if new_password == old_password {
                    return Err(Error::new(ErrorKind::PasswordNoChange));
                }
                let new_password_chk = rpassword::prompt_password(REENTER_KEY_PASSWORD_PROMPT)?;
                if new_password != new_password_chk {
                    return Err(Error::new(ErrorKind::PasswordMismatch));
                }

                key.rewrap(&old_password, &new_password)?;
                let file = fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&key_path)?;
                serde_json::to_writer(file, &key)?;
            }
        },
        Command::Enc(args) => {
            let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
            let file = fs::OpenOptions::new().read(true).open(&key_path)?;
            let key_file: KeyFile = serde_json::from_reader(file)?;
            let password = rpassword::prompt_password(KEY_PASSWORD_PROMPT)?;
            let parent_key = key_file.unwrap(&password)?;

            let mut io_args = enc_args_to_io(args.file, args.output, args.force)?;

            let nonce = HeaderNonce::try_from_crypto_rand(&mut OsRng)?;

            let header = HeaderBuilder::new(&parent_key, &nonce).build();
            let header_bytes = header.bytes();
            io_args.output.write_all(header_bytes)?;

            let mut writer = ZymicStream::new(io_args.output, &header);
            let mut buf_reader = io::BufReader::new(io_args.input);
            io::copy(&mut buf_reader, &mut writer)?;
            writer.eof()?;
        }
        Command::Dec(args) => {
            let key_path = fs::canonicalize(resolve_key_path(args.key)?)?;
            let file = fs::OpenOptions::new().read(true).open(&key_path)?;
            let key_file: KeyFile = serde_json::from_reader(file)?;
            let password = rpassword::prompt_password(KEY_PASSWORD_PROMPT)?;
            let key = key_file.unwrap(&password)?;

            let mut io_args = dec_args_to_io(args.file, args.output, args.force)?;

            let mut header_bytes = HeaderBytes::default();
            io_args.input.read_exact(&mut header_bytes)?;
            let header = Header::from_bytes(&key, header_bytes)?;

            let mut buf_writer = io::BufWriter::new(io_args.output);
            let mut reader = ZymicStream::new(io_args.input, &header);
            io::copy(&mut reader, &mut buf_writer)?;
            reader.is_eof_or_err()?;
        }
    }
    Ok(())
}
