// SPDX-License-Identifier: MIT
use std::{fmt, time::SystemTimeError};

#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    kind: ErrorKind,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ErrorKind {
    Authentication,
    Core(zymic_core::Error),
    DirNotSupported,
    InvalidExtension,
    Io(String),
    Json(String),
    OutputIsDir,
    Kdf(String),
    KeyExists(String),
    KeyNotFound,
    PasswordMismatch,
    PasswordNoChange,
    SysTime(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            ErrorKind::Authentication => write!(f, "authentication failure"),
            ErrorKind::Core(e) => write!(f, "{e}"),
            ErrorKind::DirNotSupported => write!(f, "directory encryption is not supported"),
            ErrorKind::InvalidExtension => write!(
                f,
                "input file extension is not valid, only .zym is supported"
            ),
            ErrorKind::Io(e) => write!(f, "{e}"),
            ErrorKind::Json(e) => write!(f, "json: {e}"),
            ErrorKind::OutputIsDir => write!(f, "output file is a directory"),
            ErrorKind::Kdf(e) => write!(f, "key derivation: {e}"),
            ErrorKind::KeyExists(k) => write!(f, "key '{k}' already exists"),
            ErrorKind::KeyNotFound => write!(f, "key file could not be found"),
            ErrorKind::PasswordMismatch => write!(f, "passwords do not match"),
            ErrorKind::PasswordNoChange => write!(f, "new password is the same as old password"),
            ErrorKind::SysTime(e) => write!(f, "failed to get system time: {e}"),
        }?;
        Ok(())
    }
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl std::error::Error for Error {}

impl From<zymic_core::Error> for Error {
    fn from(error: zymic_core::Error) -> Self {
        Self::new(ErrorKind::Core(error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorKind::Io(error.to_string()))
    }
}

impl From<argon2::Error> for Error {
    fn from(error: argon2::Error) -> Self {
        Self::new(ErrorKind::Kdf(error.to_string()))
    }
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        Self::other(error)
    }
}

impl From<SystemTimeError> for Error {
    fn from(error: SystemTimeError) -> Self {
        Self::new(ErrorKind::SysTime(error.to_string()))
    }
}

impl From<aes_kw::Error> for Error {
    fn from(_: aes_kw::Error) -> Self {
        Self::new(ErrorKind::Authentication)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::new(ErrorKind::Json(error.to_string()))
    }
}
