// SPDX-License-Identifier: MIT
//! Error types for the Zymic core crate.
use alloc::string::{String, ToString};
use core::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    kind: ErrorKind,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ErrorKind {
    Authentication,
    Cipher(String),
    #[cfg(feature = "std")]
    IntegerOverflow,
    InvalidArgument,
    InvalidArrayLength(usize, usize),
    InvalidBufLength,
    InvalidEndLength(u32),
    InvalidFrameLength(u8),
    InvalidMagicNumber(u32),
    #[cfg(feature = "std")]
    Io(String),
    ParentKeyIdMismatch,
    #[cfg(feature = "rand_core")]
    Rng(String),
    #[cfg(feature = "std")]
    Truncation,
    TryFromInt(core::num::TryFromIntError),
    #[cfg(feature = "std")]
    UnexpectedEof,
    UnexpectedSeqNum(u32, u32),
    UnsupportedCrypto(u16),
    UnsupportedVersion(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            ErrorKind::Authentication => write!(f, "authentication failure"),
            ErrorKind::Cipher(e) => write!(f, "cipher failure: {e}"),
            #[cfg(feature = "std")]
            ErrorKind::IntegerOverflow => write!(f, "integer overflow"),
            ErrorKind::InvalidArgument => write!(f, "invalid argument"),
            ErrorKind::InvalidArrayLength(e, r) => {
                write!(f, "invalid array length: expected {e}, received {r}")
            }
            ErrorKind::InvalidBufLength => write!(f, "invalid buffer length"),
            ErrorKind::InvalidEndLength(n) => {
                write!(f, "invalid end length of {n} bytes")
            }
            ErrorKind::InvalidFrameLength(n) => {
                write!(f, "invalid frame length of 2^{n} bytes")
            }
            ErrorKind::InvalidMagicNumber(n) => write!(f, "invalid magic number: {n}"),
            #[cfg(feature = "std")]
            ErrorKind::Io(e) => write!(f, "I/O error: {e}"),
            ErrorKind::ParentKeyIdMismatch => write!(
                f,
                "parent key ID does not match the parent key ID found in the header"
            ),
            #[cfg(feature = "rand_core")]
            ErrorKind::Rng(e) => write!(f, "failed to generate random data: {e}"),
            #[cfg(feature = "std")]
            ErrorKind::Truncation => write!(f, "data has been truncated"),
            ErrorKind::TryFromInt(e) => write!(f, "integer conversion failure: {e}"),
            #[cfg(feature = "std")]
            ErrorKind::UnexpectedEof => write!(f, "unexpected end of file"),
            ErrorKind::UnexpectedSeqNum(e, r) => write!(
                f,
                "unexpected sequence number: expected {e}, but received {r}"
            ),
            ErrorKind::UnsupportedCrypto(v) => write!(f, "unsupported crypto algorithm: {v}"),
            ErrorKind::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
        }?;
        Ok(())
    }
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorKind::Io(error.to_string()))
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        Self::other(error)
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(error: aes_gcm::Error) -> Self {
        Self::new(ErrorKind::Cipher(error.to_string()))
    }
}

impl From<core::num::TryFromIntError> for Error {
    fn from(error: core::num::TryFromIntError) -> Self {
        Self::new(ErrorKind::TryFromInt(error))
    }
}
