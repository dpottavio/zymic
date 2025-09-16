// SPDX-License-Identifier: MIT

//! Zymic: a streaming Authenticated Encryption with Associated Data
//! (AEAD) format.
//!
//! This crate provides a compact frame-based format and supporting types for
//! encrypting large streams (files, pipes) with integrity and authenticity.
//! It is suitable for at-rest encryption on disk and for sequential or random
//! access to encrypted data.
//!
//! This crate may be used to encrypt data to be stored on disk.
//!
//! # Getting Started
//!
//! If you’re on `std`, start with the [`stream`] module and the
//! [`ZymicStream`] type, which implements `std::io::{Read, Write,
//! Seek}` for file-like access.  For embedded / `no_std`
//! environments, use [`FrameBuf`] to build and parse encrypted frames
//! directly.
//!
//! [`stream`]: crate::stream
//! [`ZymicStream`]: crate::stream::ZymicStream
//! [`FrameBuf`]: crate::stream::FrameBuf
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod bytes;
pub mod error;
pub use error::Error;
pub mod key;
pub mod stream;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use rand_core::{TryCryptoRng, TryRngCore};

#[cfg(feature = "os_rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "os_rng")))]
pub use rand_core::OsRng;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub use serde::{Deserialize, Serialize};
