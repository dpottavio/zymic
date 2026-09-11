// SPDX-License-Identifier: MIT

//! Zymic: a streaming Authenticated Encryption with Associated Data
//! (AEAD) format.
//!
//! This crate provides a compact frame-based format and supporting types for
//! encrypting large streams (files, pipes) with integrity and authenticity.
//! It is suitable for at-rest encryption on disk and for sequential or random
//! access to encrypted data.
//!
//! # Getting Started
//!
#![cfg_attr(
    feature = "std",
    doc = "Start with the [`stream::v2`] module
    and the [`ZymicReader`] and [`ZymicWriter`] types, which implement
    the appropriate [`std::io`] traits for file-like access.

[`ZymicReader`]: crate::stream::ZymicReader
[`ZymicWriter`]: crate::stream::ZymicWriter
[`stream`]: crate::stream::v2
"
)]
//! For embedded / `no_std` environments, use [`FrameBuf`] to build and parse
//! encrypted frames directly.
//!
//! [`stream`]: crate::stream
//! [`FrameBuf`]: crate::stream::FrameBuf
//!
//! # Stream Immutability
//!
//! Streams are immutable. Once encoded, a stream's Header and Frames
//! must not be modified. Any change to the plaintext must be encoded
//! as a new stream.
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

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub use serde::{Deserialize, Serialize};
