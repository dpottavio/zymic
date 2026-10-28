// SPDX-License-Identifier: MIT

//! Versioned implementations of the Zymic stream format.

#[cfg(feature = "v1")]
pub mod v1;

pub mod v2;

pub use v2::{
    CryptoAlgorithm, FrameBuf, FrameLength, Header, HeaderBuilder, HeaderBytes, HeaderNonce,
    SequenceNumber,
};

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use v2::{ZymicReader, ZymicReaderBuilder, ZymicWriter};
