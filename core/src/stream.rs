// SPDX-License-Identifier: MIT

//! Versioned implementations of the Zymic stream format.

#[cfg(feature = "v1")]
pub mod v1;

pub mod v2;

pub use v2::{
    FrameBuf, FrameHeader, FrameHeaderBuilder, FrameLength, Header, HeaderBuilder, HeaderBytes,
    HeaderNonce,
};

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use v2::ZymicStream;
