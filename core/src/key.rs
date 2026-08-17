// SPDX-License-Identifier: MIT
//! A module for defining cryptographic key types.
use crate::{bytes::ByteArray, error::Error};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Parent Key identifier buffer. A Parent Key is a cryptographic key
/// used to derive per-stream subkeys.
pub type ParentKeyId = ByteArray<16>;

/// Parent Key secret buffer.
pub type ParentKeySecret = ByteArray<32>;

/// A type representing a Zymic Parent Key.
///
/// A Parent Key is a cryptographic key used to derive per-stream Data Keys
/// via a Key Derivation Function (KDF). It consists of:
///
/// - A 16-byte unique public identifier.
///
/// - A 32-byte secret value used to derive the Data Key
#[derive(Default)]
pub struct ParentKey {
    id: ParentKeyId,
    secret: ParentKeySecret,
}

impl ParentKey {
    /// Create a new instance from an existing `id` and `secret`.
    pub fn new(id: ParentKeyId, secret: ParentKeySecret) -> Self {
        Self { id, secret }
    }

    /// Return the unique identifier for this instance.
    pub fn id(&self) -> &ParentKeyId {
        &self.id
    }

    /// Return the secret key material for this instance.
    pub fn secret(&self) -> &ParentKeySecret {
        &self.secret
    }

    /// Generates a parent key using a caller-provided secure byte source.
    ///
    /// `fill` must completely fill each buffer using a cryptographically
    /// secure random source. The function is called once for the public ID
    /// and once for the secret.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] containing the fill function's error message if
    /// either call to the fill function fails.
    pub fn try_from_fill<F, E>(mut fill: F) -> Result<Self, Error>
    where
        F: FnMut(&mut [u8]) -> Result<(), E>,
        E: core::fmt::Display,
    {
        let id = ParentKeyId::try_from_fill(&mut fill)?;
        let secret = ParentKeySecret::try_from_fill(fill)?;

        Ok(Self::new(id, secret))
    }
}

#[cfg(feature = "zeroize")]
impl Drop for ParentKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_key_try_from_fill() {
        let mut calls = 0u8;
        let parent_key = ParentKey::try_from_fill(|buf| {
            calls += 1;
            buf.fill(calls);
            Ok::<(), &str>(())
        })
        .unwrap();

        assert_eq!(parent_key.id().as_slice(), &[1; ParentKeyId::LEN]);
        assert_eq!(parent_key.secret().as_slice(), &[2; ParentKeySecret::LEN]);
        assert_eq!(calls, 2);
    }
}
