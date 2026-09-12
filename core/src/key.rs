// SPDX-License-Identifier: MIT
//! A module for defining cryptographic key types.
use crate::{bytes::ByteArray, error::Error};

/// Parent Key identifier buffer. A Parent Key is a cryptographic key
/// used to derive per-stream subkeys.
pub type ParentKeyId = ByteArray<16>;

const KEY_SECRET_LEN: usize = 32;

/// Parent Key secret. A 32 byte buffer for holding the Parent Key
/// secret bytes.
pub struct ParentKeySecret {
    bytes: ByteArray<KEY_SECRET_LEN>,
}

/// A type representing a Zymic Parent Key.
///
/// A Parent Key is a cryptographic key used to derive per-stream Data Keys
/// via a Key Derivation Function (KDF). It consists of:
///
/// - A 16-byte unique public identifier.
///
/// - A 32-byte secret value used to derive the Data Key
#[derive(Debug)]
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

    /// Generates a parent key using a caller-provided secure byte
    /// source.
    ///
    /// `fill` must completely fill each buffer using a
    /// cryptographically secure random source. The function is called
    /// once for the public ID and once for the secret.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] containing the fill function's error
    /// message if either call to the fill function fails.
    ///
    /// # Example
    ///
    /// Generate a parent key's public ID and secret using
    /// `getrandom`:
    ///
    /// ```rust
    /// # use zymic_core::key::ParentKey;
    /// # fn main() -> Result<(), zymic_core::Error> {
    /// let key = ParentKey::try_from_fill(getrandom::fill)?;
    /// assert_eq!(key.id().len(), 16);
    /// assert_eq!(key.secret().as_bytes().len(), 32);
    /// # Ok(())
    /// # }
    /// ```
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

impl ParentKeySecret {
    /// Convenience field assigned to 32, the length of the secret in
    /// bytes.
    pub const LEN: usize = KEY_SECRET_LEN;

    /// Create a new instance from an existing array.
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self {
            bytes: ByteArray::<KEY_SECRET_LEN>::from_array(bytes),
        }
    }

    /// Generates a parent key secret using a caller-provided secure
    /// byte source. The `fill` function must completely fill the
    /// buffer using secure randomness.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] containing the fill function's error
    /// message if the call to the `fill` function fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use zymic_core::key::ParentKeySecret;
    /// # fn main() -> Result<(), zymic_core::Error> {
    /// let key = ParentKeySecret::try_from_fill(getrandom::fill)?;
    /// assert_eq!(key.as_bytes().len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_from_fill<F, E>(fill: F) -> Result<Self, Error>
    where
        F: FnOnce(&mut [u8]) -> Result<(), E>,
        E: core::fmt::Display,
    {
        Ok(Self {
            bytes: ByteArray::try_from_fill(fill)?,
        })
    }

    /// Returns the Parent Key secret as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.bytes.as_array()
    }
}

impl core::fmt::Debug for ParentKeySecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ParentKeySecret(<REDACTED>)")
    }
}

#[cfg(test)]
mod tests {
    use crate::key::{ParentKey, ParentKeyId};

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
        assert_eq!(parent_key.secret().as_bytes(), &[2; 32]);
        assert_eq!(calls, 2);
    }
}
