// SPDX-License-Identifier: MIT
//! A module for defining cryptographic key types.
use crate::bytes::ByteArray;

#[cfg(feature = "rand_core")]
use crate::error::Error;

#[cfg(feature = "rand_core")]
use crate::{TryCryptoRng, TryRngCore};

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

    /// Create a new instance from a secure pseudo-random number generator.
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    pub fn try_from_crypto_rand<R>(rand_source: &mut R) -> Result<Self, Error>
    where
        R: TryCryptoRng + TryRngCore,
    {
        let id = ParentKeyId::try_from_crypto_rand(rand_source)?;
        let secret = ParentKeySecret::try_from_crypto_rand(rand_source)?;
        Ok(Self { id, secret })
    }
}

#[cfg(feature = "zeroize")]
impl Drop for ParentKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
