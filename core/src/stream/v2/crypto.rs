use crate::{
    bytes::ByteArray,
    error::{Error, ErrorKind},
    key::ParentKey,
};
pub use aes_gcm::Tag;
use aes_gcm::{
    aead::{array::Array, AeadCore, AeadInOut},
    aes::{
        cipher::consts::{U12, U16, U32},
        Aes256,
    },
    AesGcm, KeyInit as AesKeyInit,
};
#[cfg(feature = "chacha20poly1305")]
use chacha20poly1305::ChaCha20Poly1305;
use core::fmt;
use hkdf::Hkdf;
use sha2::Sha256;

/// AES-256-GCM using a 12-byte nonce.
type Aes256Gcm = AesGcm<Aes256, FrameNonceLen>;

/// AEAD nonce length.
type FrameNonceLen = U12;

/// Symmetric key for encryption/decryption.
pub type DataKey = Array<u8, U32>;

/// Nonce/IV used for AEAD encryption/decryption.
pub type AeadNonce = Array<u8, FrameNonceLen>;

/// Header MAC byte buffer
pub type HeaderMac = ByteArray<32>;

/// Supported cipher and key derivation algorithms.
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub enum CryptoAlgorithm {
    /// aes-256-gcm using hkdf-sha2-256 for key derivation
    #[default]
    Aes256GcmHkdfSha256 = 0,
    #[cfg(feature = "chacha20poly1305")]
    #[cfg_attr(docsrs, doc(cfg(feature = "chacha20poly1305")))]
    /// chacha20-poly1305 ([RFC-8439](https://www.rfc-editor.org/info/rfc8439/)) using
    /// hkdf-sha2-256 for key derivation
    ChaCha20Poly1305HkdfSha256 = 1,
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Aes256GcmHkdfSha256 => write!(f, "aes-256-gcm/hkdf-sha2-256"),
            #[cfg(feature = "chacha20poly1305")]
            Self::ChaCha20Poly1305HkdfSha256 => write!(f, "chacha20-poly1305/hkdf-sha2-256"),
        }
    }
}

impl TryFrom<u16> for CryptoAlgorithm {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(CryptoAlgorithm::Aes256GcmHkdfSha256),
            #[cfg(feature = "chacha20poly1305")]
            1 => Ok(CryptoAlgorithm::ChaCha20Poly1305HkdfSha256),
            _ => Err(Error::new(ErrorKind::UnsupportedCrypto(value))),
        }
    }
}

/// A cipher type implementing the supported crypto algorithms.
#[allow(clippy::large_enum_variant)]
pub enum Cipher {
    AesGcm256(Aes256Gcm),
    #[cfg(feature = "chacha20poly1305")]
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Cipher {
    /// Return an instantiated cipher instance that corresponds to the
    /// `algo` type using a symmetric `key`.
    pub fn from_algorithm(algo: CryptoAlgorithm, key: &DataKey) -> Self {
        match algo {
            CryptoAlgorithm::Aes256GcmHkdfSha256 => Cipher::AesGcm256(AesKeyInit::new(key)),
            #[cfg(feature = "chacha20poly1305")]
            CryptoAlgorithm::ChaCha20Poly1305HkdfSha256 => {
                Cipher::ChaCha20Poly1305(ChaCha20Poly1305::new(key))
            }
        }
    }

    /// Encrypt the payload buffer in-place.
    pub fn encrypt_inplace(&self, nonce: &AeadNonce, payload: &mut [u8]) -> Tag {
        match self {
            Cipher::AesGcm256(cipher) => Self::aead_encrypt(cipher, nonce, payload),
            #[cfg(feature = "chacha20poly1305")]
            Cipher::ChaCha20Poly1305(cipher) => Self::aead_encrypt(cipher, nonce, payload),
        }
    }

    /// Decrypt the payload buffer in-place.
    pub fn decrypt_inplace(
        &self,
        nonce: &AeadNonce,
        payload: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        match self {
            Cipher::AesGcm256(cipher) => Self::aead_decrypt(cipher, nonce, payload, tag),
            #[cfg(feature = "chacha20poly1305")]
            Cipher::ChaCha20Poly1305(cipher) => Self::aead_decrypt(cipher, nonce, payload, tag),
        }
    }

    fn aead_encrypt<T>(cipher: &T, nonce: &AeadNonce, buf: &mut [u8]) -> Tag
    where
        T: AeadInOut + AeadCore<NonceSize = FrameNonceLen, TagSize = U16>,
    {
        cipher
            .encrypt_inout_detached(nonce, &[], buf.into())
            .expect("buffer of sufficient size")
    }

    fn aead_decrypt<T>(
        cipher: &T,
        nonce: &AeadNonce,
        buf: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error>
    where
        T: AeadInOut + AeadCore<NonceSize = FrameNonceLen, TagSize = U16>,
    {
        cipher
            .decrypt_inout_detached(nonce, &[], buf.into(), tag)
            .map_err(|_| Error::new(ErrorKind::CipherDecrypt))
    }
}

/// Derive the data key and header MAC.
pub fn derive_data_key(parent_key: &ParentKey, info: &[u8]) -> (HeaderMac, DataKey) {
    let hkdf =
        Hkdf::<Sha256>::from_prk(parent_key.secret().as_bytes()).expect("valid HKDF PRK length");

    let mut header_mac = HeaderMac::default();
    hkdf.expand_multi_info(&[b"mac", info], header_mac.as_mut())
        .expect("HKDF header MAC expansion");

    let mut data_key = DataKey::default();
    hkdf.expand_multi_info(&[b"key", info], &mut data_key)
        .expect("HKDF data key expansion");

    (header_mac, data_key)
}
