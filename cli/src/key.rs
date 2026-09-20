// SPDX-License-Identifier: MIT

//! Crypto key serialization.
//!
//! This module provides tools for creating and storing cryptographic
//! keys to disk.
use crate::error::Error;
use aes_kw::{KeyInit, KwAes192, KwAes256};
use argon2::Argon2;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{fmt, time::SystemTime};
use zeroize::{Zeroize, Zeroizing};
use zymic_core::{
    bytes::ByteArray,
    key::{ParentKey, ParentKeyId, ParentKeySecret},
};

/// Wrapped symmetric key buffer for use with aes-key-wrap.  The
/// wrapped secret len is 32 bytes + an extra 8 bytes which is used by
/// aes-key-wrap as a authentication tag.
type WrappedSecret = ByteArray<{ ParentKeySecret::LEN + 8 }>;

type ArgonHash = ByteArray<32>;

/// Argon cpu focused parameter settings
const ARGON_CPU_M: u32 = 1 << 16;
const ARGON_CPU_P: u32 = 4;
const ARGON_CPU_T: u32 = 3;

/// Argon memory focused parameter settings
const ARGON_MEM_M: u32 = 1 << 18;
const ARGON_MEM_P: u32 = 4;
const ARGON_MEM_T: u32 = 1;

/// UNIX timestamp, i.e., duration in seconds since the EPOCH
pub type UnixTime = u64;

/// Setting for configuring Argon2. Each setting value represents a
/// valid Argon2 parameter tuple of `m`,`p`, and `t`.
#[non_exhaustive]
#[derive(Default, Serialize_repr, Deserialize_repr, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum ArgonSetting {
    /// CPU focused workload with higher iteration count and less
    /// memory usage.
    ///
    /// m = 2^16, p = 4, t = 3
    #[default]
    Cpu = 1,
    /// Memory focused workload with more memory usage and one
    /// iteration.
    ///
    /// m = 2^18, p = 4, t = 1
    Mem = 2,
}

/// A container for storing symmetric encryption keys on disk.
///
/// Keys may be protected by wrapping the secret using AES Key Wrap
/// ([RFC-3394](https://datatracker.ietf.org/doc/html/rfc3394)) and a
/// password-derived key. Without password protection, the public Parent Key ID
/// and creation date form an AES-192 wrapping key to retain AES Key Wrap's
/// corruption check.
#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    #[serde(with = "serde_base64")]
    id: ParentKeyId,
    date: UnixTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon: Option<ArgonSetting>,
    #[serde(with = "serde_base64")]
    wrapped_secret: WrappedSecret,
}

/// Compute an argon hash value using `id || date` as the salt value.
fn argon_hash(
    setting: ArgonSetting,
    id: &ParentKeyId,
    date: UnixTime,
    password: &str,
) -> Result<ArgonHash, Error> {
    const SALT_LEN: usize = ParentKeyId::LEN + 8;
    let mut salt = Vec::with_capacity(SALT_LEN);
    salt.extend_from_slice(id.as_slice());
    salt.extend_from_slice(&date.to_le_bytes());

    let params = setting.to_params();
    let mut mem_blocks = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    let mut out = ArgonHash::default();
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into_with_memory(password.as_bytes(), &salt, &mut out, &mut mem_blocks)?;

    Ok(out)
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:>13}", "id:")?;
        write!(f, " ")?;
        for (i, byte) in self.id.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            if i < self.id.len() - 1 {
                write!(f, ":")?;
            }
        }
        writeln!(f)?;
        let date = DateTime::<Utc>::from_timestamp(self.date() as i64, 0)
            .map_or("<date out of range>".to_string(), |d| {
                d.to_rfc3339_opts(SecondsFormat::Secs, true)
            });
        writeln!(f, "{:>13} {}", "date:", date)?;
        match self.argon {
            Some(argon) => {
                writeln!(f, "{:>13} password", "protection:")?;
                write!(f, "{:>13} {}", "argon:", argon)?;
            }
            None => write!(f, "{:>13} none", "protection:")?,
        }

        Ok(())
    }
}

impl ArgonSetting {
    /// Convert to argon2::Params
    fn to_params(self) -> argon2::Params {
        // unwrap safety: These values are const and checked via unit
        // tests. Therefore, safe to unwrap.
        match self {
            Self::Cpu => argon2::ParamsBuilder::new()
                .m_cost(ARGON_CPU_M)
                .p_cost(ARGON_CPU_P)
                .t_cost(ARGON_CPU_T)
                .build()
                .unwrap(),
            Self::Mem => argon2::ParamsBuilder::new()
                .m_cost(ARGON_MEM_M)
                .p_cost(ARGON_MEM_P)
                .t_cost(ARGON_MEM_T)
                .build()
                .unwrap(),
        }
    }
}

impl fmt::Display for ArgonSetting {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Cpu => write!(f, "cpu"),
            Self::Mem => write!(f, "mem"),
        }
    }
}

impl KeyFile {
    /// Create a new instance that contains a wrapped copy of `key`
    /// protected by the caller provided `password`.
    ///
    /// The `id` parameter must be unique.
    ///
    /// Argon2id is used to derive the key for wrapping `key`. The
    /// `argon` setting argument configures this operation.
    pub fn new(
        id: ParentKeyId,
        secret: &ParentKeySecret,
        argon: ArgonSetting,
        password: &str,
    ) -> Result<Self, Error> {
        let date = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let wrapped_secret = Self::wrap_secret(&id, date, argon, password, secret)?;

        Ok(Self {
            id,
            date,
            argon: Some(argon),
            wrapped_secret,
        })
    }

    /// Create a new key file without password protection.
    pub fn new_unprotected(id: ParentKeyId, secret: &ParentKeySecret) -> Result<Self, Error> {
        let date = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let wrapped_secret = Self::wrap_unprotected_secret(&id, date, secret)?;
        Ok(Self {
            id,
            date,
            argon: None,
            wrapped_secret,
        })
    }

    /// Return a Unix timestamp when this key instances was created.
    pub fn date(&self) -> UnixTime {
        self.date
    }

    /// Return whether this key requires a password.
    pub fn is_password_protected(&self) -> bool {
        self.argon.is_some()
    }

    /// Return a copy of the key unwrapped. Caller must provide a
    /// `password` to unwrap a password-protected key.
    pub fn unwrap(&self, password: &str) -> Result<ParentKey, Error> {
        let secret = match self.argon {
            Some(argon) => {
                let mut hash = argon_hash(argon, &self.id, self.date, password)?;
                let kek = KwAes256::new(hash.as_array().into());
                hash.zeroize();
                let mut bytes = Zeroizing::new([0u8; ParentKeySecret::LEN]);
                kek.unwrap_key(&self.wrapped_secret, bytes.as_mut())?;
                ParentKeySecret::from_array(*bytes)
            }
            None => Self::unwrap_unprotected_secret(&self.id, self.date, &self.wrapped_secret)?,
        };

        Ok(ParentKey::new(self.id.clone(), secret))
    }

    /// Rewrap this instance with a new password.
    pub fn rewrap(&mut self, old_password: &str, new_password: &str) -> Result<(), Error> {
        let argon = self.argon.unwrap_or_default();
        let key = self.unwrap(old_password)?;
        self.wrapped_secret =
            Self::wrap_secret(&self.id, self.date, argon, new_password, key.secret())?;
        self.argon = Some(argon);
        Ok(())
    }

    /// Remove password protection from this instance.
    pub fn remove_password(&mut self, old_password: &str) -> Result<(), Error> {
        let key = self.unwrap(old_password)?;
        self.wrapped_secret = Self::wrap_unprotected_secret(&self.id, self.date, key.secret())?;
        self.argon = None;
        Ok(())
    }

    /// Compute and return a wrapped copy of `key`.
    fn wrap_secret(
        id: &ParentKeyId,
        date: UnixTime,
        argon: ArgonSetting,
        password: &str,
        secret: &ParentKeySecret,
    ) -> Result<WrappedSecret, Error> {
        let mut hash = argon_hash(argon, id, date, password)?;
        let kek = KwAes256::new(hash.as_array().into());
        hash.zeroize();
        let mut bytes = Zeroizing::new([0u8; WrappedSecret::LEN]);
        kek.wrap_key(secret.as_bytes(), bytes.as_mut())?;

        Ok(WrappedSecret::from_array(*bytes))
    }

    /// Wrap a secret without password protection. The Parent Key ID and date
    /// are public, so this provides corruption detection but no confidentiality
    /// or authentication against an attacker who can modify the key file.
    fn wrap_unprotected_secret(
        id: &ParentKeyId,
        date: UnixTime,
        secret: &ParentKeySecret,
    ) -> Result<WrappedSecret, Error> {
        let mut key = [0u8; 24];
        key[..ParentKeyId::LEN].copy_from_slice(id);
        key[ParentKeyId::LEN..].copy_from_slice(&date.to_le_bytes());
        let kek = KwAes192::new((&key).into());
        let mut bytes = Zeroizing::new([0u8; WrappedSecret::LEN]);
        kek.wrap_key(secret.as_bytes(), bytes.as_mut())?;

        Ok(WrappedSecret::from_array(*bytes))
    }

    /// Unwrap a secret without password protection using the public Parent Key
    /// ID and date as the AES-192 wrapping key. Unwrapping verifies AES Key
    /// Wrap's corruption check.
    fn unwrap_unprotected_secret(
        id: &ParentKeyId,
        date: UnixTime,
        wrapped_secret: &WrappedSecret,
    ) -> Result<ParentKeySecret, Error> {
        let mut key = [0u8; 24];
        key[..ParentKeyId::LEN].copy_from_slice(id);
        key[ParentKeyId::LEN..].copy_from_slice(&date.to_le_bytes());
        let kek = KwAes192::new((&key).into());
        let mut bytes = Zeroizing::new([0u8; ParentKeySecret::LEN]);
        kek.unwrap_key(wrapped_secret, bytes.as_mut())?;

        Ok(ParentKeySecret::from_array(*bytes))
    }
}

mod serde_base64 {
    //! Encode and decode fixed-size byte arrays as JSON Base64 strings.
    use base64::{engine::general_purpose as b64, Engine as _};
    use serde::{de, Deserialize, Serializer};
    use zymic_core::bytes::ByteArray;

    pub(super) fn serialize<const N: usize, S>(
        data: &ByteArray<N>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let b64 = b64::STANDARD.encode(data);
        serializer.serialize_str(&b64)
    }

    pub(super) fn deserialize<'de, const N: usize, D>(
        deserializer: D,
    ) -> Result<ByteArray<N>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes = ByteArray::<N>::default();
        let encoded: String = Deserialize::deserialize(deserializer)?;
        let len = b64::STANDARD
            .decode_slice(encoded, &mut bytes)
            .map_err(|e| de::Error::custom(format!("base64 decoding error: {}", e)))?;
        if len != N {
            return Err(de::Error::custom(format!(
                "base64 decoding error: expecting array length of {} but received {}",
                N, len
            )));
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArgonSetting, KeyFile, ARGON_CPU_M, ARGON_CPU_P, ARGON_CPU_T, ARGON_MEM_M, ARGON_MEM_P,
        ARGON_MEM_T,
    };
    use zymic_core::key::{ParentKeyId, ParentKeySecret};

    #[test]
    fn key() {
        let password = "foo";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Cpu, password).unwrap();
        let _ = key_file.unwrap(password).unwrap();

        let json = serde_json::to_value(key_file).unwrap();
        assert!(json.get("argon").is_some());
        assert!(json.get("wrapped_secret").is_some());
        assert!(json.get("secret").is_none());
    }

    #[test]
    fn key_bad_password() {
        let password = "foo";
        let bad_password = "bar";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Cpu, password).unwrap();
        let result = key_file.unwrap(bad_password);
        assert!(result.is_err())
    }

    #[test]
    fn key_bad_date() {
        let password = "foo";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Cpu, password).unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json["date"] = serde_json::Value::Number(serde_json::value::Number::from(12345));
        let key_bad: KeyFile = serde_json::from_str(&json.to_string()).unwrap();
        let result = key_bad.unwrap(password);
        assert!(result.is_err())
    }

    #[test]
    fn key_bad_id() {
        let password = "foo";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Cpu, password).unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json["id"] = serde_json::Value::String("MDAwMDAwMDAwMDAwMDAwCg==".to_string());
        let key_bad: KeyFile = serde_json::from_str(&json.to_string()).unwrap();
        let result = key_bad.unwrap(password);
        assert!(result.is_err())
    }

    #[test]
    fn unprotected_key() {
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([7u8; ParentKeySecret::LEN]);
        let key_file = KeyFile::new_unprotected(id, &secret).unwrap();

        assert!(!key_file.is_password_protected());
        let key = key_file.unwrap("").unwrap();
        assert_eq!(key.secret().as_bytes(), secret.as_bytes());

        let json = serde_json::to_value(&key_file).unwrap();
        assert!(json.get("secret").is_none());
        assert!(json.get("argon").is_none());
        assert!(json.get("wrapped_secret").is_some());

        let decoded: KeyFile = serde_json::from_value(json).unwrap();
        assert!(!decoded.is_password_protected());
    }

    #[test]
    fn unprotected_key_rejects_corruption() {
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);
        let mut key_file = KeyFile::new_unprotected(id, &secret).unwrap();

        key_file.wrapped_secret[0] ^= 1;
        assert!(key_file.unwrap("").is_err());

        let mut key_file = KeyFile::new_unprotected(ParentKeyId::default(), &secret).unwrap();
        key_file.id[0] ^= 1;
        assert!(key_file.unwrap("").is_err());

        let mut key_file = KeyFile::new_unprotected(ParentKeyId::default(), &secret).unwrap();
        key_file.date ^= 1;
        assert!(key_file.unwrap("").is_err());
    }

    #[test]
    fn key_file_accepts_unknown_fields() {
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);

        let key_file = KeyFile::new(id.clone(), &secret, ArgonSetting::Cpu, "foo").unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json["future"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<KeyFile>(json).is_ok());

        let key_file = KeyFile::new_unprotected(id, &secret).unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json["future"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<KeyFile>(json).is_ok());
    }

    #[test]
    fn key_file_rejects_missing_material() {
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([0u8; ParentKeySecret::LEN]);

        let key_file = KeyFile::new_unprotected(id.clone(), &secret).unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json.as_object_mut().unwrap().remove("wrapped_secret");
        assert!(serde_json::from_value::<KeyFile>(json).is_err());

        let key_file = KeyFile::new(id, &secret, ArgonSetting::Cpu, "foo").unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json.as_object_mut().unwrap().remove("wrapped_secret");
        assert!(serde_json::from_value::<KeyFile>(json).is_err());
    }

    #[test]
    fn rewrap_password_protection() {
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([7u8; ParentKeySecret::LEN]);
        let mut key_file = KeyFile::new_unprotected(id, &secret).unwrap();

        key_file.rewrap("", "foo").unwrap();
        assert!(key_file.is_password_protected());
        assert!(key_file.unwrap("").is_err());
        assert_eq!(
            key_file.unwrap("foo").unwrap().secret().as_bytes(),
            secret.as_bytes()
        );

        key_file.remove_password("foo").unwrap();
        assert!(!key_file.is_password_protected());
        assert_eq!(
            key_file.unwrap("").unwrap().secret().as_bytes(),
            secret.as_bytes()
        );
    }

    #[test]
    fn empty_password_remains_password_protected() {
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::from_array([7u8; ParentKeySecret::LEN]);
        let mut key_file = KeyFile::new(id, &secret, ArgonSetting::Cpu, "").unwrap();

        assert!(key_file.is_password_protected());
        assert_eq!(
            key_file.unwrap("").unwrap().secret().as_bytes(),
            secret.as_bytes()
        );

        key_file.rewrap("", "").unwrap();
        assert!(key_file.is_password_protected());

        key_file.remove_password("").unwrap();
        assert!(!key_file.is_password_protected());
    }

    #[test]
    fn argon_setting() {
        let setting = ArgonSetting::default();
        assert_eq!(ArgonSetting::Cpu, setting);

        let params = setting.to_params();
        assert_eq!(ARGON_CPU_M, params.m_cost());
        assert_eq!(ARGON_CPU_P, params.p_cost());
        assert_eq!(ARGON_CPU_T, params.t_cost());

        let setting = ArgonSetting::Mem;
        let params = setting.to_params();
        assert_eq!(ARGON_MEM_M, params.m_cost());
        assert_eq!(ARGON_MEM_P, params.p_cost());
        assert_eq!(ARGON_MEM_T, params.t_cost());
    }
}
