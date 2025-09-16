// SPDX-License-Identifier: MIT

//! Crypto key serialization.
//!
//! This module provides tools for creating and storing cryptographic
//! keys to disk.
use crate::error::Error;
use aes_kw::KekAes256;
use argon2::Argon2;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{fmt, time::SystemTime};
use zymic_core::{
    bytes::ByteArray,
    key::{ParentKey, ParentKeyId, ParentKeySecret},
};

/// Wrapped symmetric key buffer for use with aes-key-wrap.  The
/// wrapped secret len is 32 bytes + an extra 8 bytes which is used by
/// aes-key-wrap as a authentication tag.
type WrappedSecret = ByteArray<{ ParentKeySecret::LEN + 8 }>;

type ArgonHash = ByteArray<32>;

/// Argon minimum parameter settings
const ARGON_MIN_M: u32 = 8;
const ARGON_MIN_P: u32 = 1;
const ARGON_MIN_T: u32 = 1;

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
    /// Minimum setting. This setting uses the fewest resources for
    /// computing Argon hashes. As a result, this is the **least
    /// secure** setting but also the most performant. This should
    /// only be used for testing or use-cases where the security of
    /// Argon computation is not necessary.
    ///
    /// m = 8, p = 1, t = 1
    Min = 3,
}

/// A container for safely storing symmetric encryption keys to
/// disk. This is achieved by wrapping (i.e., encrypting) the key using
/// the AES Key Wrap algorithm
/// ([RFC-3394](https://datatracker.ietf.org/doc/html/rfc3394)). The
/// key used to wrap the symmetric key is derived from a user password
/// using the Argon2id hash algorithm
/// ([RFC-9106](https://datatracker.ietf.org/doc/html/rfc9106)).
///
/// Only a wrapped version of the symmetric key may be serialized. To
/// use the key for encryption or decryption, it must first be unwrapped
/// with the user password.
#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    #[serde(with = "serde_base64")]
    id: ParentKeyId,
    date: UnixTime,
    argon: ArgonSetting,
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
    let mut mem_blocks = vec![argon2::Block::default(); params.block_count()];
    let mut out = ArgonHash::default();
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into_with_memory(password.as_bytes(), &salt, &mut out, &mut mem_blocks)?;

    Ok(out)
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id:\t")?;
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
        writeln!(f, "date:\t{}", date)?;
        write!(f, "argon:\t{}", self.argon)?;

        Ok(())
    }
}

impl ArgonSetting {
    /// Convert to argon2::Params
    fn to_params(self) -> argon2::Params {
        // unwrap safety: These values are const and checked via unit
        // tests. Therefore, safe to unwrap.
        match self {
            Self::Min => argon2::ParamsBuilder::new()
                .m_cost(ARGON_MIN_M)
                .p_cost(ARGON_MIN_P)
                .t_cost(ARGON_MIN_T)
                .build()
                .unwrap(),
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
            Self::Min => write!(f, "min"),
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
            argon,
            wrapped_secret,
        })
    }

    /// Return a Unix timestamp when this key instances was created.
    pub fn date(&self) -> UnixTime {
        self.date
    }

    /// Return a copy of the key unwrapped. Caller must provide a
    /// 'password' to unwrap the key.
    pub fn unwrap(&self, password: &str) -> Result<ParentKey, Error> {
        let hash = argon_hash(self.argon, &self.id, self.date, password)?;

        let kek = KekAes256::try_from(hash.as_slice())?;
        let mut secret = ParentKeySecret::default();
        kek.unwrap(&self.wrapped_secret, &mut secret)?;

        Ok(ParentKey::new(self.id.clone(), secret))
    }

    /// Rewrap this instance with a new password.
    pub fn rewrap(&mut self, old_password: &str, new_password: &str) -> Result<(), Error> {
        let key = self.unwrap(old_password)?;
        self.wrapped_secret =
            Self::wrap_secret(&self.id, self.date, self.argon, new_password, key.secret())?;
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
        let hash = argon_hash(argon, id, date, password)?;
        let kek = KekAes256::try_from(hash.as_slice())?;
        let mut wrapped_secret = WrappedSecret::default();
        kek.wrap(secret, &mut wrapped_secret)?;

        Ok(wrapped_secret)
    }
}

mod serde_base64 {
    //! Encode/Decode into base64 format if the
    //! serializer/deserializer is human readable.
    use base64::{engine::general_purpose as b64, Engine as _};
    use serde::{de, Deserialize, Serializer};
    use zymic_core::bytes::ByteArray;

    pub fn serialize<const N: usize, S>(
        data: &ByteArray<N>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let b64 = b64::STANDARD.encode(data);
            serializer.serialize_str(&b64)
        } else {
            serializer.serialize_bytes(data)
        }
    }

    pub fn deserialize<'de, const N: usize, D>(deserializer: D) -> Result<ByteArray<N>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes = ByteArray::<N>::default();
        if deserializer.is_human_readable() {
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
        } else {
            let data: &[u8] = Deserialize::deserialize(deserializer)?;
            if data.len() != N {
                return Err(de::Error::custom(format!(
                    "decoding error: expecting array length of {} but received {}",
                    N,
                    data.len()
                )));
            }
            bytes.copy_from_slice(data);
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArgonSetting, KeyFile, ARGON_CPU_M, ARGON_CPU_P, ARGON_CPU_T, ARGON_MEM_M, ARGON_MEM_P,
        ARGON_MEM_T, ARGON_MIN_M, ARGON_MIN_P, ARGON_MIN_T,
    };
    use zymic_core::key::{ParentKeyId, ParentKeySecret};

    #[test]
    fn key() {
        let password = "foo";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::default();
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Min, password).unwrap();
        let _ = key_file.unwrap(password).unwrap();
    }

    #[test]
    fn key_bad_password() {
        let password = "foo";
        let bad_password = "bar";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::default();
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Min, password).unwrap();
        let result = key_file.unwrap(bad_password);
        assert!(result.is_err())
    }

    #[test]
    fn key_bad_date() {
        let password = "foo";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::default();
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Min, password).unwrap();
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
        let secret = ParentKeySecret::default();
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Min, password).unwrap();
        let mut json = serde_json::to_value(key_file).unwrap();
        json["id"] = serde_json::Value::String("MDAwMDAwMDAwMDAwMDAwCg==".to_string());
        let key_bad: KeyFile = serde_json::from_str(&json.to_string()).unwrap();
        let result = key_bad.unwrap(password);
        assert!(result.is_err())
    }

    #[test]
    fn serde_non_human_readable() {
        let password = "foo";
        let id = ParentKeyId::default();
        let secret = ParentKeySecret::default();
        let key_file = KeyFile::new(id, &secret, ArgonSetting::Min, password).unwrap();
        let blob = postcard::to_stdvec(&key_file).unwrap();
        let result: Result<KeyFile, _> = postcard::from_bytes(&blob);
        assert!(result.is_ok());
    }

    #[test]
    fn argon_setting() {
        let setting = ArgonSetting::default();
        assert_eq!(ArgonSetting::Cpu, setting);

        let params = setting.to_params();
        assert_eq!(ARGON_CPU_M, params.m_cost());
        assert_eq!(ARGON_CPU_P, params.p_cost());
        assert_eq!(ARGON_CPU_T, params.t_cost());

        let setting = ArgonSetting::Min;
        let params = setting.to_params();
        assert_eq!(ARGON_MIN_M, params.m_cost());
        assert_eq!(ARGON_MIN_P, params.p_cost());
        assert_eq!(ARGON_MIN_T, params.t_cost());

        let setting = ArgonSetting::Mem;
        let params = setting.to_params();
        assert_eq!(ARGON_MEM_M, params.m_cost());
        assert_eq!(ARGON_MEM_P, params.p_cost());
        assert_eq!(ARGON_MEM_T, params.t_cost());
    }
}
