// SPDX-License-Identifier: MIT

//! Read-only support for Zymic stream format version 1.
//!
//! This module is intentionally isolated from the current stream
//! implementation. Applications that need to decode an existing v1 stream
//! must opt into the `v1` feature and select [`Reader`] explicitly.
//! New streams must be encoded with [`crate::stream::v2`].

use crate::{
    bytes::{ByteArray, ByteCursor},
    error::{Error, ErrorKind},
    key::{ParentKey, ParentKeyId},
};
use aes_gcm::{
    aead::AeadInOut,
    aes::{cipher::consts::U12, Aes256},
    AesGcm, KeyInit as AesKeyInit, Nonce as AesNonce, Tag,
};
use alloc::vec::Vec;
use core::{fmt, ops::Range};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const KEY_LEN_256: usize = 32;

/// Header nonce byte buffer used by the v1 format.
pub type HeaderNonce = ByteArray<16>;

type HeaderMac = ByteArray<32>;

const MAGIC_NUM_LEN: usize = 4;
const VERSION_LEN: usize = 1;
const ALGO_LEN: usize = 2;
const FRAME_LEN_LEN: usize = 1;
const RESERVED_LEN: usize = 8;

const HEADER_LEN: usize = MAGIC_NUM_LEN
    + VERSION_LEN
    + ALGO_LEN
    + FRAME_LEN_LEN
    + RESERVED_LEN
    + HeaderNonce::LEN
    + ParentKeyId::LEN
    + HeaderMac::LEN;

/// Serialized v1 stream header.
pub type HeaderBytes = ByteArray<HEADER_LEN>;

const VERSION_OFFSET: usize = MAGIC_NUM_LEN;
const ALGO_OFFSET: usize = VERSION_OFFSET + VERSION_LEN;
const FRAME_LEN_OFFSET: usize = ALGO_OFFSET + ALGO_LEN;
const RESERVED_OFFSET: usize = FRAME_LEN_OFFSET + FRAME_LEN_LEN;
const NONCE_OFFSET: usize = RESERVED_OFFSET + RESERVED_LEN;
const KEY_ID_OFFSET: usize = NONCE_OFFSET + HeaderNonce::LEN;
const HEADER_MAC_OFFSET: usize = KEY_ID_OFFSET + ParentKeyId::LEN;

const HEADER_KEY_ID_RANGE: Range<usize> = KEY_ID_OFFSET..KEY_ID_OFFSET + ParentKeyId::LEN;
const HEADER_MAC_RANGE: Range<usize> = HEADER_MAC_OFFSET..HEADER_MAC_OFFSET + HeaderMac::LEN;
const HKDF_INFO_RANGE: Range<usize> = 0..NONCE_OFFSET;
const HKDF_SALT_RANGE: Range<usize> =
    NONCE_OFFSET..NONCE_OFFSET + HeaderNonce::LEN + ParentKeyId::LEN;

const SEQ_NUM_LEN: usize = 4;
const INVOCATION_LEN: usize = 8;
const END_LEN: usize = 4;
const FRAME_TAG_LEN: usize = 16;
const FRAME_HEADER_LEN: usize = SEQ_NUM_LEN + INVOCATION_LEN + END_LEN;
const FRAME_META_LEN: usize = FRAME_HEADER_LEN + FRAME_TAG_LEN;
const PAYLOAD_OFFSET: usize = FRAME_HEADER_LEN;

type FrameNonceLen = U12;
type Aes256Gcm = AesGcm<Aes256, FrameNonceLen>;

const DATA_KEY_LEN: usize = KEY_LEN_256;
const MAGIC_NUM: u32 = 0x6d797a2e;
const VERSION: u8 = 1;

#[repr(u16)]
enum CryptoAlgorithm {
    Aes256GcmHkdfSha256 = 0,
}

/// Frame lengths supported by the v1 format.
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub enum FrameLength {
    /// 4 KiB.
    Len4KiB = 12,
    /// 8 KiB.
    Len8KiB = 13,
    /// 16 KiB.
    #[default]
    Len16KiB = 14,
    /// 32 KiB.
    Len32KiB = 15,
    /// 64 KiB.
    Len64KiB = 16,
}

/// A validated v1 stream header and its derived Data Key.
#[derive(PartialEq, Clone)]
pub struct Header {
    frame_len: FrameLength,
    data_key: aes_gcm::Key<Aes256Gcm>,
    bytes: HeaderBytes,
}

/// A read-only buffer for decoding one v1 frame without `std`.
///
/// Load an encoded frame with [`copy_from_encrypted_bytes`](Self::copy_from_encrypted_bytes),
/// or write directly into [`chunk_mut`](Self::chunk_mut) and then call
/// [`commit_chunk_mut`](Self::commit_chunk_mut). After [`decrypt`](Self::decrypt)
/// succeeds, [`payload`](Self::payload) returns the authenticated plaintext.
///
/// This type intentionally provides no v1 encryption operations.
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub struct FrameBuf {
    buf: Vec<u8>,
    frame_len: usize,
    max_payload_len: usize,
    payload_len: usize,
    cipher: Aes256Gcm,
}

/// A read-only decoder for v1 frame data.
///
/// The serialized [`Header`] is not part of `inner`; parse it separately with
/// [`Header::from_bytes`] and construct the reader over the bytes immediately
/// following that header.
///
/// This type is available only with both the `v1` and `std` features.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v1", feature = "std"))))]
pub struct Reader<T> {
    seq_num: u32,
    start_seq_num: u32,
    payload_pos: usize,
    end_len: Option<usize>,
    frame_buf: FrameBuf,
    inner: T,
}

fn derive_data_key(
    parent_key: &ParentKey,
    salt: &[u8],
    info: &[u8],
) -> (HeaderMac, aes_gcm::Key<Aes256>) {
    let mut hkdf_out = [0u8; HeaderMac::LEN + DATA_KEY_LEN];
    let hkdf = Hkdf::<Sha256>::new(Some(salt), parent_key.secret());
    hkdf.expand(info, &mut hkdf_out).expect("hkdf expansion");

    let digest = HeaderMac::from(&hkdf_out[..HeaderMac::LEN]);
    let mut data_key = aes_gcm::Key::<Aes256Gcm>::default();
    data_key.copy_from_slice(&hkdf_out[HeaderMac::LEN..]);

    (digest, data_key)
}

impl TryFrom<u8> for FrameLength {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            12 => Ok(Self::Len4KiB),
            13 => Ok(Self::Len8KiB),
            14 => Ok(Self::Len16KiB),
            15 => Ok(Self::Len32KiB),
            16 => Ok(Self::Len64KiB),
            _ => Err(Error::new(ErrorKind::InvalidFrameLength(value))),
        }
    }
}

impl fmt::Display for FrameLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_usize())
    }
}

impl FrameLength {
    /// Return the encoded frame length in bytes.
    pub fn as_usize(self) -> usize {
        1 << (self as u8)
    }
}

impl Header {
    /// Parse and authenticate a serialized v1 header.
    ///
    /// This rejects headers for every version other than version 1. Callers
    /// must therefore choose this legacy decoder explicitly rather than rely
    /// on version dispatch.
    pub fn from_bytes(parent_key: &ParentKey, bytes: HeaderBytes) -> Result<Self, Error> {
        let mut byte_buf = ByteCursor::new(&bytes);

        let magic_num = byte_buf.get_u32_le();
        if magic_num != MAGIC_NUM {
            return Err(Error::new(ErrorKind::InvalidMagicNumber(magic_num)));
        }
        let version = byte_buf.get_u8();
        if version != VERSION {
            return Err(Error::new(ErrorKind::UnsupportedVersion(version)));
        }
        let algorithm = byte_buf.get_u16_le();
        if algorithm != CryptoAlgorithm::Aes256GcmHkdfSha256 as u16 {
            return Err(Error::new(ErrorKind::UnsupportedCrypto(algorithm)));
        }
        if &bytes[HEADER_KEY_ID_RANGE] != parent_key.id().as_slice() {
            return Err(Error::new(ErrorKind::ParentKeyIdMismatch));
        }
        let frame_len = FrameLength::try_from(byte_buf.get_u8())?;

        let info = &bytes.as_slice()[HKDF_INFO_RANGE];
        let salt = &bytes.as_slice()[HKDF_SALT_RANGE];
        let expected_mac = &bytes.as_slice()[HEADER_MAC_RANGE];
        let (header_mac, data_key) = derive_data_key(parent_key, salt, info);

        if header_mac.as_ref().ct_eq(expected_mac).unwrap_u8() != 1 {
            return Err(Error::new(ErrorKind::Authentication));
        }

        Ok(Self {
            frame_len,
            data_key,
            bytes,
        })
    }

    /// Return the serialized v1 header.
    pub fn bytes(&self) -> &HeaderBytes {
        &self.bytes
    }

    /// Return the frame length encoded by this header.
    pub fn frame_len(&self) -> FrameLength {
        self.frame_len
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Header {
    fn drop(&mut self) {
        self.data_key.zeroize();
    }
}

impl FrameBuf {
    /// Create an empty v1 frame buffer using the frame size and Data Key from
    /// `header`.
    pub fn new(header: &Header) -> Self {
        let frame_len = header.frame_len.as_usize();
        let max_payload_len = frame_len - FRAME_META_LEN;

        Self {
            buf: Vec::with_capacity(frame_len),
            frame_len,
            max_payload_len,
            payload_len: 0,
            cipher: AesKeyInit::new(&header.data_key),
        }
    }

    /// Return the authenticated plaintext after a successful call to
    /// [`decrypt`](Self::decrypt).
    pub fn payload(&self) -> &[u8] {
        if self.buf.len() < PAYLOAD_OFFSET {
            &self.buf[..0]
        } else {
            &self.buf[PAYLOAD_OFFSET..PAYLOAD_OFFSET + self.payload_len]
        }
    }

    /// Authenticate and decrypt the loaded v1 frame in place.
    ///
    /// The caller must supply the expected sequence number so missing or
    /// reordered frames are rejected. Returns `true` for an End Frame and
    /// `false` for a Body Frame.
    pub fn decrypt(&mut self, expected_seq_num: u32) -> Result<bool, Error> {
        if self.buf.len() < FRAME_META_LEN {
            return Err(Error::new(ErrorKind::InvalidBufLength));
        }

        // In v1, the serialized sequence number and invocation count together
        // form the 12-byte AEAD nonce. The invocation count is retained only
        // as an on-wire compatibility detail; the read-only API never exposes
        // or advances it.
        let (nonce, frame) = self.buf.split_at_mut(SEQ_NUM_LEN + INVOCATION_LEN);
        let (end_len_bytes, frame) = frame.split_at_mut(END_LEN);
        let end_len = u32::from_le_bytes(
            end_len_bytes
                .try_into()
                .expect("v1 end length should be four bytes"),
        );

        let (payload_len, is_end) = if end_len == u32::MAX {
            (self.frame_len - FRAME_META_LEN, false)
        } else {
            if end_len as usize > self.max_payload_len {
                return Err(Error::new(ErrorKind::InvalidEndLength(end_len)));
            }
            (end_len as usize, true)
        };

        let body_len = payload_len + FRAME_TAG_LEN;
        if frame.len() < body_len {
            return Err(Error::new(ErrorKind::InvalidEndLength(end_len)));
        }

        let (payload, mac) = frame.split_at_mut(payload_len);
        let tag = Tag::try_from(&mac[..FRAME_TAG_LEN]).expect("v1 tag should be 16 bytes");
        let nonce =
            AesNonce::<FrameNonceLen>::try_from(&nonce[..]).expect("v1 nonce should be 12 bytes");

        self.cipher
            .decrypt_inout_detached(&nonce, end_len_bytes, payload.into(), &tag)?;

        let decoded_seq_num = u32::from_le_bytes(
            nonce[..SEQ_NUM_LEN]
                .try_into()
                .expect("v1 sequence number should be four bytes"),
        );
        if expected_seq_num != decoded_seq_num {
            return Err(Error::new(ErrorKind::UnexpectedSeqNum(
                expected_seq_num,
                decoded_seq_num,
            )));
        }

        self.payload_len = payload_len;
        Ok(is_end)
    }

    /// Prepare the buffer for a direct read and return a writable slice sized
    /// to the configured frame length.
    ///
    /// Call [`commit_chunk_mut`](Self::commit_chunk_mut) with the number of
    /// bytes actually written before decrypting.
    pub fn chunk_mut(&mut self) -> &mut [u8] {
        self.buf.clear();
        self.buf.resize(self.frame_len, 0);
        self.payload_len = 0;
        &mut self.buf
    }

    /// Commit the number of encoded bytes written through
    /// [`chunk_mut`](Self::chunk_mut).
    pub fn commit_chunk_mut(&mut self, len: usize) -> Result<(), Error> {
        if len > self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidBufLength));
        }
        self.buf.truncate(len);
        self.payload_len = 0;
        Ok(())
    }

    /// Copy one encoded v1 frame into this buffer.
    ///
    /// At most the configured frame length is copied. The returned value is
    /// the number of bytes consumed from `src`.
    pub fn copy_from_encrypted_bytes(&mut self, src: &[u8]) -> usize {
        let len = usize::min(src.len(), self.frame_len);
        self.buf.resize(len, 0);
        self.payload_len = 0;
        self.buf[..len].copy_from_slice(&src[..len]);
        len
    }

    #[cfg(feature = "std")]
    fn is_partial(&self) -> bool {
        self.buf.len() < FRAME_HEADER_LEN
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v1", feature = "std"))))]
impl<T> Reader<T> {
    /// Create a reader beginning at sequence number zero.
    pub fn new(inner: T, header: &Header) -> Self {
        Self::new_with_seq_num(inner, header, 0)
    }

    /// Create a reader at a known v1 frame boundary and sequence number.
    pub fn new_with_seq_num(inner: T, header: &Header, seq_num: u32) -> Self {
        Self {
            seq_num,
            start_seq_num: seq_num,
            payload_pos: 0,
            end_len: None,
            frame_buf: FrameBuf::new(header),
            inner,
        }
    }

    /// Consume the reader and return its underlying input.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Return whether the authenticated End Frame has been consumed.
    pub fn is_eof(&self) -> bool {
        self.end_len
            .is_some_and(|end_len| self.payload_pos == end_len)
    }

    /// Confirm that the stream ended with an authenticated End Frame.
    pub fn is_eof_or_err(&self) -> Result<(), Error> {
        if self.is_eof() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Truncation))
        }
    }

    fn frame_idx_to_frame_off(&self, frame_idx: u32) -> Result<u64, Error> {
        (frame_idx as u64)
            .checked_mul(self.frame_buf.frame_len as u64)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))
    }

    fn byte_off_to_frame_idx(&self, byte_off: u64) -> Result<u32, Error> {
        Ok(u32::try_from(byte_off / self.frame_buf.frame_len as u64)?)
    }

    fn payload_off_to_frame_idx(&self, payload_off: u64) -> Result<u32, Error> {
        Ok(u32::try_from(
            payload_off / self.frame_buf.max_payload_len as u64,
        )?)
    }

    fn payload_off_to_frame_off(&self, payload_off: u64) -> Result<u64, Error> {
        let frame_idx = payload_off / self.frame_buf.max_payload_len as u64;
        frame_idx
            .checked_mul(self.frame_buf.frame_len as u64)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))
    }

    fn current_payload_off(&self) -> Result<u64, Error> {
        let frame_idx = self.current_frame_idx();
        let payload_off = (frame_idx as usize)
            .checked_mul(self.frame_buf.max_payload_len)
            .and_then(|value| value.checked_add(self.payload_pos))
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
        Ok(payload_off as u64)
    }

    fn total_payload_len(&self) -> Result<u64, Error> {
        let frame_idx = self.current_frame_idx();
        let payload_len = (frame_idx as usize)
            .checked_mul(self.frame_buf.max_payload_len)
            .and_then(|value| value.checked_add(self.frame_buf.payload_len))
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
        Ok(payload_len as u64)
    }

    fn current_frame_idx(&self) -> u32 {
        let frame_idx = self.seq_num - self.start_seq_num;
        if self.end_len.is_none() && self.frame_buf.payload_len > 0 {
            frame_idx.saturating_sub(1)
        } else {
            frame_idx
        }
    }

    fn frame_payload_remaining(&self) -> usize {
        self.frame_buf.payload_len.saturating_sub(self.payload_pos)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v1", feature = "std"))))]
impl<T: Read> Reader<T> {
    fn read_next_frame(&mut self) -> Result<bool, Error> {
        let mut buf = self.frame_buf.chunk_mut();
        let mut total_len = 0;

        while !buf.is_empty() {
            let len = self.inner.read(buf)?;
            if len == 0 {
                break;
            }
            buf = &mut buf[len..];
            total_len += len;
        }

        self.frame_buf.commit_chunk_mut(total_len)?;
        if total_len == 0 {
            self.payload_pos = 0;
            return Ok(false);
        }
        if self.frame_buf.is_partial() {
            return Err(Error::new(ErrorKind::UnexpectedEof));
        }

        let is_end = self.frame_buf.decrypt(self.seq_num)?;
        self.end_len = is_end.then_some(self.frame_buf.payload_len);
        self.payload_pos = 0;
        Ok(true)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v1", feature = "std"))))]
impl<T: Read> Read for Reader<T> {
    fn read(&mut self, mut output: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut total_len = 0;

        while !output.is_empty() && !self.is_eof() {
            if self.frame_payload_remaining() == 0
                && self.read_next_frame()?
                && self.end_len.is_none()
            {
                self.seq_num = self
                    .seq_num
                    .checked_add(1)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
            }

            let remaining = self.frame_payload_remaining();
            if remaining == 0 {
                break;
            }
            let payload = self.frame_buf.payload();
            if payload.is_empty() {
                break;
            }

            let len = usize::min(remaining, output.len());
            output[..len].copy_from_slice(&payload[self.payload_pos..self.payload_pos + len]);
            output = &mut output[len..];
            self.payload_pos += len;
            total_len += len;
        }

        Ok(total_len)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v1", feature = "std"))))]
impl<T: Seek + Read> Reader<T> {
    fn seek_to_payload_off(&mut self, payload_off: u64) -> Result<(), Error> {
        let frame_off = self.payload_off_to_frame_off(payload_off)?;
        self.inner.seek(SeekFrom::Start(frame_off))?;
        self.seq_num = self
            .payload_off_to_frame_idx(payload_off)?
            .checked_add(self.start_seq_num)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

        if !self.read_next_frame()? {
            return Err(Error::new(ErrorKind::UnexpectedEof));
        }
        if self.end_len.is_none() {
            self.seq_num = self
                .seq_num
                .checked_add(1)
                .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
        }

        let frame_payload_off = payload_off as usize % self.frame_buf.max_payload_len;
        if frame_payload_off < self.frame_buf.payload_len
            || (self.end_len.is_some() && frame_payload_off == self.frame_buf.payload_len)
        {
            self.payload_pos = frame_payload_off;
            Ok(())
        } else {
            Err(Error::new(ErrorKind::UnexpectedEof))
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "v1", feature = "std"))))]
impl<T: Seek + Read> Seek for Reader<T> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, std::io::Error> {
        let payload_off = match pos {
            SeekFrom::Start(payload_off) => {
                self.seek_to_payload_off(payload_off)?;
                payload_off
            }
            SeekFrom::End(payload_off) => {
                if payload_off > 0 {
                    return Err(Error::new(ErrorKind::UnexpectedEof).into());
                }

                let encoded_end = self.inner.seek(SeekFrom::End(0))?.saturating_sub(1);
                let end_frame_idx = self.byte_off_to_frame_idx(encoded_end)?;
                let end_frame_off = self.frame_idx_to_frame_off(end_frame_idx)?;
                self.inner.seek(SeekFrom::Start(end_frame_off))?;
                self.seq_num = end_frame_idx
                    .checked_add(self.start_seq_num)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                if !self.read_next_frame()? {
                    return Err(Error::new(ErrorKind::UnexpectedEof).into());
                }

                let payload_len = self.total_payload_len()?;

                if payload_off == 0 {
                    self.payload_pos = self.frame_buf.payload_len;
                    payload_len
                } else {
                    let payload_len = i64::try_from(payload_len)
                        .map_err(|error| Error::new(ErrorKind::TryFromInt(error)))?;
                    let new_payload_off = payload_len
                        .checked_add(payload_off)
                        .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                    if new_payload_off < 0 {
                        return Err(std::io::ErrorKind::InvalidInput.into());
                    }
                    self.seek_to_payload_off(new_payload_off as u64)?;
                    new_payload_off as u64
                }
            }
            SeekFrom::Current(payload_off) => {
                let current_payload_off = i64::try_from(self.current_payload_off()?)
                    .map_err(|error| Error::new(ErrorKind::TryFromInt(error)))?;
                let new_payload_off = payload_off
                    .checked_add(current_payload_off)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                if new_payload_off < 0 {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                self.seek_to_payload_off(new_payload_off as u64)?;
                new_payload_off as u64
            }
        };

        Ok(payload_off)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
