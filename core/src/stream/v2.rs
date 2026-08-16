// spdx-License-Identifier: MIT

//! # Zymic Stream
//!
//! Zymic is a stream‑oriented encryption format for protecting data
//! at rest using AEAD (Authenticated Encryption with Associated
//! Data). It divides plaintext into independently encrypted frames
//! and authenticates both metadata and payloads, enabling detection
//! of tampering, reordering, and truncation.
//!
//! ## Format
//!
//! A Zymic stream consists of one Header, zero or more Body Frames,
//! and exactly one End Frame. Frames are strictly ordered; any
//! reordering/removal is detectable during decryption. Each stream
//! uses a unique Data Key derived from a higher-level Parent Key; the
//! Parent Key itself never encrypts frames directly.
//!
//!```text
//! +--------+--------------+--------------+------------+
//! | Header | Body Frame 1 | Body Frame 2 | End Frame  |
//! +--------+--------------+--------------+------------+
//!```
//!
//! ## Getting Started
//!
//! Choose an API based on whether the Rust standard library is
//! available:
//!
//! - `std` → use [`ZymicStream`], which implements [`std::io::Read`],
//!   [`std::io::Write`], and [`std::io::Seek`] over a framed AEAD
//!   stream. This is the most ergonomic option for file or socket I/O
//!   on desktop and server systems, and is the recommended type when
//!   targeting ordinary Rust applications.
//!
//! - `no_std` → use [`FrameBuf`], a lower-level buffer type for
//!   constructing, encrypting, and decrypting individual frames
//!   directly. `FrameBuf` is suitable for embedded and constrained
//!   environments where `std` is not available, or when you need
//!   fine-grained control over how frames are stored and transmitted.
//!
//! Both APIs operate on the same Zymic stream format (Header, Body
//! Frames, End Frame), so data encrypted with one can be decrypted
//! with the other. Choose the abstraction level that best fits your
//! environment and I/O model.
//!
//! Streams are immutable. See the crate-level
//! [stream immutability requirements](crate#stream-immutability).
//!
//! [`ZymicStream`]: crate::stream::ZymicStream
//! [`FrameBuf`]: crate::stream::FrameBuf
use crate::{
    bytes::{ByteArray, ByteCursor, ByteCursorMut},
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
use std::io::{Read, Seek, SeekFrom, Write};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Length of 256-bit key in bytes.
const KEY_LEN_256: usize = 32;

/// Header nonce byte buffer.
pub type HeaderNonce = ByteArray<16>;

/// Header MAC byte buffer
type HeaderMac = ByteArray<32>;

/// Length of the header in bytes.
const HEADER_LEN: usize = MAGIC_NUM_LEN
    + VERSION_LEN
    + ALGO_LEN
    + FRAME_LEN_LEN
    + RESERVED_LEN
    + HeaderNonce::LEN
    + ParentKeyId::LEN
    + HeaderMac::LEN;

/// Stream header byte buffer.
pub type HeaderBytes = ByteArray<HEADER_LEN>;

// Header field lengths

/// header magic number field length in bytes
const MAGIC_NUM_LEN: usize = 4;

/// header version field length in bytes
const VERSION_LEN: usize = 1;

/// header algorithm field length in bytes
const ALGO_LEN: usize = 2;

/// header frame-length field length in bytes
const FRAME_LEN_LEN: usize = 1;

/// header reserved field length in bytes
const RESERVED_LEN: usize = 8;

// Header field offsets.

/// magic number field offset
const MAGIC_NUM_OFFSET: usize = 0;

/// version field offset
const VERSION_OFFSET: usize = MAGIC_NUM_OFFSET + MAGIC_NUM_LEN;

/// algorithm field offset
const ALGO_OFFSET: usize = VERSION_OFFSET + VERSION_LEN;

/// frame-length field offset
const FRAME_LEN_OFFSET: usize = ALGO_OFFSET + ALGO_LEN;

/// reserved field offset
const RESERVED_OFFSET: usize = FRAME_LEN_OFFSET + FRAME_LEN_LEN;

/// nonce field offset
const NONCE_OFFSET: usize = RESERVED_OFFSET + RESERVED_LEN;

/// key id field offset
const KEY_ID_OFFSET: usize = NONCE_OFFSET + HeaderNonce::LEN;

/// header MAC field offset
const HEADER_MAC_OFFSET: usize = KEY_ID_OFFSET + ParentKeyId::LEN;

// Header field ranges.

/// header parent ID range
const HEADER_KEY_ID_RANGE: Range<usize> = KEY_ID_OFFSET..KEY_ID_OFFSET + ParentKeyId::LEN;

/// header MAC range
const HEADER_MAC_RANGE: Range<usize> = HEADER_MAC_OFFSET..HEADER_MAC_OFFSET + HeaderMac::LEN;

/// Range over the header used as the `info` parameter into the HKDF
/// used to derive the data key.
const HKDF_INFO_RANGE: Range<usize> = 0..NONCE_OFFSET;

/// Range over the header used as the `salt` parameter into the HKDF
/// used to derive the data key.
const HKDF_SALT_RANGE: Range<usize> =
    NONCE_OFFSET..NONCE_OFFSET + HeaderNonce::LEN + ParentKeyId::LEN;

// Frame field lengths.

/// frame sequence number field length in bytes
const SEQ_NUM_LEN: usize = 4;

/// frame End Length field length in bytes
const END_LEN: usize = 4;

/// frame TAG field length in bytes
///
/// The design specifies that the frame tag length depends on the AEAD
/// algorithm. However, AES-GCM uses 16 byte tags and is the only
/// available algorithm as of this comment. This length can be made
/// more dynamic if a newer algorithm is adopted that needs a larger
/// tag.
const FRAME_TAG_LEN: usize = 16;

/// Total length in bytes of all non-payload frame fields.
const FRAME_META_LEN: usize = FRAME_TAG_LEN + SEQ_NUM_LEN + END_LEN;

const FRAME_HEADER_LEN: usize = SEQ_NUM_LEN + END_LEN;

/// AES-256-GCM nonce length.
type FrameNonceLen = U12;

// Frame field offsets.

/// frame sequence number field offset
const SEQ_NUM_OFFSET: usize = 0;

/// frame End Len field offset
const END_LEN_OFFSET: usize = SEQ_NUM_OFFSET + SEQ_NUM_LEN;

/// frame payload field offset
const PAYLOAD_OFFSET: usize = END_LEN_OFFSET + END_LEN;

/// data key length in bytes
const DATA_KEY_LEN: usize = KEY_LEN_256;

/// header magic number value
const MAGIC_NUM: u32 = 0x6d797a2e;

/// current codec version
const VERSION: u8 = 2;

// AES-256-GCM using a 12-byte nonce.
type Aes256Gcm = AesGcm<Aes256, FrameNonceLen>;

#[repr(u16)]
#[derive(Debug, PartialEq)]
enum CryptoAlgorithm {
    /// AES-256-GCM using HKDF-SHA2-256 for data key derivation
    Aes256GcmHkdfSha256 = 0,
}

/// Valid frame lengths.
///
/// The numerical value assigned to each enum type is the bit-shift
/// value used to compute the length in bytes. The value is written to
/// the frame-length header field.
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub enum FrameLength {
    /// 4 KiB
    Len4KiB = 12,
    /// 8 Kib
    Len8KiB = 13,
    #[default]
    /// 16 KiB
    Len16KiB = 14,
    /// 32 Kib
    Len32KiB = 15,
    /// 64 KiB
    Len64KiB = 16,
}

/// This type is responsible for encoding/decoding the stream header
/// and deriving the stream data key.
#[derive(PartialEq, Clone, Debug)]
pub struct Header {
    frame_len: FrameLength,
    data_key: aes_gcm::Key<Aes256Gcm>,
    bytes: HeaderBytes,
}

/// Builder for the [`Header`] type.
pub struct HeaderBuilder<'a> {
    parent_key: &'a ParentKey,
    nonce: &'a HeaderNonce,
    frame_len: FrameLength,
}

/// A Frame header type that contains the sequence number and frame
/// type for a given frame encoding.
#[derive(Default)]
pub struct FrameHeader {
    seq_num: u32,
    is_end: bool,
}

/// Builder type for [`FrameHeader`].
///
/// # Example
///
///```rust
/// use zymic_core::stream::FrameHeaderBuilder;
///
/// let header = FrameHeaderBuilder::new(0).end().build();
///
/// assert_eq!(header.seq_num(), 0);
/// assert!(header.is_end());
///```
pub struct FrameHeaderBuilder {
    seq_num: u32,
    is_end: bool,
}

/// A buffer for a single frame, capable of holding up to one
/// [`FrameLength`] worth of data.
///
/// This is a lower-level data structure for working with Zymic frames
/// directly. For bulk encryption/decryption, prefer [`ZymicStream`],
/// which implements [`Read`] and [`Write`]. If `std` is unavailable,
/// or you need finer control, [`FrameBuf`] is the no-std-friendly
/// alternative.
///
/// The buffer stores three contiguous sections:
///
/// 1. Frame header — frame metadata (sequence number and end length).
///
/// 2. Payload — plaintext before [`encrypt`] / after
///    [`decrypt`]; ciphertext after [`encrypt`].
///
/// 3. Authentication tag — appended after encryption.
///
/// # Encryption
///
/// Write plaintext into the payload with [`write_payload`]. When all
/// data is written (or the buffer is full), call [`encrypt`] to
/// encrypt the payload in place and append the authentication tag.
/// An existing frame must not be re-encrypted. See the crate-level
/// [stream immutability requirements](crate#stream-immutability).
///
/// # Decryption
///
/// To decrypt, load the raw encrypted frame bytes into a [`FrameBuf`]
/// and then call [`decrypt`]. There are two ways to load bytes:
///
/// * Copy from a slice using
///   [`copy_from_encrypted_bytes`]. This copies up to the
///   configured [`FrameLength`].
///
/// * Write directly into the internal buffer via [`chunk_mut`],
///   then finalize with [`commit_chunk_mut`]. This is
///   convenient when reading from a device or DMA into a provided
///   slice.
///
/// # Example
///
/// The example below encrypts a single End frame, copies the bytes out,
/// then loads and decrypts them.
///
/// ```rust
/// # #[cfg(feature = "os_rng")]
/// # {
/// use zymic_core::{
///     key::ParentKey,
///     stream::{FrameBuf, FrameHeaderBuilder, HeaderBuilder, HeaderNonce},
/// };
/// # use zymic_core::Error;
/// # use zymic_core::OsRng;
/// #
/// # fn main() -> Result<(), Error> {
/// # #[cfg(feature = "os_rng")]
/// # {
/// let plain = vec![1, 2, 3, 4, 5];
///
/// // Build header/keying material per your application.
/// let parent_key = ParentKey::try_from_crypto_rand(&mut OsRng)?;
/// let nonce = HeaderNonce::try_from_crypto_rand(&mut OsRng)?;
/// let header = HeaderBuilder::new(&parent_key, &nonce).build();
///
/// // Prepare a frame and encrypt the payload.
/// let mut fb = FrameBuf::new(&header);
/// let _wrote = fb.write_payload(0, &plain)?;
/// let seq = 0;
/// let fh = FrameHeaderBuilder::new(seq).end().build();
/// fb.encrypt(&fh);
///
/// // Copy encrypted frame bytes somewhere (e.g., to send or store).
/// let mut cipher = Vec::new();
/// cipher.extend_from_slice(fb.as_ref());
/// fb.clear(); // reuse the buffer for another frame if desired
///
/// // Load the encrypted bytes back and decrypt.
/// let mut fb = FrameBuf::new(&header);
/// let copied = fb.copy_from_encrypted_bytes(&cipher);
/// assert_eq!(copied, cipher.len()); // detect truncation if any
/// fb.decrypt(seq)?;
///
/// let decrypted = fb.payload();
/// assert_eq!(decrypted, &plain[..]);
/// # }
/// # Ok(())
/// # }
/// # }
/// ```
///
/// [`FrameBuf`]: crate::stream::FrameBuf
/// [`FrameLength`]: crate::stream::FrameLength
/// [`Read`]: std::io::Read
/// [`Write`]: std::io::Write
/// [`ZymicStream`]: crate::stream::ZymicStream
/// [`commit_chunk_mut`]: Self::commit_chunk_mut
/// [`copy_from_encrypted_bytes`]: Self::copy_from_encrypted_bytes
/// [`chunk_mut`]: Self::chunk_mut
/// [`decrypt`]: Self::decrypt
/// [`encrypt`]: Self::encrypt
/// [`write_payload`]: Self::write_payload
pub struct FrameBuf {
    /// Backing byte buffer for the entire frame (header + payload + tag).
    buf: Vec<u8>,
    /// The total frame length in bytes, as defined by the stream header.
    frame_len: usize,
    /// Max number of payload bytes this frame buffer can consume.
    ///
    /// This is determined by the `frame_len`.
    max_payload_len: usize,
    /// Max position in the buffer that can contain payload data.
    ///
    /// Computed as PAYLOAD_OFFSET + max_payload_len. This value does
    /// not change for the life of a `FrameBuf` instance.
    max_payload_pos: usize,
    /// Current length in bytes of the payload section.
    ///
    /// Updated as payload is written into or read out of the buffer.
    payload_len: usize,
    /// Cipher used to encrypt and decrypt the payload section of the
    /// frame.
    cipher: Aes256Gcm,
}

/// Stream implementation of the Zymic AEAD encoding format.
///
/// The stream implements [`Read`], [`Write`], and [`Seek`] over a
/// Zymic encoded inner type `T` when the `std` feature is enabled.
/// Writes are supported only while encoding a new Stream. Once the
/// Stream has been finalized or an existing Frame has been read,
/// further writes fail because Streams are immutable. See the
/// crate-level [stream immutability requirements](crate#stream-immutability).
///
/// # Usage
///
/// On the write path, plain text data is written to the
/// stream. Encrypted frames are written to the inner type `T`. The
/// basic usage is as follows:
///
/// 1. Write plaintext with [`Write`].
///
/// 2. Call [`eof`] to flush the stream and mark the end of the
///    stream.
///
/// 3. The wrapped writer may be recovered with
///    [`into_inner`].
///
/// On the read path plain text data may be read from the underlying
/// encrypted inner type `T` using [`Read`]. Basic usage is as
/// follows:
///
/// 1. Read plaintext with [`Read`] Data integrity, including frame
///    reordering is handled internally by the stream type. If data
///    fails an integrity check or reordering is detected an [`Error`]
///    is returned.
///
/// 2. To detect if a stream has been truncated, the caller must
///    [`Read`] to the end of the stream and call [`is_eof_or_err`].
///
/// [`eof`]: ZymicStream::eof
/// [`into_inner`]: ZymicStream::into_inner
/// [`Error`]: crate::Error
/// [`Read`]: std::io::Read
/// [`Seek`]: std::io::Seek
/// [`Write`]: std::io::Write
/// [`is_eof_or_err`]: ZymicStream::is_eof_or_err
///
/// # Example
///
///```rust
/// #
/// #
/// # #[cfg(all(feature = "std", feature = "os_rng"))]
/// # {
/// use std::io::{Cursor, copy};
/// use zymic_core::{OsRng, key::ParentKey,
///     stream::{HeaderBuilder, HeaderNonce, ZymicStream}
/// };
/// # use zymic_core::Error;
/// #
/// # fn main() -> Result<(), Error> {
/// #
/// //
/// // Encrypt a simple Vec
/// //
/// let plain_txt = vec![1,2,3,4,5];
/// let mut plain_cursor = Cursor::new(plain_txt);
/// let parent_key = ParentKey::try_from_crypto_rand(&mut OsRng)?;
/// let nonce = HeaderNonce::try_from_crypto_rand(&mut OsRng)?;
/// let header = HeaderBuilder::new(&parent_key, &nonce).build();
/// let mut cipher_txt = Vec::default();
/// let mut writer = ZymicStream::new(cipher_txt, &header);
/// copy(&mut plain_cursor, &mut writer);
/// writer.eof()?;
/// //
/// // Decrypt the data
/// //
/// let cipher_txt = writer.into_inner();
/// let mut cipher_cursor = Cursor::new(cipher_txt);
/// let mut decoded_txt = Vec::default();
/// let mut reader = ZymicStream::new(cipher_cursor, &header);
/// copy(&mut reader, &mut decoded_txt);
/// reader.is_eof_or_err()?;
/// let plain_txt = plain_cursor.into_inner();
/// assert_eq!(vec![1,2,3,4,5], decoded_txt);
/// #
/// # Ok(())
/// # }
/// # }
///```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub struct ZymicStream<T> {
    /// Sequence number tracker.
    ///
    /// For normal read/write operations, this field always holds the
    /// next sequence number to be assigned — it is incremented
    /// immediately after a frame is successfully read or written.
    ///
    /// When a seek is performed, it instead reflects the sequence
    /// number of the frame that the seek landed on.
    seq_num: u32,
    /// Sequence number at which the stream was initialized.
    ///
    /// May be greater than zero if the stream starts reading from
    /// beyond the first frame.
    start_seq_num: u32,
    /// Whether this instance may still encode a new stream.
    ///
    /// Reading an existing Frame or emitting the End Frame makes the
    /// stream immutable and permanently disables further writes.
    can_write: bool,
    /// Current byte position in the payload section.
    ///
    /// Updated on each read or write to track the next payload offset.
    payload_pos: usize,
    /// End-of-stream marker.
    ///
    /// `Some(len)` once the End Frame is reached, where `len` is the
    /// End Length specified in the frame header. `None` otherwise.
    end_len: Option<usize>,
    /// Buffer for the currently active frame.
    frame_buf: FrameBuf,
    /// Contains the encoded Zymic stream.
    ///
    /// On Read, data is coped from `inner` into `frame_buf` and
    /// decrypted.
    ///
    /// On write, encrypted data is copied from `frame_buf` into
    /// `inner`.
    inner: T,
}

/// Derive and return a stream header message digest and data key.
fn derive_data_key(
    parent_key: &ParentKey,
    salt: &[u8],
    info: &[u8],
) -> (HeaderMac, aes_gcm::Key<Aes256>) {
    let mut hkdf_out = [0u8; HeaderMac::LEN + DATA_KEY_LEN];
    let hkdf = Hkdf::<Sha256>::new(Some(salt), parent_key.secret());
    hkdf.expand(info, &mut hkdf_out).expect("hdkf expansion");

    let digest = HeaderMac::from(&hkdf_out[..HeaderMac::LEN]);

    let mut data_key = aes_gcm::Key::<Aes256Gcm>::default();
    data_key.copy_from_slice(&hkdf_out[HeaderMac::LEN..]);

    (digest, data_key)
}

/// Construct an algorithm-sized AEAD nonce from a Frame Sequence
/// Number. The Sequence Number is encoded as an unsigned
/// little-endian integer and zero-extended to the nonce width.
fn frame_nonce(seq_num: u32) -> AesNonce<FrameNonceLen> {
    let mut nonce = AesNonce::<FrameNonceLen>::default();
    nonce[..SEQ_NUM_LEN].copy_from_slice(&seq_num.to_le_bytes());
    nonce
}

impl TryFrom<u8> for FrameLength {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self, Error> {
        match val {
            12 => Ok(FrameLength::Len4KiB),
            13 => Ok(FrameLength::Len8KiB),
            14 => Ok(FrameLength::Len16KiB),
            15 => Ok(FrameLength::Len32KiB),
            16 => Ok(FrameLength::Len64KiB),
            _ => Err(Error::new(ErrorKind::InvalidFrameLength(val))),
        }
    }
}

impl From<FrameLength> for u8 {
    fn from(value: FrameLength) -> Self {
        value as u8
    }
}

impl fmt::Display for FrameLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_usize())
    }
}

impl FrameLength {
    /// Return the frame length in bytes as a `usize`.
    ///
    /// The [`FrameLength`] value encodes the size as an exponent `N`,
    /// where the actual byte length is `2^N`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use zymic_core::stream::FrameLength;
    /// let len = FrameLength::Len4KiB.as_usize();
    /// assert_eq!(len, 4096);
    /// ```
    pub fn as_usize(self) -> usize {
        1 << (self as u8)
    }
}

impl FrameBuf {
    /// Create a new empty frame buffer.
    ///
    /// The maximum capacity of the buffer is determined by the
    /// [`FrameLength`] value encoded in the provided [`Header`].
    ///
    /// The buffer is initialized to an empty state; payload and metadata
    /// must be written before the frame can be used for encryption or
    /// decryption.
    ///
    /// [`FrameLength`]: crate::stream::FrameLength
    /// [`Header`]: crate::stream::Header
    pub fn new(header: &Header) -> Self {
        let frame_len = header.frame_len.as_usize();
        let max_payload_len = frame_len - FRAME_META_LEN;
        let cipher = AesKeyInit::new(&header.data_key);

        Self {
            buf: Vec::with_capacity(frame_len),
            frame_len,
            max_payload_len,
            max_payload_pos: PAYLOAD_OFFSET + max_payload_len,
            payload_len: 0,
            cipher,
        }
    }

    /// Write `payload` to the payload section of the frame at the
    /// `payload_off` offset. Returns the number of bytes written.
    ///
    /// If a length of 0 is returned, the buffer is full.
    ///
    /// The diagram below illustrates the binary layout of the buffer
    /// including the payload section. Payload data is written to the
    /// Payload section of the buffer at the specified
    /// `payload_off`. A `payload_off of 0 is the start of the Payload
    /// section.
    ///
    ///```text
    ///                  Buffer Length
    /// <---------------------------------------------->
    ///                           Payload      Payload
    ///      Frame Header         Length       Capacity
    /// <-------------------> <-------------> <-------->
    ///
    /// +----------+---------+---------------+----------+
    /// | Seq. Num | End Len |    Payload    |  (free)  |
    /// +----------+---------+---------------+----------+
    ///                      ^
    ///                      |
    /// payload_off: 0 ------+
    ///```
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if `payload_off` exceeds
    /// the number of payload bytes written.
    ///
    /// [`Error`]: crate::Error
    pub fn write_payload(&mut self, payload_off: usize, payload: &[u8]) -> Result<usize, Error> {
        if payload_off > self.payload_len {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let abs_payload_off = PAYLOAD_OFFSET + payload_off;
        let buf_len = usize::min(self.max_payload_pos, abs_payload_off + payload.len());
        if buf_len > self.buf.len() {
            self.buf.resize(buf_len, 0);
        }
        let copy_len = buf_len - abs_payload_off;

        self.buf[abs_payload_off..abs_payload_off + copy_len].copy_from_slice(&payload[..copy_len]);

        self.payload_len = usize::max(self.payload_len, payload_off + copy_len);

        Ok(copy_len)
    }

    /// Return a slice of the current payload contents.
    ///
    /// The slice refers into the internal buffer:
    /// * Ciphertext after a call to [`encrypt`].
    /// * Plaintext after a successful call to [`decrypt`].
    ///
    /// If no payload has been written yet, returns an empty slice.
    ///
    /// Note: the returned slice does not include header or tag bytes.
    ///
    /// [`decrypt`]: Self::decrypt
    /// [`encrypt`]: Self::encrypt
    pub fn payload(&self) -> &[u8] {
        if self.buf.len() < PAYLOAD_OFFSET {
            &self.buf[..0]
        } else {
            &self.buf[PAYLOAD_OFFSET..PAYLOAD_OFFSET + self.payload_len]
        }
    }

    /// Returns `true` if additional bytes can still be written
    /// into the payload section.
    pub fn has_payload_capacity(&self) -> bool {
        self.payload_capacity() > 0
    }

    /// Return the number of bytes that may still be written into
    /// the payload section before the maximum frame payload length
    /// is reached.
    pub fn payload_capacity(&self) -> usize {
        self.max_payload_len - self.payload_len
    }

    /// Encrypt the frame in place.
    ///
    /// The payload and metadata in this buffer are encrypted using the
    /// supplied [`FrameHeader`], and the buffer is updated to contain
    /// the ciphertext and authentication tag.
    ///
    /// This low-level API does not track nonce use. The caller MUST
    /// encrypt at most one Frame for each Sequence Number under a
    /// given Header's Data Key. Changing an encrypted Frame requires a
    /// new Stream Header and Data Key.
    ///
    /// The diagram below illustrates the binary layout of the buffer
    /// after [`encrypt`] is called.
    ///
    ///```text
    ///                   Buffer Length
    ///  <----------------------------------------------->
    ///                                        Payload
    ///            Frame Header                Length
    ///  <-------------------------------> <------------->
    ///
    /// +----------+---------+---------------+-----------+
    /// | Seq. Num | End Len |    Payload    |  Auth Tag |
    /// +----------+---------+---------------+-----------+
    ///```
    /// [`encrypt`]: Self::encrypt
    /// [`FrameHeader`]: crate::stream::FrameHeader
    pub fn encrypt(&mut self, frame_header: &FrameHeader) {
        if self.buf.len() < FRAME_HEADER_LEN {
            self.buf.resize(FRAME_HEADER_LEN, 0);
        }
        debug_assert!(self.payload_len <= self.buf.len() - FRAME_HEADER_LEN);

        let seq_num_bytes = frame_header.seq_num().to_le_bytes();
        self.set_bytes(seq_num_bytes.as_slice(), SEQ_NUM_OFFSET);

        let eof_len_bytes = if frame_header.is_end() {
            u32::try_from(self.payload_len)
                .expect("payload len should be 4 bytes")
                .to_le_bytes()
        } else {
            u32::MAX.to_le_bytes()
        };
        self.set_bytes(eof_len_bytes.as_slice(), END_LEN_OFFSET);

        let nonce = frame_nonce(frame_header.seq_num());
        let (frame_header, payload) = self.buf.split_at_mut(FRAME_HEADER_LEN);
        let eof_len = &frame_header[END_LEN_OFFSET..PAYLOAD_OFFSET];

        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, eof_len, (&mut payload[..self.payload_len]).into())
            .expect("buffer of sufficient size");

        // Ensure that we can append the authentication tag after the
        // payload.
        self.buf.truncate(self.payload_len + FRAME_HEADER_LEN);

        self.buf.extend_from_slice(&tag);
    }

    /// Decrypt the frame in-place and return its parsed header.
    ///
    /// # Errors
    ///
    /// This method returns an [`Error`] if:
    ///
    /// * The buffer is too short to contain the required frame
    ///   fields. At minimum, the sequence number, end length, and tag
    ///   must be present.
    ///
    /// * The supplied `seq_num` does not match the sequence number
    ///   recovered and authenticated from the frame. This indicates
    ///   a missing or reordered frame.
    ///
    /// * For an End Frame, the end length does not match the actual
    ///   payload length.
    ///
    /// * Authentication fails: the computed AEAD tag does not match the
    ///   tag stored in the frame.
    ///
    /// [`Error`]: crate::error::Error
    pub fn decrypt(&mut self, seq_num: u32) -> Result<FrameHeader, Error> {
        if self.buf.len() < FRAME_META_LEN {
            return Err(Error::new(ErrorKind::InvalidBufLength));
        }
        let (frame_header, frame) = self.buf.split_at_mut(FRAME_HEADER_LEN);
        let (seq_num_bytes, eof_len_bytes) = frame_header.split_at_mut(END_LEN_OFFSET);

        let seq_num_decoded =
            u32::from_le_bytes(seq_num_bytes.try_into().expect("seq num should be 4 bytes"));

        let eof_len =
            u32::from_le_bytes(eof_len_bytes.try_into().expect("eof len should be 4 bytes"));

        let (payload_len, is_end) = if eof_len != u32::MAX {
            if eof_len as usize > self.max_payload_len {
                return Err(Error::new(ErrorKind::InvalidEndLength(eof_len)));
            }
            (eof_len as usize, true)
        } else {
            (self.frame_len - FRAME_META_LEN, false)
        };

        // Confirm that the computed payload len is valid
        let body_len = payload_len + FRAME_TAG_LEN;
        if frame.len() < body_len {
            return Err(Error::new(ErrorKind::InvalidEndLength(eof_len)));
        }

        let (payload, mac) = frame.split_at_mut(payload_len);

        let tag = Tag::try_from(&mac[..FRAME_TAG_LEN]).expect("tag should be 16 bytes");
        let nonce = frame_nonce(seq_num_decoded);

        self.cipher
            .decrypt_inout_detached(&nonce, eof_len_bytes, payload.into(), &tag)?;

        if seq_num != seq_num_decoded {
            return Err(Error::new(ErrorKind::UnexpectedSeqNum(
                seq_num,
                seq_num_decoded,
            )));
        }
        self.payload_len = payload_len;

        Ok(FrameHeader::new(seq_num, is_end))
    }

    /// Reset the frame buffer to an empty state.
    ///
    /// This removes all data from the internal buffer and sets the
    /// payload length back to `0`. After calling this, the buffer can
    /// be reused for writing a new frame payload.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.payload_len = 0;
    }

    /// Returns `true` if the buffer contains no data.
    ///
    /// Used only in tests to check whether the frame buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Return the number of bytes in the frame buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Copy raw encrypted bytes (one frame) into this buffer.
    ///
    /// Copies up to this frame’s `FrameLength` from `src`, replacing
    /// the current contents, and returns the number of bytes
    /// copied. If the return value is less than `src.len()`, the
    /// input was truncated to fit.
    ///
    /// This function does not validate or decrypt; call [`decrypt`]
    /// next.
    ///
    ///
    /// [`decrypt`]: Self::decrypt
    pub fn copy_from_encrypted_bytes(&mut self, src: &[u8]) -> usize {
        let len = usize::min(src.len(), self.frame_len);
        self.buf.resize(len, 0);
        self.payload_len = 0;
        self.buf[..len].copy_from_slice(&src[..len]);
        len
    }

    /// Returns a writable chunk sized to this frame’s configured [`FrameLength`].
    ///
    /// This prepares the buffer for a raw, zero-copy read of one
    /// on-wire frame (header + encrypted payload + tag). It clears
    /// any previous contents and resizes the internal buffer to
    /// exactly `FrameLength`, then returns a mutable slice you can
    /// fill (e.g., via a device read).
    ///
    /// After writing, call [`commit_chunk_mut`] with the number
    /// of bytes actually written. This function does not validate or
    /// decrypt the bytes; call [`decrypt`] afterwards.
    ///
    /// [`decrypt`]: Self::decrypt
    /// [`FrameLength`]: crate::stream::FrameLength
    /// [`commit_chunk_mut`]: Self::commit_chunk_mut
    pub fn chunk_mut(&mut self) -> &mut [u8] {
        self.clear_resize_to_full();
        &mut self.buf
    }

    /// Commit the number of bytes written into the slice returned by
    /// [`chunk_mut`].
    ///
    /// Truncates the internal buffer to `len`. This does not perform
    /// structural validation or decryption; [`decrypt`] will do that.
    ///
    /// # Errors Returns [`Error`] if `len` exceeds the length
    /// of the prepared buffer.
    ///
    /// [`Error`]: crate::Error
    /// [`decrypt`]: Self::decrypt
    /// [`chunk_mut`]: Self::chunk_mut
    pub fn commit_chunk_mut(&mut self, len: usize) -> Result<(), Error> {
        if len > self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidBufLength));
        }
        self.buf.truncate(len);
        self.payload_len = 0;

        Ok(())
    }

    /// Returns true if the length of this instance is less than the
    /// frame header length.
    ///
    /// This indicates that the buffer does not yet contain enough
    /// bytes to parse a complete frame header.
    ///
    /// Currently this is only used by `ZymicStream`.
    #[cfg(any(feature = "std", test))]
    fn is_partial(&self) -> bool {
        self.buf.len() < FRAME_HEADER_LEN
    }

    /// Overwrite bytes in the buffer starting at the given `offset`.
    ///
    /// The slice `bytes` is copied directly into the buffer at
    /// `offset..offset + bytes.len()`.
    ///
    /// # Panics
    ///
    /// Panics if the offset and length exceed the current buffer
    /// capacity.
    fn set_bytes(&mut self, bytes: &[u8], offset: usize) {
        self.buf[offset..offset + bytes.len()].copy_from_slice(bytes)
    }

    /// Clear the buffer and expand it to the full frame length.
    ///
    /// The internal buffer is emptied and then resized to the maximum
    /// capacity defined by `frame_len`, filling new bytes with `0`.
    ///
    /// This is typically used to prepare the buffer for reading or
    /// decrypting an entire frame from an input source.
    fn clear_resize_to_full(&mut self) {
        self.buf.clear();
        self.buf.resize(self.frame_len, 0);
        self.payload_len = 0;
    }
}

impl AsRef<[u8]> for FrameBuf {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl core::ops::Deref for FrameBuf {
    type Target = [u8];

    /// Dereferences to the entire on-wire frame bytes (header +
    /// payload + optional tag). For just the payload, use
    /// [`payload`].
    ///
    /// [`payload`]: Self::payload
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl Header {
    /// Parse and validate a [`Header`] from its serialized byte form.
    ///
    /// This function decodes the raw [`HeaderBytes`] produced by
    /// serialization and validates it against the provided [`ParentKey`].
    /// On success it returns a new [`Header`] containing the derived
    /// Data Key and associated parameters.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if any of the following conditions are met:
    ///
    /// * The magic number is invalid (stream does not conform to Zymic).
    /// * The version field is not supported by this implementation.
    /// * The algorithm identifier is not recognized.
    /// * The parent key ID embedded in the header does not match the
    ///   provided [`ParentKey`].
    /// * The frame length is invalid or unsupported.
    /// * The HKDF-derived header MAC does not match the value stored in
    ///   the header (authentication failure).
    ///
    /// [`Header`]: crate::stream::Header
    /// [`HeaderBytes`]: crate::stream::HeaderBytes
    /// [`ParentKey`]: crate::key::ParentKey
    /// [`Error`]: crate::error::Error
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
        let algo = byte_buf.get_u16_le();
        if algo != CryptoAlgorithm::Aes256GcmHkdfSha256 as u16 {
            return Err(Error::new(ErrorKind::UnsupportedCrypto(algo)));
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
        };

        Ok(Self {
            frame_len,
            data_key,
            bytes,
        })
    }

    /// Return the serialized header as raw bytes.
    ///
    /// This is the encoded [`Header`] in its on-wire format,
    /// as stored internally when the header was constructed
    /// or parsed.
    ///
    /// The returned value is a borrowed reference and remains
    /// valid for the lifetime of this [`Header`].
    ///
    /// [`Header`]: crate::stream::Header
    pub fn bytes(&self) -> &HeaderBytes {
        &self.bytes
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Header {
    fn drop(&mut self) {
        self.data_key.zeroize();
    }
}

impl<'a> HeaderBuilder<'a> {
    /// Create a new instance. The `key_id`, and `nonce` should be
    /// unique values, preferably generated from a CSRNG. The
    /// `parent_key` parameter **must** be generated from a CSRNG.
    pub fn new(parent_key: &'a ParentKey, nonce: &'a HeaderNonce) -> Self {
        Self {
            parent_key,
            nonce,
            frame_len: Default::default(),
        }
    }

    /// Set the frame length for the stream header.
    pub fn with_frame_len(mut self, len: FrameLength) -> Self {
        self.frame_len = len;
        self
    }

    /// Return a new [`Header`] instance from the configuration of
    /// this instance.
    pub fn build(self) -> Header {
        // Encode the binary header fields for the stream header.
        let bytes = HeaderBytes::default();
        let mut cur = ByteCursorMut::new(bytes);
        cur.push_u32_le(MAGIC_NUM);
        cur.push_u8(VERSION);
        cur.push_u16_le(CryptoAlgorithm::Aes256GcmHkdfSha256 as u16);
        cur.push_u8(self.frame_len.into());
        cur.push_bytes(&[0u8; RESERVED_LEN]);
        cur.push_bytes(self.nonce);
        cur.push_bytes(self.parent_key.id());
        let mut bytes = cur.into_inner();

        let info = &bytes[HKDF_INFO_RANGE];
        let salt = &bytes[HKDF_SALT_RANGE];

        let (header_mac, data_key) = derive_data_key(self.parent_key, salt, info);
        bytes.as_mut()[HEADER_MAC_OFFSET..].copy_from_slice(&header_mac);

        Header {
            frame_len: self.frame_len,
            data_key,
            bytes,
        }
    }
}

impl FrameHeader {
    /// Create a new header.
    ///
    /// If `is_end` is `true`, this header describes an **End Frame**.
    /// Otherwise it describes a **Body Frame**.
    fn new(seq_num: u32, is_end: bool) -> Self {
        Self { seq_num, is_end }
    }

    /// Return the sequence number for this header.
    pub fn seq_num(&self) -> u32 {
        self.seq_num
    }

    /// Returns `true` if this instance represents an End Frame.
    ///
    /// Returns `false` for Body Frames.
    pub fn is_end(&self) -> bool {
        self.is_end
    }
}

impl FrameHeaderBuilder {
    /// Create a new instance specifying the sequence number. The
    /// sequence number must be incremented for each frame.
    pub fn new(seq_num: u32) -> Self {
        Self {
            seq_num,
            is_end: false,
        }
    }

    /// Set the type as an End Frame.
    pub fn end(mut self) -> Self {
        self.is_end = true;
        self
    }

    /// Return a new [`FrameHeader`] instance.
    pub fn build(self) -> FrameHeader {
        FrameHeader::new(self.seq_num, self.is_end)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T> ZymicStream<T> {
    /// Create a new instance starting at sequence number 0.
    ///
    /// The stream’s frame sizing and data key are taken from
    /// `header`.  This is the common constructor for reading or
    /// writing a fresh stream.
    ///
    /// See [`new_with_seq_num`] if you need to resume at
    /// a non‑zero sequence number.
    ///
    /// [`new_with_seq_num`]: Self::new_with_seq_num
    pub fn new(inner: T, header: &Header) -> Self {
        Self::new_with_seq_num(inner, header, 0)
    }

    /// Create a new instance starting at sequence number `seq_num`.
    ///
    /// This is intended for resuming from a known frame boundary—for
    /// example, when continuing decryption at a checkpoint or
    /// appending frames when you already know the next sequence
    /// number.
    pub fn new_with_seq_num(inner: T, header: &Header, seq_num: u32) -> Self {
        let frame_buf = FrameBuf::new(header);

        Self {
            seq_num,
            start_seq_num: seq_num,
            can_write: true,
            payload_pos: 0,
            end_len: None,
            frame_buf,
            inner,
        }
    }

    /// Consume this instance and return the inner type.
    ///
    /// This is useful when you need to recover ownership of the
    /// underlying reader or writer after finishing with the stream.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Return true if the stream has reached its End Frame.
    pub fn is_eof(&self) -> bool {
        self.end_len
            .map_or_else(|| false, |end_len| self.payload_pos == end_len)
    }

    /// Confirm that the stream has ended cleanly.
    ///
    /// Returns `Ok(())` if the stream has reached its End Frame.
    /// Returns an [`Error`] if the stream is not at EOF, which may indicate
    /// that the stream was truncated or is otherwise incomplete.
    ///
    /// [`Error`]: crate::error::Error
    pub fn is_eof_or_err(&self) -> Result<(), Error> {
        if self.is_eof() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Truncation))
        }
    }

    /// Convert a frame index to an frame offset.
    ///
    /// A frame offset is the byte offset position at the start of a
    /// frame.
    #[inline]
    fn frame_idx_to_frame_off(&self, frame_idx: u32) -> Result<u64, Error> {
        let frame_off = (frame_idx as u64)
            .checked_mul(self.frame_buf.frame_len as u64)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

        Ok(frame_off)
    }

    /// Convert an stream byte offset to a frame index.
    ///
    /// A frame offset is the byte offset position at the start of a
    /// frame.
    #[inline]
    fn byte_off_to_frame_idx(&self, abs_off: u64) -> Result<u32, Error> {
        let frame_idx = abs_off / self.frame_buf.frame_len as u64;

        Ok(u32::try_from(frame_idx)?)
    }

    /// Convert a payload offset into a frame index.
    ///
    /// Payload offset is a position within the logical payload data
    /// of the stream (excluding header metadata).
    #[inline]
    fn payload_off_to_frame_idx(&self, payload_offset: u64) -> Result<u32, Error> {
        let frame_idx = payload_offset / self.frame_buf.max_payload_len as u64;

        Ok(u32::try_from(frame_idx)?)
    }

    /// Convert a payload offset to an frame offset.
    ///
    /// Payload offset is position within the logical payload data of
    /// the stream (excluding header metadata).
    ///
    /// Frame offset is the corresponding byte position of the
    /// containing frame in the full stream.
    #[inline]
    fn payload_off_to_frame_off(&self, payload_offset: u64) -> Result<u64, Error> {
        let frame_idx = payload_offset / self.frame_buf.max_payload_len as u64;
        let frame_off = frame_idx
            .checked_mul(self.frame_buf.frame_len as u64)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

        Ok(frame_off)
    }

    /// Return the current absolute payload offset.
    #[inline]
    fn current_payload_off(&self) -> Result<u64, Error> {
        let frame_off = self.current_frame_idx();
        let abs_payload_off = (frame_off as usize)
            .checked_mul(self.frame_buf.max_payload_len)
            //.and_then(|v| v.checked_sub(self.frame_buf.max_payload_len))
            .and_then(|v| v.checked_add(self.payload_pos))
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

        Ok(abs_payload_off as u64)
    }

    /// Return the payload offset of the last frame in the stream.
    #[inline]
    fn payload_end_off(&self) -> Result<u64, Error> {
        let frame_off = self.current_frame_idx();
        let abs_payload_len = (frame_off as usize)
            .checked_mul(self.frame_buf.max_payload_len)
            .and_then(|v| v.checked_add(self.frame_buf.payload_len.saturating_sub(1)))
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

        Ok(abs_payload_len as u64)
    }

    /// Return the current frame index.
    #[inline]
    fn current_frame_idx(&self) -> u32 {
        self.seq_num - self.start_seq_num
    }

    /// Return the number of payload bytes remaining in the current
    /// frame of the stream.
    #[inline]
    fn frame_payload_remaining(&self) -> usize {
        self.frame_buf.payload_len - self.payload_pos
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T> ZymicStream<T> {}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: Write> ZymicStream<T> {
    /// Finalize the stream by encrypting and writing its End Frame.
    ///
    /// The End Frame marks the logical end of a Zymic stream. This
    /// method encrypts the frame, writes it to the inner [`Write`]
    /// target, and flushes the output.
    ///
    /// Call this once after all plaintext has been written; a stream
    /// without an End Frame is considered truncated and invalid.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if writing to or flushing the inner
    /// target fails, or if the Stream has already been finalized or
    /// read and is therefore immutable.
    ///
    /// [`Write`]: std::io::Write
    /// [`Error`]: crate::error::Error
    pub fn eof(&mut self) -> Result<(), Error> {
        if !self.can_write {
            return Err(Error::new(ErrorKind::StreamImmutable));
        }

        self.can_write = false;
        self.frame_buf
            .encrypt(&FrameHeaderBuilder::new(self.seq_num).end().build());
        self.inner.write_all(self.frame_buf.as_ref())?;
        self.inner.flush()?;

        let len = self.frame_buf.payload_len;
        self.end_len = Some(len);
        self.payload_pos = len;

        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: Read> ZymicStream<T> {
    /// Read the next frame of the stream and decrypt the payload
    /// section in-place.
    ///
    /// Returns `true` if the frame buffer is filled with the next
    /// frame read from the underlying `inner` type. The payload
    /// section is decrypted in-place.
    ///
    /// Returns `false` the end-of-file was reached on the underlying
    /// `inner` type and no data was copied into the frame buffer.
    ///
    /// # Errors
    ///
    /// * If the stream reaches an unexpected end of file.
    ///
    /// * For any failure reading the underlying inner type.
    ///
    /// * Integrity check failure during decryption.
    fn read_next_frame(&mut self) -> Result<bool, Error> {
        self.can_write = false;
        self.frame_buf.clear_resize_to_full();
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
            return Ok(false);
        }
        if self.frame_buf.is_partial() {
            return Err(Error::new(ErrorKind::UnexpectedEof));
        }

        let frame_header = self.frame_buf.decrypt(self.seq_num)?;
        self.end_len = frame_header.is_end().then_some(self.frame_buf.payload_len);
        self.payload_pos = 0;

        Ok(true)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: Read> Read for ZymicStream<T> {
    /// Read decrypted plaintext bytes from the stream into the
    /// internal frame buffer.
    ///
    /// This implementation transparently handles frame boundaries:
    /// when the current frame is exhausted, the next frame is read,
    /// decrypted, and verified before more bytes are copied into the
    /// frame buffer.
    ///
    /// The internal sequence number is incremented after each frame is
    /// successfully processed. The End Frame marks the logical EOF for
    /// the stream; once reached, further reads will return `Ok(0)`.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if:
    /// * The underlying read fails.
    /// * Decryption fails due to authentication or integrity checks.
    /// * The sequence number overflows.
    ///
    /// On decryption failure, the error’s inner cause is a [`Error`]
    /// describing the integrity violation.
    ///
    /// [`Error`]: crate::error::Error
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut total_len = 0;

        while !buf.is_empty() && !self.is_eof() {
            if self.frame_payload_remaining() == 0 && self.read_next_frame()? {
                // The End Frame consumes the current sequence number but
                // does not require a subsequent one. This allows
                // `u32::MAX` to be used by a valid terminal Frame.
                if self.end_len.is_none() {
                    self.seq_num = self
                        .seq_num
                        .checked_add(1)
                        .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                }
            }
            let remaining = self.frame_payload_remaining();
            if remaining == 0 {
                break;
            }
            let payload = self.frame_buf.payload();
            if payload.is_empty() {
                break;
            }
            let len = usize::min(remaining, buf.len());
            buf[..len].copy_from_slice(&payload[self.payload_pos..self.payload_pos + len]);

            buf = &mut buf[len..];
            self.payload_pos += len;
            total_len += len;
        }

        Ok(total_len)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: Write> Write for ZymicStream<T> {
    /// Write and encrypt plaintext bytes to the stream.
    ///
    /// This implementation transparently handles frame boundaries:
    /// when the current frame is exhausted, it is encrypted and
    /// flushed to the underlying stream.
    ///
    /// The internal sequence number is incremented after each frame
    /// is successfully flushed.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the underlying write fails or
    /// if the Stream has already been finalized or read and is
    /// therefore immutable.
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, std::io::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.can_write {
            return Err(Error::new(ErrorKind::StreamImmutable).into());
        }

        let mut total_len = 0;

        while !buf.is_empty() {
            if !self.frame_buf.has_payload_capacity() {
                // A Body Frame must always leave a sequence number for
                // the required End Frame. Check before encrypting or
                // writing so that `u32::MAX` remains available as the
                // terminal sequence number.
                let next_seq_num = self
                    .seq_num
                    .checked_add(1)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                self.frame_buf
                    .encrypt(&FrameHeaderBuilder::new(self.seq_num).build());
                if let Err(err) = self.inner.write_all(self.frame_buf.as_ref()) {
                    // A partial write may have exposed this nonce, so the
                    // Frame cannot be encrypted or emitted again safely.
                    self.can_write = false;
                    return Err(err);
                }
                self.frame_buf.clear();
                self.seq_num = next_seq_num;
                self.payload_pos = 0;
            }
            let len = self.frame_buf.write_payload(self.payload_pos, buf)?;
            buf = &buf[len..];
            self.payload_pos += len;
            total_len += len;
        }
        Ok(total_len)
    }

    /// No-op flush.
    ///
    /// This stream does not emit partial frames on
    /// `flush()`. Flushing the underlying writer is handled when
    /// closing the stream.
    ///
    /// To close the stream and ensure all encrypted data is written
    /// and flushed, call [`ZymicStream::eof`].
    ///
    /// # Errors
    ///
    /// This method never returns an error.
    ///
    /// [`ZymicStream::eof`]: crate::stream::ZymicStream::eof
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: Seek + Read> ZymicStream<T> {
    /// Seek to an payload offset position.
    ///
    /// This positions the stream at `payload_off` within the logical
    /// payload` (excluding header/metadata). The containing frame is
    /// located, read, authenticated, and decrypted; then
    /// `payload_pos` is set to the target offset within that frame.
    ///
    /// # Errors
    ///
    /// * If the `payload_off` offseet argument is beyond the end of
    ///   the stream.
    ///
    /// * If the frame that contains the `payload_off` offset fails
    ///   decryption.
    ///
    fn seek_to_payload_off(&mut self, payload_off: u64) -> Result<(), Error> {
        let frame_off = self.payload_off_to_frame_off(payload_off)?;
        self.inner.seek(SeekFrom::Start(frame_off))?;
        self.seq_num = self
            .payload_off_to_frame_idx(payload_off)?
            .checked_add(self.start_seq_num)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

        // Read the frame into the frame buffer at the seek poistion.
        if !self.read_next_frame()? {
            return Err(Error::new(ErrorKind::UnexpectedEof));
        }

        // The above read_next_frame moves the inner seek position to
        // the end of the frame. Therefore, we need to call seek back
        // to the indented position.
        self.inner.seek(SeekFrom::Start(frame_off))?;

        let payload_off = payload_off as usize % self.frame_buf.max_payload_len;
        if payload_off < self.frame_buf.payload_len || payload_off == 0 {
            self.payload_pos = payload_off;
        } else {
            return Err(Error::new(ErrorKind::UnexpectedEof));
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: Seek + Read> Seek for ZymicStream<T> {
    /// Seek to a position within the stream.
    ///
    /// The `pos` argument corresponds to a position of plaintext
    /// payload in the stream.
    ///
    /// On success, this method reads and authenticates the frame that
    /// contains the target payload offset.
    ///
    /// # Errors
    ///
    /// * If the position is beyond the end of the stream.
    ///
    /// * If the position is before the start of the stream.
    ///
    /// * If the frame the seek position maps to fails to decrypt.
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, std::io::Error> {
        let payload_off = match pos {
            SeekFrom::Start(payload_off) => {
                self.seek_to_payload_off(payload_off)?;

                payload_off
            }
            SeekFrom::End(payload_off) => {
                if payload_off > 0 {
                    // No support for exceeding the end of the file.
                    return Err(Error::new(ErrorKind::UnexpectedEof).into());
                }
                //
                // Read the last frame
                //
                let abs_end = self.inner.seek(SeekFrom::End(0))?.saturating_sub(1);
                let end_frame_idx = self.byte_off_to_frame_idx(abs_end)?;
                let end_frame_off = self.frame_idx_to_frame_off(end_frame_idx)?;

                // let abs_end_frame_off = self.abs_off_to_abs_frame_off(abs_end)?;
                self.inner.seek(SeekFrom::Start(end_frame_off))?;
                self.seq_num = end_frame_idx
                    .checked_add(self.start_seq_num)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                if !self.read_next_frame()? {
                    return Err(Error::new(ErrorKind::UnexpectedEof).into());
                }
                //
                // Compute the absolute length of the payload based on
                // the frame offset and the payload length of the last
                // frame.
                //
                let payload_end_off = self.payload_end_off()?;
                let abs_payload_len = payload_end_off
                    .checked_add(u64::from(payload_end_off > 0))
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;

                // If the input parameter `abs_payload_off` is 0, then
                // the returned offset is the length of the
                // payload. Otherwise, it's an offset value from
                // [0..n).
                if payload_off == 0 {
                    let inner_seek_off = abs_payload_len.saturating_sub(1);
                    self.seek_to_payload_off(inner_seek_off)?;
                    abs_payload_len
                } else {
                    let abs_payload_len = i64::try_from(abs_payload_len)
                        .map_err(|e| Error::new(ErrorKind::TryFromInt(e)))?;
                    // Apply the seek offset to the length of the absolute
                    // payload to get the new offset.
                    let inner_seek_off = abs_payload_len
                        .checked_add(payload_off)
                        .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                    if inner_seek_off < 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
                    }
                    self.seek_to_payload_off(inner_seek_off as u64)?;
                    inner_seek_off as u64
                }
            }
            SeekFrom::Current(payload_off) => {
                let current_abs_payload_off = i64::try_from(self.current_payload_off()?)
                    .map_err(|e| Error::new(ErrorKind::TryFromInt(e)))?;

                let new_abs_payload_off = payload_off
                    .checked_add(current_abs_payload_off)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                if new_abs_payload_off < 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
                }

                self.seek_to_payload_off(new_abs_payload_off as u64)?;

                new_abs_payload_off as u64
            }
        };

        Ok(payload_off)
    }
}

#[cfg(test)]
mod tests;
