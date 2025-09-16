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
//! [`ZymicStream`]: crate::stream::ZymicStream
//! [`FrameBuf`]: crate::stream::FrameBuf
use crate::{
    bytes::{ByteArray, ByteCursor, ByteCursorMut},
    error::{Error, ErrorKind},
    key::{ParentKey, ParentKeyId},
};
use aes_gcm::{
    aead::{
        generic_array::typenum::{Unsigned, U12},
        AeadInPlace,
    },
    aes::Aes256,
    AesGcm, KeyInit as AesKeyInit, Nonce as AesNonce, Tag,
};
use alloc::vec::Vec;
use core::{fmt, ops::Range};
use hkdf::Hkdf;
use sha2::Sha256;

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

/// frame invocation field length in bytes
const INVOCATION_LEN: usize = 8;

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
const FRAME_META_LEN: usize = FRAME_TAG_LEN + SEQ_NUM_LEN + END_LEN + INVOCATION_LEN;

const FRAME_HEADER_LEN: usize = SEQ_NUM_LEN + END_LEN + INVOCATION_LEN;

/// Length of AEAD nonce in bytes
type FrameNonceLen = U12;
const FRAME_NONCE_LEN: usize = FrameNonceLen::USIZE;

// Frame field offsets.

/// frame sequence number field offset
const SEQ_NUM_OFFSET: usize = 0;

/// frame invoation field offset
const INVOCATION_OFFSET: usize = SEQ_NUM_OFFSET + SEQ_NUM_LEN;

/// frame End Len field offset
const END_LEN_OFFSET: usize = INVOCATION_OFFSET + INVOCATION_LEN;

/// frame payload field offset
const PAYLOAD_OFFSET: usize = END_LEN_OFFSET + END_LEN;

/// data key length in bytes
const DATA_KEY_LEN: usize = KEY_LEN_256;

/// header magic number value
const MAGIC_NUM: u32 = 0x6d797a2e;

/// current codec version
const VERSION: u8 = 1;

// AES-256 GCM using SeqNum size nonce.
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

/// A Frame header type that contains the sequence number, invocation
/// number, and frame type for a given frame encoding.
#[derive(Default)]
pub struct FrameHeader {
    seq_num: u32,
    invocation: u64,
    is_end: bool,
}

/// Builder type for [`FrameHeader`].
///
/// # Example
///
///```rust
/// use zymic_core::stream::FrameHeaderBuilder;
///
/// let header = FrameHeaderBuilder::new(0).invocation(1).end().build();
///
/// assert_eq!(header.seq_num(), 0);
/// assert_eq!(header.invocation(), 1);
/// assert!(header.is_end());
///```
pub struct FrameHeaderBuilder {
    seq_num: u32,
    invocation: u64,
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
/// 1. Frame header — frame metadata (sequence number, invocation,
///    end length).
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
    /// Invocation counter for the current frame.
    ///
    /// Incremented each time the same frame is encrypted with the
    /// same data key, ensuring nonce uniqueness.
    invocation: u64,
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

impl TryFrom<u8> for FrameLength {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self, Error> {
        match val {
            12 => Ok(FrameLength::Len4KiB),
            13 => Ok(FrameLength::Len8KiB),
            14 => Ok(FrameLength::Len16KiB),
            15 => Ok(FrameLength::Len32KiB),
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
    ///                    Buffer Length
    ///  <----------------------------------------------->
    ///                                        Payload       Payload
    ///            Frame Header                Length        Capacity
    ///  <-------------------------------> <-------------> <-------->
    ///
    /// +----------+------------+---------+---------------+----------+
    /// | Seq. Num | Invocation | End Len |    Payload    |  (free)  |
    /// +----------+------------+---------+---------------+----------+
    ///                                   ^
    ///                                   |
    ///             payload_off: 0 -------+
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

    /// Encrypt the frame in place and return its header.
    ///
    /// The payload and metadata in this buffer are encrypted using the
    /// supplied [`FrameHeader`], and the buffer is updated to contain
    /// the ciphertext and authentication tag.
    ///
    /// The diagram below illistrates the binary layout of the buffer
    /// after [`encrypt`] is called.
    ///
    ///```text
    ///                       Buffer Length
    ///  <---------------------------------------------------------->
    ///                                        Payload
    ///            Frame Header                Length
    ///  <-------------------------------> <------------->
    ///
    /// +----------+------------+---------+---------------+-----------+
    /// | Seq. Num | Invocation | End Len |    Payload    |  Auth Tag |
    /// +----------+------------+---------+---------------+-----------+
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

        let invocation_bytes = frame_header.invocation().to_le_bytes();
        self.set_bytes(invocation_bytes.as_slice(), INVOCATION_OFFSET);

        let eof_len_bytes = if frame_header.is_end() {
            u32::try_from(self.payload_len)
                .expect("payload len should be 4 bytes")
                .to_le_bytes()
        } else {
            u32::MAX.to_le_bytes()
        };
        self.set_bytes(eof_len_bytes.as_slice(), END_LEN_OFFSET);

        let (nonce, frame) = self.buf.split_at_mut(FRAME_NONCE_LEN);
        let (eof_len, payload) = frame.split_at_mut(END_LEN);

        let nonce = AesNonce::<FrameNonceLen>::from_slice(nonce);

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, eof_len, &mut payload[..self.payload_len])
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
    ///   fields.  At minimum, the sequence number, invocation, end
    ///   length, and tag must be present.
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
        let (nonce, frame) = self.buf.split_at_mut(FRAME_NONCE_LEN);
        let (eof_len_bytes, frame) = frame.split_at_mut(END_LEN);

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

        let tag = Tag::from_slice(&mac[..FRAME_TAG_LEN]);
        let nonce = AesNonce::from_slice(nonce);

        self.cipher
            .decrypt_in_place_detached(nonce, eof_len_bytes, payload, tag)?;

        let seq_num_decoded = u32::from_le_bytes(
            nonce[..SEQ_NUM_LEN]
                .try_into()
                .expect("seq num should be 4 bytes"),
        );
        if seq_num != seq_num_decoded {
            return Err(Error::new(ErrorKind::UnexpectedSeqNum(
                seq_num,
                seq_num_decoded,
            )));
        }
        let invocation = u64::from_le_bytes(
            nonce[SEQ_NUM_LEN..]
                .try_into()
                .expect("invocation should be 8 bytes"),
        );
        self.payload_len = payload_len;

        Ok(FrameHeader::new(seq_num, invocation, is_end))
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

        if header_mac.as_ref() != expected_mac {
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
    /// The `invocation` counter must be incremented each time the same
    /// frame is re‑encrypted under the same data key (starting at `0`).
    ///
    /// If `is_end` is `true`, this header describes an **End Frame**.
    /// Otherwise it describes a **Body Frame**.
    fn new(seq_num: u32, invocation: u64, is_end: bool) -> Self {
        Self {
            seq_num,
            invocation,
            is_end,
        }
    }

    /// Return the sequence number for this header.
    pub fn seq_num(&self) -> u32 {
        self.seq_num
    }

    /// Return the invocation number for this header.
    pub fn invocation(&self) -> u64 {
        self.invocation
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
            invocation: 0,
            is_end: false,
        }
    }

    /// Set the type as an End Frame.
    pub fn end(mut self) -> Self {
        self.is_end = true;
        self
    }

    /// Set the invocation number. The invocation number must be
    /// incremented each time a frame is encrypted with the same data
    /// key.
    pub fn invocation(mut self, invocation: u64) -> Self {
        self.invocation = invocation;
        self
    }

    /// Return a new [`FrameHeader`] instance.
    pub fn build(self) -> FrameHeader {
        FrameHeader::new(self.seq_num, self.invocation, self.is_end)
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
            invocation: 0,
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
    /// target fails.
    ///
    /// [`Write`]: std::io::Write
    /// [`Error`]: crate::error::Error
    pub fn eof(&mut self) -> Result<(), Error> {
        self.frame_buf.encrypt(
            &FrameHeaderBuilder::new(self.seq_num)
                .invocation(self.invocation)
                .end()
                .build(),
        );
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
        // Increment the invocation field so that in the event a new
        // write is performed on this frame, the AEAD nonce is not
        // reused.
        self.invocation = frame_header
            .invocation()
            .checked_add(1)
            .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
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
    /// * The sequence number or invocation counter overflows.
    ///
    /// On decryption failure, the error’s inner cause is a [`Error`]
    /// describing the integrity violation.
    ///
    /// [`Error`]: crate::error::Error
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut total_len = 0;

        while !buf.is_empty() && !self.is_eof() {
            if self.frame_payload_remaining() == 0 && self.read_next_frame()? {
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
    /// Write and ecrypted plaintext bytes to the stream.
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
    /// Returns an [`std::io::Error`] if the underlying write fails.
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, std::io::Error> {
        let mut total_len = 0;

        while !buf.is_empty() {
            if !self.frame_buf.has_payload_capacity() {
                self.frame_buf.encrypt(
                    &FrameHeaderBuilder::new(self.seq_num)
                        .invocation(self.invocation)
                        .build(),
                );
                self.inner.write_all(self.frame_buf.as_ref())?;
                self.frame_buf.clear();
                self.seq_num = self
                    .seq_num
                    .checked_add(1)
                    .ok_or(Error::new(ErrorKind::IntegerOverflow))?;
                self.invocation = 0;
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
impl<T: Seek + Read + Write> Seek for ZymicStream<T> {
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
mod tests {
    use super::{
        Aes256Gcm, CryptoAlgorithm, FrameBuf, FrameHeader, FrameHeaderBuilder, FrameLength, Header,
        HeaderBuilder, HeaderNonce, ALGO_OFFSET, END_LEN_OFFSET, FRAME_HEADER_LEN, FRAME_LEN_LEN,
        FRAME_LEN_OFFSET, FRAME_META_LEN, FRAME_TAG_LEN, KEY_ID_OFFSET, MAGIC_NUM, NONCE_OFFSET,
        PAYLOAD_OFFSET, RESERVED_LEN, RESERVED_OFFSET, VERSION, VERSION_OFFSET,
    };
    use crate::{
        byte_array,
        bytes::ByteCursor,
        error::ErrorKind,
        key::{ParentKey, ParentKeyId, ParentKeySecret},
    };
    use alloc::{vec, vec::Vec};

    #[cfg(feature = "std")]
    use super::ZymicStream;

    #[cfg(feature = "std")]
    use crate::error::Error;

    #[cfg(feature = "std")]
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    const TEST_NONCE: HeaderNonce = byte_array![3u8; {HeaderNonce::LEN}];

    fn mock_parent_key() -> ParentKey {
        const ID: ParentKeyId = byte_array![1u8; {ParentKeyId::LEN}];
        const SECRET: ParentKeySecret = byte_array![2u8; {ParentKeySecret::LEN}];

        let id = ParentKeyId::from(ID);
        let secret = ParentKeySecret::from(SECRET);

        ParentKey::new(id, secret)
    }

    /// Compute Shannon entropy for a slice of bytes.
    fn entropy(bytes: &[u8]) -> f64 {
        let mut hist = [0u32; 256];

        for b in bytes.iter() {
            hist[*b as usize] += 1;
        }

        hist.iter()
            .filter(|v| **v > 0)
            .map(|v| {
                let p = *v as f64 / bytes.len() as f64;
                -p * p.log2()
            })
            .sum()
    }

    /// Validate the binary structure of a frame that has been encoded
    /// with a frame header and tag. This does not validate the
    /// payload contents.
    fn validate_frame_bytes(frame: &[u8], metadata: &FrameHeader) {
        let mut frame_buf = ByteCursor::new(frame);

        let seq = frame_buf.get_u32_le();
        assert_eq!(seq, metadata.seq_num());
        let invocation = frame_buf.get_u64_le();
        assert_eq!(invocation, metadata.invocation());
        let eof_len = frame_buf.get_u32_le();
        assert!(
            (!metadata.is_end() && eof_len == u32::MAX)
                || (metadata.is_end() && eof_len < u32::MAX)
        );
        let payload_len = frame.len() - FRAME_META_LEN;
        if eof_len != u32::MAX {
            assert_eq!(payload_len, eof_len as usize);
        }
        assert_eq!(FRAME_TAG_LEN + payload_len, frame_buf.remaining());
    }

    /// Validate the structure of a header.
    fn validate_header(header: &[u8], algo: CryptoAlgorithm, frame_len: FrameLength) {
        let mut header_cur = ByteCursor::new(header);
        let magic = header_cur.get_u32_le();
        assert_eq!(MAGIC_NUM, magic);
        let version = header_cur.get_u8();
        assert_eq!(VERSION, version);
        let algo_val = header_cur.get_u16_le();
        assert_eq!(algo as u16, algo_val);
        let len_val = header_cur.get_u8();
        assert_eq!(frame_len as u8, len_val);
        // reserve field
        for val in &header[RESERVED_OFFSET..RESERVED_OFFSET + RESERVED_LEN] {
            assert_eq!(0, *val)
        }
        assert_eq!(
            TEST_NONCE,
            (&header[NONCE_OFFSET..NONCE_OFFSET + HeaderNonce::LEN]).into()
        );

        let parent_key = mock_parent_key();
        assert_eq!(
            parent_key.id().as_array(),
            &header[KEY_ID_OFFSET..KEY_ID_OFFSET + ParentKeyId::LEN]
        );
    }

    /// Validate a FrameBuf instance.
    fn validate_framebuf(
        frame_buf: &FrameBuf,
        expected_payload_len: usize,
        expected_frame_len: usize,
    ) {
        if expected_payload_len > 0 {
            assert!(!frame_buf.is_empty());
            assert!(!frame_buf.is_partial())
        } else {
            assert!(frame_buf.is_empty());
            assert!(frame_buf.is_partial());
        }
        let payload = frame_buf.payload();
        assert_eq!(payload.len(), expected_payload_len);
        assert_eq!(frame_buf.payload_len, expected_payload_len);
        assert_eq!(frame_buf.frame_len, expected_frame_len);
        assert_eq!(
            frame_buf.max_payload_pos,
            PAYLOAD_OFFSET + frame_buf.max_payload_len
        );
        assert_eq!(
            frame_buf.payload_capacity(),
            frame_buf.max_payload_len - expected_payload_len,
        );
    }

    /// Validate the structure of a stream body, i.e., a contiguious
    /// slice of frames without the header.
    #[cfg(feature = "std")]
    fn validate_stream_body(stream_body: &[u8], plain_txt_len: usize, frame_len: FrameLength) {
        let payload_chunk_len = frame_len.as_usize() - FRAME_META_LEN;
        let frame_count = plain_txt_len.div_ceil(payload_chunk_len);
        let expected_len = plain_txt_len + FRAME_META_LEN * frame_count;
        assert_eq!(expected_len, stream_body.len());

        let max_seq_num = frame_count - 1;
        for (seq_num, frame) in stream_body.chunks(frame_len.as_usize()).enumerate() {
            let is_end = seq_num == max_seq_num;
            let metadata = FrameHeader::new(seq_num.try_into().unwrap(), 0, is_end);
            validate_frame_bytes(frame, &metadata);
        }
    }

    /// Swap frames in a stream body.
    #[cfg(feature = "std")]
    fn swap_frames(
        stream_body: &mut [u8],
        frame_len: FrameLength,
        frame_idx_1: usize,
        frame_idx_2: usize,
    ) {
        let frame_1 = stream_body
            .chunks(frame_len.as_usize())
            .nth(frame_idx_1)
            .unwrap()
            .to_vec();
        let frame_2 = stream_body
            .chunks(frame_len.as_usize())
            .nth(frame_idx_2)
            .unwrap()
            .to_vec();

        // Swap the frames at index 1 and 2.
        let frame = stream_body
            .chunks_mut(frame_len.as_usize())
            .nth(frame_idx_2)
            .unwrap();
        frame.copy_from_slice(&frame_1);
        let frame = stream_body
            .chunks_mut(frame_len.as_usize())
            .nth(frame_idx_1)
            .unwrap();
        frame.copy_from_slice(&frame_2);
    }

    /// Return a Vec of bytes, enough to fill `frame_count` worth of
    /// frames.
    #[cfg(feature = "std")]
    fn payload_from_frame_count(frame_count: u32, frame_len: FrameLength) -> Vec<u8> {
        let plain_txt_len =
            frame_count as usize * frame_len.as_usize() - FRAME_META_LEN * frame_count as usize;
        vec![0u8; plain_txt_len]
    }

    /// Encrypt and decrypt using std::io::copy with one writer stream
    /// and one reader stream. For each use of the copy function, the
    /// plain text is buffer is incrementally increased by the
    /// `alignment` parameter.
    #[cfg(feature = "std")]
    fn stream_io_copy(alignment: usize) {
        use std::io::Cursor;

        let frame_len = FrameLength::Len4KiB;
        let max_plain_txt_len = frame_len.as_usize() * 4;
        let mut plain_txt_len = alignment;
        let parent_key = mock_parent_key();
        while plain_txt_len < max_plain_txt_len {
            let expected_plain_txt = vec![0xffu8; plain_txt_len];
            let mut plain_txt_reader = Cursor::new(expected_plain_txt);
            let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
                .with_frame_len(frame_len)
                .build();

            let mut zym_writer = ZymicStream::new(Vec::default(), &header);
            std::io::copy(&mut plain_txt_reader, &mut zym_writer).unwrap();
            zym_writer.eof().unwrap();
            let cipher_txt = zym_writer.into_inner();

            validate_stream_body(&cipher_txt, plain_txt_len, frame_len);

            let mut zym_reader = ZymicStream::new(Cursor::new(cipher_txt), &header);
            let mut plain_txt = Vec::default();
            std::io::copy(&mut zym_reader, &mut plain_txt).unwrap();
            assert!(zym_reader.is_eof());

            let expected_plain_txt = plain_txt_reader.into_inner();
            assert_eq!(expected_plain_txt, plain_txt);
            plain_txt_len += alignment;
        }
    }

    /// Test basic header format structure.
    #[test]
    fn header_format() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let bytes = header.bytes();
        validate_header(
            bytes,
            CryptoAlgorithm::Aes256GcmHkdfSha256,
            FrameLength::default(),
        );
    }

    /// Test the default value of FrameLength.
    #[test]
    fn header_default_frame_len() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        assert_eq!(FrameLength::default(), header.frame_len);

        let empty_data_key = aes_gcm::Key::<Aes256Gcm>::default();
        assert_ne!(empty_data_key, header.data_key);
    }

    /// Test setting the FrameLength parameter for a Header instance.
    #[test]
    fn header_explicit_frame_len() {
        let frame_len = FrameLength::Len32KiB;
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        assert_eq!(frame_len, header.frame_len);

        let empty_data_key = aes_gcm::Key::<Aes256Gcm>::default();
        assert_ne!(empty_data_key, header.data_key);
    }

    /// Test allocating a Header instance from raw bytes.
    #[test]
    fn header_from_bytes() {
        let parent_key = mock_parent_key();
        let expected_header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let bytes = expected_header.bytes();
        let header = Header::from_bytes(&parent_key, bytes.clone()).unwrap();
        assert_eq!(expected_header, header);
    }

    /// Negative test trying to allocate a Header from invalid bytes.
    #[test]
    fn header_from_bytes_err() {
        let parent_key = mock_parent_key();
        let expected_header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let bytes = expected_header.bytes();
        let bad_parent_key = ParentKey::new(parent_key.id().clone(), ParentKeySecret::default());

        if let Err(e) = Header::from_bytes(&bad_parent_key, bytes.clone()) {
            assert_eq!(*e.kind(), ErrorKind::Authentication)
        } else {
            panic!("expected an error")
        }
    }

    /// Negative test trying to allocate a Header using the wrong
    /// parent key.
    #[test]
    fn header_key_id_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let wrong_key = ParentKey::default();

        if let Err(e) = Header::from_bytes(&wrong_key, header.bytes().clone()) {
            assert_eq!(*e.kind(), ErrorKind::ParentKeyIdMismatch)
        } else {
            panic!("expected an error")
        }
    }

    /// Negative test for allocating a Header using bytes with the
    /// wrong magic number.
    #[test]
    fn header_magic_num_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut header_bytes = header.bytes().clone();
        header_bytes[0] = 0;

        if let Err(e) = Header::from_bytes(&parent_key, header_bytes) {
            assert!(matches!(e.kind(), ErrorKind::InvalidMagicNumber(_)))
        } else {
            panic!("expected an error")
        }
    }

    /// Negative test for allocating a Header using bytes with the
    /// wrong version.
    #[test]
    fn header_version_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut header_bytes = header.bytes().clone();
        header_bytes[VERSION_OFFSET] = 0xff;

        if let Err(e) = Header::from_bytes(&parent_key, header_bytes) {
            assert!(matches!(e.kind(), ErrorKind::UnsupportedVersion(0xff)))
        } else {
            panic!("expected an error")
        }
    }

    /// Negative test for allocating a header using bytes with a wrong
    /// algorithm field.
    #[test]
    fn header_algo_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut header_bytes = header.bytes().clone();
        header_bytes[ALGO_OFFSET] = 0xff;
        header_bytes[ALGO_OFFSET + 1] = 0xff;

        if let Err(e) = Header::from_bytes(&parent_key, header_bytes) {
            assert!(matches!(e.kind(), ErrorKind::UnsupportedCrypto(0xffff)))
        } else {
            panic!("expected an error")
        }
    }

    /// Negative test for corrupting the frame length of a header
    #[test]
    fn header_frame_len_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut header_bytes = header.bytes().clone();
        for i in FRAME_LEN_OFFSET..FRAME_LEN_OFFSET + FRAME_LEN_LEN {
            header_bytes[i] = 0xff;
        }

        if let Err(e) = Header::from_bytes(&parent_key, header_bytes) {
            assert!(matches!(e.kind(), ErrorKind::InvalidFrameLength(_)))
        } else {
            panic!("expected an error")
        }
    }

    /// Negative test for corrupting the nonce of a header
    #[test]
    fn header_nonce_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut header_bytes = header.bytes().clone();

        for i in NONCE_OFFSET..NONCE_OFFSET + HeaderNonce::LEN {
            header_bytes[i] = !header_bytes[i]
        }

        if let Err(e) = Header::from_bytes(&parent_key, header_bytes) {
            assert!(matches!(e.kind(), ErrorKind::Authentication))
        } else {
            panic!("expected an error")
        }
    }

    /// Test FrameBuf allocation.
    #[test]
    fn framebuf_new() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();

        let frame_buf = FrameBuf::new(&header);
        validate_framebuf(&frame_buf, 0, header.frame_len.as_usize());
    }

    /// Test FrameBuf::write_payload at offset 0.
    #[test]
    fn framebuf_write_payload() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());
        validate_framebuf(&frame_buf, plain_txt.len(), header.frame_len.as_usize());
    }

    /// Test FrameBuf::write_payload by writing to an existing
    /// instance at a specific offset.
    #[test]
    fn framebuf_write_payload_inline() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt_1 = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt_1).unwrap();
        assert_eq!(len, plain_txt_1.len());
        validate_framebuf(&frame_buf, plain_txt_1.len(), header.frame_len.as_usize());

        let plain_txt_2 = vec![6, 7];
        let len = frame_buf.write_payload(2, &plain_txt_2).unwrap();
        assert_eq!(len, plain_txt_2.len());
        validate_framebuf(&frame_buf, plain_txt_1.len(), header.frame_len.as_usize());

        let payload = frame_buf.payload();
        assert_eq!(payload, vec![1, 2, 6, 7, 5]);
    }

    /// Test FrameBuf::write_payload by writing to an existing
    /// instance at a specific offset to overlap an existing buffer
    /// with a larger one.
    #[test]
    fn framebuf_write_payload_extend() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt_1 = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt_1).unwrap();
        assert_eq!(len, plain_txt_1.len());
        validate_framebuf(&frame_buf, plain_txt_1.len(), header.frame_len.as_usize());

        let plain_txt_2 = vec![6, 7, 8, 9, 10, 11, 12];
        let len = frame_buf.write_payload(2, &plain_txt_2).unwrap();
        assert_eq!(len, plain_txt_2.len());
        validate_framebuf(&frame_buf, 9, header.frame_len.as_usize());

        let payload = frame_buf.payload();
        assert_eq!(payload, vec![1, 2, 6, 7, 8, 9, 10, 11, 12]);
    }

    /// Test FrameBuf::write_payload by appending a larger buffer to a
    /// smaller instance.
    #[test]
    fn framebuf_write_payload_append() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt_1 = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt_1).unwrap();
        assert_eq!(len, plain_txt_1.len());
        validate_framebuf(&frame_buf, plain_txt_1.len(), header.frame_len.as_usize());

        let plain_txt_2 = vec![6, 7, 8, 9, 10];
        let len = frame_buf.write_payload(5, &plain_txt_2).unwrap();
        assert_eq!(len, plain_txt_2.len());
        validate_framebuf(
            &frame_buf,
            plain_txt_1.len() + plain_txt_2.len(),
            header.frame_len.as_usize(),
        );

        let payload = frame_buf.payload();
        assert_eq!(payload, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    /// Negative test trying to call FrameBuf::write_payload using an
    /// offset that exceeds the payload length of the buffer.
    #[test]
    #[should_panic]
    fn framebuf_write_payload_panic() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);

        if let Err(e) = frame_buf.write_payload(100, &plain_txt) {
            assert!(matches!(e.kind(), ErrorKind::InvalidBufLength))
        } else {
            panic!("expecting an error")
        }
    }

    #[test]
    fn framebuf_encrypt_lt_capacity() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());
        validate_framebuf(&frame_buf, plain_txt.len(), header.frame_len.as_usize());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        validate_frame_bytes(frame_buf.as_ref(), &frame_header);
    }

    #[test]
    fn framebuf_encrypt_eq_capacity() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt_len = header.frame_len.as_usize() - FRAME_META_LEN;
        let plain_txt = vec![0u8; plain_txt_len];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());
        validate_framebuf(&frame_buf, plain_txt.len(), header.frame_len.as_usize());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        validate_frame_bytes(frame_buf.as_ref(), &frame_header);
    }

    #[test]
    fn framebuf_encrypt_gt_capacity() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt_frame_len = header.frame_len.as_usize() - FRAME_META_LEN;
        // Create a plain text buffer larger than what a single frame
        // can contain.
        let plain_txt = vec![0u8; plain_txt_frame_len * 2];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt_frame_len);
        validate_framebuf(&frame_buf, plain_txt_frame_len, header.frame_len.as_usize());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        validate_frame_bytes(frame_buf.as_ref(), &frame_header);
    }

    #[test]
    fn framebuf_encrypt_empty_payload() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut frame_buf = FrameBuf::new(&header);
        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        validate_frame_bytes(frame_buf.as_ref(), &frame_header);
        let payload = frame_buf.payload();
        assert!(payload.is_empty());
    }

    #[test]
    #[should_panic]
    fn framebuf_encrypt_panic() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let frame_header = FrameHeader::new(1, 2, true);
        let mut frame_buf = FrameBuf::new(&header);
        frame_buf.payload_len = 1 << 31;
        frame_buf.encrypt(&frame_header);
    }

    #[test]
    fn framebuf_clear() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        frame_buf.write_payload(0, &plain_txt).unwrap();
        frame_buf.clear();
        validate_framebuf(&frame_buf, 0, header.frame_len.as_usize());
    }

    #[test]
    fn framebuf_clear_resize_to_full() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();

        let mut frame_buf = FrameBuf::new(&header);
        frame_buf.clear_resize_to_full();
        assert!(!frame_buf.is_empty());
        assert!(!frame_buf.is_partial());

        let payload = frame_buf.payload();
        assert!(payload.is_empty());
        assert_eq!(0, frame_buf.payload_len);
        assert_eq!(
            header.frame_len.as_usize() - FRAME_META_LEN,
            frame_buf.payload_capacity()
        );
    }

    #[test]
    fn framebuf_decrypt_in_place() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        validate_frame_bytes(frame_buf.as_ref(), &frame_header);

        frame_buf.decrypt(1).unwrap();
        let payload = frame_buf.payload();
        assert_eq!(payload, plain_txt);
    }

    #[test]
    fn framebuf_decrypt_from_copy() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        validate_frame_bytes(frame_buf.as_ref(), &frame_header);

        let mut frame_buf_2 = FrameBuf::new(&header);
        let len = frame_buf_2.copy_from_encrypted_bytes(frame_buf.as_ref());
        assert_eq!(len, frame_buf.as_ref().len());

        frame_buf_2.decrypt(1).unwrap();
        let payload = frame_buf_2.payload();
        assert_eq!(payload, plain_txt);
    }

    #[test]
    fn framebuf_copy_from_encrypted_bytes() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let data = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.copy_from_encrypted_bytes(&data);
        assert_eq!(len, data.len());

        let data = vec![0u8; header.frame_len.as_usize() + 1];
        let len = frame_buf.copy_from_encrypted_bytes(&data);
        assert_eq!(len, header.frame_len.as_usize());
    }

    #[test]
    fn framebuf_decrypt_empty_payload() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut frame_buf = FrameBuf::new(&header);
        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);
        frame_buf.decrypt(1).unwrap();
        let payload = frame_buf.payload();
        assert!(payload.is_empty());
    }

    #[test]
    fn framebuf_entropy() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut frame_buf = FrameBuf::new(&header);

        // Total payload data collected in bytes. This needs to be
        // large enough to get a reliable entropy calculation.
        let payload_len: usize = 1 << 22; // 4 MiB

        // Length of a single payload chunk that can fit in a single
        // frame
        let payload_chunk_len = header.frame_len.as_usize() - FRAME_META_LEN;

        let frame_count = payload_len.div_ceil(payload_chunk_len);

        let plain_txt = vec![0u8; payload_chunk_len];
        let mut payload = Vec::with_capacity(payload_len);

        let seq_num = 0;
        for _ in 0..frame_count - 1 {
            frame_buf.write_payload(0, &plain_txt).unwrap();
            assert!(!frame_buf.has_payload_capacity());
            // sequence number is not important
            let metadata = FrameHeaderBuilder::new(seq_num).build();
            frame_buf.encrypt(&metadata);
            payload.extend_from_slice(frame_buf.payload());
        }
        let entropy = entropy(&payload);
        assert_eq!(f64::round(entropy), 8.0);
    }

    #[test]
    fn framebuf_decrypt_empty_buf_panic() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut frame_buf = FrameBuf::new(&header);

        if let Err(e) = frame_buf.decrypt(0) {
            assert!(matches!(e.kind(), ErrorKind::InvalidBufLength));
        } else {
            panic!("expected an error");
        }
    }

    #[test]
    fn framebuf_decrypt_end_len_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);

        let bad_len: u32 = 1 << 31;
        let bad_len_bytes = bad_len.to_le_bytes();
        frame_buf.buf[END_LEN_OFFSET..END_LEN_OFFSET + bad_len_bytes.len()]
            .copy_from_slice(&bad_len_bytes);

        if let Err(e) = frame_buf.decrypt(1) {
            assert!(matches!(e.kind(), ErrorKind::InvalidEndLength(_)));
        } else {
            panic!("expected an error");
        }
    }

    /// Remove the payload bytes from an encrypted frame.
    #[test]
    fn framebuf_decrypt_truncate() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let mut frame_buf = FrameBuf::new(&header);

        // Build END frame with payload_len = 16
        let header = FrameHeader::new(1, 2, true);
        frame_buf.write_payload(0, &[0u8; 16]).unwrap();
        frame_buf.encrypt(&header);

        // Truncate: keep only header + tag, drop payload bytes
        let keep = FRAME_HEADER_LEN + FRAME_TAG_LEN;
        frame_buf.buf.truncate(keep);

        if let Err(e) = frame_buf.decrypt(1) {
            assert!(matches!(e.kind(), ErrorKind::InvalidEndLength(_)))
        } else {
            panic!("expected an error")
        }
    }

    #[test]
    fn framebuf_decrypt_seq_num_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);

        if let Err(e) = frame_buf.decrypt(2) {
            assert!(matches!(e.kind(), ErrorKind::UnexpectedSeqNum(2, 1)));
        } else {
            panic!("expected an error");
        }
    }

    #[test]
    fn framebuf_chunk_mut_commit() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let frame_data = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let chunk = frame_buf.chunk_mut();
        assert_eq!(chunk.len(), header.frame_len.as_usize());
        chunk[..frame_data.len()].copy_from_slice(&frame_data);
        assert_eq!(frame_buf.payload_len, 0);
        frame_buf.commit_chunk_mut(frame_data.len()).unwrap();
        assert_eq!(frame_buf.payload_len, 0);
        assert_eq!(frame_buf.as_ref(), &frame_data);
    }

    #[test]
    fn framebuf_chunk_mut_commit_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();

        let mut frame_buf = FrameBuf::new(&header);

        if let Err(e) = frame_buf.commit_chunk_mut(1 << 32) {
            assert!(matches!(e.kind(), ErrorKind::InvalidBufLength));
        } else {
            panic!("expected an error");
        }
    }

    #[test]
    fn framebuf_integrity_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];

        let mut frame_buf = FrameBuf::new(&header);
        let len = frame_buf.write_payload(0, &plain_txt).unwrap();
        assert_eq!(len, plain_txt.len());

        let frame_header = FrameHeader::new(1, 2, true);
        frame_buf.encrypt(&frame_header);

        // Flip the bits for each byte of the cipher text and confirm
        // that decryption fails.
        for i in 0..frame_buf.buf.len() {
            let mut buf_copy = frame_buf.buf.clone();
            buf_copy[i] = !buf_copy[i];
            let mut frame_buf_reader = FrameBuf::new(&header);
            frame_buf_reader.buf = buf_copy;
            let result = frame_buf.decrypt(0);
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_write() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cipher_txt: Vec<u8> = Vec::default();

        let mut stream = ZymicStream::new(cipher_txt, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        assert!(stream.is_eof());

        let cipher_txt = stream.into_inner();
        let expected_frame_header = FrameHeaderBuilder::new(0).end().build();

        validate_frame_bytes(&cipher_txt, &expected_frame_header);
        assert_ne!(plain_txt, cipher_txt);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_write_read_eof() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        assert!(stream.is_eof());

        let mut buf = vec![0u8; 5];
        let len = stream.read(&mut buf).unwrap();
        assert_eq!(len, 0);
        assert_eq!(buf, vec![0u8; 5]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_write_invocation() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        assert!(stream.is_eof());
        assert_eq!(stream.invocation, 0);

        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        assert!(stream.is_eof());
        assert_eq!(stream.invocation, 1)
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_read() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        stream.seek(SeekFrom::Start(0)).unwrap();

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(plain_txt, buf);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_read_eof() {
        let parent_key = mock_parent_key();
        let frame_len = FrameLength::Len4KiB;
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        let plain_txt = payload_from_frame_count(4, frame_len);

        let mut stream = ZymicStream::new(Vec::default(), &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        let cipher_txt = stream.into_inner();

        let mut stream = ZymicStream::new(Cursor::new(cipher_txt), &header);
        let mut buf = vec![0u8; plain_txt.len()];
        stream.read_exact(&mut buf).unwrap();
        assert!(stream.is_eof());
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_write_read() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        stream.seek(SeekFrom::Start(2)).unwrap();
        assert_eq!(stream.payload_pos, 2);

        let plain_txt = vec![6, 7, 8];
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        stream.rewind().unwrap();

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 6, 7, 8]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_write_read_2() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        stream.seek(SeekFrom::Start(2)).unwrap();
        assert_eq!(stream.payload_pos, 2);

        let plain_txt = vec![6, 7, 8];
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        stream.rewind().unwrap();

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 6, 7, 8]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_end() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        stream.seek(SeekFrom::End(-3)).unwrap();
        assert_eq!(stream.payload_pos, 2);

        let plain_txt = vec![6, 7, 8];
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        stream.rewind().unwrap();

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 6, 7, 8]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_end_len() {
        let parent_key = mock_parent_key();
        let frame_len = FrameLength::Len4KiB;
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        let plain_txt = payload_from_frame_count(4, frame_len);
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        let off = stream.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(off as usize, plain_txt.len());
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_current() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        stream.rewind().unwrap();

        stream.seek(SeekFrom::Current(2)).unwrap();
        assert_eq!(stream.payload_pos, 2);

        let plain_txt = vec![6, 7, 8];
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();
        stream.rewind().unwrap();

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 6, 7, 8]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_empty_payload() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&[]).unwrap();
        stream.eof().unwrap();

        let off = stream.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(off, 0);

        let off = stream.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(off, 0);

        // SeekFrom::Current(0)
        let off = stream.stream_position().unwrap();
        assert_eq!(off, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_multi_frame() {
        let parent_key = mock_parent_key();
        let frame_len = FrameLength::Len4KiB;
        let payload_len_per_frame = frame_len.as_usize() - FRAME_META_LEN;
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        let mut plain_txt = payload_from_frame_count(2, frame_len);
        plain_txt[payload_len_per_frame..].fill(0xff);

        let mut stream = ZymicStream::new(Cursor::new(Vec::default()), &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        // SeekFrom::Start
        stream.rewind().unwrap();
        let expected_off = payload_len_per_frame as u64;
        let off = stream.seek(SeekFrom::Start(expected_off)).unwrap();
        assert_eq!(off, expected_off);
        assert_eq!(stream.seq_num, 1);
        let mut buf = vec![0u8; payload_len_per_frame];
        stream.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&v| v == 0xff));

        // SeekFrom::Current
        stream.rewind().unwrap();
        let expected_off = payload_len_per_frame as i64;
        let off = stream.seek(SeekFrom::Current(expected_off)).unwrap();
        assert_eq!(off, expected_off as u64);
        assert_eq!(stream.seq_num, 1);
        let mut buf = vec![0u8; payload_len_per_frame];
        stream.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&v| v == 0xff));

        // SeekFrom::End
        stream.rewind().unwrap();
        let expected_off = payload_len_per_frame as i64;
        let off = stream.seek(SeekFrom::End(-expected_off)).unwrap();
        assert_eq!(off, expected_off as u64);
        assert_eq!(stream.seq_num, 1);
        let mut buf = vec![0u8; payload_len_per_frame];
        stream.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&v| v == 0xff));
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_unexpected_eof_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        if let Err(e) = stream.seek(SeekFrom::Start(1 << 21)) {
            let inner = e.get_ref().unwrap().downcast_ref::<Error>().unwrap();
            assert!(matches!(inner.kind(), ErrorKind::UnexpectedEof))
        } else {
            panic!("expecting an error")
        }

        if let Err(e) = stream.seek(SeekFrom::End(1)) {
            let inner = e.get_ref().unwrap().downcast_ref::<Error>().unwrap();
            assert!(matches!(inner.kind(), ErrorKind::UnexpectedEof))
        } else {
            panic!("expecting an error")
        }

        if let Err(e) = stream.seek(SeekFrom::Current(32)) {
            let inner = e.get_ref().unwrap().downcast_ref::<Error>().unwrap();
            assert!(matches!(inner.kind(), ErrorKind::UnexpectedEof))
        } else {
            panic!("expecting an error")
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seek_invalid_err() {
        let parent_key = mock_parent_key();
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
        let plain_txt = vec![1, 2, 3, 4, 5];
        let cursor = Cursor::new(Vec::default());

        let mut stream = ZymicStream::new(cursor, &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        if let Err(e) = stream.seek(SeekFrom::End(-32)) {
            assert!(matches!(e.kind(), std::io::ErrorKind::InvalidInput))
        } else {
            panic!("expecting an error")
        }

        if let Err(e) = stream.seek(SeekFrom::Current(-32)) {
            assert!(matches!(e.kind(), std::io::ErrorKind::InvalidInput))
        } else {
            panic!("expecting an error")
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seq_num_err() {
        let parent_key = mock_parent_key();
        let frame_len = FrameLength::Len4KiB;
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        let plain_txt = payload_from_frame_count(4, frame_len);

        let mut stream = ZymicStream::new(Vec::default(), &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        let mut cipher_txt = stream.into_inner();
        swap_frames(&mut cipher_txt, frame_len, 2, 3);

        let mut stream = ZymicStream::new(Cursor::new(cipher_txt), &header);
        let mut buf = vec![0u8; plain_txt.len()];

        if let Err(e) = stream.read_exact(&mut buf) {
            let inner = e.get_ref().unwrap().downcast_ref::<Error>().unwrap();
            assert!(matches!(inner.kind(), ErrorKind::UnexpectedSeqNum(2, 3)))
        } else {
            panic!("expecting an error")
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_seq_num_err_2() {
        let parent_key = mock_parent_key();
        let frame_len = FrameLength::Len4KiB;
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        let plain_txt = payload_from_frame_count(4, frame_len);

        let mut stream = ZymicStream::new(Vec::default(), &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        let mut cipher_txt = stream.into_inner();
        swap_frames(&mut cipher_txt, frame_len, 1, 2);

        let mut stream = ZymicStream::new(Cursor::new(cipher_txt), &header);
        let mut buf = vec![0u8; plain_txt.len()];

        if let Err(e) = stream.read_exact(&mut buf) {
            let inner = e.get_ref().unwrap().downcast_ref::<Error>().unwrap();
            assert!(matches!(inner.kind(), ErrorKind::UnexpectedSeqNum(1, 2)))
        } else {
            panic!("expecting an error")
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_truncated_err() {
        let parent_key = mock_parent_key();
        let frame_len = FrameLength::Len4KiB;
        let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
            .with_frame_len(frame_len)
            .build();
        let plain_txt = payload_from_frame_count(4, frame_len);

        let mut stream = ZymicStream::new(Vec::default(), &header);
        stream.write_all(&plain_txt).unwrap();
        stream.eof().unwrap();

        let mut cipher_txt = stream.into_inner();
        cipher_txt.truncate(frame_len.as_usize() * 3);

        // Try to read the first 3 frames and detect that the 4th was
        // trucated.
        let mut stream = ZymicStream::new(Cursor::new(cipher_txt), &header);
        let mut buf = vec![0u8; plain_txt.len() - frame_len.as_usize()];
        stream.read_exact(&mut buf).unwrap();
        assert!(!stream.is_eof());
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_io_copy_aligned() {
        stream_io_copy(128);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stream_io_copy_unaligned() {
        stream_io_copy(317);
    }
}
