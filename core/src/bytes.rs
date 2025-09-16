// SPDX-License-Identifier: MIT
//! A module for working with raw bytes.

use crate::error::{Error, ErrorKind};

#[cfg(feature = "rand_core")]
use crate::{TryCryptoRng, TryRngCore};

#[cfg(feature = "rand_core")]
use alloc::format;

#[cfg(feature = "serde")]
use core::fmt;
use core::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeTo};
#[cfg(feature = "serde")]
use serde::{
    de,
    de::{SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A convenience macro to create a `ByteArray<N>` from a literal
/// array expression.
///
/// This macro wraps `ByteArray::from_array()` and can be used in
/// `const` contexts.
///
/// # Example
///
/// ```
/// use zymic_core::byte_array;
///
/// let bytes = byte_array![1, 2, 3, 4];
/// assert_eq!(bytes.as_array(), &[1, 2, 3, 4]);
///
/// let bytes = byte_array![0xffu8; 32];
/// assert_eq!(bytes.as_array(), &[0xffu8; 32]);
/// ```
#[macro_export]
macro_rules! byte_array {

    // Match repeated value form: array_vec![val; N]
    ($val:expr; $n:expr) => {
        $crate::bytes::ByteArray::<$n>::from_array([$val; $n])
    };

    // Match list of elements form: array_vec![1, 2, 3]
    ($($x:expr),* $(,)? ) => {
        $crate::bytes::ByteArray::<{ [$($x),*].len() }>::from_array([ $($x),* ])
    };
}

/// A fixed-size byte array of length `N`. The purpose of this type is
/// to offer a simple byte buffer without complex generics or Vec-like
/// semantics. The primary use-case for this type is storing bytes in
/// a fixed size buffer.
///
/// # Examples
///
///```
/// use zymic_core::bytes::ByteArray;
///
/// const BUF_LEN: usize = 4;
/// type MyBuf = ByteArray<BUF_LEN>;
///
/// let mut buf = MyBuf::default();
/// for (i, val) in buf.iter_mut().enumerate() {
///     *val = i as u8
/// }
///
/// for (i, val) in buf.iter().enumerate() {
///     assert_eq!(i as u8, *val);
/// }
///```
///
/// A `ByteArray` may also be allocated using the a fixed byte array
/// using the `byte_array!` macro.
///
///```
///use zymic_core::byte_array;
///
/// let bytes = byte_array![1, 2, 3, 4];
/// assert_eq!(bytes.as_array(), &[1, 2, 3, 4]);
///
/// let bytes = byte_array![0xffu8; 32];
/// assert_eq!(bytes.as_array(), &[0xffu8; 32]);
///```
///
/// The following example requires the `os_rng` feature.
///
///```
/// # #[cfg(feature = "os_rng")]
/// # {
/// use zymic_core::{OsRng, bytes::ByteArray};
/// # use zymic_core::Error;
/// #
/// # fn main() -> Result<(), Error> {
/// #
///
/// // Allocate a 16 byte cryptographic key.
/// let key = ByteArray::<16>::try_from_crypto_rand(&mut OsRng)?;
/// #
/// # Ok(())
/// # }
/// # }
///```
#[derive(Debug, PartialEq, Clone)]
#[repr(transparent)]
pub struct ByteArray<const N: usize> {
    bytes: [u8; N],
}

/// Mutable byte buffer cursor. This type maintains a cursor position
/// for an inner byte buffer while providing adapter methods for
/// writing bytes to the underlying buffer.
pub(crate) struct ByteCursorMut<T> {
    inner: T,
    pos: usize,
}

/// Non-mutable byte buffer cursor. This type maintains a cursor
/// position for an inner byte buffer while providing adapter methods
/// for reading bytes from the underlying buffer.
pub(crate) struct ByteCursor<'a> {
    inner: &'a [u8],
    pos: usize,
}

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        Self { bytes: [0u8; N] }
    }
}

impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}

/// Panics if the slice does not equal `N`.
impl<const N: usize> From<&[u8]> for ByteArray<N> {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> AsMut<[u8]> for ByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<const N: usize> Serialize for ByteArray<N> {
    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.bytes)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de, const N: usize> Deserialize<'de> for ByteArray<N> {
    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    fn deserialize<D>(deserializer: D) -> Result<ByteArray<N>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ByteArrayVisitor::<N>)
    }
}

impl<const N: usize> Index<usize> for ByteArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_ref()[index]
    }
}

impl<const N: usize> Index<Range<usize>> for ByteArray<N> {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.as_ref()[range]
    }
}

impl<const N: usize> Index<RangeFrom<usize>> for ByteArray<N> {
    type Output = [u8];

    fn index(&self, range: RangeFrom<usize>) -> &Self::Output {
        &self.as_ref()[range.start..]
    }
}

impl<const N: usize> Index<RangeTo<usize>> for ByteArray<N> {
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.as_ref()[..range.end]
    }
}

impl<const N: usize> IndexMut<usize> for ByteArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut()[index]
    }
}

impl<const N: usize> IndexMut<Range<usize>> for ByteArray<N> {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.as_mut()[range]
    }
}

impl<const N: usize> IndexMut<RangeFrom<usize>> for ByteArray<N> {
    fn index_mut(&mut self, range: RangeFrom<usize>) -> &mut Self::Output {
        &mut self.as_mut()[range.start..]
    }
}

impl<const N: usize> IndexMut<RangeTo<usize>> for ByteArray<N> {
    fn index_mut(&mut self, range: RangeTo<usize>) -> &mut Self::Output {
        &mut self.as_mut()[..range.end]
    }
}

impl<const N: usize> ByteArray<N> {
    /// Construct a `ByteArray<N>` by filling it with random bytes from a
    /// fallible, cryptographically secure RNG.
    ///
    /// # Features
    /// - Requires the `rand_core` feature.
    ///
    /// # Errors
    /// Returns an error if the RNG fails to produce bytes.
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    pub fn try_from_crypto_rand<R>(rand_source: &mut R) -> Result<Self, Error>
    where
        R: TryCryptoRng + TryRngCore,
    {
        let mut buf = Self::default();
        rand_source
            .try_fill_bytes(&mut buf)
            .map_err(|e| Error::new(ErrorKind::Rng(format!("{e}"))))?;
        Ok(buf)
    }
}

#[cfg(feature = "serde")]
struct ByteArrayVisitor<const N: usize>;

#[cfg(feature = "serde")]
impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = ByteArray<N>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a byte array of length {}", N)
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<ByteArray<N>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut bytes = ByteArray::<N>::default();
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        Ok(bytes)
    }

    fn visit_bytes<E>(self, s: &[u8]) -> Result<ByteArray<N>, E>
    where
        E: de::Error,
    {
        ByteArray::<N>::try_from_slice(s).map_err(|_| E::invalid_length(s.len(), &self))
    }

    fn visit_str<E>(self, v: &str) -> Result<ByteArray<N>, E>
    where
        E: de::Error,
    {
        self.visit_bytes(v.as_bytes())
    }
}

impl<const N: usize> ByteArray<N> {
    /// Length of the instance in bytes.
    pub const LEN: usize = N;

    /// Copies a `[u8]` slice into a new ByteArray instance.
    ///
    /// # Panics
    ///
    /// Panics if the slice does not equal `N`.
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Self { bytes }
    }

    /// Create a new instance from an existing array. This function is
    /// `const`, so it can be used in constant expressions and static
    /// initialization.
    pub const fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Copies a `[u8]` slice into a new ByteArray instance. Returns
    /// `Err` if the length of 'slice' is not equal to N.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != N {
            Err(Error::new(ErrorKind::InvalidArrayLength(N, slice.len())))
        } else {
            Ok(Self::from(slice))
        }
    }

    /// Returns the length of the instance, which is always `N`.
    pub fn len(&self) -> usize {
        N
    }

    /// Returns true if the instance is empty, which is only true when `N == 0`.
    pub fn is_empty(&self) -> bool {
        N == 0
    }

    /// Convert this instance into the equivalent backing array type.
    pub fn into_array(self) -> [u8; N] {
        self.bytes
    }

    /// Return the backing array as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the backing array as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Return a reference to the backing array.
    pub fn as_array(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Return a mutable reference to the backing array.
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }
}

impl<T> ByteCursorMut<T>
where
    T: AsRef<[u8]>
        + AsMut<[u8]>
        + Index<usize>
        + Index<Range<usize>, Output = [u8]>
        + IndexMut<usize>
        + IndexMut<Range<usize>, Output = [u8]>,
{
    /// Create a new instance starting at the beginning of the `inner`
    /// buffer.
    pub fn new(inner: T) -> Self {
        Self { inner, pos: 0 }
    }

    /// Return the number of remaining bytes before this instance
    /// reaches the end of the underlying buffer.
    pub fn remaining(&self) -> usize {
        self.inner.as_ref().len() - self.pos
    }

    /// Append bytes to the current cursor position. The cursor
    /// position is incremented by the length of `bytes`.
    ///
    /// # Panic
    ///
    /// This function panics if the length of `bytes` exceeds the
    /// remaining bytes of this instance.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        let remaining = self.remaining();
        if remaining < bytes.len() {
            panic!(
                "attempting to copy bytes of length {} into a buffer with only {} bytes remaining",
                bytes.len(),
                remaining
            );
        }
        let len = bytes.len();
        let pos = self.pos;
        self.inner[pos..pos + len].copy_from_slice(bytes);
        self.pos += len;
    }

    /// Append u32 in little-endian format. Current position is
    /// incremented by 4 bytes.
    pub fn push_u32_le(&mut self, val: u32) {
        self.push_bytes(&val.to_le_bytes())
    }

    /// Append u16 in little-endian format. Current position is
    /// incremented by 2 bytes.
    pub fn push_u16_le(&mut self, val: u16) {
        self.push_bytes(&val.to_le_bytes())
    }

    /// Append u8. Current position is incremented by 1 byte.
    pub fn push_u8(&mut self, val: u8) {
        self.push_bytes(&[val])
    }

    /// Return the underlying byte buffer buffer.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<'a> ByteCursor<'a> {
    pub fn new(inner: &'a [u8]) -> Self {
        Self { inner, pos: 0 }
    }

    /// Return the number of remaining bytes before this instance
    /// reaches the end of the underlying buffer.
    pub fn remaining(&self) -> usize {
        self.inner.len() - self.pos
    }

    /// Copy bytes into the `bytes` parameter and advance the cursor
    /// position by the length of `bytes`.
    ///
    /// # Panic
    ///
    /// This function panics if the length of `bytes` exceeds the
    /// remaining bytes of this instance.
    pub fn get_bytes(&mut self, bytes: &mut [u8]) {
        let remaining = self.remaining();
        if remaining < bytes.len() {
            panic!("attempting to read bytes beyond the bounds of a buffer");
        }
        let len = bytes.len();
        let pos = self.pos;
        bytes[..len].copy_from_slice(&self.inner[pos..pos + len]);
        self.pos += len;
    }

    /// Read a 8 byte integer in little-endian format and return a
    /// u32. The cursor position is advanced by 8 bytes. Currently
    /// only used for unit tests.
    #[cfg(test)]
    pub fn get_u64_le(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.get_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Read a 4 byte integer in little-endian format and return a
    /// u32. The cursor position is advanced by 4 bytes.
    pub fn get_u32_le(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.get_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Read a 2 byte integer in little-endian format and return a
    /// u16. The cursor position is advanced by 2 bytes.
    pub fn get_u16_le(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.get_bytes(&mut buf);
        u16::from_le_bytes(buf)
    }

    /// Read a byte and return a u8. The cursor position is advanced
    /// by 1 bytes.
    pub fn get_u8(&mut self) -> u8 {
        let mut buf = [0u8; 1];
        self.get_bytes(&mut buf);
        buf[0]
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteArray, ByteCursor, ByteCursorMut};
    use crate::error::ErrorKind;

    #[test]
    fn byte_array_is_empty() {
        let a = ByteArray::<0>::default();
        assert!(a.is_empty());
    }

    #[test]
    fn byte_array_len() {
        const LEN: usize = 8;
        let a = ByteArray::<LEN>::default();
        assert_eq!(LEN, a.len())
    }

    #[test]
    fn byte_array_into_array() {
        const LEN: usize = 8;
        let a = ByteArray::<LEN>::default();
        let _: [u8; LEN] = a.into_array();
    }

    #[test]
    fn byte_array_as_slice() {
        const LEN: usize = 8;
        let a = ByteArray::<LEN>::default();
        let _: &[u8] = a.as_slice();
    }

    #[test]
    fn byte_array_as_mut_slice() {
        const LEN: usize = 8;
        let mut a = ByteArray::<LEN>::default();
        let _: &mut [u8] = a.as_mut_slice();
    }

    #[test]
    fn byte_array_as_array() {
        const LEN: usize = 8;
        let a = ByteArray::<LEN>::default();
        let _: &[u8; LEN] = a.as_array();
    }

    #[test]
    fn byte_array_as_mut_array() {
        const LEN: usize = 8;
        let mut a = ByteArray::<LEN>::default();
        let _: &mut [u8; LEN] = a.as_mut_array();
    }

    #[test]
    fn byte_array_from_slice() {
        const LEN: usize = 8;
        let s = &[0u8; LEN];
        let _ = ByteArray::<LEN>::from_slice(s);
    }

    #[test]
    #[should_panic]
    fn byte_array_from_slice_panic() {
        const LEN: usize = 8;
        let s = &[0u8; 2];
        let _ = ByteArray::<LEN>::from_slice(s);
    }

    #[test]
    fn byte_array_try_from_slice() {
        const LEN: usize = 8;
        let s = &[0u8; 2];
        if let Err(r) = ByteArray::<LEN>::try_from_slice(s) {
            let kind = r.kind();
            assert!(matches!(kind, ErrorKind::InvalidArrayLength(8, 2)));
        } else {
            panic!("expecting an error")
        }
    }

    #[test]
    fn byte_array_index_from() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        assert_eq!(&buf[2..], &[3, 4])
    }

    #[test]
    fn byte_array_index_to() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        assert_eq!(&buf[..2], &[1, 2])
    }

    /// Exceed the buffer capacity.
    #[test]
    #[should_panic]
    fn byte_cursor_mut_push_bytes_panic() {
        let buf = ByteArray::<4>::default();
        let mut buf_cur = ByteCursorMut::new(buf);
        buf_cur.push_bytes(&[1, 2, 3, 4, 5]);
    }

    #[test]
    fn byte_cursor_get_bytes() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        let mut buf_cur = ByteCursor::new(&buf);
        assert_eq!(buf_cur.remaining(), 4);
        buf_cur.get_u16_le();
        let mut bytes: [u8; 2] = [0, 0];
        buf_cur.get_bytes(&mut bytes);
        assert_eq!(bytes, [3, 4]);
        assert_eq!(buf_cur.remaining(), 0);
    }

    /// Exceed the remaining bytes
    #[test]
    #[should_panic]
    fn byte_cursor_get_bytes_panic() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        let mut buf_cur = ByteCursor::new(&buf);
        assert_eq!(buf_cur.remaining(), 4);
        buf_cur.get_u16_le();
        let mut bytes = [0u8; 5];
        buf_cur.get_bytes(&mut bytes);
    }

    #[test]
    fn byte_cursor_get_u64_le() {
        let mut buf = ByteArray::<8>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        buf[4] = 5;
        buf[5] = 6;
        buf[6] = 7;
        buf[7] = 8;
        let mut buf_cur = ByteCursor::new(&buf);
        let val = buf_cur.get_u64_le();
        assert_eq!(val, 0x0807060504030201);
        assert_eq!(buf_cur.remaining(), 0);
    }

    #[test]
    fn byte_cursor_get_u32_le() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        let mut buf_cur = ByteCursor::new(&buf);
        let val = buf_cur.get_u32_le();
        assert_eq!(val, 0x04030201);
        assert_eq!(buf_cur.remaining(), 0);
    }

    #[test]
    fn byte_cursor_get_u16_le() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        let mut buf_cur = ByteCursor::new(&buf);
        let val = buf_cur.get_u16_le();
        assert_eq!(val, 0x0201);
        assert_eq!(buf_cur.remaining(), 2);
    }

    #[test]
    fn byte_cursor_get_u8() {
        let mut buf = ByteArray::<4>::default();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 4;
        let mut buf_cur = ByteCursor::new(&buf);
        let val = buf_cur.get_u8();
        assert_eq!(val, 0x01);
        assert_eq!(buf_cur.remaining(), 3);
    }

    #[test]
    fn byte_array_macro() {
        let bytes = byte_array![1, 2, 3, 4];
        assert_eq!(bytes.as_array(), &[1, 2, 3, 4])
    }
}
