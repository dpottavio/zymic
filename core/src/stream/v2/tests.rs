// SPDX-License-Identifier: MIT

use super::{
    frame_nonce, Aes256Gcm, CryptoAlgorithm, FrameBuf, FrameHeader, FrameHeaderBuilder,
    FrameLength, Header, HeaderBuilder, HeaderNonce, ALGO_OFFSET, END_LEN_OFFSET, FRAME_HEADER_LEN,
    FRAME_LEN_LEN, FRAME_LEN_OFFSET, FRAME_META_LEN, FRAME_TAG_LEN, KEY_ID_OFFSET, MAGIC_NUM,
    NONCE_OFFSET, PAYLOAD_OFFSET, RESERVED_LEN, RESERVED_OFFSET, VERSION, VERSION_OFFSET,
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
    let eof_len = frame_buf.get_u32_le();
    assert!(
        (!metadata.is_end() && eof_len == u32::MAX) || (metadata.is_end() && eof_len < u32::MAX)
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
fn validate_framebuf(frame_buf: &FrameBuf, expected_payload_len: usize, expected_frame_len: usize) {
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
        let metadata = FrameHeader::new(seq_num.try_into().unwrap(), is_end);
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

/// Test the version 2 constants and nonce encoding.
#[test]
fn format_v2() {
    assert_eq!(VERSION, 2);
    assert_eq!(FRAME_HEADER_LEN, 8);
    assert_eq!(FRAME_META_LEN, 24);

    let nonce = frame_nonce(0x1234_5678);
    assert_eq!(
        &nonce[..],
        &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0]
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

/// Test the largest frame length supported by the design.
#[test]
fn header_max_frame_len() {
    let parent_key = mock_parent_key();
    let expected_header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
        .with_frame_len(FrameLength::Len64KiB)
        .build();
    let header = Header::from_bytes(&parent_key, expected_header.bytes().clone()).unwrap();
    assert_eq!(expected_header, header);
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
    header_bytes[VERSION_OFFSET] = 1;

    if let Err(e) = Header::from_bytes(&parent_key, header_bytes) {
        assert!(matches!(e.kind(), ErrorKind::UnsupportedVersion(1)))
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

    let frame_header = FrameHeader::new(1, true);
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

    let frame_header = FrameHeader::new(1, true);
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

    let frame_header = FrameHeader::new(1, true);
    frame_buf.encrypt(&frame_header);
    validate_frame_bytes(frame_buf.as_ref(), &frame_header);
}

#[test]
fn framebuf_encrypt_empty_payload() {
    let parent_key = mock_parent_key();
    let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
    let mut frame_buf = FrameBuf::new(&header);
    let frame_header = FrameHeader::new(1, true);
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
    let frame_header = FrameHeader::new(1, true);
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

    let frame_header = FrameHeader::new(1, true);
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

    let frame_header = FrameHeader::new(1, true);
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
    let frame_header = FrameHeader::new(1, true);
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

    for seq_num in 0..frame_count - 1 {
        frame_buf.write_payload(0, &plain_txt).unwrap();
        assert!(!frame_buf.has_payload_capacity());
        let metadata = FrameHeaderBuilder::new(seq_num.try_into().unwrap()).build();
        frame_buf.encrypt(&metadata);
        payload.extend_from_slice(frame_buf.payload());
        frame_buf.clear();
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

    let frame_header = FrameHeader::new(1, true);
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
    let header = FrameHeader::new(1, true);
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

    let frame_header = FrameHeader::new(1, true);
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

    let frame_header = FrameHeader::new(1, true);
    frame_buf.encrypt(&frame_header);

    // Flip the bits for each byte of the cipher text and confirm
    // that decryption fails.
    for i in 0..frame_buf.buf.len() {
        let mut buf_copy = frame_buf.buf.clone();
        buf_copy[i] = !buf_copy[i];
        let mut frame_buf_reader = FrameBuf::new(&header);
        frame_buf_reader.buf = buf_copy;
        let result = frame_buf_reader.decrypt(1);
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
fn stream_max_seq_end() {
    let parent_key = mock_parent_key();
    let frame_len = FrameLength::Len4KiB;
    let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
        .with_frame_len(frame_len)
        .build();
    let plain_txt = payload_from_frame_count(2, frame_len);
    let start_seq_num = u32::MAX - 1;

    let mut writer = ZymicStream::new_with_seq_num(Vec::new(), &header, start_seq_num);
    writer.write_all(&plain_txt).unwrap();
    writer.eof().unwrap();

    let cipher_txt = writer.into_inner();
    let mut frames = cipher_txt.chunks_exact(frame_len.as_usize());
    validate_frame_bytes(
        frames.next().unwrap(),
        &FrameHeaderBuilder::new(start_seq_num).build(),
    );
    validate_frame_bytes(
        frames.next().unwrap(),
        &FrameHeaderBuilder::new(u32::MAX).end().build(),
    );
    assert!(frames.next().is_none());
    assert!(frames.remainder().is_empty());

    let mut reader = ZymicStream::new_with_seq_num(Cursor::new(cipher_txt), &header, start_seq_num);
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).unwrap();
    reader.is_eof_or_err().unwrap();
    assert_eq!(decoded, plain_txt);
}

#[cfg(feature = "std")]
#[test]
fn stream_max_seq_body_err() {
    let parent_key = mock_parent_key();
    let frame_len = FrameLength::Len4KiB;
    let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
        .with_frame_len(frame_len)
        .build();
    let plain_txt = payload_from_frame_count(1, frame_len);

    let mut stream = ZymicStream::new_with_seq_num(Vec::new(), &header, u32::MAX);
    stream.write_all(&plain_txt).unwrap();
    assert!(stream.inner.is_empty());

    let err = stream.write(&[0]).unwrap_err();
    let inner = err.get_ref().unwrap().downcast_ref::<Error>().unwrap();
    assert!(matches!(inner.kind(), ErrorKind::IntegerOverflow));
    assert!(stream.inner.is_empty());

    stream.eof().unwrap();
    validate_frame_bytes(
        &stream.into_inner(),
        &FrameHeaderBuilder::new(u32::MAX).end().build(),
    );
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
fn stream_write_after_eof_err() {
    let parent_key = mock_parent_key();
    let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
    let plain_txt = vec![1, 2, 3, 4, 5];
    let cursor = Cursor::new(Vec::default());

    let mut stream = ZymicStream::new(cursor, &header);
    stream.write_all(&plain_txt).unwrap();
    stream.eof().unwrap();
    assert!(stream.is_eof());

    let err = stream.write(&plain_txt).unwrap_err();
    let inner = err.get_ref().unwrap().downcast_ref::<Error>().unwrap();
    assert!(matches!(inner.kind(), ErrorKind::StreamImmutable));

    let err = stream.eof().unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::StreamImmutable));
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
fn stream_seek_write_err() {
    let parent_key = mock_parent_key();
    let header = HeaderBuilder::new(&parent_key, &TEST_NONCE).build();
    let plain_txt = vec![1, 2, 3, 4, 5];
    let cursor = Cursor::new(Vec::default());

    let mut stream = ZymicStream::new(cursor, &header);
    stream.write_all(&plain_txt).unwrap();
    stream.eof().unwrap();

    stream.seek(SeekFrom::Start(2)).unwrap();
    assert_eq!(stream.payload_pos, 2);

    let err = stream.write(&[6, 7, 8]).unwrap_err();
    let inner = err.get_ref().unwrap().downcast_ref::<Error>().unwrap();
    assert!(matches!(inner.kind(), ErrorKind::StreamImmutable));

    let mut buf = vec![0u8; 3];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(buf, vec![3, 4, 5]);
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

    let off = stream.seek(SeekFrom::End(-3)).unwrap();
    assert_eq!(off, 2);
    assert_eq!(stream.payload_pos, 2);

    let mut buf = vec![0u8; 3];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(buf, vec![3, 4, 5]);
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

    let off = stream.seek(SeekFrom::Current(2)).unwrap();
    assert_eq!(off, 2);
    assert_eq!(stream.payload_pos, 2);

    let mut buf = vec![0u8; 3];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(buf, vec![3, 4, 5]);
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
