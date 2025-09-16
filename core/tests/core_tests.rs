// SPDX-License-Identifier: MIT

//! core Integration Tests

#[cfg(all(feature = "std", test))]
mod core_integ_tests {
    use zymic_core::{
        byte_array,
        key::{ParentKey, ParentKeyId, ParentKeySecret},
        stream::{FrameLength, HeaderBuilder, HeaderNonce, ZymicStream},
    };

    use std::io::{Cursor, Read, Seek};

    const FRAME_LENGTHS: [FrameLength; 5] = [
        FrameLength::Len4KiB,
        FrameLength::Len8KiB,
        FrameLength::Len16KiB,
        FrameLength::Len32KiB,
        FrameLength::Len64KiB,
    ];

    const MOCK_NONCE: HeaderNonce = byte_array![3u8; {HeaderNonce::LEN}];

    fn mock_parent_key() -> ParentKey {
        const ID: ParentKeyId = byte_array![1u8; {ParentKeyId::LEN}];
        const SECRET: ParentKeySecret = byte_array![2u8; {ParentKeySecret::LEN}];

        let id = ParentKeyId::from(ID);
        let secret = ParentKeySecret::from(SECRET);

        ParentKey::new(id, secret)
    }

    fn stream_by_file_size(sizes: &[usize]) {
        const CHUNK_READ_LEN: usize = 4096;
        let mock_key = mock_parent_key();

        for frame_len in FRAME_LENGTHS {
            let header = HeaderBuilder::new(&mock_key, &MOCK_NONCE)
                .with_frame_len(frame_len)
                .build();

            for size in sizes {
                let mut plain_txt = Cursor::new(vec![0x0u8; *size]);
                let cipher_txt = Vec::default();
                let mut stream = ZymicStream::new(Cursor::new(cipher_txt), &header);
                std::io::copy(&mut plain_txt, &mut stream).unwrap();
                stream.eof().unwrap();
                stream.rewind().unwrap();

                let plain_txt = plain_txt.into_inner();
                let mut buf = [0u8; CHUNK_READ_LEN];
                for chunk in plain_txt.chunks(CHUNK_READ_LEN) {
                    let buf_chunk = &mut buf[..chunk.len()];
                    stream.read_exact(buf_chunk).unwrap();
                    assert_eq!(buf_chunk, chunk);
                }
            }
        }
    }

    /// Encrypt/Decrypt files from 0-1K bytes
    #[test]
    fn tiny_files() {
        let sizes = vec![
            0, 41, 50, 57, 109, 119, 140, 167, 182, 228, 231, 235, 267, 290, 314, 337, 344, 349,
            353, 382, 407, 479, 483, 492, 495, 549, 559, 576, 627, 647, 648, 652, 659, 662, 682,
            730, 756, 762, 831, 832, 837, 848, 852, 887, 901, 916, 969, 992, 994, 1024,
        ];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 1K-64K bytes
    #[test]
    fn small_files_1() {
        let sizes = vec![
            1428, 2080, 3575, 5575, 10111, 14199, 15121, 15256, 16350, 17339,
        ];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 1K-64K bytes
    #[test]
    fn small_files_2() {
        let sizes = vec![
            18041, 20420, 20668, 21679, 22791, 23617, 23935, 28960, 31502, 31507,
        ];
        stream_by_file_size(&sizes);
    }

    #[test]
    fn small_files_3() {
        let sizes = vec![
            31517, 31761, 31912, 32204, 36027, 37933, 39189, 40488, 41269, 41877,
        ];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 1K-64K bytes
    #[test]
    fn small_files_4() {
        let sizes = vec![
            42480, 43922, 43936, 45008, 47737, 48010, 48714, 49213, 50935, 51725,
        ];
        stream_by_file_size(&sizes);
    }

    #[test]
    fn small_files_5() {
        let sizes = vec![
            52999, 53587, 53740, 54788, 58854, 59432, 61159, 61793, 62727, 65536,
        ];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes    
    #[test]
    fn medium_files_1() {
        let sizes = vec![69648, 91767, 128319, 130988, 162853];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_2() {
        let sizes = vec![180645, 186386, 216527, 228538, 237645];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_3() {
        let sizes = vec![247942, 257761, 262165, 295484, 302633];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_4() {
        let sizes = vec![307016, 335103, 370518, 395376, 455533];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_5() {
        let sizes = vec![473407, 509383, 518865, 520824, 521765];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes    
    #[test]
    fn medium_files_6() {
        let sizes = vec![525475, 547051, 548241, 624664, 627090];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_7() {
        let sizes = vec![646697, 663167, 689739, 719304, 719502];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_8() {
        let sizes = vec![737267, 739747, 741123, 747926, 780127];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_9() {
        let sizes = vec![808563, 837569, 864991, 868544, 920998];
        stream_by_file_size(&sizes);
    }

    /// Encrypt/Decrypt files from 64K-1M bytes
    #[test]
    fn medium_files_10() {
        let sizes = vec![938547, 985619, 1030257, 1035074, 1048576];
        stream_by_file_size(&sizes);
    }
}
