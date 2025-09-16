use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;
use zymic_core::{
    byte_array,
    key::ParentKey,
    stream::{FrameLength, HeaderBuilder, HeaderNonce, ZymicStream},
};

const PLAIN_TXT_LEN: usize = 1 << 27; // 128 MiB
const TEST_NONCE: HeaderNonce = byte_array![3u8; {HeaderNonce::LEN}];

// TODO: This needs documentation

fn stream_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream");
    group.measurement_time(Duration::new(60, 0));

    let plain_txt = vec![0u8; PLAIN_TXT_LEN];
    let parent_key = ParentKey::default();

    let frame_len = FrameLength::Len16KiB;
    let header = HeaderBuilder::new(&parent_key, &TEST_NONCE)
        .with_frame_len(frame_len)
        .build();
    let frame_len_kib = frame_len.as_usize() / 1024;
    let cipher_txt_len = PLAIN_TXT_LEN + (PLAIN_TXT_LEN.div_ceil(frame_len.as_usize()) * 24);

    #[cfg(feature = "std")]
    {
        //
        // std::io endcoding / decoding
        //
        group.throughput(Throughput::Bytes(plain_txt.len() as u64));
        group.bench_function(
            format!("stream/encoding/frame_size_{}_KiB", frame_len_kib),
            |b| {
                b.iter(|| {
                    let mut writer = ZymicStream::new(Vec::with_capacity(cipher_txt_len), &header);
                    let mut reader: &[u8] = &plain_txt;
                    let len = std::io::copy(&mut reader, &mut writer).unwrap();
                    assert!(len > 0);
                })
            },
        );

        let cipher_txt = Vec::with_capacity(cipher_txt_len);
        let mut plain_txt = std::io::Cursor::new(vec![0u8; PLAIN_TXT_LEN]);
        let mut writer = ZymicStream::new(cipher_txt, &header);
        let len = std::io::copy(&mut plain_txt, &mut writer).unwrap();
        assert!(len > 0);

        let cipher_txt = writer.into_inner();
        assert!(!cipher_txt.is_empty());
        let mut plain_txt = plain_txt.into_inner();
        assert!(!plain_txt.is_empty());

        group.throughput(Throughput::Bytes(cipher_txt.len() as u64));
        group.bench_function(
            format!("stream/decoding/frame_size_{}_KiB", frame_len_kib),
            |b| {
                b.iter(|| {
                    plain_txt.clear();
                    let mut reader =
                        ZymicStream::new(std::io::Cursor::new(cipher_txt.clone()), &header);
                    let len = std::io::copy(&mut reader, &mut plain_txt).unwrap();
                    assert!(len > 0);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, stream_benchmark);
criterion_main!(benches);
