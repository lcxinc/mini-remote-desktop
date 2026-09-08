use gpu_test_2::protocol::FrameHeader;
use gpu_test_2::transport::{read_frame_message, write_frame_message};

#[tokio::test]
async fn reads_two_frames_from_one_stream() {
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let first = FrameHeader::new(640, 360, 1, 0, 2);
    let second = FrameHeader::new(640, 360, 2, 0, 3);

    write_frame_message(&mut writer, &first, &[1, 2]).await.unwrap();
    write_frame_message(&mut writer, &second, &[3, 4, 5]).await.unwrap();

    let parsed1 = read_frame_message(&mut reader).await.unwrap();
    let parsed2 = read_frame_message(&mut reader).await.unwrap();
    assert_eq!(parsed1.header.pts, 1);
    assert_eq!(parsed2.header.pts, 2);
}

#[tokio::test]
async fn stream_reader_can_consume_multiple_messages_without_eof_between_frames() {
    let (mut writer, mut reader) = tokio::io::duplex(4096);

    // Write several frames
    for i in 0..5u64 {
        let header = FrameHeader::new(640, 360, i, 0, 10);
        let payload = vec![i as u8; 10];
        write_frame_message(&mut writer, &header, &payload).await.unwrap();
    }

    // Close writer to signal end of stream
    drop(writer);

    // Read all frames until EOF
    let mut count = 0;
    loop {
        match read_frame_message(&mut reader).await {
            Ok(parsed) => {
                assert_eq!(parsed.header.pts, count);
                count += 1;
            }
            Err(e) if e.downcast_ref::<std::io::Error>().map(|e| e.kind()) == Some(std::io::ErrorKind::UnexpectedEof) => break,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(count, 5);
}
