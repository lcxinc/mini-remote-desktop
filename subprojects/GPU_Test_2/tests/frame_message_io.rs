use tokio::io::duplex;

use gpu_test_2::protocol::FrameHeader;
use gpu_test_2::transport::{read_frame_message, write_frame_message};

#[tokio::test]
async fn writes_and_reads_one_complete_frame_message() {
    let header = FrameHeader::new(800, 600, 1, 0, 3);
    let payload = vec![1u8, 2, 3];
    let (mut writer, mut reader) = duplex(1024);

    write_frame_message(&mut writer, &header, &payload)
        .await
        .expect("write should succeed");
    drop(writer);

    let parsed = read_frame_message(&mut reader)
        .await
        .expect("read should succeed");

    assert_eq!(parsed.payload, payload);
}
