# GPU Test 2 - DXGI Desktop Duplication + NVENC + QUIC

使用 DXGI Desktop Duplication API 采集桌面画面，使用 NVENC 编码 H.264，并通过 QUIC 传输到接收端进行软件解码与落盘验证。

## 功能特性

### 桌面采集
- **桌面分辨率**: 2560x1440
- **窗口大小**: 1264x681
- **采集帧率**: 56-59 fps
- **帧率波动**: ±1 fps

### 最小链路验证
- **链路**: 本机采集 -> NVENC H.264 -> QUIC -> OpenH264 解码 -> PPM 落盘
- **发送端**: `examples/nvenc_quic_sender_serial.rs` (串行), `examples/nvenc_quic_sender_parallel.rs` (并行，推荐)
- **接收端**: `examples/nvenc_quic_receiver.rs`
- **输出文件**: `artifacts/first_frame.h264`, `artifacts/first_frame.ppm`

### QUIC 传输
- **协议**: QUIC (基于 UDP)
- **库**: Quinn 0.11
- **TLS**: 自签名证书
- **多路复用**: 支持多个并发流

## 技术特点

1. **绕过 DWM**: 直接从 GPU 获取桌面纹理，不受桌面窗口管理器限制
2. **GPU 加速**: 使用 D3D11 暂存纹理读取 GPU 数据
3. **QUIC 传输**: 低延迟、高吞吐量的网络传输
4. **软件解码**: 接收端使用 OpenH264 还原首帧
5. **最小协议**: 自定义薄帧头传输宽高、PTS 和 payload 长度

## 依赖

- Windows 10 或更高版本
- DirectX 11 支持
- Rust 1.70 或更高版本

## 使用方法

### 编译

```bash
cargo build --release
```

### 运行示例

```bash
# 仅桌面采集
cargo run --release

# QUIC 服务端（基础）
cargo run --example quic_server --release

# QUIC 客户端（基础）
cargo run --example quic_client --release

# 桌面采集 + QUIC 传输（服务端）
cargo run --example dxgi_quic_server --release

# 桌面采集 + QUIC 传输（客户端）
cargo run --example dxgi_quic_client --release
```

### 最小端到端验证

先启动接收端：

```bash
cargo run --example nvenc_quic_receiver
```

再启动发送端（串行版本，用于单帧测试）：

```bash
cargo run --example nvenc_quic_sender_serial
```

验证输出：

```text
artifacts/first_frame.h264
artifacts/first_frame.ppm
```

如果 `first_frame.ppm` 可以正常打开，并且内容与发送时桌面一致，则说明最小链路已经打通。

### 低延迟流式传输测试（30 秒 soak）

测试低延迟连续流式传输性能，自动运行 30 秒后退出。

**终端 1 - 启动接收端：**

```bash
cargo run --example nvenc_quic_receiver --release
```

**终端 2 - 启动发送端（并行版本，推荐）：**

```bash
cargo run --example nvenc_quic_sender_parallel --release
```

**实际输出（并行处理架构，约 80 fps）：**

发送端每秒报告：
```text
sender: 81.2 fps out | 142.3 fps cap | enc: 81 sent: 81 | enc_drop: 60
```

接收端每秒报告：
```text
receiver: 81.0 fps recv, 81.0 fps decode, 10.2 mbps, 5.2 ms avg latency, total: 81
wrote artifacts/latest.ppm
```

最终统计（30 秒后）：
```text
sender stats (30s):
  captured: 4269 (142.3 fps)
  encoded: 2436 (81.2 fps) | dropped: 1833
  sent: 2436 (81.2 fps)
  capture_timeouts: 0 | encode_errors: 0 | send_errors: 0

receiver finished: received 2436 frames in 30.0s (81.2 avg fps)
wrote artifacts/final.ppm
```

**注：** 并行处理架构使用 `mpsc + watch` channel 实现 latest-frame 语义：
- capture → encode 使用 `std::sync::mpsc`，编码线程用 `drain_latest_frame()` 清空队列
- encode → network 使用 `tokio::sync::watch`，总是保留最新编码帧
- capture → encode → send 三阶段并行运行，端到端延迟最低

NVENC 编码器使用**资源复用**优化：
- D3D11 输入纹理创建一次，每帧通过 UpdateSubresource 更新内容
- NVENC 注册资源创建一次，复用于所有帧
- Bitstream 输出缓冲区创建一次，每帧 lock/unlock 复用
- 消除了每帧创建/销毁资源的开销

**端到端延迟测量**：
- 捕获时间戳在 `CaptureSession::capture_next_frame()` 成功后立即记录（UNIX epoch 纳秒）
- 包含完整端到端延迟：捕获处理、通道队列等待、编码、网络传输、解码
- 显示 60 帧移动平均（使用循环缓冲区的真正滑动窗口）

**成功标准（当前实现）：**
- 发送和接收帧率稳定在 ~80 fps（编码器瓶颈）
- 连接稳定，无错误累积
- `artifacts/latest.ppm` 每秒更新一次
- 使用首帧 IDR + 后续 P-帧编码策略（提高效率）

**串行版本（用于对比）：**
```bash
cargo run --example nvenc_quic_sender_serial --release
```
串行版本帧率约 22 fps，仅用于性能基准对比。

## 代码结构

```
src/
  main.rs - DXGI Desktop Duplication 实现
  capture.rs - 单帧桌面采集
  encoder.rs - NVENC 单帧编码
  decode.rs - OpenH264 单帧解码
  protocol.rs - 最小帧消息协议
  transport.rs - QUIC 帧消息读写
  artifacts.rs - H.264 / PPM 落盘

examples/
  quic_server.rs - QUIC 服务端基础示例
  quic_client.rs - QUIC 客户端基础示例
  dxgi_quic_server.rs - 桌面采集 + QUIC 传输（服务端）
  dxgi_quic_client.rs - 桌面采集 + QUIC 传输（客户端）
  nvenc_quic_sender_serial.rs - 串行发送端（单帧测试）
  nvenc_quic_sender_parallel.rs - 并行发送端（推荐，~80 fps）
  nvenc_quic_receiver.rs - QUIC 接收 + 软件解码 + 落盘
```

## 关键技术点

### DXGI Desktop Duplication

```rust
// 创建输出复制
let duplication = output1.DuplicateOutput(&device)?;

// 采集帧
duplication.AcquireNextFrame(0, &mut frame_info, &mut frame_resource)?;

// 复制到暂存纹理
context.CopyResource(&staging_texture, &desktop_texture);

// 读取数据
context.Map(&staging_texture, 0, D3D11_MAP_READ, 0, &mut mapped)?;

// 释放帧
duplication.ReleaseFrame()?;
```

### NVENC + QUIC 传输

并行流水线架构（推荐）：

```rust
// Channels for pipeline stages
// (frame, pts, capture_time_ns) - capture_time_ns recorded at actual capture time
let (capture_tx, capture_rx) = mpsc::channel::<(CapturedFrame, u64, u64)>();
let (encode_tx, encode_rx) = watch::channel::<Option<EncodedData>>(None);

// ENCODER TASK: blocking thread pool
spawn_blocking(move || {
    while !stop_flag.load(Ordering::Acquire) {
        match capture_rx.recv_timeout(Duration::from_millis(100)) {
            Ok((frame, pts, capture_time_ns)) => {
                let (frame, pts, capture_time_ns) = drain_latest_frame(
                    &capture_rx, frame, pts, capture_time_ns, &telemetry
                );
                let encoded = encoder.encode_frame(&frame, pts)?;
                let _ = encode_tx.send(Some(EncodedData {
                    bitstream: encoded.bitstream,
                    width: encoded.width,
                    height: encoded.height,
                    pts,
                    capture_time_ns,
                }));
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
});

// NETWORK TASK: async runtime
tokio::spawn(async move {
    loop {
        tokio::select! {
            result = encode_rx.changed() => {
                if result.is_err() { break; }
                if let Some(data) = encode_rx.borrow().clone() {
                    let header = FrameHeader::new(
                        data.width, data.height, data.pts,
                        data.capture_time_ns,  // Absolute UNIX epoch timestamp
                        data.bitstream.len() as u32,
                    );
                    write_frame_message(&mut send, &header, &data.bitstream).await?;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => continue,
        }
    }
});
```

### 软件解码

```rust
let frame = read_frame_message(&mut recv).await?;
let decoded = decode_first_frame(&frame.payload)?;
let ppm = encode_ppm(decoded.width, decoded.height, &decoded.rgb)?;
write_artifact("artifacts/first_frame.ppm", &ppm)?;
```

## 性能数据

### 桌面采集
| 指标 | 值 |
|------|-----|
| 桌面分辨率 | 2560x1440 |
| 窗口大小 | 1264x681 |
| 采集帧率 | 56-59 fps |
| 帧率波动 | ±1 fps |

### QUIC 传输
| 指标 | 值 |
|------|-----|
| 协议 | QUIC (UDP) |
| 库 | Quinn 0.11 |
| TLS | 自签名证书 |
| 并发流 | 100+ |

## 性能对比

| 采集方式 | 帧率 | 说明 |
|----------|------|------|
| scrap crate | 29 fps | 受 DWM 限制 |
| **DXGI Desktop Duplication** | **58 fps** | **绕过 DWM 限制** |

## 扩展

已实现：
- ✅ 连续流式传输（30 秒 soak 测试）
- ✅ 并行流水线架构（~80 fps）
- ✅ Latest-frame 语义（mpsc + watch）

可以继续扩展的功能：
1. **帧率自适应**: 根据网络条件动态调整编码参数
2. **多显示器支持**: 扩展 DXGI Desktop Duplication 支持多个显示器
3. **音频采集**: 添加 WASAPI 音频捕获和多路复用
4. **硬件解码**: 接收端使用 CUDA/NVDEC 解码降低 CPU 占用
5. **带宽自适应**: 根据网络状况动态调整码率和分辨率
6. **错误恢复**: 连接断开后的自动重连和状态同步

## 许可证

MIT License
