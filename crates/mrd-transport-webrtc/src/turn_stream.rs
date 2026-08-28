use std::{collections::HashMap, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use rustls::{pki_types::ServerName, ClientConfig};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsConnector;

use crate::{config::IceServerConfig, TransportError};

const MAX_STREAM_BRIDGES: usize = 8;
const MAX_CLIENTS_PER_BRIDGE: usize = 8;
const CLIENT_PACKET_QUEUE: usize = 8;
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TURN_DATAGRAM: usize = 65_507;
const STUN_HEADER_LEN: usize = 20;
const CHANNEL_DATA_HEADER_LEN: usize = 4;
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

trait TurnStreamIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> TurnStreamIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}
type BoxedTurnStream = Pin<Box<dyn TurnStreamIo>>;

#[derive(Clone)]
struct StreamTarget {
    host: String,
    port: u16,
    tls: bool,
    #[cfg(test)]
    tls_config: Option<Arc<ClientConfig>>,
}

/// Owns every local bridge created for one physical peer. Dropping the owner aborts both the
/// dispatcher and all per-client stream tasks (the latter are held by the dispatcher's JoinSet).
pub(crate) struct TurnStreamBridgeOwner {
    tasks: Vec<JoinHandle<()>>,
}

impl TurnStreamBridgeOwner {
    pub(crate) fn empty() -> Self {
        Self { tasks: Vec::new() }
    }

    pub(crate) async fn prepare(
        ice_servers: &mut [IceServerConfig],
    ) -> Result<Self, TransportError> {
        // webrtc-rs and the platform verifier can enable different rustls providers in the same
        // process. Install the workspace's ring provider once so downstream rustls users do not
        // panic while trying to infer a provider from an ambiguous feature union.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let stream_count = ice_servers
            .iter()
            .flat_map(|server| &server.urls)
            .filter(|url| parse_stream_target(url).is_some())
            .count();
        if stream_count > MAX_STREAM_BRIDGES {
            return Err(TransportError::Message(format!(
                "too many TURN TCP/TLS endpoints; maximum is {MAX_STREAM_BRIDGES}"
            )));
        }

        let mut owner = Self::empty();
        for server in ice_servers {
            for url in &mut server.urls {
                let Some(target) = parse_stream_target(url) else {
                    continue;
                };
                let (local_addr, task) = start_bridge(target).await.map_err(|error| {
                    TransportError::Message(format!(
                        "start local TURN stream bridge failed: {error}"
                    ))
                })?;
                owner.tasks.push(task);
                *url = format!(
                    "turn:{}:{}?transport=udp",
                    local_addr.ip(),
                    local_addr.port()
                );
            }
        }
        Ok(owner)
    }

    pub(crate) async fn shutdown(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for TurnStreamBridgeOwner {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn parse_stream_target(url: &str) -> Option<StreamTarget> {
    let (scheme, remainder) = url.split_once(':')?;
    let tls = scheme.eq_ignore_ascii_case("turns");
    if !tls && !scheme.eq_ignore_ascii_case("turn") {
        return None;
    }
    let (authority, query) = remainder
        .split_once('?')
        .map_or((remainder, None), |(authority, query)| {
            (authority, Some(query))
        });
    let uses_tcp = tls
        || query.is_some_and(|query| {
            query.split_once('=').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("transport") && value.eq_ignore_ascii_case("tcp")
            })
        });
    if !uses_tcp {
        return None;
    }
    let (host, port) = split_authority(authority)?;
    Some(StreamTarget {
        host: host.to_owned(),
        port,
        tls,
        #[cfg(test)]
        tls_config: None,
    })
}

fn split_authority(authority: &str) -> Option<(&str, u16)> {
    if authority.starts_with('[') {
        let closing = authority.find(']')?;
        let host = authority.get(1..closing)?;
        let port = authority.get(closing + 1..)?.strip_prefix(':')?;
        return port.parse().ok().map(|port| (host, port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    port.parse().ok().map(|port| (host, port))
}

async fn start_bridge(target: StreamTarget) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    let local_addr = socket.local_addr()?;
    let task = tokio::spawn(run_dispatcher(socket, target));
    Ok((local_addr, task))
}

async fn run_dispatcher(socket: Arc<UdpSocket>, target: StreamTarget) {
    let mut clients = HashMap::<SocketAddr, ClientRoute>::new();
    let mut sessions = JoinSet::<(SocketAddr, u64)>::new();
    let mut next_session_id = 0_u64;
    let mut buffer = vec![0_u8; u16::MAX as usize + 1];

    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, client_addr)) = received else {
                    break;
                };
                let mut packet = Some(buffer[..length].to_vec());
                let mut start_new = false;
                match clients.get(&client_addr) {
                    Some(route) => match route.sender.try_send(packet.take().expect("packet is owned")) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(returned)) => {
                            clients.remove(&client_addr);
                            packet = Some(returned);
                            start_new = true;
                        }
                    },
                    None => start_new = true,
                }
                if start_new && clients.len() < MAX_CLIENTS_PER_BRIDGE {
                    let (sender, receiver) = mpsc::channel(CLIENT_PACKET_QUEUE);
                    let first_packet = packet.expect("new client retains its first packet");
                    let session_id = next_session_id;
                    next_session_id = next_session_id.wrapping_add(1);
                    clients.insert(client_addr, ClientRoute { session_id, sender });
                    let session_socket = Arc::clone(&socket);
                    let session_target = target.clone();
                    sessions.spawn(async move {
                        let _ = run_client_session(
                            session_socket,
                            client_addr,
                            session_target,
                            first_packet,
                            receiver,
                        )
                        .await;
                        (client_addr, session_id)
                    });
                }
            }
            completed = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Ok((client_addr, session_id))) = completed {
                    if clients
                        .get(&client_addr)
                        .is_some_and(|route| route.session_id == session_id)
                    {
                        clients.remove(&client_addr);
                    }
                }
            }
        }
    }
}

struct ClientRoute {
    session_id: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

async fn run_client_session(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    target: StreamTarget,
    first_packet: Vec<u8>,
    mut outbound: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let stream = tokio::time::timeout(STREAM_CONNECT_TIMEOUT, connect_turn_stream(&target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TURN stream connect timed out"))??;
    let (mut reader, mut writer) = tokio::io::split(stream);
    write_udp_frame(&mut writer, &first_packet).await?;

    let (remote_tx, mut remote_rx) = mpsc::channel::<io::Result<Vec<u8>>>(CLIENT_PACKET_QUEUE);
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = read_stream_frame(&mut reader).await;
            let finished = frame.is_err();
            if remote_tx.send(frame).await.is_err() || finished {
                break;
            }
        }
    });
    let reader_guard = AbortTaskOnDrop(reader_task);

    loop {
        tokio::select! {
            packet = outbound.recv() => {
                let Some(packet) = packet else {
                    break;
                };
                write_udp_frame(&mut writer, &packet).await?;
            }
            frame = remote_rx.recv() => {
                match frame {
                    Some(Ok(frame)) => {
                        socket.send_to(&frame, client_addr).await?;
                    }
                    Some(Err(error)) => return Err(error),
                    None => break,
                }
            }
        }
    }
    drop(reader_guard);
    Ok(())
}

struct AbortTaskOnDrop(JoinHandle<()>);

impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect_turn_stream(target: &StreamTarget) -> io::Result<BoxedTurnStream> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    tcp.set_nodelay(true)?;
    if !target.tls {
        return Ok(Box::pin(tcp));
    }

    // Select ring explicitly because the process may contain dependencies that enable both
    // rustls crypto providers. Relying on the process-wide implicit provider would then panic.
    #[cfg(test)]
    let configured_for_test = target.tls_config.clone();
    #[cfg(not(test))]
    let configured_for_test: Option<Arc<ClientConfig>> = None;
    let config = if let Some(config) = configured_for_test {
        config
    } else {
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|error| io::Error::other(format!("configure TURN TLS versions: {error}")))?
                .with_platform_verifier()
                .map_err(|error| {
                    io::Error::other(format!("configure platform TLS verifier: {error}"))
                })?
                .with_no_client_auth(),
        )
    };
    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TURN TLS server name"))?;
    let stream = TlsConnector::from(config).connect(server_name, tcp).await?;
    Ok(Box::pin(stream))
}

async fn write_udp_frame<W>(writer: &mut W, datagram: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_stream_frame(datagram)?;
    writer.write_all(&frame).await
}

fn encode_stream_frame(datagram: &[u8]) -> io::Result<Vec<u8>> {
    let frame = classify_datagram(datagram)?;
    let mut encoded = datagram[..frame.wire_len].to_vec();
    if frame.channel_data {
        encoded.resize(round_up_to_four(frame.wire_len), 0);
    }
    Ok(encoded)
}

async fn read_stream_frame<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; CHANNEL_DATA_HEADER_LEN];
    reader.read_exact(&mut prefix).await?;
    match prefix[0] >> 6 {
        0 => {
            let body_len = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
            if body_len % 4 != 0 || STUN_HEADER_LEN + body_len > MAX_TURN_DATAGRAM {
                return Err(invalid_frame("invalid STUN stream length"));
            }
            let mut frame = vec![0_u8; STUN_HEADER_LEN + body_len];
            frame[..CHANNEL_DATA_HEADER_LEN].copy_from_slice(&prefix);
            reader
                .read_exact(&mut frame[CHANNEL_DATA_HEADER_LEN..])
                .await?;
            if frame[4..8] != STUN_MAGIC_COOKIE {
                return Err(invalid_frame("invalid STUN magic cookie"));
            }
            Ok(frame)
        }
        1 => {
            let body_len = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
            let wire_len = CHANNEL_DATA_HEADER_LEN + body_len;
            if wire_len > MAX_TURN_DATAGRAM {
                return Err(invalid_frame("invalid ChannelData stream length"));
            }
            let padded_len = round_up_to_four(wire_len);
            let mut frame = vec![0_u8; padded_len];
            frame[..CHANNEL_DATA_HEADER_LEN].copy_from_slice(&prefix);
            reader
                .read_exact(&mut frame[CHANNEL_DATA_HEADER_LEN..])
                .await?;
            frame.truncate(wire_len);
            Ok(frame)
        }
        _ => Err(invalid_frame("invalid TURN stream frame type")),
    }
}

struct DatagramFrame {
    wire_len: usize,
    channel_data: bool,
}

fn classify_datagram(datagram: &[u8]) -> io::Result<DatagramFrame> {
    if datagram.len() < CHANNEL_DATA_HEADER_LEN || datagram.len() > MAX_TURN_DATAGRAM {
        return Err(invalid_frame("invalid TURN datagram length"));
    }
    match datagram[0] >> 6 {
        0 => {
            if datagram.len() < STUN_HEADER_LEN || datagram[4..8] != STUN_MAGIC_COOKIE {
                return Err(invalid_frame("invalid STUN datagram"));
            }
            let body_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
            let wire_len = STUN_HEADER_LEN + body_len;
            if body_len % 4 != 0 || datagram.len() != wire_len {
                return Err(invalid_frame("inconsistent STUN datagram length"));
            }
            Ok(DatagramFrame {
                wire_len,
                channel_data: false,
            })
        }
        1 => {
            let body_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
            let wire_len = CHANNEL_DATA_HEADER_LEN + body_len;
            let padded_len = round_up_to_four(wire_len);
            if datagram.len() != wire_len && datagram.len() != padded_len {
                return Err(invalid_frame("inconsistent ChannelData datagram length"));
            }
            Ok(DatagramFrame {
                wire_len,
                channel_data: true,
            })
        }
        _ => Err(invalid_frame("invalid TURN datagram frame type")),
    }
}

fn round_up_to_four(length: usize) -> usize {
    (length + 3) & !3
}

fn invalid_frame(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{pki_types::PrivatePkcs8KeyDer, ClientConfig, RootCertStore, ServerConfig};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    use tokio_rustls::TlsAcceptor;

    use super::{
        connect_turn_stream, encode_stream_frame, parse_stream_target, read_stream_frame,
        start_bridge, StreamTarget, TurnStreamBridgeOwner,
    };
    use crate::IceServerConfig;

    fn stun_frame(message_type: [u8; 2]) -> Vec<u8> {
        let mut frame = vec![0_u8; 20];
        frame[..2].copy_from_slice(&message_type);
        frame[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        frame[8..20].copy_from_slice(b"transaction!");
        frame
    }

    #[test]
    fn parses_tcp_and_tls_targets_without_downgrading_tls() {
        let tcp = parse_stream_target("turn:relay.example.test:3478?transport=tcp")
            .expect("TURN/TCP target");
        assert_eq!(tcp.host, "relay.example.test");
        assert_eq!(tcp.port, 3478);
        assert!(!tcp.tls);
        let tls =
            parse_stream_target("turns:[2001:db8::1]:5349?transport=tcp").expect("TURN/TLS target");
        assert_eq!(tls.host, "2001:db8::1");
        assert_eq!(tls.port, 5349);
        assert!(tls.tls);
        assert!(parse_stream_target("turn:relay.example.test:3478?transport=udp").is_none());
    }

    #[tokio::test]
    async fn preparation_rewrites_only_stream_endpoints_to_private_udp_bridges() {
        let udp = "turn:relay.example.test:3478?transport=udp".to_owned();
        let mut servers = vec![IceServerConfig::new(
            vec![
                udp.clone(),
                "turn:relay.example.test:3478?transport=tcp".into(),
                "turns:relay.example.test:5349?transport=tcp".into(),
            ],
            "temporary-user".into(),
            "temporary-password".into(),
        )];

        let mut owner = TurnStreamBridgeOwner::prepare(&mut servers)
            .await
            .expect("prepare local bridges");

        assert_eq!(servers[0].urls[0], udp);
        for rewritten in &servers[0].urls[1..] {
            assert!(rewritten.starts_with("turn:127.0.0.1:"));
            assert!(rewritten.ends_with("?transport=udp"));
            assert!(!rewritten.starts_with("turns:"));
        }
        owner.shutdown().await;
    }

    #[test]
    fn channel_data_is_padded_only_on_the_stream() {
        let datagram = [0x40, 0x01, 0, 3, 1, 2, 3];
        assert_eq!(
            encode_stream_frame(&datagram).expect("encode ChannelData"),
            [0x40, 0x01, 0, 3, 1, 2, 3, 0]
        );
    }

    #[tokio::test]
    async fn stream_decoder_removes_channel_padding_and_preserves_next_frame() {
        let first = [0x40, 0x01, 0, 3, 1, 2, 3, 0];
        let second = stun_frame([0x01, 0x01]);
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_all(&first).await.expect("write first");
        writer.write_all(&second).await.expect("write second");

        assert_eq!(
            read_stream_frame(&mut reader).await.expect("first frame"),
            first[..7]
        );
        assert_eq!(
            read_stream_frame(&mut reader).await.expect("second frame"),
            second
        );
    }

    #[tokio::test]
    async fn tcp_bridge_roundtrips_real_stream_framing() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake TURN TCP listener");
        let target = StreamTarget {
            host: "127.0.0.1".into(),
            port: listener.local_addr().expect("listener address").port(),
            tls: false,
            tls_config: None,
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept bridge stream");
            let request = read_stream_frame(&mut stream).await.expect("read request");
            assert_eq!(request[..2], [0x00, 0x01]);
            let response = stun_frame([0x01, 0x01]);
            stream.write_all(&response).await.expect("write response");
        });
        let (bridge_addr, bridge) = start_bridge(target).await.expect("start bridge");
        let client = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind client");
        client
            .send_to(&stun_frame([0x00, 0x01]), bridge_addr)
            .await
            .expect("send request");
        let mut response = [0_u8; 64];
        let length = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv(&mut response),
        )
        .await
        .expect("bridge response timeout")
        .expect("receive bridge response");
        assert_eq!(&response[..length], stun_frame([0x01, 0x01]));

        bridge.abort();
        server.await.expect("fake server task");
    }

    #[tokio::test]
    async fn tls_bridge_roundtrips_with_a_trusted_ip_certificate() {
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec!["127.0.0.1".into()])
            .expect("generate local TURN TLS certificate");
        let certificate = cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("server TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .expect("server certificate");
        let mut roots = RootCertStore::empty();
        roots.add(certificate).expect("test trust anchor");
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake TURN TLS listener");
        let target = StreamTarget {
            host: "127.0.0.1".into(),
            port: listener.local_addr().expect("listener address").port(),
            tls: true,
            tls_config: Some(Arc::new(client_config)),
        };
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept bridge TCP stream");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("accept bridge TLS stream");
            let request = read_stream_frame(&mut stream)
                .await
                .expect("read TLS request");
            assert_eq!(request[..2], [0x00, 0x01]);
            stream
                .write_all(&stun_frame([0x01, 0x01]))
                .await
                .expect("write TLS response");
        });
        let (bridge_addr, bridge) = start_bridge(target).await.expect("start TLS bridge");
        let client = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind TLS bridge client");
        client
            .send_to(&stun_frame([0x00, 0x01]), bridge_addr)
            .await
            .expect("send TLS bridge request");
        let mut response = [0_u8; 64];
        let length = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv(&mut response),
        )
        .await
        .expect("TLS bridge response timeout")
        .expect("receive TLS bridge response");
        assert_eq!(&response[..length], stun_frame([0x01, 0x01]));

        bridge.abort();
        server.await.expect("fake TLS server task");
    }

    #[tokio::test]
    async fn tls_target_never_falls_back_to_plaintext() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind plaintext listener");
        let port = listener.local_addr().expect("listener address").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept TLS attempt");
            let mut hello = [0_u8; 5];
            stream
                .read_exact(&mut hello)
                .await
                .expect("read ClientHello");
            assert_eq!(hello[0], 0x16, "bridge sent plaintext to a TLS endpoint");
        });
        let target = StreamTarget {
            host: "127.0.0.1".into(),
            port,
            tls: true,
            tls_config: None,
        };

        assert!(connect_turn_stream(&target).await.is_err());
        server.await.expect("plaintext server task");
    }

    #[test]
    fn owner_is_send_sync_for_cross_platform_peer_cleanup() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<super::TurnStreamBridgeOwner>();
        let _ = Arc::new(super::TurnStreamBridgeOwner::empty());
    }
}
