// Cross-platform IPC transport
//
// Windows: Named Pipes
// Unix: Unix Domain Sockets

use anyhow::Result;
use serde::Serialize;

/// Default Windows named pipe used by `mrd-service`.
pub const SERVICE_PIPE_NAME: &str = r"\\.\pipe\mrd-service";
#[cfg(unix)]
/// Default Unix domain socket used by `mrd-service`.
pub const SERVICE_SOCKET_PATH: &str = "/tmp/mrd-service.sock";
/// Environment variable that overrides the service IPC endpoint.
pub const SERVICE_ENDPOINT_ENV: &str = "MRD_SERVICE_IPC_ENDPOINT";

const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// IPC endpoint used by clients and servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Windows named pipe endpoint.
    #[cfg(windows)]
    NamedPipe(String),
    /// Unix domain socket endpoint.
    #[cfg(unix)]
    UnixSocket(String),
}

impl IpcEndpoint {
    /// Default service endpoint used by production Rdesk and mrd-service.
    pub fn default_service() -> Self {
        #[cfg(windows)]
        {
            Self::NamedPipe(SERVICE_PIPE_NAME.to_string())
        }

        #[cfg(unix)]
        {
            Self::UnixSocket(SERVICE_SOCKET_PATH.to_string())
        }
    }

    /// Construct a Windows named pipe endpoint.
    #[cfg(windows)]
    pub fn named_pipe(path: impl Into<String>) -> Self {
        Self::NamedPipe(path.into())
    }

    /// Construct a Unix domain socket endpoint.
    #[cfg(unix)]
    pub fn unix_socket(path: impl Into<String>) -> Self {
        Self::UnixSocket(path.into())
    }

    /// Build a service endpoint from a non-empty environment variable value.
    pub fn from_env_value(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }

        #[cfg(windows)]
        {
            Some(Self::NamedPipe(value.to_string()))
        }

        #[cfg(unix)]
        {
            Some(Self::UnixSocket(value.to_string()))
        }
    }

    /// Resolve the service endpoint from `MRD_SERVICE_IPC_ENDPOINT`, or use the default.
    pub fn service_from_env_or_default() -> Self {
        std::env::var(SERVICE_ENDPOINT_ENV)
            .ok()
            .and_then(|value| Self::from_env_value(&value))
            .unwrap_or_else(Self::default_service)
    }

    #[cfg(windows)]
    fn pipe_name(&self) -> &str {
        match self {
            Self::NamedPipe(path) => path,
        }
    }

    #[cfg(unix)]
    fn socket_path(&self) -> &str {
        match self {
            Self::UnixSocket(path) => path,
        }
    }
}

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};

async fn read_message<R: tokio::io::AsyncReadExt + std::marker::Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("IPC message too large: {} bytes", len);
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_message<W: tokio::io::AsyncWriteExt + std::marker::Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_json_message<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: tokio::io::AsyncWriteExt + std::marker::Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(message)?;
    write_message(writer, &json).await
}

// Unix server
#[cfg(unix)]
/// Unix domain socket IPC server.
pub struct IpcServer {
    listener: UnixListener,
}

#[cfg(unix)]
impl IpcServer {
    /// Bind the default service endpoint.
    pub async fn bind() -> Result<Self> {
        Self::bind_with_endpoint(IpcEndpoint::default_service()).await
    }

    /// Bind a custom Unix domain socket endpoint.
    pub async fn bind_with_endpoint(endpoint: IpcEndpoint) -> Result<Self> {
        let socket_path = endpoint.socket_path();
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        Ok(Self { listener })
    }

    /// Accept a single IPC stream from a client.
    pub async fn accept(&self) -> Result<IpcStream> {
        let socket = self.listener.accept().await?.0;
        Ok(IpcStream { socket })
    }
}

// Windows server
#[cfg(windows)]
/// Windows named-pipe IPC server.
pub struct IpcServer {
    endpoint: IpcEndpoint,
}

#[cfg(windows)]
impl IpcServer {
    /// Bind the default service endpoint.
    pub async fn bind() -> Result<Self> {
        Self::bind_with_endpoint(IpcEndpoint::default_service()).await
    }

    /// Bind a custom Windows named-pipe endpoint.
    pub async fn bind_with_endpoint(endpoint: IpcEndpoint) -> Result<Self> {
        Ok(Self { endpoint })
    }

    /// Accept a single IPC stream from a client.
    pub async fn accept(&self) -> Result<IpcStream> {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(self.endpoint.pipe_name())?;
        server.connect().await?;
        Ok(IpcStream::Server(server))
    }
}

// Unix client
#[cfg(unix)]
/// Unix IPC client factory.
pub struct IpcClient;

#[cfg(unix)]
impl IpcClient {
    /// Connect to the default service endpoint.
    pub async fn connect() -> Result<IpcStream> {
        Self::connect_with_endpoint(&IpcEndpoint::default_service()).await
    }

    /// Connect to a custom Unix domain socket endpoint.
    pub async fn connect_with_endpoint(endpoint: &IpcEndpoint) -> Result<IpcStream> {
        let socket = UnixStream::connect(endpoint.socket_path()).await?;
        Ok(IpcStream { socket })
    }
}

// Windows client
#[cfg(windows)]
/// Windows IPC client factory.
pub struct IpcClient;

#[cfg(windows)]
impl IpcClient {
    /// Connect to the default service endpoint.
    pub async fn connect() -> Result<IpcStream> {
        Self::connect_with_endpoint(&IpcEndpoint::default_service()).await
    }

    /// Connect to a custom Windows named-pipe endpoint.
    pub async fn connect_with_endpoint(endpoint: &IpcEndpoint) -> Result<IpcStream> {
        let pipe = ClientOptions::new().open(endpoint.pipe_name())?;
        Ok(IpcStream::Client(pipe))
    }
}

// Unix stream
#[cfg(unix)]
/// Unix IPC stream.
pub struct IpcStream {
    socket: UnixStream,
}

#[cfg(unix)]
impl IpcStream {
    /// Send an IPC request.
    pub async fn send_request(&mut self, request: &crate::IpcRequest) -> Result<()> {
        write_json_message(&mut self.socket, request).await
    }

    /// Receive an IPC response.
    pub async fn recv_response(&mut self) -> Result<crate::IpcResponse> {
        let buf = read_message(&mut self.socket).await?;
        let response: crate::IpcResponse = serde_json::from_slice(&buf)?;
        Ok(response)
    }

    /// Send an IPC response.
    pub async fn send_response(&mut self, response: &crate::IpcResponse) -> Result<()> {
        write_json_message(&mut self.socket, response).await
    }

    /// Receive an IPC request.
    pub async fn recv_request(&mut self) -> Result<crate::IpcRequest> {
        let buf = read_message(&mut self.socket).await?;
        let request: crate::IpcRequest = serde_json::from_slice(&buf)?;
        Ok(request)
    }
}

// Windows stream
#[cfg(windows)]
/// Windows IPC stream backed by a named-pipe client or server handle.
pub enum IpcStream {
    /// Client-side pipe handle.
    Client(NamedPipeClient),
    /// Server-side pipe handle.
    Server(tokio::net::windows::named_pipe::NamedPipeServer),
}

#[cfg(windows)]
impl IpcStream {
    /// Send an IPC request.
    pub async fn send_request(&mut self, request: &crate::IpcRequest) -> Result<()> {
        match self {
            IpcStream::Client(pipe) => write_json_message(pipe, request).await,
            IpcStream::Server(pipe) => write_json_message(pipe, request).await,
        }
    }

    /// Receive an IPC response.
    pub async fn recv_response(&mut self) -> Result<crate::IpcResponse> {
        let buf = match self {
            IpcStream::Client(pipe) => read_message(pipe).await?,
            IpcStream::Server(pipe) => read_message(pipe).await?,
        };
        let response: crate::IpcResponse = serde_json::from_slice(&buf)?;
        Ok(response)
    }

    /// Send an IPC response.
    pub async fn send_response(&mut self, response: &crate::IpcResponse) -> Result<()> {
        match self {
            IpcStream::Client(pipe) => write_json_message(pipe, response).await,
            IpcStream::Server(pipe) => write_json_message(pipe, response).await,
        }
    }

    /// Receive an IPC request.
    pub async fn recv_request(&mut self) -> Result<crate::IpcRequest> {
        let buf = match self {
            IpcStream::Client(pipe) => read_message(pipe).await?,
            IpcStream::Server(pipe) => read_message(pipe).await?,
        };
        let request: crate::IpcRequest = serde_json::from_slice(&buf)?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpcRequest;
    #[cfg(unix)]
    use crate::IpcResponse;

    #[test]
    fn frame_format_is_valid() {
        let request = IpcRequest::ListDevices;
        let json = serde_json::to_string(&request).unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        let len = bytes.len() as u32;
        assert_eq!(bytes, json.as_bytes());
        assert_eq!(len.to_le_bytes().len(), 4);
    }

    #[test]
    #[cfg(windows)]
    fn endpoint_from_env_value_uses_named_pipe_on_windows() {
        let endpoint = IpcEndpoint::from_env_value(r"\\.\pipe\mrd-service-local-controller")
            .expect("custom endpoint");
        assert_eq!(
            endpoint,
            IpcEndpoint::named_pipe(r"\\.\pipe\mrd-service-local-controller")
        );
    }

    #[test]
    #[cfg(unix)]
    fn endpoint_from_env_value_uses_unix_socket_on_unix() {
        let endpoint =
            IpcEndpoint::from_env_value("/tmp/mrd-service-local-controller.sock").unwrap();
        assert_eq!(
            endpoint,
            IpcEndpoint::unix_socket("/tmp/mrd-service-local-controller.sock")
        );
    }

    #[test]
    fn endpoint_from_env_value_rejects_blank_values() {
        assert!(IpcEndpoint::from_env_value("  ").is_none());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn unix_socket_ipc_roundtrip() -> Result<()> {
        use tokio::time::{sleep, Duration};

        let server_handle = tokio::spawn(async {
            let server = IpcServer::bind().await?;
            let mut stream = server.accept().await?;

            let request = stream.recv_request().await?;
            assert!(matches!(request, IpcRequest::ListDevices));

            let response = IpcResponse::DeviceList { devices: vec![] };
            stream.send_response(&response).await?;
            Ok::<(), anyhow::Error>(())
        });

        sleep(Duration::from_millis(100)).await;

        let mut stream = IpcClient::connect().await?;
        stream.send_request(&IpcRequest::ListDevices).await?;
        let response = stream.recv_response().await?;
        assert!(matches!(response, IpcResponse::DeviceList { .. }));

        server_handle.await??;
        Ok(())
    }
}
