use std::io;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::utils::GITHUB_PINNED_IPS;

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(ring::default_provider()))
        .clone()
}

fn root_store() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let native = rustls_native_certs::load_native_certs();
            store.add_parsable_certificates(native.certs);
            Arc::new(store)
        })
        .clone()
}

#[derive(Debug)]
struct IgnoreHostname {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for IgnoreHostname {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName))
            | Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                ..
            })) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn build_tls_config(roots: Arc<RootCertStore>, ignore_hostname: bool, alpn: &[&[u8]]) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("tls protocol versions");
    let mut config = if ignore_hostname {
        let inner = WebPkiServerVerifier::builder_with_provider(roots, provider())
            .build()
            .expect("webpki verifier");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(IgnoreHostname { inner }))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

pub fn tls_verified() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| Arc::new(build_tls_config(root_store(), false, &[])))
        .clone()
}

pub fn tls_fronting() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| Arc::new(build_tls_config(root_store(), true, &[])))
        .clone()
}

pub fn tls_h2() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| Arc::new(build_tls_config(root_store(), false, &[b"h2"])))
        .clone()
}

pub fn connector(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

pub fn server_name(host: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad server name {host}: {e}")))
}

pub fn set_sock_opts(stream: &TcpStream, buffer_size: usize) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(buffer_size);
    let _ = sock.set_send_buffer_size(buffer_size);
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

const MAX_HTTP_BODY: usize = 8 * 1024 * 1024;

fn bad_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn decode_chunked(raw: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| bad_data("truncated chunk header"))?;
        let size_text = String::from_utf8_lossy(&raw[pos..pos + line_end]).to_string();
        let size_text = size_text.split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_text, 16).map_err(|_| bad_data("bad chunk size"))?;
        pos += line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if pos + size > raw.len() {
            return Err(bad_data("truncated chunk"));
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        if out.len() > MAX_HTTP_BODY {
            return Err(bad_data("response too large"));
        }
        pos += size + 2;
    }
}

pub async fn http_exchange<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> io::Result<HttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
    );
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(bad_data("connection closed before headers"));
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > 64 * 1024 {
            return Err(bad_data("response headers too large"));
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad_data("bad status line"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut body = raw[header_end + 4..].to_vec();
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > MAX_HTTP_BODY + 1024 {
            return Err(bad_data("response too large"));
        }
    }
    let response = HttpResponse { status, headers, body };
    let chunked = response
        .header("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        let decoded = decode_chunked(&response.body)?;
        return Ok(HttpResponse { body: decoded, ..response });
    }
    if let Some(length) = response.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if response.body.len() < length {
            return Err(bad_data("incomplete response body"));
        }
        let mut response = response;
        response.body.truncate(length);
        return Ok(response);
    }
    Ok(response)
}

async fn https_get_once(
    connect_to: Option<IpAddr>,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> io::Result<HttpResponse> {
    let tcp = match connect_to {
        Some(ip) => TcpStream::connect((ip, 443)).await?,
        None => TcpStream::connect((host, 443)).await?,
    };
    let _ = tcp.set_nodelay(true);
    let mut tls = connector(tls_verified()).connect(server_name(host)?, tcp).await?;
    http_exchange(&mut tls, host, path, extra_headers).await
}

pub async fn https_get(
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> io::Result<HttpResponse> {
    let pinned: Option<IpAddr> = GITHUB_PINNED_IPS
        .iter()
        .find(|(name, _)| *name == host)
        .and_then(|(_, ip)| ip.parse().ok());
    let attempt = async {
        if let Some(ip) = pinned {
            if let Ok(response) = https_get_once(Some(ip), host, path, extra_headers).await {
                return Ok(response);
            }
        }
        https_get_once(None, host, path, extra_headers).await
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn serve(mut server: tokio::io::DuplexStream, payload: &'static [u8]) {
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(request.starts_with("GET /x HTTP/1.1\r\nHost: h.test\r\n"));
        assert!(request.contains("X-Test: 1\r\n"));
        server.write_all(payload).await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn plain_body_with_content_length() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(serve(
            server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhelloEXTRA",
        ));
        let response = http_exchange(&mut client, "h.test", "/x", &[("X-Test", "1")]).await.unwrap();
        task.await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header("x-a"), Some("b"));
    }

    #[tokio::test]
    async fn chunked_body_is_decoded() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(serve(
            server,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        ));
        let response = http_exchange(&mut client, "h.test", "/x", &[("X-Test", "1")]).await.unwrap();
        task.await.unwrap();
        assert_eq!(response.body, b"hello world");
    }

    #[tokio::test]
    async fn truncated_body_is_an_error() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(serve(server, b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort"));
        let result = http_exchange(&mut client, "h.test", "/x", &[("X-Test", "1")]).await;
        task.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn error_status_is_reported_not_raised() {
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(serve(server, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"));
        let response = http_exchange(&mut client, "h.test", "/x", &[("X-Test", "1")]).await.unwrap();
        task.await.unwrap();
        assert_eq!(response.status, 404);
    }

    #[test]
    fn tls_configs_build() {
        assert!(tls_verified().alpn_protocols.is_empty());
        assert!(tls_fronting().alpn_protocols.is_empty());
        assert_eq!(tls_h2().alpn_protocols, vec![b"h2".to_vec()]);
    }
}
