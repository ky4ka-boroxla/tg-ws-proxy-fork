use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use futures_util::FutureExt;
use rand::Rng;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::net::{connector, server_name, set_sock_opts, tls_fronting, tls_verified};

pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;
pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("HTTP {status_code}: {status_line}")]
    Handshake {
        status_code: u16,
        status_line: String,
        headers: HashMap<String, String>,
        location: Option<String>,
    },
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("WebSocket closed")]
    Closed,
    #[error("{0}")]
    Protocol(String),
    #[error("timed out")]
    Timeout,
}

impl WsError {
    pub fn is_redirect(&self) -> bool {
        matches!(self, WsError::Handshake { status_code, .. } if [301, 302, 303, 307, 308].contains(status_code))
    }

    pub fn status_code(&self) -> Option<u16> {
        match self {
            WsError::Handshake { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }
}

pub fn xor_in_place(data: &mut [u8], mask: [u8; 4]) {
    let wide = u64::from_le_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let mut chunks = data.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let value = u64::from_le_bytes(chunk.try_into().expect("8 byte chunk")) ^ wide;
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in chunks.into_remainder().iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

pub fn xor_mask(data: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = data.to_vec();
    xor_in_place(&mut out, mask);
    out
}

pub fn build_frame(opcode: u8, data: &[u8], mask: bool) -> Vec<u8> {
    let length = data.len();
    let first = 0x80 | opcode;
    let mask_bit: u8 = if mask { 0x80 } else { 0 };
    let mut frame = Vec::with_capacity(length + 14);
    frame.push(first);
    if length < 126 {
        frame.push(mask_bit | length as u8);
    } else if length < 65536 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(length as u64).to_be_bytes());
    }
    if mask {
        let mut key = [0u8; 4];
        rand::thread_rng().fill(&mut key);
        frame.extend_from_slice(&key);
        let start = frame.len();
        frame.extend_from_slice(data);
        xor_in_place(&mut frame[start..], key);
    } else {
        frame.extend_from_slice(data);
    }
    frame
}

fn close_reason_name(code: u16) -> Option<&'static str> {
    Some(match code {
        1000 => "normal",
        1001 => "going_away",
        1002 => "protocol_error",
        1003 => "unsupported_data",
        1006 => "abnormal",
        1007 => "bad_data",
        1008 => "policy_violation",
        1009 => "too_big",
        1010 => "missing_extension",
        1011 => "internal_error",
        _ => return None,
    })
}

pub fn parse_close(payload: &[u8]) -> (Option<u16>, String) {
    if payload.len() < 2 {
        return (None, String::new());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let text = String::from_utf8_lossy(&payload[2..]).into_owned();
    match close_reason_name(code) {
        Some(name) => (Some(code), format!("{text} ({name})")),
        None => (Some(code), text),
    }
}

struct ReaderState {
    io: BufReader<BoxRead>,
    frag: Vec<u8>,
}

pub struct RawWebSocket {
    reader: Mutex<ReaderState>,
    writer: Mutex<BoxWrite>,
    closed: AtomicBool,
}

#[derive(Clone, Debug)]
pub struct ConnectOptions {
    pub sni: Option<String>,
    pub secure: bool,
    pub port: Option<u16>,
    pub buffer_size: usize,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self { sni: None, secure: true, port: None, buffer_size: 0 }
    }
}

impl RawWebSocket {
    pub fn from_parts(reader: BoxRead, writer: BoxWrite) -> Self {
        Self {
            reader: Mutex::new(ReaderState { io: BufReader::new(reader), frag: Vec::new() }),
            writer: Mutex::new(writer),
            closed: AtomicBool::new(false),
        }
    }

    pub async fn connect(
        host: &str,
        domain: &str,
        timeout: Duration,
        path: &str,
        options: &ConnectOptions,
    ) -> Result<Self, WsError> {
        let connect_timeout = timeout.min(Duration::from_secs(10));
        let sni = options.sni.clone().unwrap_or_else(|| domain.to_string());
        let secure = options.secure;
        let port = options.port.unwrap_or(if secure { 443 } else { 80 });
        let establish = async {
            let tcp = TcpStream::connect((host, port)).await?;
            if options.buffer_size > 0 {
                set_sock_opts(&tcp, options.buffer_size);
            } else {
                let _ = tcp.set_nodelay(true);
            }
            if !secure {
                let (r, w) = tokio::io::split(tcp);
                return Ok::<_, io::Error>((Box::new(r) as BoxRead, Box::new(w) as BoxWrite));
            }
            let config = if options.sni.is_some() { tls_fronting() } else { tls_verified() };
            let tls = connector(config).connect(server_name(&sni)?, tcp).await?;
            let (r, w) = tokio::io::split(tls);
            Ok((Box::new(r) as BoxRead, Box::new(w) as BoxWrite))
        };
        let (reader, writer) = match tokio::time::timeout(connect_timeout, establish).await {
            Ok(result) => result?,
            Err(_) => return Err(WsError::Timeout),
        };
        let ws = Self::from_parts(reader, writer);
        ws.handshake(domain, path, timeout).await?;
        Ok(ws)
    }

    async fn handshake(&self, domain: &str, path: &str, timeout: Duration) -> Result<(), WsError> {
        let mut key_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut key_bytes);
        let ws_key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: binary\r\n\r\n"
        );
        {
            let mut writer = self.writer.lock().await;
            writer.write_all(request.as_bytes()).await?;
            writer.flush().await?;
        }
        let mut lines: Vec<String> = Vec::new();
        let mut state = self.reader.lock().await;
        loop {
            let mut line = Vec::new();
            let read = tokio::time::timeout(timeout, state.io.read_until(b'\n', &mut line))
                .await
                .map_err(|_| WsError::Timeout)??;
            if read == 0 || line == b"\r\n" || line == b"\n" {
                break;
            }
            lines.push(String::from_utf8_lossy(&line).trim().to_string());
        }
        if lines.is_empty() {
            return Err(WsError::Handshake {
                status_code: 0,
                status_line: "empty response".to_string(),
                headers: HashMap::new(),
                location: None,
            });
        }
        let first = lines[0].clone();
        let status_code = first
            .splitn(3, ' ')
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if status_code == 101 {
            return Ok(());
        }
        let mut headers = HashMap::new();
        for line in &lines[1..] {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        let location = headers.get("location").cloned();
        Err(WsError::Handshake { status_code, status_line: first, headers, location })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn is_alive(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let Ok(mut state) = self.reader.try_lock() else {
            return true;
        };
        match state.io.fill_buf().now_or_never() {
            None => true,
            Some(Ok(buf)) => !buf.is_empty(),
            Some(Err(_)) => false,
        }
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), WsError> {
        if self.is_closed() {
            return Err(WsError::Closed);
        }
        let frame = build_frame(OP_BINARY, data, true);
        let mut writer = self.writer.lock().await;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn send_batch<T: AsRef<[u8]>>(&self, parts: &[T]) -> Result<(), WsError> {
        if self.is_closed() {
            return Err(WsError::Closed);
        }
        let mut buffer = Vec::new();
        for part in parts {
            buffer.extend_from_slice(&build_frame(OP_BINARY, part.as_ref(), true));
        }
        let mut writer = self.writer.lock().await;
        writer.write_all(&buffer).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn write_control(&self, opcode: u8, payload: &[u8]) {
        let frame = build_frame(opcode, payload, true);
        let mut writer = self.writer.lock().await;
        if writer.write_all(&frame).await.is_ok() {
            let _ = writer.flush().await;
        }
    }

    pub async fn recv(&self) -> Result<Option<Vec<u8>>, WsError> {
        let mut state = self.reader.lock().await;
        while !self.is_closed() {
            let (opcode, payload, fin) = read_frame(&mut state.io).await?;
            match opcode {
                OP_CLOSE => {
                    self.closed.store(true, Ordering::Release);
                    let (code, reason) = parse_close(&payload);
                    log::debug!("WS OP_CLOSE from upstream: code={code:?} reason={reason:?}");
                    let echo: &[u8] = if payload.len() >= 2 { &payload[..2] } else { &[] };
                    self.write_control(OP_CLOSE, echo).await;
                    return Ok(None);
                }
                OP_PING => {
                    self.write_control(OP_PONG, &payload).await;
                }
                OP_PONG => {}
                OP_CONT | OP_TEXT | OP_BINARY => {
                    if fin && state.frag.is_empty() {
                        return Ok(Some(payload));
                    }
                    state.frag.extend_from_slice(&payload);
                    if state.frag.len() > MAX_MESSAGE_LEN {
                        return Err(WsError::Protocol(format!(
                            "WS message too large: {} bytes",
                            state.frag.len()
                        )));
                    }
                    if !fin {
                        continue;
                    }
                    return Ok(Some(std::mem::take(&mut state.frag)));
                }
                _ => {}
            }
        }
        Ok(None)
    }

    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let frame = build_frame(OP_CLOSE, &[], true);
        let mut writer = self.writer.lock().await;
        let _ = writer.write_all(&frame).await;
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    }
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>, bool), WsError> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0F;
    let mut length = (header[1] & 0x7F) as u64;
    if length == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        length = u16::from_be_bytes(ext) as u64;
    } else if length == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        length = u64::from_be_bytes(ext);
    }
    if length > MAX_MESSAGE_LEN as u64 {
        return Err(WsError::Protocol(format!("WS frame too large: {length} bytes")));
    }
    let masked = header[1] & 0x80 != 0;
    let mut mask_key = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask_key).await?;
    }
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    if masked {
        xor_in_place(&mut payload, mask_key);
    }
    Ok((opcode, payload, fin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn raw_frame(opcode: u8, data: &[u8], fin: bool) -> Vec<u8> {
        let first = if fin { 0x80 } else { 0x00 } | opcode;
        let n = data.len();
        let mut out = vec![first];
        if n < 126 {
            out.push(n as u8);
        } else if n < 65536 {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
        out.extend_from_slice(data);
        out
    }

    async fn ws_with_incoming(chunks: &[Vec<u8>]) -> (RawWebSocket, tokio::io::DuplexStream) {
        let (client, mut server) = duplex(64 * 1024 * 1024);
        for chunk in chunks {
            server.write_all(chunk).await.unwrap();
        }
        let (read_half, write_half) = tokio::io::split(client);
        (RawWebSocket::from_parts(Box::new(read_half), Box::new(write_half)), server)
    }

    #[test]
    fn xor_matches_bytewise_at_boundaries() {
        for length in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 125, 126, 127, 255, 511, 512, 513, 16384, 65537] {
            let data: Vec<u8> = (0..length).map(|i| (i % 256) as u8).collect();
            for mask in [[0u8; 4], [0xff; 4], [0x01, 0x7f, 0x80, 0xff]] {
                let expected: Vec<u8> =
                    data.iter().enumerate().map(|(i, v)| v ^ mask[i % 4]).collect();
                assert_eq!(xor_mask(&data, mask), expected, "len={length} mask={mask:?}");
            }
        }
    }

    #[test]
    fn xor_roundtrip_and_empty() {
        let data: Vec<u8> = (0..768).map(|i| (i % 256) as u8).collect();
        let mask = [1, 2, 3, 4];
        assert_eq!(xor_mask(&xor_mask(&data, mask), mask), data);
        assert!(xor_mask(&[], mask).is_empty());
    }

    #[test]
    fn masked_frame_wire_format_across_length_encodings() {
        for length in [1usize, 125, 126, 511, 512, 513, 65535, 65536, 65537] {
            let data: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let frame = build_frame(OP_BINARY, &data, true);
            assert_eq!(frame[0], 0x82);
            let (header_len, declared) = if length < 126 {
                (2, (frame[1] & 0x7f) as usize)
            } else if length < 65536 {
                assert_eq!(frame[1], 0x80 | 126);
                (4, u16::from_be_bytes([frame[2], frame[3]]) as usize)
            } else {
                assert_eq!(frame[1], 0x80 | 127);
                (10, u64::from_be_bytes(frame[2..10].try_into().unwrap()) as usize)
            };
            assert_eq!(declared, length);
            assert!(frame[1] & 0x80 != 0);
            let key: [u8; 4] = frame[header_len..header_len + 4].try_into().unwrap();
            let payload = &frame[header_len + 4..];
            assert_eq!(xor_mask(payload, key), data);
        }
    }

    #[test]
    fn unmasked_frames() {
        assert_eq!(build_frame(OP_BINARY, b"abc", false), vec![0x82, 3, b'a', b'b', b'c']);
        let medium = build_frame(OP_BINARY, &vec![0u8; 300], false);
        assert_eq!(&medium[..4], &[0x82, 126, 0x01, 0x2c]);
    }

    #[tokio::test]
    async fn recv_returns_unfragmented_message() {
        let (ws, _server) = ws_with_incoming(&[raw_frame(OP_BINARY, b"hello", true)]).await;
        assert_eq!(ws.recv().await.unwrap(), Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn recv_reassembles_fragments_and_skips_control_frames() {
        let (ws, _server) = ws_with_incoming(&[
            raw_frame(OP_BINARY, b"ab", false),
            raw_frame(OP_PING, b"p", true),
            raw_frame(OP_PONG, b"", true),
            raw_frame(OP_CONT, b"cd", false),
            raw_frame(OP_CONT, b"ef", true),
        ])
        .await;
        assert_eq!(ws.recv().await.unwrap(), Some(b"abcdef".to_vec()));
    }

    #[tokio::test]
    async fn ping_is_answered_with_masked_pong() {
        let (ws, mut server) = ws_with_incoming(&[
            raw_frame(OP_PING, b"xyz", true),
            raw_frame(OP_BINARY, b"data", true),
        ])
        .await;
        assert_eq!(ws.recv().await.unwrap(), Some(b"data".to_vec()));
        let mut header = [0u8; 2];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x80 | OP_PONG);
        assert_eq!(header[1], 0x80 | 3);
        let mut rest = [0u8; 7];
        server.read_exact(&mut rest).await.unwrap();
        let key: [u8; 4] = rest[..4].try_into().unwrap();
        assert_eq!(xor_mask(&rest[4..], key), b"xyz");
    }

    #[tokio::test]
    async fn close_frame_returns_none_and_marks_closed() {
        let mut payload = 1000u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"bye");
        let (ws, _server) = ws_with_incoming(&[raw_frame(OP_CLOSE, &payload, true)]).await;
        assert_eq!(ws.recv().await.unwrap(), None);
        assert!(ws.is_closed());
        assert!(matches!(ws.send(b"x").await, Err(WsError::Closed)));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_reading_payload() {
        let mut header = vec![0x82, 127];
        header.extend_from_slice(&((MAX_MESSAGE_LEN as u64) + 1).to_be_bytes());
        let (ws, _server) = ws_with_incoming(&[header]).await;
        let err = ws.recv().await.unwrap_err();
        assert!(matches!(err, WsError::Protocol(m) if m.contains("too large")));
    }

    #[tokio::test]
    async fn reassembled_message_exceeding_limit_is_rejected() {
        let half = vec![0u8; MAX_MESSAGE_LEN / 2 + 1];
        let (ws, _server) = ws_with_incoming(&[
            raw_frame(OP_BINARY, &half, false),
            raw_frame(OP_CONT, &half, true),
        ])
        .await;
        assert!(matches!(ws.recv().await, Err(WsError::Protocol(_))));
    }

    #[test]
    fn parse_close_names_known_codes() {
        let mut payload = 1001u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"bye");
        assert_eq!(parse_close(&payload), (Some(1001), "bye (going_away)".to_string()));
        assert_eq!(parse_close(&[]), (None, String::new()));
        assert_eq!(parse_close(&4000u16.to_be_bytes()), (Some(4000), String::new()));
    }

    #[test]
    fn redirect_status_codes() {
        for code in [301u16, 302, 303, 307, 308] {
            let err = WsError::Handshake {
                status_code: code,
                status_line: String::new(),
                headers: HashMap::new(),
                location: None,
            };
            assert!(err.is_redirect());
        }
        let err = WsError::Handshake {
            status_code: 200,
            status_line: String::new(),
            headers: HashMap::new(),
            location: None,
        };
        assert!(!err.is_redirect());
    }

    async fn local_server<F, Fut>(handler: F) -> u16
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler(stream).await;
        });
        port
    }

    async fn read_request(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn connect_performs_upgrade_and_exchanges_frames() {
        let port = local_server(|mut stream| async move {
            let request = read_request(&mut stream).await;
            assert!(request.starts_with("GET /apiws?dst=1 HTTP/1.1\r\nHost: example.test\r\n"));
            assert!(request.contains("Upgrade: websocket\r\n"));
            assert!(request.contains("Sec-WebSocket-Protocol: binary\r\n"));
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(&raw_frame(OP_BINARY, b"from-server", true)).await.unwrap();
            let mut header = [0u8; 2];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x82);
            let len = (header[1] & 0x7f) as usize;
            let mut rest = vec![0u8; 4 + len];
            stream.read_exact(&mut rest).await.unwrap();
            let key: [u8; 4] = rest[..4].try_into().unwrap();
            assert_eq!(xor_mask(&rest[4..], key), b"from-client");
        })
        .await;
        let options = ConnectOptions { secure: false, port: Some(port), ..Default::default() };
        let ws = RawWebSocket::connect(
            "127.0.0.1",
            "example.test",
            Duration::from_secs(5),
            "/apiws?dst=1",
            &options,
        )
        .await
        .unwrap();
        assert_eq!(ws.recv().await.unwrap(), Some(b"from-server".to_vec()));
        ws.send(b"from-client").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn failed_upgrade_reports_status_and_location() {
        let port = local_server(|mut stream| async move {
            let _ = read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://other.test/\r\n\r\n")
                .await
                .unwrap();
        })
        .await;
        let options = ConnectOptions { secure: false, port: Some(port), ..Default::default() };
        let err = RawWebSocket::connect("127.0.0.1", "x.test", Duration::from_secs(5), "/apiws", &options)
            .await
            .err()
            .unwrap();
        assert!(err.is_redirect());
        match err {
            WsError::Handshake { location, status_code, .. } => {
                assert_eq!(status_code, 302);
                assert_eq!(location.as_deref(), Some("https://other.test/"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_response_is_a_handshake_error() {
        let port = local_server(|mut stream| async move {
            let _ = read_request(&mut stream).await;
        })
        .await;
        let options = ConnectOptions { secure: false, port: Some(port), ..Default::default() };
        let err = RawWebSocket::connect("127.0.0.1", "x.test", Duration::from_secs(5), "/apiws", &options)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, WsError::Handshake { status_code: 0, .. }));
    }

    #[tokio::test]
    async fn silent_server_times_out_the_upgrade() {
        let port = local_server(|mut stream| async move {
            let _ = read_request(&mut stream).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        let options = ConnectOptions { secure: false, port: Some(port), ..Default::default() };
        let err = RawWebSocket::connect("127.0.0.1", "x.test", Duration::from_millis(200), "/apiws", &options)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, WsError::Timeout));
    }

    #[tokio::test]
    async fn liveness_detects_remote_close() {
        let (client, server) = duplex(1024);
        let (r, w) = tokio::io::split(client);
        let ws = RawWebSocket::from_parts(Box::new(r), Box::new(w));
        assert!(ws.is_alive());
        drop(server);
        assert!(!ws.is_alive());
    }

    #[tokio::test]
    async fn close_is_idempotent_and_sends_close_frame() {
        let (client, mut server) = duplex(1024);
        let (r, w) = tokio::io::split(client);
        let ws = RawWebSocket::from_parts(Box::new(r), Box::new(w));
        ws.close().await;
        ws.close().await;
        assert!(!ws.is_alive());
        let mut header = [0u8; 2];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x80 | OP_CLOSE);
    }
}
