use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stats::{inc, stats};

type HmacSha256 = Hmac<Sha256>;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

pub const CLIENT_RANDOM_OFFSET: usize = 11;
pub const CLIENT_RANDOM_LEN: usize = 32;
pub const SESSION_ID_OFFSET: usize = 44;
pub const SESSION_ID_LEN: usize = 32;
pub const TIMESTAMP_TOLERANCE: i64 = 120;
pub const TLS_APPDATA_MAX: usize = 16384;

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
const SH_RANDOM_OFF: usize = 11;
const SH_SESSID_OFF: usize = 44;
const SH_PUBKEY_OFF: usize = 89;

fn server_hello_template() -> Vec<u8> {
    let mut template = Vec::with_capacity(127);
    template.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x7a]);
    template.extend_from_slice(&[0x02, 0x00, 0x00, 0x76]);
    template.extend_from_slice(&[0x03, 0x03]);
    template.extend_from_slice(&[0u8; 32]);
    template.push(0x20);
    template.extend_from_slice(&[0u8; 32]);
    template.extend_from_slice(&[0x13, 0x01, 0x00]);
    template.extend_from_slice(&[0x00, 0x2e]);
    template.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    template.extend_from_slice(&[0u8; 32]);
    template.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    template
}

fn hmac_sha256(secret: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct ClientHello {
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    pub session_id: [u8; SESSION_ID_LEN],
    pub timestamp: u32,
}

pub fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<ClientHello> {
    verify_client_hello_at(data, secret, now_secs())
}

pub fn verify_client_hello_at(data: &[u8], secret: &[u8], now: i64) -> Option<ClientHello> {
    let n = data.len();
    if n < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }
    let mut client_random = [0u8; CLIENT_RANDOM_LEN];
    client_random.copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].fill(0);
    let expected = hmac_sha256(secret, &[&zeroed]);

    let mut diff = 0u8;
    for i in 0..28 {
        diff |= expected[i] ^ client_random[i];
    }
    if diff != 0 {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes);
    if (now - timestamp as i64).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; SESSION_ID_LEN];
    if n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }
    Some(ClientHello { client_random, session_id, timestamp })
}

pub fn build_server_hello(secret: &[u8], client_random: &[u8], session_id: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut hello = server_hello_template();
    hello[SH_SESSID_OFF..SH_SESSID_OFF + 32].copy_from_slice(session_id);
    let mut pubkey = [0u8; 32];
    rng.fill(&mut pubkey);
    hello[SH_PUBKEY_OFF..SH_PUBKEY_OFF + 32].copy_from_slice(&pubkey);

    let encrypted_size: usize = rng.gen_range(1900..=2100);
    let mut encrypted = vec![0u8; encrypted_size];
    rng.fill(&mut encrypted[..]);

    let mut response = hello;
    response.extend_from_slice(&CCS_FRAME);
    response.extend_from_slice(&[0x17, 0x03, 0x03]);
    response.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    response.extend_from_slice(&encrypted);

    let server_random = hmac_sha256(secret, &[client_random, &response]);
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    response
}

pub fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    for chunk in data.chunks(TLS_APPDATA_MAX) {
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

pub struct FakeTlsReader<R> {
    inner: R,
    read_left: usize,
}

impl<R: AsyncRead + Unpin> FakeTlsReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, read_left: 0 }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.read_left > 0 {
            let want = self.read_left.min(buf.len());
            let n = self.inner.read(&mut buf[..want]).await?;
            self.read_left -= n;
            return Ok(n);
        }
        loop {
            let mut header = [0u8; 5];
            match self.inner.read_exact(&mut header).await {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(err) => return Err(err),
            }
            let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[0] == TLS_RECORD_CCS {
                if record_len > 0 {
                    let mut skip = vec![0u8; record_len];
                    self.inner.read_exact(&mut skip).await?;
                }
                continue;
            }
            if header[0] != TLS_RECORD_APPDATA {
                return Ok(0);
            }
            let want = record_len.min(65536).min(buf.len());
            if want == 0 {
                return Ok(0);
            }
            let n = self.inner.read(&mut buf[..want]).await?;
            if n == 0 {
                return Ok(0);
            }
            self.read_left = record_len - n;
            return Ok(n);
        }
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += n;
        }
        Ok(())
    }
}

pub struct FakeTlsWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> FakeTlsWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(&wrap_tls_record(data)).await?;
        self.inner.flush().await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

pub enum ClientReader {
    Plain(tokio::net::tcp::OwnedReadHalf),
    Tls(FakeTlsReader<tokio::net::tcp::OwnedReadHalf>),
}

impl ClientReader {
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientReader::Plain(r) => r.read(buf).await,
            ClientReader::Tls(r) => r.read(buf).await,
        }
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            ClientReader::Plain(r) => r.read_exact(buf).await.map(|_| ()),
            ClientReader::Tls(r) => r.read_exact(buf).await,
        }
    }
}

pub enum ClientWriter {
    Plain(tokio::net::tcp::OwnedWriteHalf),
    Tls(FakeTlsWriter<tokio::net::tcp::OwnedWriteHalf>),
}

impl ClientWriter {
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            ClientWriter::Plain(w) => {
                w.write_all(data).await?;
                w.flush().await
            }
            ClientWriter::Tls(w) => w.write_all(data).await,
        }
    }

    pub async fn shutdown(&mut self) {
        let _ = match self {
            ClientWriter::Plain(w) => w.shutdown().await,
            ClientWriter::Tls(w) => w.shutdown().await,
        };
    }
}

pub async fn proxy_to_masking_domain(
    client: &mut TcpStream,
    initial_data: &[u8],
    domain: &str,
    label: &str,
) {
    let upstream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((domain, 443))).await;
    let mut upstream = match upstream {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            log::warn!("[{label}] masking: cannot connect to {domain}:443: {err:?}");
            return;
        }
        Err(_) => {
            log::warn!("[{label}] masking: cannot connect to {domain}:443: timed out");
            return;
        }
    };
    log::debug!("[{label}] masking -> {domain}:443");
    inc(&stats().connections_masked);
    if !initial_data.is_empty() && upstream.write_all(initial_data).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(client, &mut upstream).await;
}

#[cfg(test)]
pub fn build_client_hello_for_tests(secret: &[u8], timestamp: u32, session_id: [u8; 32]) -> Vec<u8> {
    let mut body = vec![0u8; 517];
    body[0] = TLS_RECORD_HANDSHAKE;
    body[1] = 0x03;
    body[2] = 0x01;
    let record_len = (body.len() - 5) as u16;
    body[3..5].copy_from_slice(&record_len.to_be_bytes());
    body[5] = 0x01;
    body[43] = 0x20;
    body[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&session_id);
    let digest = hmac_sha256(secret, &[&body]);
    let mut client_random = digest;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        client_random[28 + i] = digest[28 + i] ^ ts[i];
    }
    body[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].copy_from_slice(&client_random);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const SECRET: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];

    fn client_hello(secret: &[u8], timestamp: u32, session_id: [u8; 32]) -> Vec<u8> {
        let mut body = vec![0u8; 517];
        body[0] = TLS_RECORD_HANDSHAKE;
        body[1] = 0x03;
        body[2] = 0x01;
        let record_len = (body.len() - 5) as u16;
        body[3..5].copy_from_slice(&record_len.to_be_bytes());
        body[5] = 0x01;
        body[43] = 0x20;
        body[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&session_id);
        let digest = hmac_sha256(secret, &[&body]);
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&digest);
        let ts = timestamp.to_le_bytes();
        for i in 0..4 {
            client_random[28 + i] = digest[28 + i] ^ ts[i];
        }
        body[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].copy_from_slice(&client_random);
        body
    }

    fn random_32() -> [u8; 32] {
        let mut out = [0u8; 32];
        rand::thread_rng().fill(&mut out);
        out
    }

    #[test]
    fn accepts_well_formed_hello() {
        let session_id = random_32();
        let now = now_secs() as u32;
        let hello = client_hello(&SECRET, now, session_id);
        let parsed = verify_client_hello(&hello, &SECRET).unwrap();
        assert_eq!(parsed.session_id, session_id);
        assert_eq!(parsed.timestamp, now);
        assert_eq!(parsed.client_random.len(), CLIENT_RANDOM_LEN);
    }

    #[test]
    fn rejects_wrong_secret() {
        let other: [u8; 16] = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00];
        let hello = client_hello(&SECRET, now_secs() as u32, random_32());
        assert!(verify_client_hello(&hello, &other).is_none());
    }

    #[test]
    fn rejects_stale_timestamp() {
        let stale = (now_secs() - 3600) as u32;
        let hello = client_hello(&SECRET, stale, random_32());
        assert!(verify_client_hello(&hello, &SECRET).is_none());
        assert!(verify_client_hello_at(&hello, &SECRET, stale as i64 + 60).is_some());
        assert!(verify_client_hello_at(&hello, &SECRET, stale as i64 + 121).is_none());
    }

    #[test]
    fn rejects_tampered_body() {
        let mut hello = client_hello(&SECRET, now_secs() as u32, random_32());
        hello[300] ^= 0xff;
        assert!(verify_client_hello(&hello, &SECRET).is_none());
    }

    #[test]
    fn rejects_short_and_non_handshake_records() {
        assert!(verify_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x10], &SECRET).is_none());
        let mut hello = client_hello(&SECRET, now_secs() as u32, random_32());
        hello[0] = 0x17;
        assert!(verify_client_hello(&hello, &SECRET).is_none());
        let mut hello = client_hello(&SECRET, now_secs() as u32, random_32());
        hello[5] = 0x02;
        assert!(verify_client_hello(&hello, &SECRET).is_none());
    }

    #[test]
    fn server_hello_echoes_session_id_and_binds_client_random() {
        let session_id = random_32();
        let client_random = random_32();
        let response = build_server_hello(&SECRET, &client_random, &session_id);
        assert_eq!(response[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(&response[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN], &session_id);
        let mut zeroed = response.clone();
        zeroed[11..43].fill(0);
        let expected = hmac_sha256(&SECRET, &[&client_random, &zeroed]);
        assert_eq!(&response[11..43], &expected);
    }

    #[test]
    fn server_hello_padding_length_varies() {
        let sizes: std::collections::HashSet<usize> = (0..40)
            .map(|_| build_server_hello(&SECRET, &random_32(), &random_32()).len())
            .collect();
        assert!(sizes.len() > 1);
    }

    #[test]
    fn server_hello_template_layout() {
        let template = server_hello_template();
        assert_eq!(template.len(), 127);
        assert_eq!(template[43], 0x20);
        assert_eq!(&template[121..], &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn short_payload_becomes_one_record() {
        assert_eq!(wrap_tls_record(b"hello"), b"\x17\x03\x03\x00\x05hello");
    }

    #[test]
    fn long_payload_is_chunked_to_record_limit() {
        let mut payload = vec![0u8; TLS_APPDATA_MAX + 100];
        rand::thread_rng().fill(&mut payload[..]);
        let wrapped = wrap_tls_record(&payload);
        let mut offset = 0;
        let mut joined = Vec::new();
        let mut count = 0;
        while offset < wrapped.len() {
            let len = u16::from_be_bytes([wrapped[offset + 3], wrapped[offset + 4]]) as usize;
            assert!(len <= TLS_APPDATA_MAX);
            joined.extend_from_slice(&wrapped[offset + 5..offset + 5 + len]);
            offset += 5 + len;
            count += 1;
        }
        assert_eq!(count, 2);
        assert_eq!(joined, payload);
    }

    #[test]
    fn empty_payload_produces_no_records() {
        assert!(wrap_tls_record(b"").is_empty());
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let (server, client) = tokio::join!(listener.accept(), connect);
        (server.unwrap().0, client.unwrap())
    }

    #[tokio::test]
    async fn reader_skips_ccs_and_reassembles_split_records() {
        let (server, mut client) = pair().await;
        let (read_half, _write_half) = server.into_split();
        let mut reader = FakeTlsReader::new(read_half);
        let mut wire = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        wire.extend_from_slice(&wrap_tls_record(b"hello "));
        wire.extend_from_slice(&wrap_tls_record(b"world"));
        client.write_all(&wire).await.unwrap();
        let mut buf = [0u8; 11];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[tokio::test]
    async fn reader_handles_partial_reads_inside_a_record() {
        let (server, mut client) = pair().await;
        let (read_half, _write_half) = server.into_split();
        let mut reader = FakeTlsReader::new(read_half);
        client.write_all(&wrap_tls_record(b"abcdefghij")).await.unwrap();
        let mut first = [0u8; 4];
        assert_eq!(reader.read(&mut first).await.unwrap(), 4);
        assert_eq!(&first, b"abcd");
        let mut rest = [0u8; 16];
        let n = reader.read(&mut rest).await.unwrap();
        assert_eq!(&rest[..n], b"efghij");
    }

    #[tokio::test]
    async fn reader_reports_eof_on_foreign_record_type_and_close() {
        let (server, mut client) = pair().await;
        let (read_half, _write_half) = server.into_split();
        let mut reader = FakeTlsReader::new(read_half);
        client.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);

        let (server, client) = pair().await;
        let (read_half, _write_half) = server.into_split();
        let mut reader = FakeTlsReader::new(read_half);
        drop(client);
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn writer_wraps_every_write_in_records() {
        let (server, mut client) = pair().await;
        let (_read_half, write_half) = server.into_split();
        let mut writer = FakeTlsWriter::new(write_half);
        writer.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"\x17\x03\x03\x00\x04ping");
    }
}
