use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::cf_h2::bridge_h2;
use crate::config::ProxyConfig;
use crate::crypto::AesCtr;
use crate::fake_tls::{ClientReader, ClientWriter};
use crate::pool::{worker_path, CfWorkerPool};
use crate::proxy::Shared;
use crate::stats::{add, inc, stats};
use crate::utils::{
    dc_default_ip, dc_test_ip, human_bytes, PROTO_ABRIDGED_INT, PROTO_INTERMEDIATE_INT,
    PROTO_PADDED_INTERMEDIATE_INT,
};
use crate::ws::{ConnectOptions, RawWebSocket, WsError};

const TCP_BACKOFF_INITIAL: f64 = 30.0;
const TCP_BACKOFF_MAX: f64 = 3600.0;

pub struct CryptoCtx {
    pub clt_dec: AesCtr,
    pub clt_enc: AesCtr,
    pub tg_enc: AesCtr,
    pub tg_dec: AesCtr,
}

enum Next {
    NeedMore,
    Disable,
    Len(usize),
}

pub struct MsgSplitter {
    proto: u32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

impl MsgSplitter {
    pub fn new(proto: u32) -> Self {
        Self { proto, cipher_buf: Vec::new(), plain_buf: Vec::new(), disabled: false }
    }

    pub fn split(&mut self, chunk: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }
        self.cipher_buf.extend_from_slice(chunk);
        self.plain_buf.extend_from_slice(plain);

        let mut parts = Vec::new();
        let mut offset = 0;
        let buf_len = self.cipher_buf.len();
        while offset < buf_len {
            match self.next_packet_len(offset, buf_len - offset) {
                Next::NeedMore => break,
                Next::Disable => {
                    parts.push(self.cipher_buf[offset..].to_vec());
                    offset = buf_len;
                    self.disabled = true;
                    break;
                }
                Next::Len(len) => {
                    parts.push(self.cipher_buf[offset..offset + len].to_vec());
                    offset += len;
                }
            }
        }
        if offset > 0 {
            self.cipher_buf.drain(..offset);
            self.plain_buf.drain(..offset);
        }
        parts
    }

    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return Vec::new();
        }
        self.plain_buf.clear();
        vec![std::mem::take(&mut self.cipher_buf)]
    }

    fn next_packet_len(&self, offset: usize, avail: usize) -> Next {
        if avail == 0 {
            return Next::NeedMore;
        }
        match self.proto {
            PROTO_ABRIDGED_INT => self.next_abridged_len(offset, avail),
            PROTO_INTERMEDIATE_INT | PROTO_PADDED_INTERMEDIATE_INT => {
                self.next_intermediate_len(offset, avail)
            }
            _ => Next::Disable,
        }
    }

    fn next_abridged_len(&self, offset: usize, avail: usize) -> Next {
        let first = self.plain_buf[offset];
        let (payload_len, header_len) = if first == 0x7F || first == 0xFF {
            if avail < 4 {
                return Next::NeedMore;
            }
            let b = &self.plain_buf[offset + 1..offset + 4];
            ((u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize) * 4, 4)
        } else {
            (((first & 0x7F) as usize) * 4, 1)
        };
        if payload_len == 0 {
            return Next::Disable;
        }
        let packet_len = header_len + payload_len;
        if avail < packet_len {
            return Next::NeedMore;
        }
        Next::Len(packet_len)
    }

    fn next_intermediate_len(&self, offset: usize, avail: usize) -> Next {
        if avail < 4 {
            return Next::NeedMore;
        }
        let b = &self.plain_buf[offset..offset + 4];
        let payload_len = (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x7FFF_FFFF) as usize;
        if payload_len == 0 {
            return Next::Disable;
        }
        let packet_len = 4 + payload_len;
        if avail < packet_len {
            return Next::NeedMore;
        }
        Next::Len(packet_len)
    }
}

#[derive(Default)]
struct BackoffState {
    failures: HashMap<(String, u16), u32>,
    retry_after: HashMap<(String, u16), Instant>,
    connecting: HashSet<(String, u16)>,
}

#[derive(Default)]
pub struct TcpBackoff {
    state: Mutex<BackoffState>,
}

pub fn backoff_delay(failures: u32) -> f64 {
    (TCP_BACKOFF_INITIAL * 2f64.powi(failures.saturating_sub(1).min(7) as i32)).min(TCP_BACKOFF_MAX)
}

struct ConnectingGuard<'a> {
    backoff: &'a TcpBackoff,
    key: (String, u16),
}

impl Drop for ConnectingGuard<'_> {
    fn drop(&mut self) {
        self.backoff.state.lock().connecting.remove(&self.key);
    }
}

impl TcpBackoff {
    pub fn reset(&self) {
        let mut state = self.state.lock();
        state.failures.clear();
        state.retry_after.clear();
        state.connecting.clear();
    }

    pub fn failures(&self, dst: &str, port: u16) -> u32 {
        self.state.lock().failures.get(&(dst.to_string(), port)).copied().unwrap_or(0)
    }

    pub fn retry_after(&self, dst: &str, port: u16) -> Option<Instant> {
        self.state.lock().retry_after.get(&(dst.to_string(), port)).copied()
    }

    pub fn is_connecting(&self) -> bool {
        !self.state.lock().connecting.is_empty()
    }

    fn begin(&self, key: &(String, u16)) -> Option<ConnectingGuard<'_>> {
        let mut state = self.state.lock();
        if state.connecting.contains(key) {
            return None;
        }
        if let Some(after) = state.retry_after.get(key) {
            if Instant::now() < *after {
                return None;
            }
        }
        state.connecting.insert(key.clone());
        Some(ConnectingGuard { backoff: self, key: key.clone() })
    }

    fn record_failure(&self, key: &(String, u16)) -> f64 {
        let mut state = self.state.lock();
        let failures = state.failures.get(key).copied().unwrap_or(0) + 1;
        state.failures.insert(key.clone(), failures);
        let delay = backoff_delay(failures);
        state.retry_after.insert(key.clone(), Instant::now() + Duration::from_secs_f64(delay));
        delay
    }

    fn record_success(&self, key: &(String, u16)) {
        let mut state = self.state.lock();
        state.failures.remove(key);
        state.retry_after.remove(key);
    }
}

pub struct FallbackRequest<'a> {
    pub relay_init: &'a [u8],
    pub label: &'a str,
    pub dc: i32,
    pub is_test_dc: bool,
    pub is_media: bool,
    pub proto_tag: [u8; 4],
}

pub async fn do_fallback(
    shared: &Arc<Shared>,
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    ctx: &mut CryptoCtx,
    mut splitter: Option<MsgSplitter>,
    request: &FallbackRequest<'_>,
) -> bool {
    let config = &shared.config;
    let fallback_dst = if request.is_test_dc { dc_test_ip(request.dc) } else { dc_default_ip(request.dc) };
    let use_cf = config.fallback_cfproxy && !request.is_test_dc;
    let has_workers = !config.cfproxy_worker_domains.is_empty();

    let mut methods: Vec<&str> = Vec::new();
    if has_workers && fallback_dst.is_some() {
        methods.push("cf_worker");
    }
    if use_cf {
        methods.push("cf");
    }
    if fallback_dst.is_some() {
        methods.push("tcp");
    }

    for method in methods {
        let ok = match method {
            "cf_worker" => {
                let dst = fallback_dst.unwrap_or_default();
                cfproxy_worker_fallback(shared, reader, writer, ctx, request, dst).await
            }
            "cf" => {
                if request.is_media {
                    if let Some(pool) = &shared.h2_pool {
                        if let Some(channel) = pool.open(request.dc, request.label).await {
                            inc(&stats().connections_h2);
                            inc(&stats().connections_cfproxy);
                            bridge_h2(reader, writer, channel, ctx, request.proto_tag).await;
                            return true;
                        }
                    }
                }
                cfproxy_fallback(shared, reader, writer, ctx, request, splitter.take()).await
            }
            _ => {
                let dst = fallback_dst.unwrap_or_default();
                tcp_fallback(shared, reader, writer, ctx, request, dst, 443).await
            }
        };
        if ok {
            return true;
        }
    }
    false
}

async fn cfproxy_worker_fallback(
    shared: &Arc<Shared>,
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    ctx: &mut CryptoCtx,
    request: &FallbackRequest<'_>,
    fallback_dst: &str,
) -> bool {
    let media_tag = if request.is_media { " media" } else { "" };
    let worker_domains = &shared.config.cfproxy_worker_domains;
    if worker_domains.is_empty() {
        return false;
    }
    let (dc, label) = (request.dc, request.label);
    let pooled = if request.is_test_dc {
        None
    } else {
        shared.cf_worker_pool.get(dc, fallback_dst, worker_domains)
    };
    let ws = if let Some((ws, domain)) = pooled {
        log::info!("[{label}] DC{dc}{media_tag} -> CF worker pool hit via {domain} for {fallback_dst}");
        ws
    } else {
        let path = worker_path(fallback_dst, dc);
        let mut found = None;
        for domain in shared.cf_worker_pool.available_domains(worker_domains) {
            log::info!("[{label}] DC{dc}{media_tag} -> trying CF worker {domain} for {fallback_dst}");
            let options = connect_options(&shared.config, None);
            match shared.dialer.dial(&domain, &domain, Duration::from_secs(10), &path, options).await {
                Ok(ws) => {
                    found = Some(ws);
                    break;
                }
                Err(err) => {
                    shared.cf_worker_pool.report_failure(&domain, &err);
                    log::warn!("[{label}] DC{dc}{media_tag} CF worker {domain} failed: {err:?}");
                }
            }
        }
        match found {
            Some(ws) => ws,
            None => return false,
        }
    };
    inc(&stats().connections_cfproxy);
    if let Err(err) = ws.send(request.relay_init).await {
        log::warn!("[{label}] DC{dc}{media_tag} CF worker init failed: {err:?}");
        return false;
    }
    bridge_ws_reencrypt(reader, writer, &ws, label, ctx, Some(dc), request.is_media, None).await;
    true
}

fn connect_options(config: &ProxyConfig, sni: Option<String>) -> ConnectOptions {
    ConnectOptions {
        sni,
        secure: !config.disable_secure,
        port: None,
        buffer_size: config.buffer_size,
    }
}

async fn cfproxy_fallback(
    shared: &Arc<Shared>,
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    ctx: &mut CryptoCtx,
    request: &FallbackRequest<'_>,
    splitter: Option<MsgSplitter>,
) -> bool {
    let media_tag = if request.is_media { " media" } else { "" };
    let (dc, label) = (request.dc, request.label);
    log::info!("[{label}] DC{dc}{media_tag} -> trying CF proxy");
    let started = Instant::now();
    let mut chosen: Option<(RawWebSocket, String)> = None;
    for base_domain in shared.balancer.get_domains_for_dc(dc) {
        let domain = format!("kws{dc}.{base_domain}");
        let options = connect_options(&shared.config, None);
        match shared.dialer.dial(&domain, &domain, Duration::from_secs(10), "/apiws", options).await {
            Ok(ws) => {
                chosen = Some((ws, base_domain));
                break;
            }
            Err(err) => log::warn!("[{label}] DC{dc}{media_tag} CF proxy failed: {err:?}"),
        }
    }
    let Some((ws, base_domain)) = chosen else { return false };
    log::debug!(
        "[{label}] WS CONNECT DC{dc}{media_tag} route=cf setup_ms={:.0}",
        started.elapsed().as_secs_f64() * 1000.0
    );
    if shared.balancer.update_domain_for_dc(dc, &base_domain) {
        log::info!("[{label}] Switched active CF domain");
    }
    inc(&stats().connections_cfproxy);
    if let Err(err) = ws.send(request.relay_init).await {
        log::warn!("[{label}] DC{dc}{media_tag} CF proxy init failed: {err:?}");
        return false;
    }
    bridge_ws_reencrypt(reader, writer, &ws, label, ctx, Some(dc), request.is_media, splitter).await;
    true
}

async fn tcp_fallback(
    shared: &Arc<Shared>,
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    ctx: &mut CryptoCtx,
    request: &FallbackRequest<'_>,
    dst: &str,
    port: u16,
) -> bool {
    let key = (dst.to_string(), port);
    let label = request.label;
    let Some(guard) = shared.tcp_backoff.begin(&key) else {
        log::debug!("[{label}] TCP fallback to {dst}:{port} skipped (backoff or connecting)");
        return false;
    };
    log::info!("[{label}] TCP fallback to {dst}:{port}");
    let attempt = async {
        let mut remote = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((dst, port)))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        remote.write_all(request.relay_init).await?;
        remote.flush().await?;
        Ok::<_, std::io::Error>(remote)
    }
    .await;
    drop(guard);
    let remote = match attempt {
        Ok(remote) => remote,
        Err(err) => {
            let delay = shared.tcp_backoff.record_failure(&key);
            log::warn!("[{label}] TCP fallback to {dst}:{port} failed: {err:?}; retry in {delay:.0}s");
            return false;
        }
    };
    shared.tcp_backoff.record_success(&key);
    inc(&stats().connections_tcp_fallback);
    bridge_tcp_reencrypt(reader, writer, remote, label, ctx).await;
    true
}

fn describe(err: &dyn std::fmt::Display) -> String {
    err.to_string()
}

pub async fn bridge_ws_reencrypt(
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    ws: &RawWebSocket,
    label: &str,
    ctx: &mut CryptoCtx,
    dc: Option<i32>,
    is_media: bool,
    splitter: Option<MsgSplitter>,
) {
    let dc_tag = match dc {
        Some(dc) if dc != 0 => format!("DC{dc}{}", if is_media { "m" } else { "" }),
        _ => "DC?".to_string(),
    };
    let up_bytes = AtomicU64::new(0);
    let down_bytes = AtomicU64::new(0);
    let up_packets = AtomicU64::new(0);
    let down_packets = AtomicU64::new(0);
    let close_reason = Mutex::new(String::from("normal"));
    let started = Instant::now();

    let CryptoCtx { clt_dec, clt_enc, tg_enc, tg_dec } = ctx;

    let tcp_to_ws = async {
        let mut splitter = splitter;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) => {
                    if let Some(sp) = splitter.as_mut() {
                        if let Some(tail) = sp.flush().into_iter().next() {
                            if let Err(err) = ws.send(&tail).await {
                                *close_reason.lock() = format!("client: {}", describe(&err));
                            }
                        }
                    }
                    break;
                }
                Ok(n) => n,
                Err(err) => {
                    *close_reason.lock() = format!("client: {:?}", err.kind());
                    break;
                }
            };
            add(&stats().bytes_up, n as u64);
            up_bytes.fetch_add(n as u64, Ordering::Relaxed);
            up_packets.fetch_add(1, Ordering::Relaxed);
            let plain = clt_dec.update(&buf[..n]);
            let chunk = tg_enc.update(&plain);
            let result = match splitter.as_mut() {
                Some(sp) => {
                    let parts = sp.split(&chunk, &plain);
                    match parts.len() {
                        0 => continue,
                        1 => ws.send(&parts[0]).await,
                        _ => ws.send_batch(&parts).await,
                    }
                }
                None => ws.send(&chunk).await,
            };
            if let Err(err) = result {
                *close_reason.lock() = format!("client: {}", describe(&err));
                break;
            }
        }
    };

    let ws_to_tcp = async {
        loop {
            match ws.recv().await {
                Ok(Some(data)) => {
                    let n = data.len() as u64;
                    add(&stats().bytes_down, n);
                    down_bytes.fetch_add(n, Ordering::Relaxed);
                    down_packets.fetch_add(1, Ordering::Relaxed);
                    let plain = tg_dec.update(&data);
                    let out = clt_enc.update(&plain);
                    if let Err(err) = writer.write_all(&out).await {
                        *close_reason.lock() = format!("upstream: {:?}", err.kind());
                        break;
                    }
                }
                Ok(None) => {
                    let mut reason = close_reason.lock();
                    if *reason == "normal" {
                        *reason = "upstream: ws_close".to_string();
                    }
                    break;
                }
                Err(WsError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    *close_reason.lock() = "upstream: tcp_reset".to_string();
                    break;
                }
                Err(err) => {
                    *close_reason.lock() = format!("upstream: {}", describe(&err));
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = tcp_to_ws => {}
        _ = ws_to_tcp => {}
    }

    log::info!(
        "[{label}] {dc_tag} WS session closed ({}): ^{} ({} pkts) v{} ({} pkts) in {:.1}s",
        close_reason.lock(),
        human_bytes(up_bytes.load(Ordering::Relaxed)),
        up_packets.load(Ordering::Relaxed),
        human_bytes(down_bytes.load(Ordering::Relaxed)),
        down_packets.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64()
    );
    ws.close().await;
    writer.shutdown().await;
}

pub async fn bridge_tcp_reencrypt(
    reader: &mut ClientReader,
    writer: &mut ClientWriter,
    remote: TcpStream,
    label: &str,
    ctx: &mut CryptoCtx,
) {
    let (mut remote_read, mut remote_write) = remote.into_split();
    let CryptoCtx { clt_dec, clt_enc, tg_enc, tg_dec } = ctx;

    let up = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    add(&stats().bytes_up, n as u64);
                    let plain = clt_dec.update(&buf[..n]);
                    let out = tg_enc.update(&plain);
                    if let Err(err) = remote_write.write_all(&out).await {
                        log::debug!("[{label}] forward ended: {err:?}");
                        break;
                    }
                }
                Err(err) => {
                    log::debug!("[{label}] forward ended: {err:?}");
                    break;
                }
            }
        }
    };
    let down = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match remote_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    add(&stats().bytes_down, n as u64);
                    let plain = tg_dec.update(&buf[..n]);
                    let out = clt_enc.update(&plain);
                    if let Err(err) = writer.write_all(&out).await {
                        log::debug!("[{label}] forward ended: {err:?}");
                        break;
                    }
                }
                Err(err) => {
                    log::debug!("[{label}] forward ended: {err:?}");
                    break;
                }
            }
        }
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    writer.shutdown().await;
}

pub fn pool_for_tests(_pool: &CfWorkerPool) {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_init() -> Vec<u8> {
        let mut v = vec![0u8; 64];
        rand::thread_rng().fill(&mut v[..]);
        v
    }

    fn encryptor(init: &[u8]) -> AesCtr {
        let mut enc = AesCtr::new(&init[8..40], &init[40..56]);
        enc.update(&[0u8; 64]);
        enc
    }

    fn abridged(payload: &[u8]) -> Vec<u8> {
        let words = payload.len() / 4;
        let mut out = if words < 0x7f {
            vec![words as u8]
        } else {
            let mut v = vec![0x7f];
            v.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
            v
        };
        out.extend_from_slice(payload);
        out
    }

    fn intermediate(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn run_split(proto: u32, packets: &[Vec<u8>], chunk_sizes: Option<&[usize]>) -> (Vec<u8>, Vec<Vec<u8>>) {
        let init = random_init();
        let mut splitter = MsgSplitter::new(proto);
        let mut enc = encryptor(&init);
        let plain: Vec<u8> = packets.concat();
        let stream = enc.update(&plain);
        let mut chunks = Vec::new();
        match chunk_sizes {
            None => chunks.push(stream.clone()),
            Some(sizes) => {
                let mut offset = 0;
                for size in sizes {
                    let end = (offset + size).min(stream.len());
                    chunks.push(stream[offset..end].to_vec());
                    offset = end;
                }
                if offset < stream.len() {
                    chunks.push(stream[offset..].to_vec());
                }
            }
        }
        let mut parts = Vec::new();
        let mut offset = 0;
        for chunk in &chunks {
            parts.extend(splitter.split(chunk, &plain[offset..offset + chunk.len()]));
            offset += chunk.len();
        }
        (stream, parts)
    }

    #[test]
    fn abridged_stream_splits_into_packets() {
        let packets = vec![abridged(&[b'a'; 4]), abridged(&[b'b'; 16]), abridged(&[b'c'; 40])];
        let (stream, parts) = run_split(PROTO_ABRIDGED_INT, &packets, None);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts.concat(), stream);
        assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![5, 17, 41]);
    }

    #[test]
    fn intermediate_stream_splits_into_packets() {
        let packets = vec![intermediate(&[b'a'; 8]), intermediate(&[b'b'; 12])];
        let (stream, parts) = run_split(PROTO_INTERMEDIATE_INT, &packets, None);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.concat(), stream);
    }

    #[test]
    fn padded_intermediate_uses_intermediate_framing() {
        let packets = vec![intermediate(&[b'z'; 20])];
        let (stream, parts) = run_split(PROTO_PADDED_INTERMEDIATE_INT, &packets, None);
        assert_eq!(parts, vec![stream]);
    }

    #[test]
    fn partial_packet_is_buffered_until_complete() {
        let packets = vec![abridged(&[b'a'; 20])];
        let sizes = vec![1usize; packets[0].len() - 1];
        let (stream, parts) = run_split(PROTO_ABRIDGED_INT, &packets, Some(&sizes));
        assert_eq!(parts, vec![stream]);
    }

    #[test]
    fn split_preserves_stream_across_arbitrary_chunking() {
        let packets: Vec<Vec<u8>> = (0..8u8).map(|i| intermediate(&[i; 16])).collect();
        let (stream, parts) = run_split(PROTO_INTERMEDIATE_INT, &packets, Some(&[7, 3, 50, 11]));
        assert_eq!(parts.concat(), stream);
        assert_eq!(parts.len(), 8);
    }

    #[test]
    fn empty_chunk_yields_nothing() {
        let mut splitter = MsgSplitter::new(PROTO_INTERMEDIATE_INT);
        assert!(splitter.split(&[], &[]).is_empty());
    }

    #[test]
    fn zero_length_packet_disables_splitting() {
        let init = random_init();
        let mut splitter = MsgSplitter::new(PROTO_INTERMEDIATE_INT);
        let mut enc = encryptor(&init);
        let mut plain = 0u32.to_le_bytes().to_vec();
        plain.extend_from_slice(b"tail");
        let stream = enc.update(&plain);
        assert_eq!(splitter.split(&stream, &plain), vec![stream.clone()]);
        assert_eq!(splitter.split(b"raw", b"raw"), vec![b"raw".to_vec()]);
    }

    #[test]
    fn unknown_protocol_passes_through() {
        let mut splitter = MsgSplitter::new(0x1234_5678);
        assert_eq!(splitter.split(b"abcdef", b"abcdef"), vec![b"abcdef".to_vec()]);
    }

    #[test]
    fn flush_returns_buffered_tail_once() {
        let init = random_init();
        let mut splitter = MsgSplitter::new(PROTO_INTERMEDIATE_INT);
        let mut enc = encryptor(&init);
        let plain = intermediate(&[b'x'; 32])[..10].to_vec();
        let partial = enc.update(&plain);
        assert!(splitter.split(&partial, &plain).is_empty());
        assert_eq!(splitter.flush(), vec![partial]);
        assert!(splitter.flush().is_empty());
    }

    #[test]
    fn extended_and_quick_ack_headers_can_cross_chunk_boundaries() {
        type Framer = fn(&[u8]) -> Vec<u8>;
        let cases: [(u32, Framer); 3] = [
            (PROTO_ABRIDGED_INT, abridged),
            (PROTO_INTERMEDIATE_INT, intermediate),
            (PROTO_PADDED_INTERMEDIATE_INT, intermediate),
        ];
        for (proto, frame) in cases {
            for size in [16usize, 512, 65536] {
                let mut packet = frame(&vec![b'p'; size]);
                let flag_index = if proto == PROTO_ABRIDGED_INT { 0 } else { 3 };
                packet[flag_index] |= 0x80;
                let packets = vec![packet.clone(), frame(&[b't'; 8])];
                for header_split in [1usize, 2, 3] {
                    let (stream, parts) = run_split(
                        proto,
                        &packets,
                        Some(&[header_split, 1, 11, size - 8]),
                    );
                    assert_eq!(
                        parts,
                        vec![stream[..packet.len()].to_vec(), stream[packet.len()..].to_vec()],
                        "proto={proto:#x} size={size} split={header_split}"
                    );
                }
            }
        }
    }

    #[test]
    fn backoff_delay_doubles_and_caps() {
        let delays: Vec<f64> = (1..=10).map(backoff_delay).collect();
        assert_eq!(delays, vec![30.0, 60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0, 3600.0]);
    }

    #[test]
    fn backoff_tracks_failure_success_and_connecting() {
        let backoff = TcpBackoff::default();
        let key = ("192.0.2.1".to_string(), 443u16);
        let guard = backoff.begin(&key).unwrap();
        assert!(backoff.begin(&key).is_none());
        assert!(backoff.is_connecting());
        drop(guard);
        assert!(!backoff.is_connecting());
        assert_eq!(backoff.record_failure(&key), 30.0);
        assert_eq!(backoff.record_failure(&key), 60.0);
        assert!(backoff.begin(&key).is_none());
        assert!(backoff.begin(&("192.0.2.2".to_string(), 443)).is_some());
        assert!(backoff.begin(&("192.0.2.1".to_string(), 80)).is_some());
        backoff.record_success(&key);
        assert_eq!(backoff.failures("192.0.2.1", 443), 0);
        assert!(backoff.retry_after("192.0.2.1", 443).is_none());
        assert!(backoff.begin(&key).is_some());
    }
}
