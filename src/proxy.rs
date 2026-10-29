use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::balancer::Balancer;
use crate::bridge::{
    bridge_ws_reencrypt, do_fallback, CryptoCtx, FallbackRequest, MsgSplitter, TcpBackoff,
};
use crate::cf_h2::CfH2Pool;
use crate::config::{spawn_cfproxy_domain_refresh, ProxyConfig};
use crate::crypto::AesCtr;
use crate::fake_tls::{
    build_server_hello, proxy_to_masking_domain, verify_client_hello, ClientReader, ClientWriter,
    FakeTlsReader, FakeTlsWriter, TLS_RECORD_HANDSHAKE,
};
use crate::net::set_sock_opts;
use crate::pool::{CfWorkerPool, RealDialer, WsDialer, WsPool};
use crate::stats::{inc, stats};
use crate::utils::*;

const READ_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Shared {
    pub config: Arc<ProxyConfig>,
    pub balancer: Arc<Balancer>,
    pub ws_pool: Arc<WsPool>,
    pub cf_worker_pool: Arc<CfWorkerPool>,
    pub h2_pool: Option<Arc<CfH2Pool>>,
    pub tcp_backoff: TcpBackoff,
    pub dialer: Arc<dyn WsDialer>,
}

impl Shared {
    pub fn new(config: Arc<ProxyConfig>) -> Arc<Self> {
        Self::with_dialer(config, Arc::new(RealDialer))
    }

    pub fn with_dialer(config: Arc<ProxyConfig>, dialer: Arc<dyn WsDialer>) -> Arc<Self> {
        let balancer = Arc::new(Balancer::new());
        let h2_pool = config.h2_enabled().then(|| CfH2Pool::new(balancer.clone()));
        Arc::new(Self {
            ws_pool: WsPool::with_dialer(config.clone(), dialer.clone()),
            cf_worker_pool: CfWorkerPool::with_dialer(config.clone(), dialer.clone()),
            balancer,
            h2_pool,
            tcp_backoff: TcpBackoff::default(),
            dialer,
            config,
        })
    }
}

pub struct HandshakeInfo {
    pub dc: i32,
    pub is_media: bool,
    pub proto_tag: [u8; 4],
    pub prekey_iv: [u8; 48],
}

pub fn try_handshake(handshake: &[u8; 64], secret: &[u8]) -> Option<HandshakeInfo> {
    let mut prekey_iv = [0u8; 48];
    prekey_iv.copy_from_slice(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    let mut hasher = Sha256::new();
    hasher.update(&prekey_iv[..PREKEY_LEN]);
    hasher.update(secret);
    let key = hasher.finalize();
    let mut decryptor = AesCtr::new(&key, &prekey_iv[PREKEY_LEN..]);
    let decrypted = decryptor.update(handshake);

    let mut proto_tag = [0u8; 4];
    proto_tag.copy_from_slice(&decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]);
    if proto_tag != PROTO_TAG_ABRIDGED && proto_tag != PROTO_TAG_INTERMEDIATE && proto_tag != PROTO_TAG_SECURE {
        return None;
    }
    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]) as i32;
    Some(HandshakeInfo { dc: dc_idx.abs(), is_media: dc_idx < 0, proto_tag, prekey_iv })
}

pub fn generate_relay_init(proto_tag: [u8; 4], dc_idx: i16) -> [u8; 64] {
    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 64];
    loop {
        rng.fill(&mut rnd[..]);
        if rnd[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if RESERVED_STARTS.iter().any(|start| rnd[..4] == start[..]) {
            continue;
        }
        if rnd[4..8] == RESERVED_CONTINUE {
            continue;
        }
        break;
    }
    let mut encryptor = AesCtr::new(
        &rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
        &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN],
    );
    let mut tail_plain = [0u8; 8];
    tail_plain[..4].copy_from_slice(&proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    tail_plain[6] = rng.gen();
    tail_plain[7] = rng.gen();

    let encrypted_full = encryptor.update(&rnd);
    let mut result = rnd;
    for i in 0..8 {
        let keystream = encrypted_full[56 + i] ^ rnd[56 + i];
        result[PROTO_TAG_POS + i] = tail_plain[i] ^ keystream;
    }
    result
}

pub fn build_crypto_ctx(prekey_iv: &[u8; 48], secret: &[u8], relay_init: &[u8; 64]) -> CryptoCtx {
    let derive = |prekey: &[u8]| {
        let mut hasher = Sha256::new();
        hasher.update(prekey);
        hasher.update(secret);
        hasher.finalize()
    };
    let clt_dec_key = derive(&prekey_iv[..PREKEY_LEN]);
    let mut reversed = *prekey_iv;
    reversed.reverse();
    let clt_enc_key = derive(&reversed[..PREKEY_LEN]);

    let mut clt_dec = AesCtr::new(&clt_dec_key, &prekey_iv[PREKEY_LEN..]);
    let clt_enc = AesCtr::new(&clt_enc_key, &reversed[PREKEY_LEN..]);
    clt_dec.update(&ZERO_64);

    let relay_prekey_iv = &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut tg_enc = AesCtr::new(&relay_prekey_iv[..KEY_LEN], &relay_prekey_iv[KEY_LEN..]);
    let mut relay_reversed = [0u8; 48];
    relay_reversed.copy_from_slice(relay_prekey_iv);
    relay_reversed.reverse();
    let tg_dec = AesCtr::new(&relay_reversed[..KEY_LEN], &relay_reversed[KEY_LEN..]);
    tg_enc.update(&ZERO_64);

    CryptoCtx { clt_dec, clt_enc, tg_enc, tg_dec }
}

pub struct ClientInit {
    pub handshake: [u8; 64],
    pub reader: ClientReader,
    pub writer: ClientWriter,
    pub label: String,
}

async fn read_line_limited(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < 256 {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(line)
}

async fn timed<T>(future: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    match tokio::time::timeout(READ_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

pub async fn read_client_init(
    mut stream: TcpStream,
    secret: &[u8],
    mut label: String,
    config: &ProxyConfig,
) -> io::Result<Option<ClientInit>> {
    let masking = config.fake_tls_domain.as_str();
    if config.proxy_protocol {
        match timed(read_line_limited(&mut stream)).await {
            Ok(line) => {
                let text = String::from_utf8_lossy(&line).trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("{}:{}", parts[2], parts[4]);
                    }
                    log::debug!("[{label}] PROXY protocol: {text}");
                } else {
                    log::debug!("[{label}] expected PROXY header, got: {:?}", &text[..text.len().min(60)]);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                log::debug!("[{label}] disconnected during PROXY header");
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
    }

    let mut first = [0u8; 1];
    match timed(async { stream.read_exact(&mut first).await.map(|_| ()) }).await {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            log::debug!("[{label}] client disconnected before handshake");
            return Ok(None);
        }
        Err(err) => return Err(err),
    }

    if first[0] == TLS_RECORD_HANDSHAKE && !masking.is_empty() {
        let mut rest = [0u8; 4];
        if timed(async { stream.read_exact(&mut rest).await.map(|_| ()) }).await.is_err() {
            log::debug!("[{label}] incomplete TLS record header");
            return Ok(None);
        }
        let record_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        let mut body = vec![0u8; record_len];
        if timed(async { stream.read_exact(&mut body).await.map(|_| ()) }).await.is_err() {
            log::debug!("[{label}] incomplete TLS record body");
            return Ok(None);
        }
        let mut hello = Vec::with_capacity(5 + record_len);
        hello.push(first[0]);
        hello.extend_from_slice(&rest);
        hello.extend_from_slice(&body);

        let Some(parsed) = verify_client_hello(&hello, secret) else {
            log::debug!(
                "[{label}] Fake TLS verify failed (size={} rec={record_len}) -> masking",
                hello.len()
            );
            proxy_to_masking_domain(&mut stream, &hello, masking, &label).await;
            return Ok(None);
        };
        log::debug!("[{label}] Fake TLS handshake ok (ts={})", parsed.timestamp);
        let server_hello = build_server_hello(secret, &parsed.client_random, &parsed.session_id);
        stream.write_all(&server_hello).await?;
        stream.flush().await?;

        let (read_half, write_half) = stream.into_split();
        let mut reader = FakeTlsReader::new(read_half);
        let mut handshake = [0u8; 64];
        match timed(reader.read_exact(&mut handshake)).await {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                log::debug!("[{label}] incomplete obfs2 init inside TLS");
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
        return Ok(Some(ClientInit {
            handshake,
            reader: ClientReader::Tls(reader),
            writer: ClientWriter::Tls(FakeTlsWriter::new(write_half)),
            label,
        }));
    }

    if !masking.is_empty() {
        log::debug!("[{label}] non-TLS byte 0x{:02X} -> HTTP redirect", first[0]);
        let redirect = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{masking}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(redirect.as_bytes()).await?;
        stream.flush().await?;
        let _ = stream.shutdown().await;
        let mut sink = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        })
        .await;
        return Ok(None);
    }

    let mut handshake = [0u8; 64];
    handshake[0] = first[0];
    match timed(async { stream.read_exact(&mut handshake[1..]).await.map(|_| ()) }).await {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            log::debug!("[{label}] client disconnected before handshake");
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    let (read_half, write_half) = stream.into_split();
    Ok(Some(ClientInit {
        handshake,
        reader: ClientReader::Plain(read_half),
        writer: ClientWriter::Plain(write_half),
        label,
    }))
}

struct ActiveGuard;

impl ActiveGuard {
    fn new() -> Self {
        stats().connections_active.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        stats().connections_active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn handle_client(shared: Arc<Shared>, stream: TcpStream, secret: Vec<u8>) {
    inc(&stats().connections_total);
    let _active = ActiveGuard::new();
    let label = stream
        .peer_addr()
        .map(|a| format!("{}:{}", a.ip(), a.port()))
        .unwrap_or_else(|_| "?".to_string());
    set_sock_opts(&stream, shared.config.buffer_size);

    match handle_client_inner(&shared, stream, &secret, label.clone()).await {
        Ok(()) => {}
        Err(err) => match err.kind() {
            io::ErrorKind::TimedOut => log::warn!("[{label}] timeout during handshake"),
            io::ErrorKind::UnexpectedEof => log::debug!("[{label}] client disconnected"),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => {
                log::debug!("[{label}] connection reset")
            }
            _ => match err.raw_os_error() {
                Some(1236) => log::debug!("[{label}] connection aborted by local system"),
                _ => log::error!("[{label}] unexpected OS error: {err:?}"),
            },
        },
    }
}

async fn handle_client_inner(
    shared: &Arc<Shared>,
    stream: TcpStream,
    secret: &[u8],
    label: String,
) -> io::Result<()> {
    let config = &shared.config;
    let Some(init) = read_client_init(stream, secret, label, config).await? else {
        return Ok(());
    };
    let ClientInit { handshake, mut reader, mut writer, label } = init;

    let Some(info) = try_handshake(&handshake, secret) else {
        inc(&stats().connections_bad);
        log::warn!("[{label}] bad handshake (wrong secret or proto)");
        let mut sink = [0u8; 4096];
        while matches!(reader.read(&mut sink).await, Ok(n) if n > 0) {}
        return Ok(());
    };

    let mut dc = info.dc;
    let is_test_dc = config.force_test_dc || dc >= 10000;
    if dc >= 10000 {
        log::info!("[{label}] test DC{dc} -> DC{}", dc - 10000);
        dc -= 10000;
    }
    let proto_int = if info.proto_tag == PROTO_TAG_ABRIDGED {
        PROTO_ABRIDGED_INT
    } else if info.proto_tag == PROTO_TAG_INTERMEDIATE {
        PROTO_INTERMEDIATE_INT
    } else {
        PROTO_PADDED_INTERMEDIATE_INT
    };
    let dc_idx = if info.is_media { -dc } else { dc } as i16;
    let media_tag = if info.is_media { " media" } else { "" };
    log::debug!("[{label}] handshake ok: DC{dc}{media_tag} proto=0x{proto_int:08X}");

    let relay_init = generate_relay_init(info.proto_tag, dc_idx);
    let mut ctx = build_crypto_ctx(&info.prekey_iv, secret, &relay_init);

    let Some(ws) = shared.ws_pool.get(dc, info.is_media, is_test_dc) else {
        log::info!("[{label}] DC{dc}{media_tag} WS pool unavailable -> fallback");
        let request = FallbackRequest {
            relay_init: &relay_init,
            label: &label,
            dc,
            is_test_dc,
            is_media: info.is_media,
            proto_tag: info.proto_tag,
        };
        let splitter = Some(MsgSplitter::new(proto_int));
        if do_fallback(shared, &mut reader, &mut writer, &mut ctx, splitter, &request).await {
            log::info!("[{label}] DC{dc}{media_tag} fallback closed");
        } else {
            log::warn!("[{label}] DC{dc}{media_tag} no fallback available");
        }
        writer.shutdown().await;
        return Ok(());
    };

    log::info!("[{label}] DC{dc}{media_tag} -> WS pool hit");
    inc(&stats().connections_ws);
    log::debug!("[{label}] MsgSplitter activated for proto 0x{proto_int:08X}");
    if let Err(err) = ws.send(&relay_init).await {
        log::warn!("[{label}] DC{dc}{media_tag} WS init failed: {err:?}");
        return Ok(());
    }
    bridge_ws_reencrypt(
        &mut reader,
        &mut writer,
        &ws,
        &label,
        &mut ctx,
        Some(dc),
        info.is_media,
        Some(MsgSplitter::new(proto_int)),
    )
    .await;
    Ok(())
}

pub fn proxy_links(config: &ProxyConfig) -> (String, String) {
    let link_host = get_link_host(&config.host);
    let dd = format!("tg://proxy?server={link_host}&port={}&secret=dd{}", config.port, config.secret);
    let ee = if config.fake_tls_domain.is_empty() {
        String::new()
    } else {
        format!(
            "tg://proxy?server={link_host}&port={}&secret=ee{}{}",
            config.port,
            config.secret,
            hex::encode(config.fake_tls_domain.as_bytes())
        )
    };
    (dd, ee)
}

fn log_banner(config: &ProxyConfig, h2: bool) {
    let (dd, ee) = proxy_links(config);
    let ftls = &config.fake_tls_domain;
    log::info!("{}", "=".repeat(60));
    log::info!("  Telegram MTProto WS Bridge Proxy");
    log::info!("  Listening on   {}:{}", config.host, config.port);
    log::info!("  Secret:        {}", config.secret);
    if !ftls.is_empty() {
        log::info!("  Fake TLS:      {ftls}");
    }
    log::info!("  Target DC IPs:");
    for (dc, ip) in &config.dc_redirects {
        log::info!("    DC{dc}: {ip}");
    }
    if config.fallback_cfproxy {
        let user = if config.cfproxy_user_domains.is_empty() {
            "auto".to_string()
        } else {
            config.cfproxy_user_domains.join(", ")
        };
        log::info!("  CF proxy:      enabled ({user})");
    }
    if !config.cfproxy_worker_domains.is_empty() {
        log::info!("  CF worker:     enabled ({})", config.cfproxy_worker_domains.join(", "));
    }
    if h2 {
        log::info!("  CF H2 media:   enabled");
    }
    if config.disable_secure {
        log::info!("  No secure:     enabled (port 80 for CF proxy/worker)");
    }
    log::info!("{}", "=".repeat(60));
    log::info!("  Connect:");
    log::info!("    {}", if ftls.is_empty() { &dd } else { &ee });
    log::info!("{}", "=".repeat(60));
}

pub async fn bind_listener(config: &ProxyConfig) -> io::Result<TcpListener> {
    let listener = TcpListener::bind((config.host.as_str(), config.port)).await?;
    Ok(listener)
}

pub async fn serve(shared: Arc<Shared>, listener: TcpListener, stop: CancellationToken) {
    let secret = match shared.config.secret_bytes() {
        Ok(secret) => secret,
        Err(err) => {
            log::error!("Secret must be valid hex: {err}");
            return;
        }
    };
    let mut listener = listener;
    let mut clients: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let shared = shared.clone();
                    let secret = secret.clone();
                    clients.spawn(handle_client(shared, stream, secret));
                }
                Err(err) => {
                    log::warn!("Listening socket error ({err}), restarting server");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    match bind_listener(&shared.config).await {
                        Ok(new_listener) => {
                            listener = new_listener;
                            log::warn!(
                                "Server restored, listening on {}:{}",
                                shared.config.host, shared.config.port
                            );
                        }
                        Err(err) => {
                            log::error!("Failed to restart server: {err:?}");
                            break;
                        }
                    }
                }
            },
        }
    }
    drop(listener);
    clients.abort_all();
    while clients.join_next().await.is_some() {}
}

pub async fn run(config: Arc<ProxyConfig>, stop: CancellationToken) -> io::Result<()> {
    let shared = Shared::new(config.clone());
    run_with(shared, stop).await
}

pub async fn run_with(shared: Arc<Shared>, stop: CancellationToken) -> io::Result<()> {
    let config = shared.config.clone();
    let listener = bind_listener(&config).await?;

    let refresh = if config.cfproxy_user_domains.is_empty() {
        Some(spawn_cfproxy_domain_refresh(config.clone(), shared.balancer.clone(), stop.clone()))
    } else {
        shared.balancer.update_domains_list(&config.cfproxy_user_domains);
        None
    };

    log_banner(&config, shared.h2_pool.is_some());

    shared.ws_pool.warmup();
    shared.cf_worker_pool.warmup();

    let stats_stop = stop.clone();
    let stats_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = stats_stop.cancelled() => return,
                _ = interval.tick() => log::info!("stats: {}", stats().summary()),
            }
        }
    });

    serve(shared.clone(), listener, stop.clone()).await;

    stats_task.abort();
    if let Some(refresh) = refresh {
        refresh.abort();
    }
    shared.ws_pool.close().await;
    shared.cf_worker_pool.close().await;
    if let Some(h2) = &shared.h2_pool {
        h2.close().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::test_support::FakeDialer;
    use tokio::io::duplex;

    const SECRET: [u8; 16] = [7u8; 16];

    fn client_handshake(proto_tag: [u8; 4], dc_idx: i16) -> ([u8; 64], AesCtr, AesCtr) {
        let mut rng = rand::thread_rng();
        let mut handshake = [0u8; 64];
        loop {
            rng.fill(&mut handshake[..]);
            if handshake[0] != RESERVED_FIRST_BYTE
                && !RESERVED_STARTS.iter().any(|s| handshake[..4] == s[..])
                && handshake[4..8] != RESERVED_CONTINUE
            {
                break;
            }
        }
        let prekey = handshake[8..40].to_vec();
        let iv = handshake[40..56].to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&prekey);
        hasher.update(SECRET);
        let key = hasher.finalize();
        let mut enc = AesCtr::new(&key, &iv);
        let mut tail = [0u8; 8];
        tail[..4].copy_from_slice(&proto_tag);
        tail[4..6].copy_from_slice(&dc_idx.to_le_bytes());
        let stream = enc.update(&handshake);
        for i in 0..8 {
            handshake[56 + i] = tail[i] ^ (stream[56 + i] ^ handshake[56 + i]);
        }
        let mut full = [0u8; 48];
        full.copy_from_slice(&handshake[8..56]);
        let mut send = AesCtr::new(&key, &iv);
        send.update(&ZERO_64);
        let mut reversed = full;
        reversed.reverse();
        let mut hasher = Sha256::new();
        hasher.update(&reversed[..32]);
        hasher.update(SECRET);
        let recv_key = hasher.finalize();
        let recv = AesCtr::new(&recv_key, &reversed[32..]);
        (handshake, send, recv)
    }

    #[test]
    fn handshake_roundtrip_extracts_dc_media_and_proto() {
        for (tag, dc_idx) in [(PROTO_TAG_ABRIDGED, 2i16), (PROTO_TAG_INTERMEDIATE, -4), (PROTO_TAG_SECURE, 10002)] {
            let (handshake, _, _) = client_handshake(tag, dc_idx);
            let info = try_handshake(&handshake, &SECRET).unwrap();
            assert_eq!(info.dc, (dc_idx as i32).abs());
            assert_eq!(info.is_media, dc_idx < 0);
            assert_eq!(info.proto_tag, tag);
        }
    }

    #[test]
    fn handshake_with_wrong_secret_is_rejected() {
        let (handshake, _, _) = client_handshake(PROTO_TAG_ABRIDGED, 2);
        assert!(try_handshake(&handshake, &[9u8; 16]).is_none());
    }

    #[test]
    fn relay_init_is_valid_and_carries_tag_and_dc() {
        for _ in 0..50 {
            let init = generate_relay_init(PROTO_TAG_INTERMEDIATE, -3);
            assert_ne!(init[0], RESERVED_FIRST_BYTE);
            assert!(!RESERVED_STARTS.iter().any(|s| init[..4] == s[..]));
            assert_ne!(init[4..8], RESERVED_CONTINUE);
            let mut dec = AesCtr::new(&init[8..40], &init[40..56]);
            let plain = dec.update(&init);
            assert_eq!(&plain[56..60], &PROTO_TAG_INTERMEDIATE);
            assert_eq!(i16::from_le_bytes([plain[60], plain[61]]), -3);
        }
    }

    #[test]
    fn crypto_ctx_roundtrips_between_client_and_telegram_sides() {
        let (handshake, mut client_send, mut client_recv) = client_handshake(PROTO_TAG_ABRIDGED, 2);
        let info = try_handshake(&handshake, &SECRET).unwrap();
        let relay_init = generate_relay_init(PROTO_TAG_ABRIDGED, 2);
        let mut ctx = build_crypto_ctx(&info.prekey_iv, &SECRET, &relay_init);

        let payload = b"mtproto payload bytes".to_vec();
        let from_client = client_send.update(&payload);
        let plain = ctx.clt_dec.update(&from_client);
        assert_eq!(plain, payload);
        let to_tg = ctx.tg_enc.update(&plain);

        let mut tg_side = AesCtr::new(&relay_init[8..40], &relay_init[40..56]);
        tg_side.update(&ZERO_64);
        assert_eq!(tg_side.update(&to_tg), payload);

        let mut tg_reply = {
            let mut rev = [0u8; 48];
            rev.copy_from_slice(&relay_init[8..56]);
            rev.reverse();
            AesCtr::new(&rev[..32], &rev[32..])
        };
        let reply = b"reply from telegram".to_vec();
        let from_tg = tg_reply.update(&reply);
        let down_plain = ctx.tg_dec.update(&from_tg);
        assert_eq!(down_plain, reply);
        let to_client = ctx.clt_enc.update(&down_plain);
        assert_eq!(client_recv.update(&to_client), reply);
    }

    #[test]
    fn links_use_dd_or_ee_secret() {
        let mut cfg = ProxyConfig::default();
        cfg.secret = "00112233445566778899aabbccddeeff".into();
        let (dd, ee) = proxy_links(&cfg);
        assert_eq!(dd, "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff");
        assert!(ee.is_empty());
        cfg.fake_tls_domain = "example.com".into();
        let (_, ee) = proxy_links(&cfg);
        assert!(ee.ends_with(&format!("secret=ee{}{}", cfg.secret, hex::encode("example.com"))));
    }

    async fn start(config: ProxyConfig, dialer: Arc<dyn WsDialer>) -> (Arc<Shared>, u16, CancellationToken) {
        let mut config = config;
        config.port = 0;
        let shared = Shared::with_dialer(Arc::new(config), dialer);
        let listener = bind_listener(&shared.config).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = CancellationToken::new();
        tokio::spawn(serve(shared.clone(), listener, stop.clone()));
        (shared, port, stop)
    }

    struct ScriptedDialer {
        servers: parking_lot::Mutex<Vec<tokio::io::DuplexStream>>,
    }

    impl WsDialer for ScriptedDialer {
        fn dial<'a>(
            &'a self,
            _host: &'a str,
            _domain: &'a str,
            _timeout: Duration,
            _path: &'a str,
            _options: crate::ws::ConnectOptions,
        ) -> futures_util::future::BoxFuture<'a, Result<crate::ws::RawWebSocket, crate::ws::WsError>> {
            Box::pin(async move {
                let (client, server) = duplex(1 << 20);
                self.servers.lock().push(server);
                let (r, w) = tokio::io::split(client);
                Ok(crate::ws::RawWebSocket::from_parts(Box::new(r), Box::new(w)))
            })
        }
    }

    async fn read_ws_frame(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        let mut len = (header[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await.unwrap();
            len = u16::from_be_bytes(ext) as usize;
        }
        let mut key = [0u8; 4];
        stream.read_exact(&mut key).await.unwrap();
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        crate::ws::xor_in_place(&mut payload, key);
        payload
    }

    #[tokio::test]
    async fn end_to_end_ws_pool_path_reencrypts_in_both_directions() {
        let dialer = Arc::new(ScriptedDialer { servers: parking_lot::Mutex::new(Vec::new()) });
        let mut cfg = ProxyConfig::default();
        cfg.secret = hex::encode(SECRET);
        cfg.pool_size = 1;
        cfg.fallback_cfproxy = false;
        let (shared, port, stop) = start(cfg, dialer.clone()).await;
        shared.ws_pool.warmup();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!dialer.servers.lock().is_empty());

        let (handshake, mut send, mut recv) = client_handshake(PROTO_TAG_INTERMEDIATE, 2);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&handshake).await.unwrap();
        let packet = {
            let mut p = 16u32.to_le_bytes().to_vec();
            p.extend_from_slice(&[0x42; 16]);
            p
        };
        client.write_all(&send.update(&packet)).await.unwrap();

        let mut upstream = {
            let mut servers = dialer.servers.lock();
            let mut found = None;
            for _ in 0..servers.len() {
                found = Some(servers.remove(0));
                break;
            }
            found.unwrap()
        };
        let relay_init = read_ws_frame(&mut upstream).await;
        assert_eq!(relay_init.len(), 64);
        let mut tg_dec = AesCtr::new(&relay_init[8..40], &relay_init[40..56]);
        tg_dec.update(&ZERO_64);
        let forwarded = read_ws_frame(&mut upstream).await;
        assert_eq!(tg_dec.update(&forwarded), packet);

        let mut rev = [0u8; 48];
        rev.copy_from_slice(&relay_init[8..56]);
        rev.reverse();
        let mut tg_enc = AesCtr::new(&rev[..32], &rev[32..]);
        let reply_plain = b"downstream-data!".to_vec();
        let reply = tg_enc.update(&reply_plain);
        let frame = crate::ws::build_frame(crate::ws::OP_BINARY, &reply, false);
        upstream.write_all(&frame).await.unwrap();

        let mut got = vec![0u8; reply_plain.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(recv.update(&got), reply_plain);
        stop.cancel();
    }

    #[tokio::test]
    async fn bad_secret_is_counted_and_drained_without_upstream_use() {
        let dialer = FakeDialer::new(|_, _| false);
        let mut cfg = ProxyConfig::default();
        cfg.secret = hex::encode([9u8; 16]);
        let (_shared, port, stop) = start(cfg, dialer.clone()).await;
        let before = stats().connections_bad.load(Ordering::Relaxed);
        let (handshake, _, _) = client_handshake(PROTO_TAG_ABRIDGED, 2);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&handshake).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(stats().connections_bad.load(Ordering::Relaxed) > before);
        stop.cancel();
    }

    #[tokio::test]
    async fn non_tls_client_gets_redirect_when_masking_enabled() {
        let dialer = FakeDialer::new(|_, _| false);
        let mut cfg = ProxyConfig::default();
        cfg.fake_tls_domain = "example.com".into();
        let (_shared, port, stop) = start(cfg, dialer).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 301 Moved Permanently"));
        assert!(text.contains("Location: https://example.com/"));
        stop.cancel();
    }

    #[tokio::test]
    async fn end_to_end_fake_tls_path_relays_through_ws_pool() {
        let dialer = Arc::new(ScriptedDialer { servers: parking_lot::Mutex::new(Vec::new()) });
        let mut cfg = ProxyConfig::default();
        cfg.secret = hex::encode(SECRET);
        cfg.pool_size = 1;
        cfg.fallback_cfproxy = false;
        cfg.fake_tls_domain = "example.com".into();
        let (shared, port, stop) = start(cfg, dialer.clone()).await;
        shared.ws_pool.warmup();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut session_id = [0u8; 32];
        rand::thread_rng().fill(&mut session_id);
        let hello = crate::fake_tls::build_client_hello_for_tests(&SECRET, now, session_id);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&hello).await.unwrap();

        let mut server_hello = vec![0u8; 127 + 6 + 5];
        client.read_exact(&mut server_hello).await.unwrap();
        assert_eq!(server_hello[0], 0x16);
        assert_eq!(&server_hello[44..76], &session_id);
        let appdata_len = u16::from_be_bytes([server_hello[127 + 6 + 3], server_hello[127 + 6 + 4]]) as usize;
        let mut padding = vec![0u8; appdata_len];
        client.read_exact(&mut padding).await.unwrap();

        let (handshake, mut send, mut recv) = client_handshake(PROTO_TAG_INTERMEDIATE, 2);
        let packet = {
            let mut p = 16u32.to_le_bytes().to_vec();
            p.extend_from_slice(&[0x33; 16]);
            p
        };
        let mut payload = handshake.to_vec();
        payload.extend_from_slice(&send.update(&packet));
        client.write_all(&crate::fake_tls::wrap_tls_record(&payload)).await.unwrap();

        let mut upstream = dialer.servers.lock().remove(0);
        let relay_init = read_ws_frame(&mut upstream).await;
        let mut tg_dec = AesCtr::new(&relay_init[8..40], &relay_init[40..56]);
        tg_dec.update(&ZERO_64);
        assert_eq!(tg_dec.update(&read_ws_frame(&mut upstream).await), packet);

        let mut rev = [0u8; 48];
        rev.copy_from_slice(&relay_init[8..56]);
        rev.reverse();
        let mut tg_enc = AesCtr::new(&rev[..32], &rev[32..]);
        let reply_plain = b"fake-tls-reply!!".to_vec();
        let frame = crate::ws::build_frame(crate::ws::OP_BINARY, &tg_enc.update(&reply_plain), false);
        upstream.write_all(&frame).await.unwrap();

        let mut record_header = [0u8; 5];
        client.read_exact(&mut record_header).await.unwrap();
        assert_eq!(record_header[0], 0x17);
        let mut body = vec![0u8; u16::from_be_bytes([record_header[3], record_header[4]]) as usize];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(recv.update(&body), reply_plain);
        stop.cancel();
    }

    #[tokio::test]
    async fn fake_tls_with_wrong_secret_is_not_served() {
        let dialer = FakeDialer::new(|_, _| false);
        let mut cfg = ProxyConfig::default();
        cfg.secret = hex::encode(SECRET);
        cfg.fake_tls_domain = "127.0.0.1".into();
        let (_shared, port, stop) = start(cfg, dialer).await;
        let before = stats().connections_masked.load(Ordering::Relaxed);
        let mut session_id = [0u8; 32];
        rand::thread_rng().fill(&mut session_id);
        let hello = crate::fake_tls::build_client_hello_for_tests(&[1u8; 16], 1, session_id);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&hello).await.unwrap();
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_)) | Err(_)));
        assert_eq!(stats().connections_masked.load(Ordering::Relaxed), before);
        stop.cancel();
    }

    #[tokio::test]
    async fn stop_token_closes_listener_and_clients() {
        let dialer = FakeDialer::new(|_, _| false);
        let (_shared, port, stop) = start(ProxyConfig::default(), dialer).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.cancel();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await.unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
}
